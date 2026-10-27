"""Async DEALER/CURVE transport with correlated requests and bounded cleanup."""

import asyncio
import json
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass

import zmq
import zmq.asyncio
from zmq.utils.monitor import parse_monitor_message

from .errors import (
    ConnectionFailureError,
    InvalidInputError,
    IpguardError,
    RelayUnavailableError,
)
from .protocol import (
    MAX_MESSAGE_BYTES,
    Packet,
    assert_android_metadata,
    decode_frames,
    validate_endpoint,
)
from .validation import validate_duration, validate_routing_identity

type PacketHandler = Callable[[Packet], Awaitable[None]]
type FailureHandler = Callable[[IpguardError], None]
type Predicate = Callable[[Packet], bool]
type SendGuard = Callable[[], None]


def _reader_task(
    reader: Coroutine[object, object, None], name: str
) -> asyncio.Task[None]:
    try:
        return asyncio.create_task(reader, name=name)
    except BaseException:
        reader.close()
        raise


@dataclass(eq=False, slots=True)
class _Waiter:
    predicate: Predicate
    future: asyncio.Future[Packet]


class ZmqTransport:
    """A single connection. It never replays requests or release writes."""

    def __init__(
        self,
        identity: str,
        endpoint: str,
        timeout: float,
        on_packet: PacketHandler,
        on_failure: FailureHandler,
        server_key: str | None = None,
    ) -> None:
        validate_endpoint(endpoint)
        validate_routing_identity(identity)
        timeout = validate_duration(timeout, 300)
        self.identity, self.endpoint, self.timeout = identity, endpoint, timeout
        self.on_packet, self.on_failure, self.server_key = (
            on_packet,
            on_failure,
            server_key,
        )
        self._context: zmq.asyncio.Context | None = None
        self._socket: zmq.asyncio.Socket | None = None
        self._monitor: zmq.asyncio.Socket | None = None
        self._reader: asyncio.Task[None] | None = None
        self._monitor_reader: asyncio.Task[None] | None = None
        self._pending: set[_Waiter] = set()
        self._send_lock = asyncio.Lock()
        self._closed = False

    async def async_start(self) -> None:
        if self.server_key is not None and not zmq.has("curve"):
            raise ConnectionFailureError(
                "CURVE support is unavailable in this runtime."
            )
        try:
            context = self._context = zmq.asyncio.Context()
            socket = self._socket = context.socket(zmq.DEALER)
            socket.setsockopt(zmq.IDENTITY, self.identity.encode())
            socket.setsockopt(zmq.LINGER, 0)
            socket.setsockopt(zmq.IMMEDIATE, 1)
            socket.setsockopt(zmq.MAXMSGSIZE, MAX_MESSAGE_BYTES)
            socket.setsockopt(zmq.HANDSHAKE_IVL, int(self.timeout * 1000))
            socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
            socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, 60)
            socket.setsockopt(zmq.TCP_KEEPALIVE_INTVL, 60)
            socket.setsockopt(zmq.TCP_KEEPALIVE_CNT, 3)
            if self.server_key is not None:
                public, secret = zmq.curve_keypair()
                socket.curve_publickey, socket.curve_secretkey = public, secret
                socket.curve_serverkey = self.server_key.encode("ascii")
            self._monitor = socket.get_monitor_socket(
                events=zmq.EVENT_DISCONNECTED
                | zmq.EVENT_HANDSHAKE_FAILED_AUTH
                | zmq.EVENT_HANDSHAKE_FAILED_PROTOCOL
            )
            socket.connect(self.endpoint)
            self._reader = _reader_task(self._read(), "ipguard-reader")
            self._monitor_reader = _reader_task(self._read_monitor(), "ipguard-monitor")
        except BaseException as error:
            await self.async_close()
            if isinstance(
                error, asyncio.CancelledError | KeyboardInterrupt | SystemExit
            ):
                raise
            raise ConnectionFailureError(
                "Could not initialize the IPGUARD connection."
            ) from None

    async def async_send(
        self, packet: Packet, callee: str = "", *, before_send: SendGuard | None = None
    ) -> None:
        assert_android_metadata(packet)
        header = packet["header"]
        if not isinstance(header, dict) or header["sender"] != self.identity:
            raise InvalidInputError("Message sender does not match this installation.")
        routing = validate_routing_identity(callee) if callee else b""
        payload = json.dumps(packet, separators=(",", ":")).encode()
        if len(routing) + len(payload) > MAX_MESSAGE_BYTES:
            raise InvalidInputError("Outgoing message exceeds supported bounds.")
        frames = [routing, payload] if callee else [payload]
        if callee and self._send_lock.locked():
            raise RelayUnavailableError(
                "The connection is busy; no release was queued."
            )
        try:
            async with asyncio.timeout(self.timeout), self._send_lock:
                if self._closed or self._socket is None:
                    raise ConnectionFailureError("IPGUARD connection is closed.")
                if before_send is not None:
                    before_send()
                try:
                    await self._socket.send_multipart(
                        frames, flags=zmq.DONTWAIT if callee else 0
                    )
                except zmq.ZMQError:
                    raise ConnectionFailureError(
                        "Could not send to the IPGUARD service."
                    ) from None
        except TimeoutError:
            raise ConnectionFailureError(
                "Timed out sending to the IPGUARD service."
            ) from None

    async def async_request(
        self,
        packet: Packet,
        predicate: Predicate,
        callee: str = "",
        *,
        before_send: SendGuard | None = None,
    ) -> Packet:
        waiter = _Waiter(predicate, asyncio.get_running_loop().create_future())
        self._pending.add(waiter)
        try:
            await self.async_send(packet, callee, before_send=before_send)
            async with asyncio.timeout(self.timeout):
                return await waiter.future
        except TimeoutError:
            raise ConnectionFailureError(
                "Timed out waiting for an IPGUARD response."
            ) from None
        finally:
            self._pending.discard(waiter)
            if not waiter.future.done():
                waiter.future.cancel()
            elif not waiter.future.cancelled():
                waiter.future.exception()

    async def _read(self) -> None:
        assert self._socket is not None
        try:
            while not self._closed:
                frames = await self._socket.recv_multipart()
                packet = decode_frames(frames)
                if packet is None:
                    continue
                await self.on_packet(packet)
                for waiter in tuple(self._pending):
                    if not waiter.future.done() and waiter.predicate(packet):
                        waiter.future.set_result(packet)
        except asyncio.CancelledError:
            raise
        except IpguardError as error:
            self._fail(error)
        except Exception:
            if not self._closed:
                self._fail(
                    ConnectionFailureError(
                        "IPGUARD connection could not read service messages."
                    )
                )

    @property
    def closed(self) -> bool:
        return self._closed

    async def _read_monitor(self) -> None:
        assert self._monitor is not None
        try:
            while not self._closed:
                message = parse_monitor_message(await self._monitor.recv_multipart())
                if int(message["event"]) in (
                    zmq.EVENT_HANDSHAKE_FAILED_AUTH,
                    zmq.EVENT_HANDSHAKE_FAILED_PROTOCOL,
                ):
                    self._fail(
                        ConnectionFailureError("IPGUARD secure handshake failed.")
                    )
                    return
                if int(message["event"]) == zmq.EVENT_DISCONNECTED:
                    self._fail(
                        ConnectionFailureError("IPGUARD connection was interrupted.")
                    )
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            if not self._closed:
                self._fail(ConnectionFailureError("IPGUARD connection monitor failed."))

    def _fail(self, error: IpguardError) -> None:
        if self._closed:
            return
        self._shutdown(error)
        self.on_failure(error)

    def _shutdown(self, error: IpguardError) -> None:
        self._closed = True
        for waiter in tuple(self._pending):
            if not waiter.future.done():
                waiter.future.set_exception(error)
        self._pending.clear()
        socket, self._socket = self._socket, None
        monitor, self._monitor = self._monitor, None
        for connection in (socket, monitor):
            if connection is not None:
                connection.close(linger=0)
        current = asyncio.current_task()
        for task in (self._reader, self._monitor_reader):
            if task is not None and task is not current:
                task.cancel()
        context, self._context = self._context, None
        if context is not None:
            context.term()

    async def async_close(self) -> None:
        self._shutdown(ConnectionFailureError("IPGUARD connection is closed."))
        current = asyncio.current_task()
        tasks = [
            task
            for task in (self._reader, self._monitor_reader)
            if task is not None and task is not current
        ]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
