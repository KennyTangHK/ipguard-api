"""Confine Python and native ZeroMQ test traffic to synthetic local fixtures."""

import ipaddress
import re
import socket
from collections.abc import Iterator
from typing import Any

import pytest
import zmq


def _check_host(host: object) -> None:
    if host == "localhost":
        return
    try:
        if isinstance(host, str) and ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise AssertionError("Tests may only use loopback hosts.")


def _check_address(sock: socket.socket, address: Any) -> None:
    if sock.family == socket.AF_UNIX:
        return
    if not isinstance(address, tuple) or not address:
        raise AssertionError("Tests may only use loopback addresses.")
    _check_host(address[0])


@pytest.fixture(autouse=True)
def prevent_provider_traffic(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Guard native libzmq separately from ordinary Python socket methods."""
    for method in ("connect", "connect_ex", "bind"):
        original = getattr(socket.socket, method)

        def guarded(
            sock: socket.socket, address: Any, *, _original: Any = original
        ) -> Any:
            _check_address(sock, address)
            return _original(sock, address)

        monkeypatch.setattr(socket.socket, method, guarded)
    sendto = socket.socket.sendto

    def local_sendto(sock: socket.socket, *args: Any) -> int:
        _check_address(sock, args[-1])
        return sendto(sock, *args)

    monkeypatch.setattr(socket.socket, "sendto", local_sendto)
    if hasattr(socket.socket, "sendmsg"):
        sendmsg = socket.socket.sendmsg

        def local_sendmsg(sock: socket.socket, *args: Any) -> int:
            if len(args) >= 4 and args[3] is not None:
                _check_address(sock, args[3])
            return sendmsg(sock, *args)

        monkeypatch.setattr(socket.socket, "sendmsg", local_sendmsg)
    getaddrinfo = socket.getaddrinfo

    def local_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        _check_host(host)
        return getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", local_getaddrinfo)
    for method in ("gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        resolve = getattr(socket, method)

        def local_resolve(host: Any, *, _resolve: Any = resolve) -> Any:
            _check_host(host)
            return _resolve(host)

        monkeypatch.setattr(socket, method, local_resolve)
    for method in ("connect", "bind"):
        zmq_original = getattr(zmq.Socket, method)

        def local_zmq(
            sock: zmq.Socket[Any], endpoint: str, *, _original: Any = zmq_original
        ) -> Any:
            if (
                not endpoint.startswith("inproc://")
                and re.fullmatch(
                    r"tcp://(?:127\.0\.0\.1|\[::1\]):(?:[0-9]{1,5}|\*)", endpoint
                )
                is None
            ):
                raise AssertionError("Protocol tests may only use loopback endpoints.")
            return _original(sock, endpoint)

        monkeypatch.setattr(zmq.Socket, method, local_zmq)
    yield
