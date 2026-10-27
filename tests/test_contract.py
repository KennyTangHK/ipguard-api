"""Verify bootstrap behavior and input/credential boundaries."""

import asyncio
import traceback
from unittest.mock import Mock
from uuid import uuid4

import pytest

from ipguard_api import (
    AuthenticationError,
    InvalidInputError,
    IpguardClient,
    Session,
    validate_identifier,
    validate_installation_label,
    validate_verification_code,
)


def test_identifiers_and_codes_preserve_the_api_values() -> None:
    assert validate_identifier(" User.Name@Example.invalid ").value == (
        "User.Name@Example.invalid"
    )
    assert validate_identifier("+44 7700 900123").value == "00447700900123"
    assert validate_identifier("00447700900123").value == "00447700900123"
    assert validate_verification_code("012345") == "012345"


@pytest.mark.parametrize(
    "identifier", ["", "invalid-email", "07700900123", "+٠٠١٢٣٤٥٦"]
)
def test_invalid_identifiers_do_not_echo_account_input(identifier: str) -> None:
    with pytest.raises(InvalidInputError) as error:
        validate_identifier(identifier)
    if identifier:
        assert identifier not in str(error.value)


@pytest.mark.parametrize("code", ["12345", "1234567", " 012345", "١٢٣٤٥٦", 123456])
def test_invalid_codes_never_appear_in_errors(code: object) -> None:
    with pytest.raises(InvalidInputError) as error:
        validate_verification_code(code)  # type: ignore[arg-type]
    assert str(code) not in str(error.value)


@pytest.mark.parametrize(
    "label", ["", "IPGUARD CLI", "Node.js", "Home Assistant", "customclient"]
)
def test_installation_label_requires_a_personal_name(label: str) -> None:
    with pytest.raises(InvalidInputError):
        validate_installation_label(label)
    assert validate_installation_label(" Clive's phone ") == "Clive's phone"


@pytest.mark.parametrize(
    "marker",
    [
        "cli",
        "node.js",
        "homeassistant",
        "customclient",
        "codex",
        "poc",
        "proof of concept",
        "automation",
        "integration",
        "script",
        "python",
        "curl",
        "bot",
        "macbook",
        "macos",
        "windows",
        "linux",
        "docker",
        "terminal",
        "laptop",
        "desktop",
        "raspberrypi",
    ],
)
def test_all_implementation_labels_are_blocked_without_filtering_account_values(
    marker: str,
) -> None:
    with pytest.raises(InvalidInputError):
        validate_installation_label(f"Personal {marker}")
    email = f"{marker.replace(' ', '-')}@example.invalid"
    assert validate_identifier(email).value == email
    assert validate_installation_label("Pixel 7") == "Pixel 7"


def test_session_serialization_is_explicit_and_repr_excludes_credentials() -> None:
    session = Session(
        identity=str(uuid4()),
        identifier=validate_identifier("user@example.invalid"),
        label="Personal phone",
        verification_code="012345",
        server_public_key="synthetic-server-public-key",
        sip_password="synthetic-password",
    )
    for value in (
        session.identity,
        session.identifier.value,
        session.label,
        session.verification_code,
        session.server_public_key,
        session.sip_password,
    ):
        if value is not None:
            assert value not in repr(session)
    assert Session.from_dict(session.to_dict()) == session
    with pytest.raises(InvalidInputError) as error:
        Session.from_dict({**session.to_dict(), "verification_code": 123456})
    assert "123456" not in str(error.value)


async def test_invalid_z85_key_is_rejected_before_connection() -> None:
    session = Session(
        identity=str(uuid4()),
        identifier=validate_identifier("user@example.invalid"),
        label="Personal phone",
        verification_code="012345",
        server_public_key="#" * 40,
        sip_password="synthetic-password",
    )
    async with IpguardClient() as client:
        with pytest.raises(AuthenticationError):
            await client.async_connect(session)
        assert not client.connected


@pytest.mark.parametrize(
    "value",
    [
        False,
        True,
        "10",
        None,
        -1,
        0,
        0.0009,
        300.001,
        float("nan"),
        float("inf"),
        10**400,
    ],
)
def test_timeout_bounds_are_typed_and_sanitized(value: object) -> None:
    with pytest.raises(InvalidInputError):
        IpguardClient(timeout=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout", [0.001, 300])
def test_timeout_boundary_values_remain_supported(timeout: float) -> None:
    assert IpguardClient(timeout=timeout).timeout == timeout


@pytest.mark.parametrize(
    "options",
    [
        {"reconnect_delay": 0.0009},
        {"reconnect_delay": 3600.001},
        {"max_reconnect_delay": float("inf")},
        {"max_reconnect_delay": 0.0009},
        {"reconnect_delay": 5, "max_reconnect_delay": 4},
    ],
)
def test_reconnect_delay_bounds(options: dict) -> None:
    with pytest.raises(InvalidInputError):
        IpguardClient(**options)
    IpguardClient(reconnect_delay=0.001, max_reconnect_delay=3600)


@pytest.mark.parametrize(
    "identifier",
    ["x" * 1025, "x" * 310 + "@example.invalid", "bad\ud800@example.invalid"],
)
def test_identifier_byte_limits_and_invalid_utf8(identifier: str) -> None:
    with pytest.raises(InvalidInputError) as raised:
        validate_identifier(identifier)
    assert identifier not in str(raised.value)


def test_email_byte_limit_accepts_boundary() -> None:
    value = "x" * 304 + "@example.invalid"
    assert len(value.encode()) == 320
    assert validate_identifier(value).value == value


@pytest.mark.parametrize(
    "identity", ["", "x" * 256, "é" * 128, "bad\ud800", "bad\0identity"]
)
def test_routing_identity_is_validated_before_resources(
    identity: str, monkeypatch
) -> None:
    import zmq.asyncio

    from ipguard_api.transport import ZmqTransport

    context = Mock()
    monkeypatch.setattr(zmq.asyncio, "Context", context)
    with pytest.raises(InvalidInputError):
        ZmqTransport(identity, "tcp://127.0.0.1:1", 1, Mock(), Mock())
    context.assert_not_called()


@pytest.mark.parametrize(
    "stage",
    ["context", "socket", "options", "monitor", "connect", "reader", "monitor_reader"],
)
async def test_socket_initialization_failure_closes_all_created_resources(
    stage: str, monkeypatch
) -> None:
    import zmq.asyncio

    from ipguard_api import ConnectionFailureError
    from ipguard_api.transport import ZmqTransport

    context, socket, monitor = Mock(), Mock(), Mock()
    context.socket.return_value = socket
    socket.get_monitor_socket.return_value = monitor
    factory = Mock(return_value=context)
    monkeypatch.setattr(zmq.asyncio, "Context", factory)
    error = OSError("synthetic-private-initialization-secret")
    if stage == "context":
        factory.side_effect = error
    elif stage == "socket":
        context.socket.side_effect = error
    elif stage == "options":
        socket.setsockopt.side_effect = error
    elif stage == "monitor":
        socket.get_monitor_socket.side_effect = error
    elif stage == "connect":
        socket.connect.side_effect = error
    else:
        create_task = asyncio.create_task
        calls = 0

        def fail_task(coroutine, **kwargs):
            nonlocal calls
            calls += 1
            if calls == (1 if stage == "reader" else 2):
                raise error
            return create_task(coroutine, **kwargs)

        monkeypatch.setattr(asyncio, "create_task", fail_task)
    transport = ZmqTransport(
        "test-installation", "tcp://127.0.0.1:1", 1, Mock(), Mock()
    )
    with pytest.raises(ConnectionFailureError) as raised:
        await transport.async_start()
    assert "synthetic-private-initialization-secret" not in "".join(
        traceback.format_exception(raised.value)
    )
    assert transport.closed and transport._context is None
    assert transport._socket is None and transport._monitor is None
    if stage != "context":
        context.term.assert_called_once()
    if stage not in ("context", "socket"):
        socket.close.assert_called_once_with(linger=0)
    if stage in ("connect", "reader", "monitor_reader"):
        monitor.close.assert_called_once_with(linger=0)
    await transport.async_close()


async def test_initialization_cancellation_cleans_resources_and_propagates(
    monkeypatch,
) -> None:
    import zmq.asyncio

    from ipguard_api.transport import ZmqTransport

    context, socket, monitor = Mock(), Mock(), Mock()
    context.socket.return_value = socket
    socket.get_monitor_socket.return_value = monitor
    socket.connect.side_effect = asyncio.CancelledError
    monkeypatch.setattr(zmq.asyncio, "Context", Mock(return_value=context))
    transport = ZmqTransport(
        "test-installation", "tcp://127.0.0.1:1", 1, Mock(), Mock()
    )
    with pytest.raises(asyncio.CancelledError):
        await transport.async_start()
    socket.close.assert_called_once_with(linger=0)
    monitor.close.assert_called_once_with(linger=0)
    context.term.assert_called_once()
