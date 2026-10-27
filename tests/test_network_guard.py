"""Verify the test suite cannot accidentally contact public or LAN services."""

import socket

import pytest
import zmq


@pytest.mark.parametrize(
    "host", ["203.0.113.1", "192.0.2.1", "192.168.1.1", "provider.example.invalid"]
)
def test_python_socket_connections_are_blocked(host):
    with socket.socket() as sock:
        with pytest.raises(AssertionError, match="loopback"):
            sock.connect((host, 80))
        with pytest.raises(AssertionError, match="loopback"):
            sock.connect_ex((host, 80))
    with socket.socket(type=socket.SOCK_DGRAM) as sock:
        with pytest.raises(AssertionError, match="loopback"):
            sock.sendto(b"synthetic", (host, 80))
    with pytest.raises(AssertionError, match="loopback"):
        socket.getaddrinfo(host, 80)


def test_python_loopback_is_available():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        with socket.create_connection(listener.getsockname()) as client:
            accepted, _ = listener.accept()
            with accepted:
                client.sendall(b"synthetic")
                assert accepted.recv(9) == b"synthetic"


@pytest.mark.parametrize(
    "endpoint",
    [
        "tcp://203.0.113.1:5579",
        "tcp://192.168.1.1:5579",
        "tcp://provider.example.invalid:5579",
        "tcp://*:5579",
    ],
)
def test_native_zmq_external_endpoints_are_blocked(endpoint):
    with zmq.Context() as context, context.socket(zmq.DEALER) as sock:
        with pytest.raises(AssertionError, match="loopback"):
            sock.connect(endpoint)
        with pytest.raises(AssertionError, match="loopback"):
            sock.bind(endpoint)
