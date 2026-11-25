"""Tests for fixed bidirectional TCP and Unix-socket bridges."""

from __future__ import annotations

import json
import socket
import socketserver
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Self

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from dojo_vulhub_harbor import fixed_bridge


def available_port() -> int:
    """Reserves and releases one loopback TCP port for a test."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    return port


def distinct_ports(count: int) -> list[int]:
    """Returns distinct currently available loopback ports."""
    ports: set[int] = set()
    while len(ports) < count:
        ports.add(available_port())
    return list(ports)


def bridge_document(
    socket_dir: Path,
    forward: list[str],
    reverse: list[str],
) -> dict[str, object]:
    """Builds one strict bridge configuration document."""
    return {
        "schema_version": "1.0",
        "socket_dir": str(socket_dir),
        "listen_host": "127.0.0.1",
        "target_host": "127.0.0.1",
        "forward": forward,
        "reverse": reverse,
    }


class EchoRequestHandler(socketserver.BaseRequestHandler):
    """Echoes all bytes after the client half-closes its write side."""

    def handle(self) -> None:
        chunks = []
        while True:
            chunk = self.request.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        self.request.sendall(b"echo:" + b"".join(chunks))


class ReusableThreadingTcpServer(socketserver.ThreadingTCPServer):
    """Threaded loopback server with deterministic cleanup."""

    allow_reuse_address = True
    daemon_threads = True


class RunningTcpServer:
    """Owns one background TCP server for a test."""

    def __init__(self, port: int):
        self.server = ReusableThreadingTcpServer(
            ("127.0.0.1", port), EchoRequestHandler
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *arguments: object) -> None:
        del arguments
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def bridge_round_trip(port: int, payload: bytes) -> bytes:
    """Sends a half-closed TCP request and reads the full response."""
    with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


class BridgeConfigTest(unittest.TestCase):
    """Exercises the fixed, strict bridge configuration."""

    def test_parses_forward_reverse_and_multiple_ports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ports = distinct_ports(8)
            config = fixed_bridge.parse_config(
                bridge_document(
                    Path(directory),
                    [f"{ports[0]}:{ports[1]}", f"{ports[2]}:{ports[3]}"],
                    [f"{ports[4]}:{ports[5]}", f"{ports[6]}:{ports[7]}"],
                )
            )
        self.assertEqual(len(config.forward), 2)
        self.assertEqual(len(config.reverse), 2)
        self.assertNotEqual(
            config.forward_socket_path(config.forward[0]),
            config.reverse_socket_path(config.reverse[0]),
        )

    def test_rejects_callback_port_in_every_mapping_position(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            other = available_port()
            cases = (
                ([f"4444:{other}"], []),
                ([f"{other}:4444"], []),
                ([], [f"4444:{other}"]),
                ([], [f"{other}:4444"]),
            )
            for forward, reverse in cases:
                with (
                    self.subTest(forward=forward, reverse=reverse),
                    self.assertRaises(fixed_bridge.BridgeConfigError),
                ):
                    fixed_bridge.parse_config(bridge_document(root, forward, reverse))

    def test_rejects_extra_keys_duplicate_listeners_and_symlink_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = distinct_ports(2)
            document = bridge_document(
                root / "sockets",
                [f"{first}:{second}", f"{first}:{second}"],
                [],
            )
            with self.assertRaises(fixed_bridge.BridgeConfigError):
                fixed_bridge.parse_config(document)

            document = bridge_document(root / "sockets", [f"{first}:{second}"], [])
            document["unexpected"] = True
            with self.assertRaises(fixed_bridge.BridgeConfigError):
                fixed_bridge.parse_config(document)

            target = root / "config.json"
            target.write_text(json.dumps(document), encoding="utf-8")
            link = root / "config-link.json"
            link.symlink_to(target)
            with self.assertRaises(fixed_bridge.BridgeConfigError):
                fixed_bridge.load_config(link)


class FixedBridgeIntegrationTest(unittest.TestCase):
    """Exercises both bridge directions and half-close propagation."""

    def test_forward_and_reverse_streams(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (
                forward_local,
                forward_target,
                reverse_target,
                reverse_main,
            ) = distinct_ports(4)
            config = fixed_bridge.parse_config(
                bridge_document(
                    Path(directory) / "sockets",
                    [f"{forward_local}:{forward_target}"],
                    [f"{reverse_target}:{reverse_main}"],
                )
            )
            main_bridge = fixed_bridge.FixedBridge("main", config)
            target_bridge = fixed_bridge.FixedBridge("target", config)
            with (
                RunningTcpServer(forward_target),
                RunningTcpServer(reverse_main),
            ):
                target_bridge.start()
                try:
                    main_bridge.start()
                    try:
                        self.assertEqual(
                            bridge_round_trip(forward_local, b"forward"),
                            b"echo:forward",
                        )
                        self.assertEqual(
                            bridge_round_trip(reverse_target, b"reverse"),
                            b"echo:reverse",
                        )
                    finally:
                        main_bridge.stop()
                finally:
                    target_bridge.stop()

    def test_refuses_to_replace_regular_file_at_socket_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local, target = distinct_ports(2)
            config = fixed_bridge.parse_config(
                bridge_document(root / "sockets", [f"{local}:{target}"], [])
            )
            socket_path = config.forward_socket_path(config.forward[0])
            socket_path.parent.mkdir(parents=True)
            socket_path.write_text("do not replace", encoding="utf-8")
            bridge = fixed_bridge.FixedBridge("target", config)
            with self.assertRaises(fixed_bridge.BridgeConfigError):
                bridge.start()
            self.assertEqual(socket_path.read_text(encoding="utf-8"), "do not replace")


if __name__ == "__main__":
    unittest.main()
