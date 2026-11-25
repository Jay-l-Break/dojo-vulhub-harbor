"""Fixed TCP to Unix-socket bridges for isolated task networks."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import socket
import stat
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "1.0"
CALLBACK_PORT = 4444
MAX_CONFIG_BYTES = 64 * 1024
MAX_SOCKET_PATH_BYTES = 103
BUFFER_BYTES = 64 * 1024


class BridgeConfigError(ValueError):
    """Raised when a bridge configuration is unsafe or malformed."""


@dataclass(frozen=True)
class BridgeMapping:
    """One immutable main-port to target-port mapping."""

    local_port: int
    target_port: int


@dataclass(frozen=True)
class BridgeConfig:
    """Public configuration shared by the main and target bridge roles."""

    socket_dir: Path
    listen_host: str
    target_host: str
    forward: tuple[BridgeMapping, ...]
    reverse: tuple[BridgeMapping, ...]

    def forward_socket_path(self, mapping: BridgeMapping) -> Path:
        """Returns the UDS for a main-to-target mapping."""
        return self.socket_dir / (
            f"forward-{mapping.local_port}-to-{mapping.target_port}.sock"
        )

    def reverse_socket_path(self, mapping: BridgeMapping) -> Path:
        """Returns the UDS for a target-to-main mapping."""
        return self.socket_dir / (
            f"reverse-{mapping.local_port}-to-{mapping.target_port}.sock"
        )


def require_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    """Rejects missing and unexpected mapping keys."""
    actual = set(value)
    if actual != expected:
        raise BridgeConfigError(
            f"{context} keys differ: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def validate_socket_dir(value: Any) -> Path:
    """Returns a safe absolute socket directory."""
    if not isinstance(value, str) or not value:
        raise BridgeConfigError("socket_dir must be a nonempty string")
    path = Path(value)
    if not path.is_absolute() or ".." in PurePosixPath(value).parts:
        raise BridgeConfigError("socket_dir must be absolute without '..'")
    return path


def validate_host(value: Any, name: str) -> str:
    """Returns a host name without control characters."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or any(character.isspace() for character in value)
        or any(ord(character) < 32 for character in value)
    ):
        raise BridgeConfigError(f"{name} must be a safe nonempty host name")
    return value


def parse_port(value: str, context: str) -> int:
    """Parses a non-callback TCP port."""
    if not value.isdigit():
        raise BridgeConfigError(f"{context} must be a decimal TCP port")
    port = int(value)
    if port < 1 or port > 65535:
        raise BridgeConfigError(f"{context} must be between 1 and 65535")
    if port == CALLBACK_PORT:
        raise BridgeConfigError(
            f"port {CALLBACK_PORT} is reserved for the target-only RCE callback"
        )
    return port


def parse_mapping(value: Any, index: int, name: str) -> BridgeMapping:
    """Parses one fixed ``listener:destination`` mapping."""
    if not isinstance(value, str) or value.count(":") != 1:
        raise BridgeConfigError(
            f"{name}[{index}] must use the 'listener:destination' form"
        )
    local, target = value.split(":", 1)
    return BridgeMapping(
        local_port=parse_port(local, f"{name}[{index}] listener port"),
        target_port=parse_port(target, f"{name}[{index}] destination port"),
    )


def parse_config(document: Any) -> BridgeConfig:
    """Parses a strict multi-port bridge configuration."""
    if not isinstance(document, dict):
        raise BridgeConfigError("bridge config must be an object")
    require_exact_keys(
        document,
        {
            "schema_version",
            "socket_dir",
            "listen_host",
            "target_host",
            "forward",
            "reverse",
        },
        "config",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise BridgeConfigError(f"schema_version must be {SCHEMA_VERSION!r}")
    if document["listen_host"] != "127.0.0.1":
        raise BridgeConfigError("listen_host must be 127.0.0.1")
    raw_forward = document["forward"]
    raw_reverse = document["reverse"]
    if not isinstance(raw_forward, list) or not isinstance(raw_reverse, list):
        raise BridgeConfigError("forward and reverse must be arrays")
    if not raw_forward and not raw_reverse:
        raise BridgeConfigError("at least one bridge mapping is required")
    forward = tuple(
        parse_mapping(value, index, "forward")
        for index, value in enumerate(raw_forward)
    )
    reverse = tuple(
        parse_mapping(value, index, "reverse")
        for index, value in enumerate(raw_reverse)
    )
    local_ports = [mapping.local_port for mapping in forward]
    if len(local_ports) != len(set(local_ports)):
        raise BridgeConfigError("forward local ports must be unique")
    reverse_ports = [mapping.local_port for mapping in reverse]
    if len(reverse_ports) != len(set(reverse_ports)):
        raise BridgeConfigError("reverse listener ports must be unique")
    config = BridgeConfig(
        socket_dir=validate_socket_dir(document["socket_dir"]),
        listen_host=validate_host(document["listen_host"], "listen_host"),
        target_host=validate_host(document["target_host"], "target_host"),
        forward=forward,
        reverse=reverse,
    )
    paths = [
        *(config.forward_socket_path(mapping) for mapping in config.forward),
        *(config.reverse_socket_path(mapping) for mapping in config.reverse),
    ]
    for path in paths:
        if len(os.fsencode(path)) > MAX_SOCKET_PATH_BYTES:
            raise BridgeConfigError("derived Unix socket path is too long")
    return config


def load_config(path: Path) -> BridgeConfig:
    """Loads a bounded regular JSON configuration file."""
    file_stat = path.lstat()
    if not stat.S_ISREG(file_stat.st_mode):
        raise BridgeConfigError("bridge config must be a regular file")
    if file_stat.st_size > MAX_CONFIG_BYTES:
        raise BridgeConfigError("bridge config exceeds 64 KiB")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeConfigError(f"cannot parse bridge config: {error}") from error
    return parse_config(document)


def prepare_socket_path(path: Path) -> None:
    """Creates the parent and removes only a stale socket."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() and not path.is_symlink():
        return
    file_stat = path.lstat()
    if not stat.S_ISSOCK(file_stat.st_mode):
        raise BridgeConfigError(f"refusing to replace non-socket bridge path {path}")
    path.unlink()


def relay_bidirectionally(first: socket.socket, second: socket.socket) -> None:
    """Copies bytes in both directions while preserving half-closes."""
    selector = selectors.DefaultSelector()
    peers = {first: second, second: first}
    selector.register(first, selectors.EVENT_READ)
    selector.register(second, selectors.EVENT_READ)
    try:
        while selector.get_map():
            for key, unused_mask in selector.select():
                del unused_mask
                source = key.fileobj
                destination = peers[source]
                try:
                    data = source.recv(BUFFER_BYTES)
                except OSError:
                    data = b""
                if data:
                    try:
                        destination.sendall(data)
                    except OSError:
                        return
                    continue
                selector.unregister(source)
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
    finally:
        selector.close()
        first.close()
        second.close()


class EndpointServer:
    """Threaded listener for one side of a fixed mapping."""

    def __init__(self) -> None:
        self.listener: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stopping = threading.Event()
        self.connection_threads: set[threading.Thread] = set()
        self.connection_lock = threading.Lock()

    def bind_listener(self) -> socket.socket:
        """Returns the role-specific bound listener."""
        raise NotImplementedError

    def connect_peer(self) -> socket.socket:
        """Connects to the role-specific fixed peer."""
        raise NotImplementedError

    def clean_up(self) -> None:
        """Removes role-specific resources after shutdown."""

    def start(self) -> None:
        """Binds and starts the accept loop."""
        self.listener = self.bind_listener()
        self.listener.listen()
        self.listener.settimeout(0.25)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        """Accepts clients until stopped."""
        if self.listener is None:
            raise RuntimeError("endpoint has not been started")
        while not self.stopping.is_set():
            try:
                client, unused_address = self.listener.accept()
                del unused_address
            except TimeoutError:
                continue
            except OSError:
                if self.stopping.is_set():
                    return
                raise
            thread = threading.Thread(
                target=self.handle_client,
                args=(client,),
                daemon=True,
            )
            with self.connection_lock:
                self.connection_threads.add(thread)
            thread.start()

    def handle_client(self, client: socket.socket) -> None:
        """Relays one client to the fixed peer."""
        try:
            peer = self.connect_peer()
            client.settimeout(None)
            peer.settimeout(None)
            relay_bidirectionally(client, peer)
        except OSError:
            client.close()
        finally:
            with self.connection_lock:
                self.connection_threads.discard(threading.current_thread())

    def stop(self) -> None:
        """Stops accepting clients and cleans up."""
        self.stopping.set()
        if self.listener is not None:
            self.listener.close()
        if self.thread is not None:
            self.thread.join(timeout=2)
        with self.connection_lock:
            threads = tuple(self.connection_threads)
        for thread in threads:
            thread.join(timeout=2)
        self.clean_up()


class ForwardMainEndpointServer(EndpointServer):
    """Exposes one loopback TCP port and connects to the shared UDS."""

    def __init__(self, config: BridgeConfig, mapping: BridgeMapping):
        super().__init__()
        self.config = config
        self.mapping = mapping

    def bind_listener(self) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.config.listen_host, self.mapping.local_port))
        return listener

    def connect_peer(self) -> socket.socket:
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.settimeout(5)
        peer.connect(str(self.config.forward_socket_path(self.mapping)))
        peer.settimeout(None)
        return peer


class ForwardTargetEndpointServer(EndpointServer):
    """Exposes one UDS and connects only to its fixed target TCP port."""

    def __init__(self, config: BridgeConfig, mapping: BridgeMapping):
        super().__init__()
        self.config = config
        self.mapping = mapping
        self.socket_path = config.forward_socket_path(mapping)

    def bind_listener(self) -> socket.socket:
        prepare_socket_path(self.socket_path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o666)
        return listener

    def connect_peer(self) -> socket.socket:
        return socket.create_connection(
            (self.config.target_host, self.mapping.target_port), timeout=5
        )

    def clean_up(self) -> None:
        try:
            file_stat = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISSOCK(file_stat.st_mode):
            self.socket_path.unlink()


class ReverseTargetEndpointServer(EndpointServer):
    """Accepts target-loopback callbacks and forwards them over a UDS."""

    def __init__(self, config: BridgeConfig, mapping: BridgeMapping):
        super().__init__()
        self.config = config
        self.mapping = mapping

    def bind_listener(self) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.config.listen_host, self.mapping.local_port))
        return listener

    def connect_peer(self) -> socket.socket:
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.settimeout(5)
        peer.connect(str(self.config.reverse_socket_path(self.mapping)))
        return peer


class ReverseMainEndpointServer(EndpointServer):
    """Accepts reverse UDS streams and connects to a main-loopback port."""

    def __init__(self, config: BridgeConfig, mapping: BridgeMapping):
        super().__init__()
        self.config = config
        self.mapping = mapping
        self.socket_path = config.reverse_socket_path(mapping)

    def bind_listener(self) -> socket.socket:
        prepare_socket_path(self.socket_path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o666)
        return listener

    def connect_peer(self) -> socket.socket:
        return socket.create_connection(
            (self.config.listen_host, self.mapping.target_port), timeout=5
        )

    def clean_up(self) -> None:
        try:
            file_stat = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISSOCK(file_stat.st_mode):
            self.socket_path.unlink()


class FixedBridge:
    """Runs every endpoint for either the main or target role."""

    def __init__(self, role: str, config: BridgeConfig):
        if role not in {"main", "target"}:
            raise BridgeConfigError("role must be 'main' or 'target'")
        forward_type = (
            ForwardMainEndpointServer if role == "main" else ForwardTargetEndpointServer
        )
        reverse_type = (
            ReverseMainEndpointServer if role == "main" else ReverseTargetEndpointServer
        )
        forward_servers = [forward_type(config, mapping) for mapping in config.forward]
        reverse_servers = [reverse_type(config, mapping) for mapping in config.reverse]
        self.servers = tuple(forward_servers + reverse_servers)

    def start(self) -> None:
        """Starts every endpoint or rolls back partial startup."""
        started: list[EndpointServer] = []
        try:
            for server in self.servers:
                server.start()
                started.append(server)
        except Exception:
            for server in reversed(started):
                server.stop()
            raise

    def stop(self) -> None:
        """Stops every endpoint."""
        for server in reversed(self.servers):
            server.stop()

    def wait(self) -> None:
        """Waits until interrupted."""
        event = threading.Event()
        try:
            event.wait()
        except KeyboardInterrupt:
            return


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parses the stable role-based command line."""
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("main", "target"))
    parser.add_argument("--config", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Runs one side of every configured fixed bridge."""
    arguments = parse_arguments(argv)
    bridge = FixedBridge(arguments.role, load_config(arguments.config))
    bridge.start()
    try:
        bridge.wait()
    finally:
        bridge.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
