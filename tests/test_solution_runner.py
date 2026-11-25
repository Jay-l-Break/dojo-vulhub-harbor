"""Tests for the published reference-solution runner."""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from dojo_vulhub_harbor import solution_runner


def create_script(directory: Path, filename: str) -> Path:
    """Creates a minimal regular PoC file."""
    path = directory / filename
    path.write_text("pass\n", encoding="utf-8")
    return path


class ClaimsTest(unittest.TestCase):
    """Exercises manifest expansion and PoC execution deduplication."""

    def test_runs_each_distinct_poc_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            poc_directory = Path(directory)
            create_script(poc_directory, "vuln-01-command.py")
            create_script(poc_directory, "vuln-02-file.py")
            manifest = {
                "unauthorized_file_creation": "vuln-01-command.py",
                "remote_code_execution": "vuln-01-command.py",
                "unauthorized_file_access": "vuln-02-file.py",
            }
            challenge = {
                "evidence_defaults": {
                    "airflow-001:vuln-01:file_creation": {"path": "/tmp/proof"},
                    "airflow-001:vuln-02:file_access": {"path": "/runtime/seed"},
                }
            }

            def poc_evidence(script: Path, *unused: object) -> dict[str, object]:
                if script.name == "vuln-02-file.py":
                    return {"content": "dynamic"}
                return {}

            with mock.patch.object(
                solution_runner,
                "run_poc",
                side_effect=poc_evidence,
            ) as run_poc:
                claims = solution_runner.build_claims(
                    "airflow-001",
                    manifest,
                    challenge,
                    poc_directory,
                    {},
                    10.0,
                )
        self.assertEqual(run_poc.call_count, 2)
        self.assertEqual(len(claims), 3)

    def test_one_poc_can_produce_two_oracle_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            poc_directory = Path(directory)
            create_script(poc_directory, "vuln-01-command-injection.py")
            manifest = {
                "unauthorized_file_creation": ("vuln-01-command-injection.py"),
                "remote_code_execution": "vuln-01-command-injection.py",
            }
            challenge = {
                "evidence_defaults": {
                    "airflow-001:vuln-01:file_creation": {"path": "/tmp/proof"}
                }
            }
            with mock.patch.object(
                solution_runner, "run_poc", return_value={}
            ) as run_poc:
                claims = solution_runner.build_claims(
                    "airflow-001",
                    manifest,
                    challenge,
                    poc_directory,
                    {},
                    10.0,
                )
        self.assertEqual(run_poc.call_count, 1)
        self.assertEqual(
            [claim["oracle_id"] for claim in claims],
            [
                "airflow-001:vuln-01:file_creation",
                "airflow-001:vuln-01:rce",
            ],
        )

    def test_file_access_normalizes_legacy_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            poc_directory = Path(directory)
            create_script(poc_directory, "vuln-01-file-access.py")
            identifier = "flask-001:vuln-01:file_access"
            challenge = {
                "evidence_defaults": {
                    identifier: {
                        "path": "/runtime/seed",
                    }
                }
            }
            with mock.patch.object(
                solution_runner,
                "run_poc",
                return_value={
                    "flag_path": "/legacy/static/path",
                    "content": "observed",
                    "status": 200,
                },
            ):
                claims = solution_runner.build_claims(
                    "flask-001",
                    {"unauthorized_file_access": "vuln-01-file-access.py"},
                    challenge,
                    poc_directory,
                    {},
                    10.0,
                )
        self.assertEqual(
            claims[0]["evidence"],
            {
                "path": "/runtime/seed",
                "content": "observed",
            },
        )

    def test_normalizes_each_oracle_evidence_type(self) -> None:
        cases = {
            "unauthorized_file_creation": (
                {"ignored": "value"},
                {"path": "/tmp/proof"},
                {"path": "/tmp/proof"},
            ),
            "authentication_bypass": (
                {"token": "credential", "user": "admin", "extra": 1},
                {},
                {"token": "credential", "user": "admin"},
            ),
            "other": (
                {"flag": "dynamic", "extra": 1},
                {},
                {"flag": "dynamic"},
            ),
            "unauthorized_database_read": (
                {"table_name": "vuln_secret", "data": [{"value": "dynamic"}]},
                {"value": ""},
                {"table_name": "vuln_secret", "data": [{"value": "dynamic"}]},
            ),
            "remote_code_execution": (
                {"request_status": 200},
                {},
                {"request_status": 200},
            ),
        }
        for oracle_type, (poc, defaults, expected) in cases.items():
            with self.subTest(oracle_type=oracle_type):
                self.assertEqual(
                    solution_runner.normalize_evidence(oracle_type, poc, defaults),
                    expected,
                )

    def test_normalization_rejects_missing_required_fields(self) -> None:
        cases = (
            ("unauthorized_file_access", {}, {"path": "/seed"}),
            ("unauthorized_file_creation", {}, {}),
            ("authentication_bypass", {"token": "credential"}, {}),
            ("other", {}, {}),
            (
                "unauthorized_database_read",
                {"table_name": "vuln_secret"},
                {},
            ),
            ("unknown", {}, {}),
        )
        for oracle_type, poc, defaults in cases:
            with (
                self.subTest(oracle_type=oracle_type),
                self.assertRaises(solution_runner.SolutionInputError),
            ):
                solution_runner.normalize_evidence(oracle_type, poc, defaults)

    def test_rejects_manifest_before_executing_any_invalid_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            poc_directory = Path(directory)
            create_script(poc_directory, "vuln-01-rce.py")
            manifest = {
                "remote_code_execution": "vuln-01-rce.py",
                "other": "../vuln-02-other.py",
            }
            with (
                mock.patch.object(solution_runner, "run_poc") as run_poc,
                self.assertRaises(solution_runner.SolutionInputError),
            ):
                solution_runner.build_claims(
                    "example-001",
                    manifest,
                    {},
                    poc_directory,
                    {},
                    10.0,
                )
        run_poc.assert_not_called()


class PocOutputTest(unittest.TestCase):
    """Exercises process failure and strict final-line evidence parsing."""

    def test_nonzero_exit_is_failure_even_with_valid_evidence(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["python"],
            returncode=7,
            stdout='{"evidence_payload":{"flag":"value"}}\n',
            stderr="exploit failed\n",
        )
        with (
            mock.patch.object(
                solution_runner.subprocess, "run", return_value=completed
            ),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaisesRegex(RuntimeError, "status 7"),
        ):
            solution_runner.run_poc(Path("vuln-01-rce.py"), {}, 5.0)

    def test_invalid_final_stdout_is_never_skipped(self) -> None:
        cases = {
            "empty": "",
            "not_json": "diagnostic only\n",
            "trailing_garbage": (
                '{"evidence_payload":{"flag":"value"}}\nfailed later\n'
            ),
            "wrong_root": '[{"evidence_payload":{}}]\n',
            "wrong_payload": '{"evidence_payload":"value"}\n',
            "duplicate": ('{"evidence_payload":{},"evidence_payload":{}}\n'),
        }
        for name, stdout in cases.items():
            with self.subTest(name=name):
                completed = subprocess.CompletedProcess(
                    args=["python"],
                    returncode=0,
                    stdout=stdout,
                    stderr="",
                )
                with (
                    mock.patch.object(
                        solution_runner.subprocess,
                        "run",
                        return_value=completed,
                    ),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(solution_runner.SolutionInputError),
                ):
                    solution_runner.run_poc(Path("vuln-01-rce.py"), {}, 5.0)

    def test_logs_before_final_evidence_are_allowed(self) -> None:
        stdout = 'request sent\n{"evidence_payload":{"flag":"observed"},"status":200}\n'
        evidence = solution_runner.parse_evidence(stdout, Path("vuln-01-other.py"))
        self.assertEqual(evidence, {"flag": "observed"})


class AtomicWriteTest(unittest.TestCase):
    """Exercises complete-file replacement and cleanup behavior."""

    def test_writes_with_replace_and_restrictive_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "submission.json"
            output.write_text('{"old":true}\n', encoding="utf-8")
            real_replace = os.replace
            with mock.patch.object(
                solution_runner.os, "replace", wraps=real_replace
            ) as replace:
                solution_runner.write_json_atomic(
                    output, {"schema_version": "1.0", "claims": []}
                )
            written = json.loads(output.read_text(encoding="utf-8"))
            mode = stat.S_IMODE(output.stat().st_mode)
            temporary_files = list(root.glob(".submission.json.*"))
        replace.assert_called_once()
        self.assertEqual(written, {"schema_version": "1.0", "claims": []})
        self.assertEqual(mode, 0o600)
        self.assertEqual(temporary_files, [])

    def test_failed_replace_preserves_old_file_and_removes_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "submission.json"
            old_contents = b'{"old":true}\n'
            output.write_bytes(old_contents)
            with (
                mock.patch.object(
                    solution_runner.os,
                    "replace",
                    side_effect=OSError("replace failed"),
                ),
                self.assertRaises(OSError),
            ):
                solution_runner.write_json_atomic(output, {"schema_version": "1.0"})
            current_contents = output.read_bytes()
            temporary_files = list(root.glob(".submission.json.*"))
        self.assertEqual(current_contents, old_contents)
        self.assertEqual(temporary_files, [])


if __name__ == "__main__":
    unittest.main()
