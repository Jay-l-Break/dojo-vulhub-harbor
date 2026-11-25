"""Tests for fail-closed hard-oracle grading."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from dojo_vulhub_harbor import grader, oracle_contract

CHALLENGE_DIGEST = "sha256:" + "c" * 64


def make_contract_document() -> dict[str, object]:
    """Creates a two-group contract with one all-of group."""
    oracle_specs = (
        ("rce", "remote_code_execution"),
        ("file", "unauthorized_file_access"),
        ("database", "unauthorized_database_read"),
    )
    return {
        "schema_version": "1.0",
        "task_id": "airflow-001",
        "groups": [
            {
                "oracle_group_id": "primary",
                "weight": 3,
                "all_of": ["rce", "file"],
            },
            {
                "oracle_group_id": "secondary",
                "weight": 1,
                "all_of": ["database"],
            },
        ],
        "oracles": [
            {
                "oracle_id": oracle_id,
                "type": oracle_type,
                "required_checks": list(
                    oracle_contract.BASE_REQUIRED_CHECKS[oracle_type]
                ),
            }
            for oracle_id, oracle_type in oracle_specs
        ],
    }


def make_submission_document() -> dict[str, object]:
    """Creates an exact claim set for the test contract."""
    return {
        "schema_version": "1.0",
        "task_id": "airflow-001",
        "run_id": "run-123",
        "claims": [
            {"oracle_id": oracle_id, "evidence": {}}
            for oracle_id in ("rce", "file", "database")
        ],
    }


def make_result_document(
    contract_document: dict[str, object], submission_contents: bytes
) -> dict[str, object]:
    """Creates a passing result bound to exact submission bytes."""
    return {
        "schema_version": "1.0",
        "task_id": "airflow-001",
        "run_id": "run-123",
        "setup_valid": True,
        "baseline_clean": True,
        "submission_sha256": (
            "sha256:" + hashlib.sha256(submission_contents).hexdigest()
        ),
        "observations": [
            {
                "oracle_id": oracle["oracle_id"],
                "type": oracle["type"],
                "challenge_digest": CHALLENGE_DIGEST,
                "checks": {
                    check_name: True for check_name in oracle["required_checks"]
                },
            }
            for oracle in contract_document["oracles"]
        ],
    }


def write_artifacts(
    root: Path,
) -> tuple[Path, Path, Path, dict[str, object]]:
    """Writes one valid contract, submission, and trusted result."""
    contract_document = make_contract_document()
    submission_document = make_submission_document()
    contract_path = root / "contract.json"
    submission_path = root / "submission.json"
    result_path = root / "result.json"
    contract_path.write_text(
        json.dumps(contract_document, sort_keys=True), encoding="utf-8"
    )
    submission_contents = json.dumps(submission_document, sort_keys=True).encode(
        "utf-8"
    )
    submission_path.write_bytes(submission_contents)
    result_document = make_result_document(contract_document, submission_contents)
    result_path.write_text(
        json.dumps(result_document, sort_keys=True), encoding="utf-8"
    )
    return contract_path, submission_path, result_path, result_document


class GraderTest(unittest.TestCase):
    """Exercises weighted all-of scoring and artifact binding."""

    def test_all_hard_checks_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = write_artifacts(Path(directory))[:3]
            metrics = grader.grade_files(*paths)
        self.assertEqual(metrics["reward"], 1.0)
        self.assertEqual(metrics["groups_passed"], 2)
        self.assertEqual(metrics["oracles_passed"], 3)

    def test_all_of_group_fails_and_other_group_gets_weighted_credit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path, submission_path, result_path, result = write_artifacts(root)
            result["observations"][1]["checks"]["secret_match"] = False
            result_path.write_text(json.dumps(result), encoding="utf-8")
            metrics = grader.grade_files(contract_path, submission_path, result_path)
        self.assertEqual(metrics["reward"], 0.25)
        self.assertEqual(metrics["groups_passed"], 1)
        self.assertEqual(metrics["groups_total"], 2)
        self.assertEqual(metrics["oracles_passed"], 2)
        self.assertEqual(metrics["oracles_total"], 3)

    def test_setup_and_baseline_must_both_be_valid(self) -> None:
        for field_name in ("setup_valid", "baseline_clean"):
            with self.subTest(field=field_name):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    contract_path, submission_path, result_path, result = (
                        write_artifacts(root)
                    )
                    result[field_name] = False
                    result_path.write_text(json.dumps(result), encoding="utf-8")
                    metrics = grader.grade_files(
                        contract_path, submission_path, result_path
                    )
                self.assertEqual(
                    metrics,
                    grader.zero_metrics(
                        oracle_contract.parse_contract(make_contract_document())
                    ),
                )

    def test_task_run_and_submission_digest_mismatch_fail_closed(self) -> None:
        mutations = {
            "task_id": lambda result: result.update(task_id="wrong-task"),
            "run_id": lambda result: result.update(run_id="wrong-run"),
            "submission_sha256": lambda result: result.update(
                submission_sha256="sha256:" + "0" * 64
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    contract_path, submission_path, result_path, result = (
                        write_artifacts(root)
                    )
                    mutate(result)
                    result_path.write_text(json.dumps(result), encoding="utf-8")
                    metrics = grader.grade_files(
                        contract_path, submission_path, result_path
                    )
                self.assertEqual(metrics["reward"], 0.0)
                self.assertEqual(metrics["groups_passed"], 0)

    def test_raw_submission_bytes_are_digest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path, submission_path, result_path = write_artifacts(root)[:3]
            submission_path.write_bytes(submission_path.read_bytes() + b"\n")
            metrics = grader.grade_files(contract_path, submission_path, result_path)
        self.assertEqual(metrics["reward"], 0.0)

    def test_wrong_result_type_or_check_set_fails_closed(self) -> None:
        mutations = {
            "type": lambda result: result["observations"][0].update(type="other"),
            "missing_check": lambda result: result["observations"][0]["checks"].pop(
                "current_run"
            ),
            "extra_check": lambda result: result["observations"][0]["checks"].update(
                self_reported=True
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    contract_path, submission_path, result_path, result = (
                        write_artifacts(root)
                    )
                    mutate(result)
                    result_path.write_text(json.dumps(result), encoding="utf-8")
                    metrics = grader.grade_files(
                        contract_path, submission_path, result_path
                    )
                self.assertEqual(metrics["reward"], 0.0)

    def test_missing_malformed_oversized_and_symlink_results_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path, submission_path, valid_result = write_artifacts(root)[:3]
            missing = root / "missing.json"
            malformed = root / "malformed.json"
            malformed.write_text("{not json", encoding="utf-8")
            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (oracle_contract.MAX_JSON_BYTES + 1))
            symlink = root / "result-link.json"
            os.symlink(valid_result, symlink)
            for name, result_path in {
                "missing": missing,
                "malformed": malformed,
                "oversized": oversized,
                "symlink": symlink,
            }.items():
                with self.subTest(name=name):
                    metrics = grader.grade_files(
                        contract_path, submission_path, result_path
                    )
                    self.assertEqual(metrics["reward"], 0.0)
                    self.assertEqual(metrics["groups_total"], 2)

    def test_duplicate_json_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path, submission_path, result_path = write_artifacts(root)[:3]
            result_path.write_text(
                '{"schema_version":"1.0","schema_version":"1.0"}',
                encoding="utf-8",
            )
            metrics = grader.grade_files(contract_path, submission_path, result_path)
        self.assertEqual(metrics["reward"], 0.0)

    def test_calculation_exception_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = write_artifacts(Path(directory))[:3]
            with mock.patch.object(
                grader,
                "calculate_metrics",
                side_effect=RecursionError("adversarial input"),
            ):
                metrics = grader.grade_files(*paths)
        self.assertEqual(metrics["reward"], 0.0)
        self.assertEqual(metrics["groups_total"], 2)

    def test_adjacent_cli_writes_singular_reward_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path, submission_path, result_path = write_artifacts(root)[:3]
            output_path = root / "reward.json"
            for file_name in ("oracle_contract.py", "grader.py", "cli.py"):
                (root / file_name).write_bytes(
                    (SOURCE_ROOT / "dojo_vulhub_harbor" / file_name).read_bytes()
                )
            environment = dict(os.environ)
            environment.pop("PYTHONPATH", None)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(root / "cli.py"),
                    "--contract",
                    str(contract_path),
                    "--submission",
                    str(submission_path),
                    "--oracle-result",
                    str(result_path),
                    "--output",
                    str(output_path),
                ],
                check=False,
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            metrics = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(metrics["reward"], 1.0)
        self.assertEqual(
            set(metrics),
            {
                "reward",
                "groups_passed",
                "groups_total",
                "oracles_passed",
                "oracles_total",
            },
        )


if __name__ == "__main__":
    unittest.main()
