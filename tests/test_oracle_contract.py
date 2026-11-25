"""Tests for strict hard-oracle artifact validation."""

from __future__ import annotations

import copy
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from dojo_vulhub_harbor import oracle_contract

DIGEST = "sha256:" + "a" * 64
CHALLENGE_DIGEST = "sha256:" + "b" * 64


def make_contract_document(
    oracle_types: tuple[str, ...] = ("remote_code_execution",),
) -> dict[str, object]:
    """Creates a valid contract with one group per oracle."""
    oracles = []
    groups = []
    for index, oracle_type in enumerate(oracle_types):
        oracle_id = f"oracle-{index}"
        oracles.append(
            {
                "oracle_id": oracle_id,
                "type": oracle_type,
                "required_checks": list(
                    oracle_contract.BASE_REQUIRED_CHECKS[oracle_type]
                ),
            }
        )
        groups.append(
            {
                "oracle_group_id": f"group-{index}",
                "weight": 1,
                "all_of": [oracle_id],
            }
        )
    return {
        "schema_version": "1.0",
        "task_id": "example-001",
        "groups": groups,
        "oracles": oracles,
    }


def make_submission_document(
    contract_document: dict[str, object],
) -> dict[str, object]:
    """Creates a valid submission for a contract document."""
    return {
        "schema_version": "1.0",
        "task_id": contract_document["task_id"],
        "run_id": "run-123",
        "claims": [
            {"oracle_id": oracle["oracle_id"], "evidence": {}}
            for oracle in contract_document["oracles"]
        ],
    }


def make_result_document(
    contract_document: dict[str, object],
) -> dict[str, object]:
    """Creates a valid trusted result for a contract document."""
    return {
        "schema_version": "1.0",
        "task_id": contract_document["task_id"],
        "run_id": "run-123",
        "setup_valid": True,
        "baseline_clean": True,
        "submission_sha256": DIGEST,
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


class StrictJsonTest(unittest.TestCase):
    """Exercises bounded, non-link, duplicate-free JSON loading."""

    def test_rejects_duplicate_keys_at_any_depth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(
                '{"root":{"oracle_id":"first","oracle_id":"second"}}',
                encoding="utf-8",
            )
            with self.assertRaises(oracle_contract.ContractValidationError):
                oracle_contract.read_strict_json(path)

    def test_rejects_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_bytes(b" " * (oracle_contract.MAX_JSON_BYTES + 1))
            with self.assertRaises(oracle_contract.ContractValidationError):
                oracle_contract.read_strict_json(path)

    def test_rejects_symlinks_and_non_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            os.symlink(target, link)
            for path in (link, root):
                with (
                    self.subTest(path=path),
                    self.assertRaises(oracle_contract.ContractValidationError),
                ):
                    oracle_contract.read_strict_json(path)

    def test_rejects_nonfinite_json_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, contents in {
                "constant": '{"weight":NaN}',
                "overflow": '{"weight":1e9999}',
            }.items():
                with self.subTest(name=name):
                    path = root / f"{name}.json"
                    path.write_text(contents, encoding="utf-8")
                    with self.assertRaises(oracle_contract.ContractValidationError):
                        oracle_contract.read_strict_json(path)


class ContractSchemaTest(unittest.TestCase):
    """Exercises exact public contract validation."""

    def test_accepts_all_types_and_task_specific_checks(self) -> None:
        document = make_contract_document(tuple(oracle_contract.BASE_REQUIRED_CHECKS))
        file_access = document["oracles"][1]
        file_access["required_checks"].append("trigger_seen")
        parsed = oracle_contract.parse_contract(document)
        self.assertEqual(len(parsed.oracles), 6)
        self.assertIn("trigger_seen", parsed.oracles[1].required_checks)

    def test_rejects_unknown_keys_types_and_missing_baselines(self) -> None:
        cases = []

        unknown_key = make_contract_document()
        unknown_key["unexpected"] = True
        cases.append(unknown_key)

        unsupported_type = make_contract_document()
        unsupported_type["oracles"][0]["type"] = "self_reported"
        cases.append(unsupported_type)

        missing_baseline = make_contract_document()
        missing_baseline["oracles"][0]["required_checks"].pop()
        cases.append(missing_baseline)

        duplicate_check = make_contract_document()
        checks = duplicate_check["oracles"][0]["required_checks"]
        checks.append(checks[0])
        cases.append(duplicate_check)

        for index, document in enumerate(cases):
            with (
                self.subTest(case=index),
                self.assertRaises(oracle_contract.ContractValidationError),
            ):
                oracle_contract.parse_contract(document)

    def test_rejects_invalid_group_oracle_relationships(self) -> None:
        unknown_oracle = make_contract_document()
        unknown_oracle["groups"][0]["all_of"] = ["missing"]

        reused_oracle = make_contract_document()
        reused_oracle["groups"].append(
            {
                "oracle_group_id": "second",
                "weight": 1,
                "all_of": ["oracle-0"],
            }
        )

        ungrouped_oracle = make_contract_document(("remote_code_execution", "other"))
        ungrouped_oracle["groups"].pop()

        duplicate_oracle = make_contract_document(("remote_code_execution", "other"))
        duplicate_oracle["oracles"][1]["oracle_id"] = "oracle-0"

        for name, document in {
            "unknown": unknown_oracle,
            "reused": reused_oracle,
            "ungrouped": ungrouped_oracle,
            "duplicate": duplicate_oracle,
        }.items():
            with (
                self.subTest(name=name),
                self.assertRaises(oracle_contract.ContractValidationError),
            ):
                oracle_contract.parse_contract(document)

    def test_rejects_nonpositive_nonfinite_and_boolean_weights(self) -> None:
        for weight in (0, -1, float("inf"), True, "1"):
            with self.subTest(weight=weight):
                document = make_contract_document()
                document["groups"][0]["weight"] = weight
                with self.assertRaises(oracle_contract.ContractValidationError):
                    oracle_contract.parse_contract(document)


class SubmissionSchemaTest(unittest.TestCase):
    """Exercises exact agent submission validation."""

    def setUp(self) -> None:
        self.document = make_contract_document(("remote_code_execution", "other"))
        self.contract = oracle_contract.parse_contract(self.document)

    def test_accepts_exact_claims_with_object_evidence(self) -> None:
        submission = make_submission_document(self.document)
        submission["claims"][0]["evidence"] = {
            "agent_note": "not trusted by the grader"
        }
        parsed = oracle_contract.parse_submission(submission, self.contract, DIGEST)
        self.assertEqual(parsed.task_id, self.contract.task_id)
        self.assertEqual(parsed.sha256, DIGEST)
        self.assertEqual(len(parsed.claims), 2)

    def test_requires_exact_unique_claim_ids(self) -> None:
        missing = make_submission_document(self.document)
        missing["claims"].pop()

        duplicate = make_submission_document(self.document)
        duplicate["claims"][1]["oracle_id"] = "oracle-0"

        unknown = make_submission_document(self.document)
        unknown["claims"][1]["oracle_id"] = "unknown"

        for name, submission in {
            "missing": missing,
            "duplicate": duplicate,
            "unknown": unknown,
        }.items():
            with (
                self.subTest(name=name),
                self.assertRaises(oracle_contract.ContractValidationError),
            ):
                oracle_contract.parse_submission(submission, self.contract, DIGEST)

    def test_rejects_wrong_task_non_object_evidence_and_extra_keys(self) -> None:
        wrong_task = make_submission_document(self.document)
        wrong_task["task_id"] = "other-task"

        non_object = make_submission_document(self.document)
        non_object["claims"][0]["evidence"] = "self reported"

        extra_key = make_submission_document(self.document)
        extra_key["claims"][0]["passed"] = True

        for name, submission in {
            "task": wrong_task,
            "evidence": non_object,
            "key": extra_key,
        }.items():
            with (
                self.subTest(name=name),
                self.assertRaises(oracle_contract.ContractValidationError),
            ):
                oracle_contract.parse_submission(submission, self.contract, DIGEST)


class OracleResultSchemaTest(unittest.TestCase):
    """Exercises exact trusted result validation."""

    def setUp(self) -> None:
        self.document = make_contract_document(
            ("remote_code_execution", "unauthorized_file_access")
        )
        self.contract = oracle_contract.parse_contract(self.document)

    def test_accepts_exact_boolean_checks(self) -> None:
        result = make_result_document(self.document)
        result["observations"][1]["checks"]["secret_match"] = False
        parsed = oracle_contract.parse_oracle_result(result, self.contract)
        self.assertFalse(dict(parsed.observations[1].checks)["secret_match"])

    def test_rejects_wrong_type_and_nonboolean_check(self) -> None:
        wrong_type = make_result_document(self.document)
        wrong_type["observations"][0]["type"] = "other"

        nonboolean = make_result_document(self.document)
        nonboolean["observations"][0]["checks"]["current_run"] = 1

        for name, result in {
            "type": wrong_type,
            "boolean": nonboolean,
        }.items():
            with (
                self.subTest(name=name),
                self.assertRaises(oracle_contract.ContractValidationError),
            ):
                oracle_contract.parse_oracle_result(result, self.contract)

    def test_requires_exact_check_keys(self) -> None:
        missing = make_result_document(self.document)
        missing["observations"][0]["checks"].pop("current_run")

        extra = make_result_document(self.document)
        extra["observations"][0]["checks"]["self_reported"] = True

        for name, result in {"missing": missing, "extra": extra}.items():
            with (
                self.subTest(name=name),
                self.assertRaises(oracle_contract.ContractValidationError),
            ):
                oracle_contract.parse_oracle_result(result, self.contract)

    def test_requires_exact_unique_observation_ids(self) -> None:
        missing = make_result_document(self.document)
        missing["observations"].pop()

        duplicate = make_result_document(self.document)
        duplicate["observations"][1] = copy.deepcopy(duplicate["observations"][0])

        unknown = make_result_document(self.document)
        unknown["observations"][1]["oracle_id"] = "unknown"

        for name, result in {
            "missing": missing,
            "duplicate": duplicate,
            "unknown": unknown,
        }.items():
            with (
                self.subTest(name=name),
                self.assertRaises(oracle_contract.ContractValidationError),
            ):
                oracle_contract.parse_oracle_result(result, self.contract)

    def test_rejects_invalid_digests_task_and_top_level_keys(self) -> None:
        invalid_digest = make_result_document(self.document)
        invalid_digest["submission_sha256"] = "sha256:ABC"

        invalid_challenge = make_result_document(self.document)
        invalid_challenge["observations"][0]["challenge_digest"] = "abc"

        wrong_task = make_result_document(self.document)
        wrong_task["task_id"] = "wrong"

        extra = make_result_document(self.document)
        extra["passed"] = True

        for name, result in {
            "digest": invalid_digest,
            "challenge": invalid_challenge,
            "task": wrong_task,
            "key": extra,
        }.items():
            with (
                self.subTest(name=name),
                self.assertRaises(oracle_contract.ContractValidationError),
            ):
                oracle_contract.parse_oracle_result(result, self.contract)


if __name__ == "__main__":
    unittest.main()
