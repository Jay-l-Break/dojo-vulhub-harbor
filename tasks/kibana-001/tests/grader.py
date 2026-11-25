"""Grades trusted hard-oracle results for Dojo Vulhub tasks."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path

try:
    from . import oracle_contract
except ImportError:
    import oracle_contract

MetricValue = float | int
Metrics = dict[str, MetricValue]


def zero_metrics(
    contract: oracle_contract.OracleContract | None = None,
) -> Metrics:
    """Returns fail-closed metrics for a contract or unknown input."""
    groups_total = len(contract.groups) if contract is not None else 0
    oracles_total = len(contract.oracles) if contract is not None else 0
    return {
        "reward": 0.0,
        "groups_passed": 0,
        "groups_total": groups_total,
        "oracles_passed": 0,
        "oracles_total": oracles_total,
    }


def calculate_metrics(
    contract: oracle_contract.OracleContract,
    submission: oracle_contract.Submission,
    result: oracle_contract.OracleResult,
) -> Metrics:
    """Calculates weighted all-of group reward from trusted observations."""
    if (
        submission.task_id != contract.task_id
        or result.task_id != contract.task_id
        or result.run_id != submission.run_id
        or result.submission_sha256 != submission.sha256
        or not result.setup_valid
        or not result.baseline_clean
    ):
        return zero_metrics(contract)

    observations = {
        observation.oracle_id: observation for observation in result.observations
    }
    oracle_passed = {
        oracle.oracle_id: all(
            check_passed
            for unused_check_name, check_passed in observations[oracle.oracle_id].checks
        )
        for oracle in contract.oracles
    }
    group_passed = {
        group.oracle_group_id: all(
            oracle_passed[oracle_id] for oracle_id in group.all_of
        )
        for group in contract.groups
    }
    total_weight = sum(group.weight for group in contract.groups)
    passed_weight = sum(
        group.weight for group in contract.groups if group_passed[group.oracle_group_id]
    )
    return {
        "reward": passed_weight / total_weight,
        "groups_passed": sum(group_passed.values()),
        "groups_total": len(contract.groups),
        "oracles_passed": sum(oracle_passed.values()),
        "oracles_total": len(contract.oracles),
    }


def grade_files(
    contract_path: str | os.PathLike[str],
    submission_path: str | os.PathLike[str],
    oracle_result_path: str | os.PathLike[str],
) -> Metrics:
    """Grades three artifacts and returns zero for every invalid state."""
    try:
        contract = oracle_contract.load_contract(contract_path)
    except (
        OSError,
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        return zero_metrics()

    try:
        submission = oracle_contract.load_submission(submission_path, contract)
        result = oracle_contract.load_oracle_result(oracle_result_path, contract)
        return calculate_metrics(contract, submission, result)
    except (
        OSError,
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        return zero_metrics(contract)


def write_metrics(
    path: str | os.PathLike[str], metrics: Mapping[str, MetricValue]
) -> None:
    """Writes the singular Harbor reward JSON file."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(dict(metrics), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
