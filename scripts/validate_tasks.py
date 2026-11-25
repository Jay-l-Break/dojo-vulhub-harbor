#!/usr/bin/env python3
"""Validate the published Dojo Vulhub exploitation benchmark."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import stat
import sys
import tomllib
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

try:
    import yaml
except ImportError as error:
    raise SystemExit("PyYAML is required to validate tasks") from error


TASK_IDS = (
    "aiohttp-001",
    "airflow-001",
    "airflow-002",
    "airflow-003",
    "budibase-001",
    "celery-001",
    "chartbrew-001",
    "comfyui-001",
    "comfyui-002",
    "django-001",
    "django-002",
    "django-003",
    "django-004",
    "django-005",
    "django-006",
    "electron-002",
    "flask-001",
    "gradio-001",
    "gradio-002",
    "jumpserver-001",
    "jupyter-001",
    "kibana-001",
    "kibana-002",
    "kibana-003",
    "langflow-001",
    "langflow-002",
    "mongo-express-001",
    "n8n-001",
    "n8n-002",
    "next-js-001",
    "node-001",
    "node-002",
    "openclaw-001",
    "pdfjs-001",
    "pgadmin-001",
    "pgadmin-002",
    "pgadmin-003",
    "pgadmin-004",
    "pickle-001",
    "react-001",
    "rocketchat-001",
    "saltstack-001",
    "saltstack-002",
    "saltstack-003",
    "scrapyd-001",
    "superset-001",
    "superset-002",
    "supervisor-001",
    "vite-001",
    "vite-002",
    "vite-003",
    "vite-004",
    "yapi-001",
    "yapi-002",
)
EXPECTED_TASK_COUNT = 54
EXPECTED_ORACLE_COUNT = 58
EXPECTED_GROUP_COUNT = 55
EXPECTED_POC_COUNT = 56
REGISTRY_DATASET_NAME = "dojo-vulhub"
REGISTRY_DATASET_VERSION = "1.0"
REGISTRY_DATASET_DESCRIPTION = (
    "Local exploitation benchmark for 54 pinned Dojo Vulhub targets."
)
EXPECTED_ORACLE_TYPES = Counter(
    {
        "authentication_bypass": 5,
        "other": 5,
        "remote_code_execution": 31,
        "unauthorized_database_read": 3,
        "unauthorized_file_access": 11,
        "unauthorized_file_creation": 3,
    }
)
ORACLE_TYPES = frozenset(EXPECTED_ORACLE_TYPES)
SCHEMA_VERSION = "1.4"
SOURCE_REPOSITORY = "https://github.com/Jay-l-Break/dojo-vulhub"
REQUIRED_METADATA_KEYS = frozenset(
    {
        "source_repository",
        "source_branch",
        "source_commit",
        "oracle_types",
    }
)
BASE_TASK_FILES = frozenset(
    {
        "task.toml",
        "instruction.md",
        "environment/Dockerfile",
        "environment/Oracle.Dockerfile",
        "environment/docker-compose.yaml",
        "environment/oracle_contract.json",
        "environment/runtime_config.json",
        "environment/forward_bridge.json",
        "environment/callback_bridge.json",
        "environment/fixed_bridge.py",
        "environment/runtime_oracle.py",
        "environment/rce_helper.go",
        "environment/main-entrypoint.sh",
        "environment/gateway-entrypoint.sh",
        "tests/Dockerfile",
        "tests/test.sh",
        "tests/oracle_contract.json",
        "tests/oracle_contract.py",
        "tests/grader.py",
        "tests/cli.py",
        "solution/solve.sh",
        "solution/solution_runner.py",
        "solution/manifest.json",
    }
)
CANONICAL_COPIES = {
    "environment/fixed_bridge.py": "src/dojo_vulhub_harbor/fixed_bridge.py",
    "environment/runtime_oracle.py": "src/dojo_vulhub_harbor/runtime_oracle.py",
    "environment/rce_helper.go": "src/dojo_vulhub_harbor/rce_helper.go",
    "tests/oracle_contract.py": "src/dojo_vulhub_harbor/oracle_contract.py",
    "tests/grader.py": "src/dojo_vulhub_harbor/grader.py",
    "tests/cli.py": "src/dojo_vulhub_harbor/cli.py",
    "solution/solution_runner.py": "src/dojo_vulhub_harbor/solution_runner.py",
}
EXECUTABLE_FILES = (
    "environment/main-entrypoint.sh",
    "environment/gateway-entrypoint.sh",
    "tests/test.sh",
    "solution/solve.sh",
)
EXPECTED_INLINE_DOCKERFILES = frozenset(
    {
        ("airflow-001", "target"),
        ("airflow-002", "target"),
        ("airflow-003", "target"),
        ("chartbrew-001", "target"),
        ("django-001", "victim"),
        ("gradio-001", "target"),
        ("gradio-002", "target"),
        ("mongo-express-001", "target"),
        ("node-001", "target"),
        ("node-002", "db"),
        ("node-002", "target"),
        ("vite-001", "target"),
    }
)
FILE_CREATION_POC_FRAGMENTS = {
    "airflow-001": "/tmp/dojo-file-creation/airflow_001_created",
    "airflow-002": "/tmp/dojo-file-creation/airflow_002_created",
    "saltstack-002": "../../tmp/dojo-file-creation/saltstack-002-write-proof",
}
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
DIGEST_IMAGE_PATTERN = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
FROM_PATTERN = re.compile(
    r"\s*FROM(?:\s+--\S+)*\s+(?P<image>\S+)"
    r"(?:\s+AS\s+(?P<alias>\S+))?\s*(?:#.*)?",
    re.IGNORECASE,
)
POC_FILENAME_PATTERN = re.compile(r"vuln-[0-9]+-[a-z0-9-]+\.py")
PRIVATE_ECR_PATTERN = re.compile(
    r"[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com",
    re.IGNORECASE,
)
AWS_KEY_PATTERN = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")
STATIC_FLAG_PATTERN = re.compile(
    r"jaylbreak\.win\{[A-Za-z0-9_:+/=.-]{8,}\}", re.IGNORECASE
)
LONG_HEX_PATTERN = re.compile(r"(?<![0-9a-f])[0-9a-f]{48,}(?![0-9a-f])")
FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "capability",
        "challenge",
        "expected_content",
        "expected_secret",
        "expected_value",
        "flag",
        "nonce",
        "private_expected",
        "secret",
    }
)
FORBIDDEN_TEXT = (
    (re.compile(r"attack_flags", re.IGNORECASE), "legacy attack_flags"),
    (re.compile(r"sarif", re.IGNORECASE), "legacy SARIF content"),
    (
        re.compile(
            r"\b(?:vulnerability[- ]detection|static[- ]analysis)\b",
            re.IGNORECASE,
        ),
        "legacy detection-benchmark content",
    ),
    (PRIVATE_ECR_PATTERN, "private ECR reference"),
    (AWS_KEY_PATTERN, "AWS access key"),
    (re.compile(r"arn:aws(?:-us-gov|-cn)?:", re.IGNORECASE), "AWS ARN"),
    (re.compile(r"/var/run/docker\.sock"), "Docker socket"),
)
NETWORK_INSTALL_PATTERN = re.compile(
    r"\b(?:apt(?:-get)?|apk|dnf|yum)\b|\b(?:pip|pip3|uv\s+pip)\s+install\b"
)


@dataclass
class ValidationResult:
    """Collect validation failures without stopping at the first one."""

    errors: list[str] = field(default_factory=list)

    def check(self, condition: bool, message: str) -> bool:
        """Record a message when a condition is false."""
        if not condition:
            self.errors.append(message)
        return condition

    def add(self, message: str) -> None:
        """Record an unconditional validation failure."""
        self.errors.append(message)


@dataclass(frozen=True)
class RepositoryModules:
    """Canonical parsers and generators loaded from this repository."""

    contract: ModuleType
    runtime: ModuleType
    bridge: ModuleType
    oracle_specs: ModuleType
    stack_specs: ModuleType


@dataclass(frozen=True)
class TaskSummary:
    """Counts collected from one valid-enough generated task."""

    task_id: str
    oracle_types: tuple[str, ...]
    group_count: int
    poc_count: int


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse validator command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Benchmark repository root.",
    )
    return parser.parse_args(argv)


def load_module(path: Path, name: str) -> ModuleType:
    """Load one repository module without requiring package installation."""
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"Cannot load module from {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def load_repository_modules(repo_root: Path) -> RepositoryModules:
    """Load the canonical task parsers and specification helpers."""
    source = repo_root / "src/dojo_vulhub_harbor"
    scripts = repo_root / "scripts"
    return RepositoryModules(
        contract=load_module(
            source / "oracle_contract.py", "validator_oracle_contract"
        ),
        runtime=load_module(source / "runtime_oracle.py", "validator_runtime"),
        bridge=load_module(source / "fixed_bridge.py", "validator_bridge"),
        oracle_specs=load_module(scripts / "oracle_specs.py", "validator_oracle_specs"),
        stack_specs=load_module(scripts / "stack_specs.py", "validator_stack_specs"),
    )


def reject_duplicate_keys(
    pairs: Sequence[tuple[str, object]],
) -> dict[str, object]:
    """Build a JSON object while rejecting duplicate member names."""
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def reject_json_constant(value: str) -> object:
    """Reject nonstandard JSON constants."""
    raise ValueError(f"invalid JSON constant: {value}")


def load_json(path: Path, result: ValidationResult) -> dict[str, object] | None:
    """Load a strict JSON object."""
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        result.add(f"{path}: invalid JSON: {error}")
        return None
    if not isinstance(document, dict):
        result.add(f"{path}: JSON root must be an object")
        return None
    return document


def load_json_array(path: Path, result: ValidationResult) -> list[object] | None:
    """Load a strict JSON array."""
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        result.add(f"{path}: invalid JSON: {error}")
        return None
    if not isinstance(document, list):
        result.add(f"{path}: JSON root must be an array")
        return None
    return document


def load_toml(path: Path, result: ValidationResult) -> dict[str, Any] | None:
    """Load one TOML document."""
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        result.add(f"{path}: invalid TOML: {error}")
        return None
    return document


def load_yaml(path: Path, result: ValidationResult) -> dict[str, Any] | None:
    """Load one YAML mapping."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        result.add(f"{path}: invalid YAML: {error}")
        return None
    if not isinstance(document, dict):
        result.add(f"{path}: YAML root must be a mapping")
        return None
    return document


def validate_task_directories(tasks_dir: Path, result: ValidationResult) -> None:
    """Require exactly the canonical 54 task directories."""
    observed = sorted(path.name for path in tasks_dir.iterdir())
    result.check(
        observed == sorted(TASK_IDS),
        "tasks directory entries differ from the canonical set: "
        f"{sorted(set(observed).symmetric_difference(TASK_IDS))}",
    )
    non_directories = sorted(
        path.name
        for path in tasks_dir.iterdir()
        if not path.is_dir() or path.is_symlink()
    )
    result.check(
        not non_directories,
        f"tasks directory contains non-directory or symlink entries: {non_directories}",
    )
    result.check(
        len(observed) == EXPECTED_TASK_COUNT,
        f"expected {EXPECTED_TASK_COUNT} task entries, found {len(observed)}",
    )


def expected_registry_document() -> list[dict[str, object]]:
    """Return the canonical native Harbor registry document."""
    return [
        {
            "name": REGISTRY_DATASET_NAME,
            "version": REGISTRY_DATASET_VERSION,
            "description": REGISTRY_DATASET_DESCRIPTION,
            "tasks": [
                {"name": task_id, "path": f"tasks/{task_id}"}
                for task_id in sorted(TASK_IDS)
            ],
            "metrics": [],
        }
    ]


def validate_registry_manifest(repo_root: Path, result: ValidationResult) -> None:
    """Require one native registry dataset selecting the exact task set."""
    registry_path = repo_root / "registry.json"
    if not result.check(
        registry_path.is_file() and not registry_path.is_symlink(),
        "registry.json must be a regular file",
    ):
        return
    document = load_json_array(registry_path, result)
    if document is None:
        return
    result.check(
        document == expected_registry_document(),
        "registry.json differs from the canonical dojo-vulhub@1.0 dataset",
    )


def validate_file_layout(
    task_id: str,
    task_dir: Path,
    manifest: Mapping[str, object] | None,
    result: ValidationResult,
) -> None:
    """Require the generated publication layout and no symlinks."""
    expected = set(BASE_TASK_FILES)
    if manifest is not None:
        expected.update(
            f"solution/poc/{filename}"
            for filename in manifest.values()
            if isinstance(filename, str)
        )
    observed = {
        path.relative_to(task_dir).as_posix()
        for path in task_dir.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    result.check(
        observed == expected,
        f"{task_id}: generated files differ: "
        f"{sorted(observed.symmetric_difference(expected))}",
    )
    for relative_path in sorted(observed):
        path = task_dir / relative_path
        if path.is_symlink():
            result.add(f"{task_id}: symlink is not allowed: {relative_path}")
            continue
        result.check(
            path.stat().st_size > 0,
            f"{task_id}: generated file is empty: {relative_path}",
        )
    for relative_path in EXECUTABLE_FILES:
        path = task_dir / relative_path
        if path.is_file():
            result.check(
                bool(path.stat().st_mode & stat.S_IXUSR),
                f"{task_id}: {relative_path} must be executable",
            )


def validate_metadata(
    task_id: str, metadata: object, result: ValidationResult
) -> tuple[str | None, tuple[str, ...]]:
    """Validate immutable public source metadata."""
    if not isinstance(metadata, dict):
        result.add(f"{task_id}: [metadata] must be a table")
        return None, ()
    result.check(
        REQUIRED_METADATA_KEYS <= set(metadata),
        f"{task_id}: metadata lacks canonical source fields",
    )
    legacy_keys = sorted(key for key in metadata if key.startswith("legacy_"))
    result.check(
        not legacy_keys,
        f"{task_id}: legacy metadata keys are forbidden: {legacy_keys}",
    )
    repository = metadata.get("source_repository")
    normalized_repository = (
        repository.removesuffix(".git").rstrip("/")
        if isinstance(repository, str)
        else ""
    )
    result.check(
        normalized_repository == SOURCE_REPOSITORY,
        f"{task_id}: source_repository must be {SOURCE_REPOSITORY}",
    )
    result.check(
        metadata.get("source_branch") == task_id,
        f"{task_id}: source_branch must equal task_id",
    )
    commit = metadata.get("source_commit")
    result.check(
        isinstance(commit, str) and SHA_PATTERN.fullmatch(commit) is not None,
        f"{task_id}: source_commit must be a 40-character lowercase SHA",
    )
    oracle_types = metadata.get("oracle_types")
    result.check(
        isinstance(oracle_types, list)
        and bool(oracle_types)
        and all(isinstance(item, str) and item in ORACLE_TYPES for item in oracle_types)
        and oracle_types == sorted(set(oracle_types)),
        f"{task_id}: oracle_types must be sorted, unique, and supported",
    )
    normalized_types = (
        tuple(oracle_types)
        if isinstance(oracle_types, list)
        and all(isinstance(item, str) for item in oracle_types)
        else ()
    )
    return commit if isinstance(commit, str) else None, normalized_types


def validate_artifacts(
    task_id: str, artifacts: object, result: ValidationResult
) -> None:
    """Require agent evidence before trusted oracle evidence."""
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        result.add(f"{task_id}: artifacts must contain exactly two entries")
        return
    expected = (
        ("/submission/evidence.json", "main"),
        ("/oracle/result.json", "oracle"),
    )
    for index, (artifact, (source, service)) in enumerate(zip(artifacts, expected)):
        if not isinstance(artifact, dict):
            result.add(f"{task_id}: artifacts[{index}] must be a table")
            continue
        result.check(
            artifact.get("source") == source,
            f"{task_id}: artifacts[{index}].source must be {source}",
        )
        actual_service = artifact.get("service", "main")
        result.check(
            actual_service == service,
            f"{task_id}: artifacts[{index}].service must be {service}",
        )
        destination = artifact.get("destination")
        result.check(
            destination is None
            or (
                isinstance(destination, str)
                and destination
                and not destination.startswith("/")
                and ".." not in Path(destination).parts
            ),
            f"{task_id}: artifacts[{index}].destination must be relative",
        )


def validate_collect_hooks(
    task_id: str,
    task_dir: Path,
    verifier: Mapping[str, Any],
    result: ValidationResult,
) -> None:
    """Require only the collection hooks needed by the runtime config."""
    runtime = load_json(task_dir / "environment/runtime_config.json", result)
    triggers = runtime.get("trigger_checks") if runtime is not None else None
    needs_target = isinstance(triggers, list) and any(
        isinstance(entry, dict) and entry.get("kind") == "file_exists"
        for entry in triggers
    )
    hooks = verifier.get("collect")
    expected_count = 2 if needs_target else 1
    if not isinstance(hooks, list) or len(hooks) != expected_count:
        result.add(
            f"{task_id}: verifier.collect must contain {expected_count} "
            "canonical hook(s)"
        )
        return
    if needs_target:
        target_hook, oracle_hook = hooks
        if not isinstance(target_hook, dict):
            result.add(f"{task_id}: first collect hook must be a table")
        else:
            result.check(
                target_hook.get("service") == "target",
                f"{task_id}: first collect hook must run in target",
            )
            result.check(
                target_hook.get("command") == "/bin/sh /run/oracle-proof/collect.sh",
                f"{task_id}: first collect hook command is not canonical",
            )
            result.check(
                target_hook.get("user") == "root",
                f"{task_id}: target collect hook must run as root",
            )
    else:
        oracle_hook = hooks[0]
    if not isinstance(oracle_hook, dict):
        result.add(f"{task_id}: final collect hook must be a table")
    else:
        command = oracle_hook.get("command")
        result.check(
            oracle_hook.get("service") == "oracle",
            f"{task_id}: final collect hook must run in oracle",
        )
        result.check(
            isinstance(command, str)
            and "runtime_oracle.py" in command
            and re.search(r"(?:^|\s)collect(?:\s|$)", command) is not None,
            f"{task_id}: oracle collect hook must call runtime_oracle.py collect",
        )


def validate_task_toml(
    task_id: str, task_dir: Path, result: ValidationResult
) -> tuple[str | None, tuple[str, ...]]:
    """Validate Harbor task configuration and return the source commit."""
    config = load_toml(task_dir / "task.toml", result)
    if config is None:
        return None, ()
    result.check(
        config.get("schema_version") == SCHEMA_VERSION,
        f"{task_id}: schema_version must be {SCHEMA_VERSION}",
    )
    task = config.get("task")
    result.check(isinstance(task, dict), f"{task_id}: [task] is required")
    if isinstance(task, dict):
        result.check(
            task.get("name") == f"jay-l-break/dojo-vulhub-{task_id}",
            f"{task_id}: task.name is not canonical",
        )
        task_text = json.dumps(task, sort_keys=True).lower()
        result.check(
            "sarif" not in task_text, f"{task_id}: task metadata mentions SARIF"
        )
        result.check(
            "exploitation" in task_text,
            f"{task_id}: task metadata must identify exploitation",
        )
    commit, metadata_oracle_types = validate_metadata(
        task_id, config.get("metadata"), result
    )
    agent = config.get("agent")
    result.check(isinstance(agent, dict), f"{task_id}: [agent] is required")
    if isinstance(agent, dict):
        result.check(
            agent.get("network_mode") == "no-network",
            f"{task_id}: agent.network_mode must be no-network",
        )
        result.check(
            agent.get("user") == "agent",
            f"{task_id}: agent.user must be agent",
        )
    verifier = config.get("verifier")
    result.check(isinstance(verifier, dict), f"{task_id}: [verifier] is required")
    if isinstance(verifier, dict):
        result.check(
            verifier.get("environment_mode") == "separate",
            f"{task_id}: verifier.environment_mode must be separate",
        )
        environment = verifier.get("environment")
        result.check(
            isinstance(environment, dict)
            and environment.get("network_mode") == "no-network",
            f"{task_id}: separate verifier must use no-network",
        )
        validate_collect_hooks(task_id, task_dir, verifier, result)
    environment = config.get("environment")
    result.check(
        isinstance(environment, dict) and environment.get("network_mode") == "public",
        f"{task_id}: setup environment must use public network mode",
    )
    validate_artifacts(task_id, config.get("artifacts"), result)
    return commit, metadata_oracle_types


def validate_manifest(
    task_id: str, task_dir: Path, result: ValidationResult
) -> dict[str, object] | None:
    """Validate the solution manifest and referenced PoC names."""
    manifest = load_json(task_dir / "solution/manifest.json", result)
    if manifest is None:
        return None
    result.check(bool(manifest), f"{task_id}: solution manifest must not be empty")
    result.check(
        set(manifest) <= ORACLE_TYPES,
        f"{task_id}: manifest contains unsupported oracle types",
    )
    filenames: list[str] = []
    for oracle_type, filename in manifest.items():
        result.check(
            isinstance(filename, str)
            and POC_FILENAME_PATTERN.fullmatch(filename) is not None
            and Path(filename).name == filename,
            f"{task_id}: invalid PoC filename for {oracle_type}: {filename!r}",
        )
        if isinstance(filename, str):
            filenames.append(filename)
    result.check(
        len(filenames) >= 1,
        f"{task_id}: manifest must reference at least one PoC",
    )
    return manifest


def validate_contract_and_runtime(
    task_id: str,
    task_dir: Path,
    manifest: Mapping[str, object] | None,
    modules: RepositoryModules,
    result: ValidationResult,
) -> TaskSummary | None:
    """Validate public contracts, runtime topology, and manifest binding."""
    environment_contract_path = task_dir / "environment/oracle_contract.json"
    tests_contract_path = task_dir / "tests/oracle_contract.json"
    try:
        environment_bytes = environment_contract_path.read_bytes()
        tests_bytes = tests_contract_path.read_bytes()
    except OSError as error:
        result.add(f"{task_id}: cannot read oracle contract copies: {error}")
        return None
    result.check(
        environment_bytes == tests_bytes,
        f"{task_id}: environment and tests oracle contracts differ",
    )
    contract_document = load_json(environment_contract_path, result)
    if contract_document is None:
        return None
    try:
        contract = modules.contract.parse_contract(contract_document)
    except (TypeError, ValueError) as error:
        result.add(f"{task_id}: strict contract validation failed: {error}")
        return None
    result.check(
        contract.task_id == task_id,
        f"{task_id}: contract task_id differs",
    )
    if manifest is not None:
        try:
            expected_contract = modules.oracle_specs.build_contract(task_id, manifest)
        except (KeyError, TypeError, ValueError) as error:
            result.add(f"{task_id}: cannot derive contract from manifest: {error}")
        else:
            result.check(
                contract_document == expected_contract,
                f"{task_id}: contract differs from canonical manifest contract",
            )
    runtime_path = task_dir / "environment/runtime_config.json"
    runtime_document = load_json(runtime_path, result)
    if runtime_document is None:
        return None
    try:
        runtime = modules.runtime.parse_runtime_config(runtime_document)
    except (KeyError, OSError, TypeError, ValueError) as error:
        result.add(f"{task_id}: strict runtime config validation failed: {error}")
        return None
    result.check(runtime.task_id == task_id, f"{task_id}: runtime task_id differs")
    result.check(
        runtime.contract == contract_document,
        f"{task_id}: runtime embeds a different oracle contract",
    )
    validate_public_runtime(task_id, runtime_document, result)
    oracle_types = tuple(oracle.oracle_type for oracle in contract.oracles)
    poc_count = len(set(manifest.values())) if manifest is not None else 0
    return TaskSummary(task_id, oracle_types, len(contract.groups), poc_count)


def walk_json(value: object, path: str = "$") -> list[tuple[str, object]]:
    """Return flattened JSON nodes for publication checks."""
    nodes = [(path, value)]
    if isinstance(value, dict):
        for key, item in value.items():
            nodes.extend(walk_json(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            nodes.extend(walk_json(item, f"{path}[{index}]"))
    return nodes


def validate_public_runtime(
    task_id: str, document: Mapping[str, object], result: ValidationResult
) -> None:
    """Reject private or precomputed oracle material in public config."""
    for path, value in walk_json(document):
        key = path.rsplit(".", 1)[-1]
        if "[" not in key:
            result.check(
                key.lower() not in FORBIDDEN_PUBLIC_KEYS,
                f"{task_id}: runtime config exposes forbidden key {path}",
            )
        if not isinstance(value, str):
            continue
        result.check(
            STATIC_FLAG_PATTERN.search(value) is None,
            f"{task_id}: runtime config contains a static flag at {path}",
        )
        result.check(
            AWS_KEY_PATTERN.search(value) is None,
            f"{task_id}: runtime config contains an AWS key at {path}",
        )
        result.check(
            LONG_HEX_PATTERN.search(value) is None,
            f"{task_id}: runtime config contains a precomputed secret at {path}",
        )


def validate_dockerfile_bases(
    task_id: str, label: str, content: str, result: ValidationResult
) -> None:
    """Require every external Dockerfile base to use an immutable digest."""
    aliases: set[str] = set()
    from_count = 0
    for line_number, line in enumerate(content.splitlines(), 1):
        if re.match(r"\s*FROM\b", line, re.IGNORECASE) is None:
            continue
        from_count += 1
        match = FROM_PATTERN.fullmatch(line)
        if match is None:
            result.add(f"{task_id}: {label}:{line_number} has invalid FROM")
            continue
        image = match.group("image")
        if image.lower() != "scratch" and image.lower() not in aliases:
            result.check(
                DIGEST_IMAGE_PATTERN.fullmatch(image) is not None,
                f"{task_id}: {label}:{line_number} base is unpinned: {image}",
            )
        alias = match.group("alias")
        if alias:
            aliases.add(alias.lower())
    result.check(from_count > 0, f"{task_id}: {label} has no FROM")


def validate_dockerfiles(
    task_id: str, task_dir: Path, result: ValidationResult
) -> None:
    """Validate generated Dockerfiles and offline verifier construction."""
    for filename in ("Dockerfile", "Oracle.Dockerfile"):
        path = task_dir / "environment" / filename
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        validate_dockerfile_bases(task_id, f"environment/{filename}", content, result)
    verifier_path = task_dir / "tests/Dockerfile"
    if verifier_path.is_file():
        verifier = verifier_path.read_text(encoding="utf-8")
        validate_dockerfile_bases(task_id, "tests/Dockerfile", verifier, result)
        result.check(
            NETWORK_INSTALL_PATTERN.search(verifier) is None,
            f"{task_id}: verifier Dockerfile performs a network install",
        )
        for directory in ("/submission", "/oracle"):
            result.check(
                directory in verifier,
                f"{task_id}: verifier Dockerfile must create {directory}",
            )


def validate_agent_image_boundary(
    task_id: str,
    task_dir: Path,
    source_commit: str | None,
    result: ValidationResult,
) -> None:
    """Keep private runtime configuration outside the agent image."""
    main_path = task_dir / "environment/Dockerfile"
    oracle_path = task_dir / "environment/Oracle.Dockerfile"
    if not main_path.is_file() or not oracle_path.is_file():
        return
    main = main_path.read_text(encoding="utf-8")
    oracle = oracle_path.read_text(encoding="utf-8")
    result.check(
        "COPY oracle_contract.json /app/oracle_contract.json" in main,
        f"{task_id}: main image must publish the scoring contract",
    )
    result.check(
        "runtime_config.json" not in main and "/oracle/private" not in main,
        f"{task_id}: main image exposes private runtime configuration",
    )
    result.check(
        "COPY runtime_config.json /oracle/config.json" in oracle,
        f"{task_id}: oracle image must receive the runtime config",
    )
    result.check(
        "/oracle/observed/file-creation" in oracle,
        f"{task_id}: oracle image must reserve the observed proof root",
    )
    if source_commit is not None:
        result.check(
            SOURCE_REPOSITORY in main and source_commit in main,
            f"{task_id}: main image source checkout is not commit pinned",
        )
    result.check(
        "rm -rf /app/repo/.git" in main,
        f"{task_id}: main image must remove Git metadata",
    )
    result.check(
        main.count("-name 'attack_scope.json' -delete") >= 2,
        f"{task_id}: main image must sanitize attack scope before and after extraction",
    )


def volume_source(specification: object) -> str | None:
    """Return the source of a short- or long-form Compose mount."""
    if isinstance(specification, str):
        return specification.split(":", 1)[0]
    if isinstance(specification, dict):
        source = specification.get("source")
        return source if isinstance(source, str) else None
    return None


def volume_target(specification: object) -> str | None:
    """Return the target of a short- or long-form Compose mount."""
    if isinstance(specification, str):
        fields = specification.split(":")
        return fields[1] if len(fields) >= 2 else None
    if isinstance(specification, dict):
        target = specification.get("target")
        return target if isinstance(target, str) else None
    return None


def service_mounts(service: Mapping[str, Any]) -> list[object]:
    """Return a service's Compose volume declarations."""
    volumes = service.get("volumes", [])
    return volumes if isinstance(volumes, list) else []


def validate_mounts(
    task_id: str,
    service_name: str,
    service: Mapping[str, Any],
    result: ValidationResult,
) -> None:
    """Reject bind mounts and Docker control sockets."""
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list):
        result.add(f"{task_id}: {service_name}.volumes must be a list")
        return
    for index, mount in enumerate(volumes):
        source = volume_source(mount)
        target = volume_target(mount)
        result.check(
            isinstance(source, str)
            and bool(source)
            and not source.startswith(("/", ".", "~"))
            and "/" not in source,
            f"{task_id}: {service_name}.volumes[{index}] must use a named volume",
        )
        result.check(
            target != "/var/run/docker.sock",
            f"{task_id}: {service_name} must not mount the Docker socket",
        )


def validate_build(
    task_id: str,
    service_name: str,
    build: object,
    source_commit: str | None,
    result: ValidationResult,
) -> bool:
    """Validate one service build and return whether it uses inline Dockerfile."""
    if isinstance(build, str):
        build = {"context": build}
    if not isinstance(build, dict):
        result.add(f"{task_id}: {service_name}.build must be a table")
        return False
    inline = build.get("dockerfile_inline")
    if inline is not None:
        result.check(
            isinstance(inline, str),
            f"{task_id}: {service_name}.dockerfile_inline must be a string",
        )
        result.check(
            "dockerfile" not in build,
            f"{task_id}: {service_name} combines dockerfile and dockerfile_inline",
        )
        if isinstance(inline, str):
            validate_dockerfile_bases(
                task_id, f"{service_name}.dockerfile_inline", inline, result
            )
    context = build.get("context")
    if isinstance(context, str) and context.startswith(("http://", "https://")):
        expected_prefix = f"{SOURCE_REPOSITORY}.git#{source_commit}"
        result.check(
            source_commit is not None
            and (
                context == expected_prefix or context.startswith(f"{expected_prefix}:")
            ),
            f"{task_id}: {service_name} remote context is not source-commit pinned",
        )
        if context.startswith(f"{expected_prefix}:"):
            subdirectory = context.removeprefix(f"{expected_prefix}:")
            result.check(
                bool(subdirectory)
                and not subdirectory.startswith("/")
                and ".." not in Path(subdirectory).parts,
                f"{task_id}: {service_name} has unsafe remote subdirectory",
            )
    return inline is not None


def validate_bridge_config(
    task_id: str,
    path: Path,
    expected_forward: Mapping[int, int] | None,
    expected_reverse: Mapping[int, int] | None,
    modules: RepositoryModules,
    result: ValidationResult,
) -> None:
    """Validate one fixed bridge config against task stack topology."""
    document = load_json(path, result)
    if document is None:
        return
    try:
        config = modules.bridge.parse_config(document)
    except (OSError, TypeError, ValueError) as error:
        result.add(f"{task_id}: invalid {path.name}: {error}")
        return
    forward = {item.local_port: item.target_port for item in config.forward}
    reverse_entries = getattr(config, "reverse", ())
    reverse = {item.local_port: item.target_port for item in reverse_entries}
    if expected_forward is not None and expected_reverse is not None:
        result.check(
            forward == dict(expected_forward),
            f"{task_id}: {path.name} forward mappings differ: {forward}",
        )
        result.check(
            reverse == dict(expected_reverse),
            f"{task_id}: {path.name} reverse mappings differ: {reverse}",
        )
    all_ports = {
        *(item.local_port for item in config.forward),
        *(item.target_port for item in config.forward),
        *(item.local_port for item in reverse_entries),
        *(item.target_port for item in reverse_entries),
    }
    result.check(
        4444 not in all_ports,
        f"{task_id}: target-only RCE port 4444 is exposed by {path.name}",
    )


def has_mount(service: Mapping[str, Any], target: str) -> bool:
    """Return whether a service mounts a volume at an exact target path."""
    return any(volume_target(mount) == target for mount in service_mounts(service))


def mounted_source(service: Mapping[str, Any], target: str) -> str | None:
    """Return the named volume mounted at an exact target path."""
    for mount in service_mounts(service):
        if volume_target(mount) == target:
            return volume_source(mount)
    return None


def mount_is_read_only(service: Mapping[str, Any], target: str) -> bool | None:
    """Return the read-only mode for an exact mount target, when present."""
    for mount in service_mounts(service):
        if volume_target(mount) != target:
            continue
        if isinstance(mount, str):
            return "ro" in mount.split(":")[2:]
        if isinstance(mount, dict):
            return mount.get("read_only") is True
    return None


def validate_target_seed_hook(
    task_id: str, target: Mapping[str, Any], result: ValidationResult
) -> None:
    """Require runtime installation from the target-only seed volume."""
    hooks = target.get("post_start")
    if not isinstance(hooks, list):
        result.add(f"{task_id}: target.post_start must be a list")
        return
    commands = [
        hook.get("command")
        for hook in hooks
        if isinstance(hook, dict) and isinstance(hook.get("command"), str)
    ]
    result.check(
        "/bin/sh /run/dojo-seed/install.sh" in commands,
        f"{task_id}: target.post_start must run the canonical install hook",
    )


def validate_compose_isolation(
    task_id: str,
    services: Mapping[str, Any],
    networks: object,
    volumes: object,
    has_file_creation: bool,
    result: ValidationResult,
) -> None:
    """Validate target netns isolation and named-volume trust boundaries."""
    core_services = {
        "main",
        "target-netns",
        "target",
        "oracle-init",
        "oracle",
        "gateway",
    }
    result.check(
        core_services <= set(services),
        f"{task_id}: missing core services {sorted(core_services - set(services))}",
    )
    target = services.get("target")
    target_netns = services.get("target-netns")
    main = services.get("main")
    oracle_init = services.get("oracle-init")
    oracle = services.get("oracle")
    gateway = services.get("gateway")
    if not all(
        isinstance(item, dict)
        for item in (target, target_netns, main, oracle_init, oracle, gateway)
    ):
        result.add(f"{task_id}: core services must be Compose mappings")
        return
    result.check(
        networks == {"target-net": {"internal": True}},
        f"{task_id}: target-net must be the sole internal Compose network",
    )
    result.check(
        target_netns.get("networks") == ["target-net"]
        and "network_mode" not in target_netns,
        f"{task_id}: target-netns must anchor the internal network",
    )
    result.check(
        "network_mode" not in main and "networks" not in main,
        f"{task_id}: main networking must remain under Harbor control",
    )
    result.check(
        oracle_init.get("network_mode") == "none" and "networks" not in oracle_init,
        f"{task_id}: oracle-init must run without a network",
    )
    for service_name, service in services.items():
        if not isinstance(service, dict):
            continue
        if service_name not in {"main", "target-netns", "oracle-init"}:
            result.check(
                service.get("network_mode") == "service:target-netns"
                and "networks" not in service,
                f"{task_id}: {service_name} must share target-netns",
            )
    main_bridge = mounted_source(main, "/run/dojo-forward")
    gateway_bridge = mounted_source(gateway, "/run/dojo-forward")
    result.check(
        main_bridge is not None and main_bridge == gateway_bridge,
        f"{task_id}: main and gateway must share the forward UDS volume",
    )
    validate_target_seed_hook(task_id, target, result)
    result.check(
        has_mount(target, "/run/dojo-seed")
        and has_mount(oracle_init, "/run/dojo-seed")
        and has_mount(oracle, "/run/dojo-seed"),
        f"{task_id}: target and oracle services must share the seed volume",
    )
    for trusted_path in ("/run/dojo-oracle", "/run/oracle-proof"):
        sources = {
            mounted_source(service, trusted_path)
            for service in (target, oracle_init, oracle)
        }
        result.check(
            None not in sources and len(sources) == 1,
            f"{task_id}: target and oracle services must share {trusted_path}",
        )
    result.check(
        mount_is_read_only(target, "/run/oracle-proof") is True,
        f"{task_id}: target proof mount must be read-only",
    )
    result.check(
        has_mount(oracle_init, "/oracle/private")
        and has_mount(oracle, "/oracle/private"),
        f"{task_id}: oracle-init and oracle must share private state",
    )
    for forbidden_path in (
        "/run/dojo-seed",
        "/run/dojo-oracle",
        "/run/oracle-proof",
        "/oracle/private",
        "/tmp/dojo-file-creation",
        "/oracle/observed/file-creation",
    ):
        result.check(
            not has_mount(main, forbidden_path),
            f"{task_id}: main must not mount trusted path {forbidden_path}",
        )
    observed_volume = "file-creation-observed"
    target_observed = mounted_source(target, "/tmp/dojo-file-creation")
    init_observed = mounted_source(oracle_init, "/oracle/observed/file-creation")
    oracle_observed = mounted_source(oracle, "/oracle/observed/file-creation")
    if has_file_creation:
        result.check(
            target_observed == observed_volume
            and init_observed == observed_volume
            and oracle_observed == observed_volume,
            f"{task_id}: file creation services must share the observed volume",
        )
        result.check(
            mount_is_read_only(target, "/tmp/dojo-file-creation") is False,
            f"{task_id}: target observed proof mount must be writable",
        )
        result.check(
            mount_is_read_only(oracle_init, "/oracle/observed/file-creation") is False,
            f"{task_id}: oracle-init observed proof mount must be writable",
        )
        result.check(
            mount_is_read_only(oracle, "/oracle/observed/file-creation") is True,
            f"{task_id}: live Oracle observed proof mount must be read-only",
        )
        result.check(
            isinstance(volumes, dict) and observed_volume in volumes,
            f"{task_id}: observed proof named volume must be declared",
        )
    else:
        result.check(
            target_observed is None
            and init_observed is None
            and oracle_observed is None,
            f"{task_id}: task without file creation mounts an observed volume",
        )
        result.check(
            not isinstance(volumes, dict) or observed_volume not in volumes,
            f"{task_id}: task without file creation declares an observed volume",
        )
    for service_name, service in services.items():
        if service_name in {"target", "oracle-init", "oracle"} or not isinstance(
            service, dict
        ):
            continue
        result.check(
            mounted_source(service, "/tmp/dojo-file-creation") is None
            and mounted_source(service, "/oracle/observed/file-creation") is None,
            f"{task_id}: {service_name} must not mount observed proof state",
        )
    result.check(
        "rce-listener" not in services,
        f"{task_id}: RCE listener must be internal to the oracle runtime",
    )
    init_text = json.dumps(oracle_init, sort_keys=True)
    result.check(
        "/usr/local/bin/dojo-rce-helper" in init_text
        and "/run/oracle-proof/helper" in init_text
        and "runtime_oracle.py" in init_text
        and " init " in f" {init_text} ",
        f"{task_id}: oracle-init must install the helper and initialize runtime state",
    )


def validate_compose(
    task_id: str,
    task_dir: Path,
    source_commit: str | None,
    modules: RepositoryModules,
    result: ValidationResult,
) -> None:
    """Validate immutable application services and isolated oracle topology."""
    compose = load_yaml(task_dir / "environment/docker-compose.yaml", result)
    if compose is None:
        return
    services = compose.get("services")
    if not isinstance(services, dict):
        result.add(f"{task_id}: Compose services must be a mapping")
        return
    inline_services: set[str] = set()
    for service_name, service in services.items():
        if not isinstance(service_name, str) or not isinstance(service, dict):
            result.add(f"{task_id}: invalid Compose service entry {service_name!r}")
            continue
        result.check(
            not service.get("ports"),
            f"{task_id}: {service_name} must not publish host ports",
        )
        for unsafe_key in ("cap_add", "devices", "extra_hosts"):
            result.check(
                not service.get(unsafe_key),
                f"{task_id}: {service_name} must not set {unsafe_key}",
            )
        result.check(
            service.get("privileged") is not True,
            f"{task_id}: {service_name} must not be privileged",
        )
        result.check(
            service.get("network_mode") != "host",
            f"{task_id}: {service_name} must not use host networking",
        )
        validate_mounts(task_id, service_name, service, result)
        image = service.get("image")
        if image is not None:
            result.check(
                isinstance(image, str)
                and DIGEST_IMAGE_PATTERN.fullmatch(image) is not None,
                f"{task_id}: {service_name} image must pin a public digest",
            )
            if isinstance(image, str):
                result.check(
                    PRIVATE_ECR_PATTERN.search(image) is None,
                    f"{task_id}: {service_name} uses private ECR",
                )
        if "build" in service and validate_build(
            task_id, service_name, service["build"], source_commit, result
        ):
            inline_services.add(service_name)
    expected_inline = {
        service
        for expected_task, service in EXPECTED_INLINE_DOCKERFILES
        if expected_task == task_id
    }
    result.check(
        inline_services == expected_inline,
        f"{task_id}: inline Dockerfile services differ: "
        f"{sorted(inline_services.symmetric_difference(expected_inline))}",
    )
    volumes = compose.get("volumes")
    result.check(
        isinstance(volumes, dict) and bool(volumes),
        f"{task_id}: Compose named volumes must be declared",
    )
    if isinstance(volumes, dict):
        for volume_name, configuration in volumes.items():
            result.check(
                isinstance(volume_name, str)
                and "/" not in volume_name
                and not volume_name.startswith((".", "~")),
                f"{task_id}: unsafe named volume {volume_name!r}",
            )
            result.check(
                configuration in (None, {})
                or (
                    isinstance(configuration, dict)
                    and not configuration.get("external")
                    and "driver_opts" not in configuration
                ),
                f"{task_id}: named volume {volume_name} has unsafe options",
            )
    runtime = load_json(task_dir / "environment/runtime_config.json", result)
    file_creations = runtime.get("file_creations") if runtime is not None else None
    has_file_creation = isinstance(file_creations, list) and bool(file_creations)
    validate_compose_isolation(
        task_id,
        services,
        compose.get("networks"),
        volumes,
        has_file_creation,
        result,
    )
    main = services.get("main")
    if isinstance(main, dict):
        environment = main.get("environment")
        expected_environment = modules.stack_specs.agent_environment(task_id)
        result.check(
            isinstance(environment, dict)
            and all(
                environment.get(key) == value
                for key, value in expected_environment.items()
            ),
            f"{task_id}: main environment lacks canonical loopback PoC settings",
        )
        gateway = services.get("gateway")
        if isinstance(gateway, dict):
            callbacks = modules.stack_specs.callback_ports(task_id)
            main_callback = mounted_source(main, "/run/dojo-callback")
            gateway_callback = mounted_source(gateway, "/run/dojo-callback")
            if callbacks:
                result.check(
                    main_callback is not None and main_callback == gateway_callback,
                    f"{task_id}: callback tasks must share one reverse UDS volume",
                )
            else:
                result.check(
                    main_callback is None and gateway_callback is None,
                    f"{task_id}: non-callback task mounts a callback UDS volume",
                )
    if task_id == "vite-003":
        target = services.get("target")
        healthcheck = target.get("healthcheck") if isinstance(target, dict) else None
        result.check(
            isinstance(healthcheck, dict)
            and "127.0.0.1:5173" in json.dumps(healthcheck, sort_keys=True),
            f"{task_id}: target healthcheck must wait for Vite on port 5173",
        )


def validate_bridges(
    task_id: str,
    task_dir: Path,
    modules: RepositoryModules,
    result: ValidationResult,
) -> None:
    """Validate forward and optional reverse callback bridge mappings."""
    forwards = modules.stack_specs.forward_ports(task_id)
    callbacks = modules.stack_specs.callback_ports(task_id)
    validate_bridge_config(
        task_id,
        task_dir / "environment/forward_bridge.json",
        forwards,
        {},
        modules,
        result,
    )
    callback_path = task_dir / "environment/callback_bridge.json"
    if callbacks:
        validate_bridge_config(
            task_id,
            callback_path,
            {},
            {port: port for port in callbacks},
            modules,
            result,
        )
    else:
        validate_bridge_config(
            task_id,
            callback_path,
            None,
            None,
            modules,
            result,
        )


def validate_bridge_entrypoints(
    task_id: str,
    task_dir: Path,
    callback_ports: tuple[int, ...],
    result: ValidationResult,
) -> None:
    """Require bridge roles that match the canonical endpoint semantics."""
    main_path = task_dir / "environment/main-entrypoint.sh"
    gateway_path = task_dir / "environment/gateway-entrypoint.sh"
    if not main_path.is_file() or not gateway_path.is_file():
        return
    main = main_path.read_text(encoding="utf-8")
    gateway = gateway_path.read_text(encoding="utf-8")
    main_forward = "fixed_bridge.py main --config /opt/dojo/forward_bridge.json"
    gateway_forward = "fixed_bridge.py target --config /opt/dojo/forward_bridge.json"
    result.check(
        main.count(main_forward) == 1,
        f"{task_id}: main must start one main-role forward bridge",
    )
    result.check(
        gateway.count(gateway_forward) == 1,
        f"{task_id}: gateway must start one target-role forward bridge",
    )
    main_callback = "fixed_bridge.py main --config /opt/dojo/callback_bridge.json"
    gateway_callback = "fixed_bridge.py target --config /opt/dojo/callback_bridge.json"
    if callback_ports:
        result.check(
            main.count(main_callback) == 1,
            f"{task_id}: main must start one main-role callback bridge",
        )
        result.check(
            gateway.count(gateway_callback) == 1,
            f"{task_id}: gateway must start one target-role callback bridge",
        )
    else:
        result.check(
            "callback_bridge.json" not in main
            and "callback_bridge.json" not in gateway,
            f"{task_id}: inactive callback bridge must not be started",
        )
    result.check(
        "fixed_bridge.py target" not in main,
        f"{task_id}: main entrypoint uses the target bridge role",
    )
    result.check(
        "fixed_bridge.py main" not in gateway,
        f"{task_id}: gateway entrypoint uses the main bridge role",
    )


def validate_canonical_copies(
    task_id: str, task_dir: Path, repo_root: Path, result: ValidationResult
) -> None:
    """Require generated runtime copies to match canonical sources byte-for-byte."""
    for generated_name, canonical_name in CANONICAL_COPIES.items():
        generated = task_dir / generated_name
        canonical = repo_root / canonical_name
        if not generated.is_file() or not canonical.is_file():
            continue
        try:
            identical = generated.read_bytes() == canonical.read_bytes()
        except OSError as error:
            result.add(f"{task_id}: cannot compare {generated_name}: {error}")
            continue
        result.check(
            identical,
            f"{task_id}: {generated_name} differs from {canonical_name}",
        )


def validate_python_source(task_id: str, path: Path, result: ValidationResult) -> None:
    """Compile one Python source without creating bytecode."""
    try:
        source = path.read_text(encoding="utf-8")
        compile(source, str(path), "exec")
    except (OSError, UnicodeError, SyntaxError) as error:
        result.add(f"{task_id}: invalid Python source {path.name}: {error}")


def validate_solution(
    task_id: str,
    task_dir: Path,
    manifest: Mapping[str, object] | None,
    result: ValidationResult,
) -> None:
    """Validate reference PoCs and their local solution runner wiring."""
    if manifest is None:
        return
    for filename in sorted(set(manifest.values()), key=str):
        if not isinstance(filename, str):
            continue
        path = task_dir / "solution/poc" / filename
        if path.is_file():
            validate_python_source(task_id, path, result)
    if "unauthorized_file_creation" in manifest:
        filename = manifest["unauthorized_file_creation"]
        expected = FILE_CREATION_POC_FRAGMENTS.get(task_id)
        result.check(
            isinstance(filename, str) and expected is not None,
            f"{task_id}: file-creation PoC has no canonical path mapping",
        )
        if isinstance(filename, str) and expected is not None:
            path = task_dir / "solution/poc" / filename
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                result.add(f"{task_id}: cannot inspect file-creation PoC: {error}")
            else:
                result.check(
                    expected in content,
                    f"{task_id}: file-creation PoC does not use observed volume",
                )
    solve_path = task_dir / "solution/solve.sh"
    if solve_path.is_file():
        solve = solve_path.read_text(encoding="utf-8")
        required_fragments = (
            "/solution/solution_runner.py",
            "/solution/manifest.json",
            "/solution/poc",
            "/submission/challenge.json",
            "/submission/evidence.json",
        )
        for fragment in required_fragments:
            result.check(
                fragment in solve,
                f"{task_id}: solution/solve.sh lacks {fragment}",
            )
    test_path = task_dir / "tests/test.sh"
    if test_path.is_file():
        command = test_path.read_text(encoding="utf-8")
        required_arguments = (
            "python3 /tests/cli.py",
            "--contract /tests/oracle_contract.json",
            "--submission /submission/evidence.json",
            "--oracle-result /oracle/result.json",
            "--output /logs/verifier/reward.json",
        )
        for fragment in required_arguments:
            result.check(
                fragment in command,
                f"{task_id}: tests/test.sh lacks {fragment}",
            )


def validate_instruction(
    task_id: str,
    task_dir: Path,
    requires_rce_protocol: bool,
    result: ValidationResult,
) -> None:
    """Require an exploitation instruction without hidden oracle details."""
    path = task_dir / "instruction.md"
    if not path.is_file():
        return
    content = path.read_text(encoding="utf-8")
    lowered = content.lower()
    result.check(
        "exploit" in lowered,
        f"{task_id}: instruction must state the exploitation objective",
    )
    result.check(
        "authorized" in lowered
        and "isolated" in lowered
        and "local-only" in lowered
        and "do not access or affect external systems" in lowered,
        f"{task_id}: instruction must state the authorized local-only boundary",
    )
    result.check(
        "/submission/evidence.json" in content,
        f"{task_id}: instruction must name the submission path",
    )
    result.check(
        "/submission/challenge.json" in content,
        f"{task_id}: instruction must name the public challenge path",
    )
    result.check(
        "/app/oracle_contract.json" in content,
        f"{task_id}: instruction must name the public scoring contract",
    )
    result.check(
        "runtime_config.json" not in content and "/oracle/private" not in content,
        f"{task_id}: instruction must not disclose private runtime state",
    )
    if requires_rce_protocol:
        protocol_fragments = (
            "target loopback `127.0.0.1:4444`",
            "fresh helper command",
            "return its output over the same connection",
            "Oracle Unix socket directly does not satisfy the proof",
        )
        result.check(
            all(fragment in content for fragment in protocol_fragments),
            f"{task_id}: instruction lacks the target-side RCE proof protocol",
        )


def validate_publication_text(
    task_id: str, task_dir: Path, result: ValidationResult
) -> None:
    """Reject legacy, private-cloud, and host-control material."""
    for path in task_dir.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeError:
            result.add(f"{task_id}: generated task contains binary file {path.name}")
            continue
        except OSError as error:
            result.add(f"{task_id}: cannot scan {path}: {error}")
            continue
        for pattern, description in FORBIDDEN_TEXT:
            result.check(
                pattern.search(content) is None,
                f"{task_id}: {path.relative_to(task_dir)} contains {description}",
            )
        if path.suffix == ".py" and "solution/poc" in path.as_posix():
            for pattern, description in (
                (re.compile(r"\b(?:boto3|botocore)\b"), "AWS SDK dependency"),
                (
                    re.compile(r"ECS_CONTAINER_METADATA|169\.254\.170\.2"),
                    "ECS metadata dependency",
                ),
                (
                    re.compile(r"VALIDATION_ENDPOINT", re.IGNORECASE),
                    "private validation endpoint",
                ),
            ):
                result.check(
                    pattern.search(content) is None,
                    f"{task_id}: {path.name} contains {description}",
                )


def validate_task(
    task_id: str,
    repo_root: Path,
    modules: RepositoryModules,
    result: ValidationResult,
) -> TaskSummary | None:
    """Validate one generated task and return its publication counts."""
    task_dir = repo_root / "tasks" / task_id
    manifest = validate_manifest(task_id, task_dir, result)
    callbacks = modules.stack_specs.callback_ports(task_id)
    validate_file_layout(task_id, task_dir, manifest, result)
    source_commit, metadata_oracle_types = validate_task_toml(task_id, task_dir, result)
    summary = validate_contract_and_runtime(
        task_id, task_dir, manifest, modules, result
    )
    if summary is not None:
        result.check(
            metadata_oracle_types == tuple(sorted(set(summary.oracle_types))),
            f"{task_id}: metadata.oracle_types differs from contract",
        )
    validate_dockerfiles(task_id, task_dir, result)
    validate_agent_image_boundary(task_id, task_dir, source_commit, result)
    validate_compose(
        task_id,
        task_dir,
        source_commit,
        modules,
        result,
    )
    validate_bridges(task_id, task_dir, modules, result)
    validate_bridge_entrypoints(task_id, task_dir, callbacks, result)
    validate_canonical_copies(task_id, task_dir, repo_root, result)
    validate_solution(task_id, task_dir, manifest, result)
    requires_rce_protocol = (
        summary is not None and "remote_code_execution" in summary.oracle_types
    )
    validate_instruction(task_id, task_dir, requires_rce_protocol, result)
    validate_publication_text(task_id, task_dir, result)
    return summary


def validate_repository_totals(
    summaries: Sequence[TaskSummary], result: ValidationResult
) -> None:
    """Require the audited task, vulnerability, oracle, and PoC totals."""
    result.check(
        len(summaries) == EXPECTED_TASK_COUNT,
        f"validated {len(summaries)} of {EXPECTED_TASK_COUNT} task summaries",
    )
    oracle_types = Counter(
        oracle_type for summary in summaries for oracle_type in summary.oracle_types
    )
    oracle_count = sum(oracle_types.values())
    group_count = sum(summary.group_count for summary in summaries)
    poc_count = sum(summary.poc_count for summary in summaries)
    result.check(
        oracle_count == EXPECTED_ORACLE_COUNT,
        f"expected {EXPECTED_ORACLE_COUNT} oracle occurrences, found {oracle_count}",
    )
    result.check(
        group_count == EXPECTED_GROUP_COUNT,
        f"expected {EXPECTED_GROUP_COUNT} oracle groups, found {group_count}",
    )
    result.check(
        poc_count == EXPECTED_POC_COUNT,
        f"expected {EXPECTED_POC_COUNT} task-local PoCs, found {poc_count}",
    )
    result.check(
        oracle_types == EXPECTED_ORACLE_TYPES,
        "oracle type counts differ: "
        f"expected={dict(EXPECTED_ORACLE_TYPES)}, actual={dict(oracle_types)}",
    )


def validate_repository(repo_root: Path) -> ValidationResult:
    """Validate the complete generated benchmark repository."""
    result = ValidationResult()
    tasks_dir = repo_root / "tasks"
    if not tasks_dir.is_dir():
        result.add(f"missing tasks directory: {tasks_dir}")
        return result
    try:
        modules = load_repository_modules(repo_root)
    except (ImportError, OSError, RuntimeError, SyntaxError) as error:
        result.add(f"cannot load canonical modules: {error}")
        return result
    validate_task_directories(tasks_dir, result)
    validate_registry_manifest(repo_root, result)
    summaries = [
        summary
        for task_id in TASK_IDS
        if (summary := validate_task(task_id, repo_root, modules, result)) is not None
    ]
    validate_repository_totals(summaries, result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    """Run repository validation and report all failures."""
    arguments = parse_arguments(argv)
    repo_root = arguments.repo_root.resolve()
    result = validate_repository(repo_root)
    if result.errors:
        print(f"Validation failed with {len(result.errors)} error(s):", file=sys.stderr)
        for error in result.errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(
        "Validated 54 exploitation tasks, 55 oracle groups, "
        "58 hard-oracle occurrences, and 56 reference PoCs."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
