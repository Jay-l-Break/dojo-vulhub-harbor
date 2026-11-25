"""Runs published reference exploits and writes a Harbor submission."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

MAX_JSON_BYTES = 64 * 1024
ORACLE_SUFFIXES = {
    "authentication_bypass": "auth_bypass",
    "other": "other",
    "remote_code_execution": "rce",
    "unauthorized_database_read": "db_read",
    "unauthorized_file_access": "file_access",
    "unauthorized_file_creation": "file_creation",
}
VULNERABILITY_FILENAME = re.compile(r"^vuln-(?P<number>\d+)-.+\.py$")


class SolutionInputError(ValueError):
    """Raised when a reference-solution input is invalid."""


class DuplicateKeyError(SolutionInputError):
    """Raised when a JSON object repeats a key."""


def reject_duplicate_keys(
    pairs: Sequence[tuple[str, object]],
) -> dict[str, object]:
    """Builds a JSON object while rejecting duplicate keys."""
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def reject_json_constant(value: str) -> object:
    """Rejects nonstandard non-finite JSON constants."""
    raise SolutionInputError(f"invalid JSON constant: {value}")


def parse_json_float(value: str) -> float:
    """Parses a finite JSON number."""
    parsed = float(value)
    if not math.isfinite(parsed):
        raise SolutionInputError("JSON number is not finite")
    return parsed


def parse_json_integer(value: str) -> int:
    """Parses a bounded JSON integer using the interpreter safety limit."""
    try:
        return int(value)
    except ValueError as error:
        raise SolutionInputError("JSON integer is too large") from error


def parse_strict_json(contents: str, context: str) -> object:
    """Parses strict JSON with duplicate and non-finite value rejection."""
    try:
        return json.loads(
            contents,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
            parse_float=parse_json_float,
            parse_int=parse_json_integer,
        )
    except (
        DuplicateKeyError,
        OverflowError,
        RecursionError,
        SolutionInputError,
        ValueError,
    ) as error:
        raise SolutionInputError(f"invalid JSON in {context}") from error


def read_bounded_regular_file(path: Path) -> bytes:
    """Reads a bounded regular file without following symbolic links."""
    try:
        path_metadata = path.lstat()
    except OSError as error:
        raise SolutionInputError(f"cannot inspect {path}") from error
    if stat.S_ISLNK(path_metadata.st_mode):
        raise SolutionInputError(f"symbolic links are not allowed: {path}")
    if not stat.S_ISREG(path_metadata.st_mode):
        raise SolutionInputError(f"not a regular file: {path}")
    if path_metadata.st_size > MAX_JSON_BYTES:
        raise SolutionInputError(f"JSON file exceeds {MAX_JSON_BYTES} bytes")

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SolutionInputError(f"cannot open {path}") from error
    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode):
            raise SolutionInputError(f"not a regular file: {path}")
        if (
            opened_metadata.st_dev != path_metadata.st_dev
            or opened_metadata.st_ino != path_metadata.st_ino
        ):
            raise SolutionInputError(f"file changed while opening: {path}")
        if opened_metadata.st_size > MAX_JSON_BYTES:
            raise SolutionInputError(f"JSON file exceeds {MAX_JSON_BYTES} bytes")
        chunks: list[bytes] = []
        remaining = MAX_JSON_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        contents = b"".join(chunks)
        if len(contents) > MAX_JSON_BYTES:
            raise SolutionInputError(f"JSON file exceeds {MAX_JSON_BYTES} bytes")
        return contents
    except OSError as error:
        raise SolutionInputError(f"cannot read {path}") from error
    finally:
        os.close(descriptor)


def read_json_object(path: Path) -> dict[str, object]:
    """Reads one bounded strict JSON object."""
    contents = read_bounded_regular_file(path)
    try:
        text = contents.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SolutionInputError(f"invalid UTF-8 in {path}") from error
    value = parse_strict_json(text, str(path))
    if not isinstance(value, dict):
        raise SolutionInputError(f"expected a JSON object in {path}")
    return value


def parse_evidence(stdout: str, script: Path) -> dict[str, object]:
    """Reads the final nonempty JSON evidence line printed by a PoC."""
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise SolutionInputError(f"{script.name} did not print JSON evidence")
    document = parse_strict_json(lines[-1], f"{script.name} stdout")
    if not isinstance(document, dict):
        raise SolutionInputError(
            f"{script.name} final stdout line must be a JSON object"
        )
    evidence = document.get("evidence_payload")
    if not isinstance(evidence, dict):
        raise SolutionInputError(
            f"{script.name} did not print an evidence_payload object"
        )
    return evidence


def validate_timeout(timeout_sec: float) -> None:
    """Requires a finite positive PoC timeout."""
    if (
        isinstance(timeout_sec, bool)
        or not isinstance(timeout_sec, (int, float))
        or not math.isfinite(timeout_sec)
        or timeout_sec <= 0
    ):
        raise SolutionInputError("timeout_sec must be finite and positive")


def run_poc(
    script: Path,
    environment: Mapping[str, str],
    timeout_sec: float,
) -> dict[str, object]:
    """Runs one reference exploit and returns its evidence payload."""
    validate_timeout(timeout_sec)
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=script.parent,
        env=dict(environment),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=timeout_sec,
    )
    if result.stdout:
        print(result.stdout, end="", file=sys.stderr)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"{script.name} exited with status {result.returncode}")
    return parse_evidence(result.stdout, script)


def oracle_id(task_id: str, oracle_type: str, filename: str) -> str:
    """Builds the canonical oracle ID for one manifest entry."""
    if Path(filename).name != filename or "\\" in filename:
        raise SolutionInputError(f"invalid PoC filename: {filename}")
    match = VULNERABILITY_FILENAME.fullmatch(filename)
    if match is None:
        raise SolutionInputError(f"invalid PoC filename: {filename}")
    suffix = ORACLE_SUFFIXES.get(oracle_type)
    if suffix is None:
        raise SolutionInputError(f"unsupported oracle type: {oracle_type}")
    number = int(match.group("number"))
    if number <= 0:
        raise SolutionInputError(f"invalid vulnerability number: {number}")
    return f"{task_id}:vuln-{number:02d}:{suffix}"


def validate_script(path: Path) -> None:
    """Requires a regular nonsymlink PoC script."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SolutionInputError(f"cannot inspect PoC script: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SolutionInputError(f"PoC script must be a regular file: {path}")


def evidence_defaults(
    challenge: Mapping[str, object], oracle_identifier: str
) -> dict[str, object]:
    """Reads public evidence defaults supplied for one runtime oracle."""
    defaults = challenge.get("evidence_defaults", {})
    if not isinstance(defaults, dict):
        raise SolutionInputError("challenge evidence_defaults must be an object")
    value = defaults.get(oracle_identifier, {})
    if not isinstance(value, dict):
        raise SolutionInputError(
            f"evidence defaults for {oracle_identifier} must be an object"
        )
    return dict(value)


def evidence_string(evidence: Mapping[str, object], field: str, context: str) -> str:
    """Returns one required nonempty evidence string."""
    value = evidence.get(field)
    if not isinstance(value, str) or not value:
        raise SolutionInputError(f"{context}.{field} must be a nonempty string")
    return value


def normalize_evidence(
    oracle_type: str,
    poc: Mapping[str, object],
    defaults: Mapping[str, object],
) -> dict[str, object]:
    """Converts legacy PoC output to the strict public submission schema."""
    if oracle_type == "unauthorized_file_access":
        return {
            "path": evidence_string(defaults, "path", "evidence_defaults"),
            "content": evidence_string(poc, "content", "evidence_payload"),
        }
    if oracle_type == "unauthorized_file_creation":
        return {"path": evidence_string(defaults, "path", "evidence_defaults")}
    if oracle_type == "authentication_bypass":
        return {
            "token": evidence_string(poc, "token", "evidence_payload"),
            "user": evidence_string(poc, "user", "evidence_payload"),
        }
    if oracle_type == "other":
        return {"flag": evidence_string(poc, "flag", "evidence_payload")}
    if oracle_type == "unauthorized_database_read":
        evidence_string(poc, "table_name", "evidence_payload")
        data = poc.get("data")
        if not isinstance(data, list) or not data:
            raise SolutionInputError("evidence_payload.data must be a nonempty array")
        return dict(poc)
    if oracle_type == "remote_code_execution":
        return dict(poc)
    raise SolutionInputError(f"unsupported oracle type: {oracle_type}")


def validate_default_ids(challenge: Mapping[str, object], oracle_ids: set[str]) -> None:
    """Rejects evidence defaults that do not belong to the manifest."""
    defaults = challenge.get("evidence_defaults", {})
    if not isinstance(defaults, dict):
        raise SolutionInputError("challenge evidence_defaults must be an object")
    unknown_ids = set(defaults) - oracle_ids
    if unknown_ids:
        raise SolutionInputError(
            f"evidence_defaults contains unknown oracle IDs: {sorted(unknown_ids)}"
        )


def build_claims(
    task_id: str,
    manifest: Mapping[str, object],
    challenge: Mapping[str, object],
    poc_directory: Path,
    environment: Mapping[str, str],
    timeout_sec: float,
) -> list[dict[str, object]]:
    """Runs each distinct PoC and builds canonical submission claims."""
    entries: list[tuple[str, str, str, Path]] = []
    for oracle_type, filename_value in manifest.items():
        if not isinstance(filename_value, str):
            raise SolutionInputError(
                f"manifest value for {oracle_type} must be a string"
            )
        identifier = oracle_id(task_id, oracle_type, filename_value)
        script = poc_directory / filename_value
        validate_script(script)
        entries.append((identifier, oracle_type, filename_value, script))
    if not entries:
        raise SolutionInputError("manifest must contain at least one oracle")
    identifiers = [
        identifier
        for identifier, unused_type, unused_filename, unused_script in entries
    ]
    if len(set(identifiers)) != len(identifiers):
        raise SolutionInputError("manifest produces duplicate oracle IDs")
    validate_default_ids(challenge, set(identifiers))

    script_evidence: dict[str, dict[str, object]] = {}
    claims: list[dict[str, object]] = []
    for identifier, oracle_type, filename, script in entries:
        if filename not in script_evidence:
            script_evidence[filename] = run_poc(script, environment, timeout_sec)
        defaults = evidence_defaults(challenge, identifier)
        evidence = normalize_evidence(oracle_type, script_evidence[filename], defaults)
        claims.append({"oracle_id": identifier, "evidence": evidence})
    return claims


def write_json_atomic(path: Path, document: Mapping[str, object]) -> None:
    """Atomically writes a JSON document with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", text=True
    )
    temporary_path = Path(temporary_name)
    descriptor_open = True
    try:
        os.fchmod(descriptor, 0o600)
        file = os.fdopen(descriptor, "w", encoding="utf-8")
        descriptor_open = False
        with file:
            json.dump(
                dict(document),
                file,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_path, path)
    finally:
        if descriptor_open:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)


def require_nonempty_string(value: object, context: str) -> str:
    """Returns a nonempty string without surrounding whitespace."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise SolutionInputError(f"{context} must be a nonempty string")
    return value


def parse_arguments(
    arguments: Sequence[str] | None = None,
) -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("/solution/manifest.json"),
    )
    parser.add_argument(
        "--poc-dir",
        type=Path,
        default=Path("/solution/poc"),
    )
    parser.add_argument(
        "--challenge",
        type=Path,
        default=Path("/submission/challenge.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/submission/evidence.json"),
    )
    parser.add_argument("--timeout-sec", type=float, default=900.0)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Runs the reference solution."""
    parsed = parse_arguments(arguments)
    task_id = require_nonempty_string(parsed.task_id, "task_id")
    validate_timeout(parsed.timeout_sec)
    manifest = read_json_object(parsed.manifest)
    challenge = read_json_object(parsed.challenge)
    run_id = require_nonempty_string(challenge.get("run_id"), "challenge.run_id")
    if challenge.get("task_id") != task_id:
        raise SolutionInputError("runtime challenge does not match the requested task")
    claims = build_claims(
        task_id,
        manifest,
        challenge,
        parsed.poc_dir,
        dict(os.environ),
        parsed.timeout_sec,
    )
    submission = {
        "schema_version": "1.0",
        "task_id": task_id,
        "run_id": run_id,
        "claims": claims,
    }
    write_json_atomic(parsed.output, submission)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
