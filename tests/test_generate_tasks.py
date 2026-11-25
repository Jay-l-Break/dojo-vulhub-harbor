"""Tests for the exploitation task generator."""

from __future__ import annotations

import dataclasses
import json
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPOSITORY_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT))

import generate_tasks


def dummy_task(task_id: str = "aiohttp-001") -> generate_tasks.TaskSource:
    """Builds the smallest task source needed by rendering tests."""
    return generate_tasks.TaskSource(
        task_id=task_id,
        source_commit="1" * 40,
        manifest={"remote_code_execution": "vuln-01-rce.py"},
        contract={
            "schema_version": "1.0",
            "task_id": task_id,
            "groups": [
                {
                    "oracle_group_id": f"{task_id}:vuln-01",
                    "weight": 1,
                    "all_of": [f"{task_id}:vuln-01:rce"],
                }
            ],
            "oracles": [
                {
                    "oracle_id": f"{task_id}:vuln-01:rce",
                    "type": "remote_code_execution",
                    "required_checks": [
                        "current_run",
                        "fresh_nonce",
                        "uds_capability_valid",
                        "single_use",
                    ],
                }
            ],
        },
        runtime_config={"trigger_checks": []},
        application_services={"target": {"build": {"context": "unused"}}},
        poc_directory=Path("/nonexistent"),
    )


def file_access_task(task_id: str = "aiohttp-001") -> generate_tasks.TaskSource:
    """Build a task source without a remote code execution oracle."""
    task = dummy_task(task_id)
    task.contract["oracles"] = [
        {
            "oracle_id": f"{task_id}:vuln-01:file_access",
            "type": "unauthorized_file_access",
            "required_checks": ["current_run", "secret_match"],
        }
    ]
    task.contract["groups"][0]["all_of"] = [f"{task_id}:vuln-01:file_access"]
    return dataclasses.replace(
        task,
        manifest={"unauthorized_file_access": "vuln-01-file-access.py"},
    )


class RegistryRenderingTest(unittest.TestCase):
    """Checks the native Harbor dataset registry."""

    def test_registry_contains_the_exact_canonical_task_set(self) -> None:
        rendered = generate_tasks.registry_json(generate_tasks.stack_specs.TASK_IDS)
        document = json.loads(rendered)

        self.assertEqual(len(document), 1)
        dataset = document[0]
        self.assertEqual(dataset["name"], "dojo-vulhub")
        self.assertEqual(dataset["version"], "1.0")
        self.assertEqual(len(dataset["tasks"]), 54)
        self.assertEqual(
            [entry["name"] for entry in dataset["tasks"]],
            sorted(generate_tasks.stack_specs.TASK_IDS),
        )
        self.assertEqual(
            dataset["tasks"][0]["path"],
            "tasks/aiohttp-001",
        )

    def test_registry_path_stays_outside_the_tasks_directory(self) -> None:
        output_directory = Path("/tmp/publication/tasks")
        registry_path = generate_tasks.default_registry_path(output_directory)

        self.assertEqual(registry_path, Path("/tmp/publication/registry.json"))
        self.assertEqual(
            generate_tasks.registry_task_root(output_directory, registry_path),
            "tasks",
        )

    def test_rejects_a_registry_inside_the_tasks_directory(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside the tasks directory"):
            generate_tasks.registry_task_root(
                Path("/tmp/publication/tasks"),
                Path("/tmp/publication/tasks/registry.json"),
            )


class BridgeRenderingTest(unittest.TestCase):
    """Checks generated bridge directions and callback isolation."""

    def test_forward_and_callback_roles_match_fixed_bridge_semantics(self) -> None:
        forward = generate_tasks.forward_bridge_config("openclaw-001")
        callback = generate_tasks.callback_bridge_config("openclaw-001")

        self.assertEqual(forward["forward"], ["80:80", "18791:18791"])
        self.assertEqual(forward["reverse"], [])
        self.assertIsNotNone(callback)
        self.assertEqual(callback["forward"], [])
        self.assertEqual(callback["reverse"], ["40000:40000"])
        self.assertNotIn("4444", str(forward))
        self.assertNotIn("4444", str(callback))
        self.assertIn("fixed_bridge.py main", generate_tasks.main_entrypoint(True))
        self.assertIn("fixed_bridge.py target", generate_tasks.gateway_entrypoint(True))
        self.assertIn(
            "printf '%s\\n' '{}' > /submission/evidence.json",
            generate_tasks.main_entrypoint(True),
        )
        self.assertNotIn(
            "/submission/evidence.json",
            generate_tasks.gateway_entrypoint(True),
        )


class RenderingTest(unittest.TestCase):
    """Checks public task, image, and PoC rendering invariants."""

    def test_database_instruction_uses_the_published_placeholder_field(self) -> None:
        task = dummy_task("django-006")
        task.contract["oracles"][0]["type"] = "unauthorized_database_read"

        instruction = generate_tasks.instruction_text(task)

        self.assertIn(
            "use that Oracle's object in `evidence_defaults` as the claim evidence",
            instruction,
        )
        self.assertIn(
            "Replace its empty string with the leaked row value",
            instruction,
        )
        self.assertIn('`{"value": ""}` placeholder', instruction)
        self.assertIn('`{"url": ""}` requires the `url` field', instruction)

    def test_rce_instruction_explains_the_target_side_proof_protocol(self) -> None:
        instruction = generate_tasks.instruction_text(dummy_task())

        self.assertIn("target loopback `127.0.0.1:4444`", instruction)
        self.assertIn("fresh helper command", instruction)
        self.assertIn("return its output over the same connection", instruction)
        self.assertIn(
            "Oracle Unix socket directly does not satisfy the proof",
            instruction,
        )

    def test_task_toml_uses_oracle_only_collection_by_default(self) -> None:
        document = tomllib.loads(generate_tasks.task_toml(dummy_task()))

        self.assertEqual(document["agent"]["network_mode"], "no-network")
        self.assertEqual(document["environment"]["workdir"], "/app/repo")
        self.assertEqual(
            document["metadata"]["oracle_types"], ["remote_code_execution"]
        )
        self.assertEqual(
            [entry["service"] for entry in document["verifier"]["collect"]],
            ["oracle"],
        )

    def test_target_collect_uses_read_only_proof_script_when_required(self) -> None:
        task = dummy_task("vite-003")
        task.runtime_config["trigger_checks"] = [
            {"kind": "file_exists"},
        ]
        document = tomllib.loads(generate_tasks.task_toml(task))

        self.assertEqual(
            [entry["service"] for entry in document["verifier"]["collect"]],
            ["target", "oracle"],
        )
        target_collect = document["verifier"]["collect"][0]
        self.assertEqual(target_collect["user"], "root")
        self.assertEqual(
            target_collect["command"],
            "/bin/sh /run/oracle-proof/collect.sh",
        )

    def test_main_image_contains_audited_source_but_not_runtime_config(self) -> None:
        dockerfile = generate_tasks.main_dockerfile(dummy_task())

        self.assertIn("git init /app/repo", dockerfile)
        self.assertIn("1" * 40, dockerfile)
        self.assertIn("rm -rf /app/repo/.git", dockerfile)
        self.assertEqual(dockerfile.count("attack_scope.json"), 2)
        self.assertIn("WORKDIR /app/repo", dockerfile)
        self.assertNotIn("runtime_config.json", dockerfile)
        self.assertIn(
            "COPY json/oracle_contract.json /app/oracle_contract.json",
            dockerfile,
        )

    def test_callback_config_is_copied_only_for_callback_tasks(self) -> None:
        ordinary_main = generate_tasks.main_dockerfile(dummy_task())
        ordinary_oracle = generate_tasks.oracle_dockerfile(dummy_task())
        callback_task = dummy_task("openclaw-001")
        callback_main = generate_tasks.main_dockerfile(callback_task)
        callback_oracle = generate_tasks.oracle_dockerfile(callback_task)

        self.assertNotIn("json/callback_bridge.json", ordinary_main)
        self.assertNotIn("json/callback_bridge.json", ordinary_oracle)
        self.assertIn("json/callback_bridge.json", callback_main)
        self.assertIn("json/callback_bridge.json", callback_oracle)

    def test_rce_helper_build_and_init_are_conditional(self) -> None:
        rce_task = dummy_task()
        non_rce_task = file_access_task()
        rce_dockerfile = generate_tasks.oracle_dockerfile(rce_task)
        non_rce_dockerfile = generate_tasks.oracle_dockerfile(non_rce_task)
        rce_services = generate_tasks.trusted_services(rce_task, False)
        non_rce_services = generate_tasks.trusted_services(non_rce_task, False)

        self.assertIn("COPY go/rce_helper.go", rce_dockerfile)
        self.assertIn("helper-builder", rce_dockerfile)
        self.assertIn(
            "/usr/local/bin/dojo-rce-helper",
            str(rce_services["oracle-init"]["command"]),
        )
        self.assertNotIn("rce_helper.go", non_rce_dockerfile)
        self.assertNotIn("helper-builder", non_rce_dockerfile)
        self.assertNotIn("dojo-rce-helper", non_rce_dockerfile)
        self.assertNotIn(
            "dojo-rce-helper",
            str(non_rce_services["oracle-init"]["command"]),
        )

    def test_compose_uses_organized_dockerfiles(self) -> None:
        task = dummy_task()
        services = {
            "main": generate_tasks.main_service(task, False),
            **generate_tasks.trusted_services(task, False),
        }

        self.assertEqual(
            services["main"]["build"]["dockerfile"],
            "docker/main.Dockerfile",
        )
        for service_name in ("oracle-init", "oracle", "gateway"):
            self.assertEqual(
                services[service_name]["build"]["dockerfile"],
                "docker/oracle.Dockerfile",
            )

    def test_comfy_adaptation_uses_fixed_loopback_listener(self) -> None:
        original = (
            "def run():\n"
            "        server = http.server.ThreadingHTTPServer("
            '("0.0.0.0", 0), handler)\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "vuln-01-rce.py"
            source.write_text(original, encoding="utf-8")
            adapted = generate_tasks.adapted_poc("comfyui-001", source)

        self.assertIn("POC_GIT_BIND_PORT", adapted)
        self.assertIn('ThreadingHTTPServer(("127.0.0.1", port), handler)', adapted)
        self.assertNotIn('("0.0.0.0", 0)', adapted)

    def test_file_creation_pocs_use_observed_volume_path(self) -> None:
        sources = {
            ("airflow-001", "vuln-01-command-injection.py"): (
                'TARGET_FILE = "/tmp/airflow_001_created"\n'
            ),
            ("airflow-002", "vuln-01-celery-broker.py"): (
                'TARGET_FILE = "/tmp/airflow_002_created"\n'
            ),
            ("saltstack-002", "vuln-02-file-write.py"): (
                'TRAVERSAL_PATH = "../../etc/salt/saltstack-002-write-proof"\n'
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for (task_id, filename), content in sources.items():
                with self.subTest(task_id=task_id):
                    source = root / filename
                    source.write_text(content, encoding="utf-8")
                    adapted = generate_tasks.adapted_poc(task_id, source)
                    self.assertIn("/tmp/dojo-file-creation/", adapted)
                    self.assertNotIn("../../etc/saltstack-002-write-proof", adapted)

    def test_file_creation_services_isolate_observed_volume(self) -> None:
        task = dummy_task("airflow-001")
        task.runtime_config["file_creations"] = [{"path": "proof"}]
        trusted = generate_tasks.trusted_services(task, has_callback=False)

        self.assertIn(
            "file-creation-observed:/oracle/observed/file-creation",
            trusted["oracle-init"]["volumes"],
        )
        self.assertIn(
            "file-creation-observed:/oracle/observed/file-creation:ro",
            trusted["oracle"]["volumes"],
        )
        self.assertNotIn(
            "file-creation-observed",
            "\n".join(trusted["gateway"]["volumes"]),
        )

    def test_pins_subdirectory_dockerfile_base(self) -> None:
        pinned, count = generate_tasks.pin_dockerfile_bases(
            "FROM python:3.12-alpine\nRUN true\n"
        )

        self.assertEqual(count, 1)
        self.assertIn("python:3.12-alpine@sha256:", pinned)


if __name__ == "__main__":
    unittest.main()
