"""Tests for hard-oracle specification generation."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "scripts" / "oracle_specs.py"
MODULE_SPEC = importlib.util.spec_from_file_location("oracle_specs", MODULE_PATH)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError("Could not load oracle_specs")
oracle_specs = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(oracle_specs)


class OracleSpecsTest(unittest.TestCase):
    """Validates canonical contracts and runtime descriptions."""

    def test_dual_oracle_is_one_all_of_group(self) -> None:
        manifest = {
            "unauthorized_file_creation": "vuln-01-command.py",
            "remote_code_execution": "vuln-01-command.py",
        }
        contract = oracle_specs.build_contract("airflow-001", manifest)
        self.assertEqual(1, len(contract["groups"]))
        self.assertEqual(2, len(contract["groups"][0]["all_of"]))

    def test_separate_vulnerabilities_make_separate_groups(self) -> None:
        manifest = {
            "unauthorized_file_access": "vuln-01-read.py",
            "unauthorized_file_creation": "vuln-02-write.py",
        }
        contract = oracle_specs.build_contract("saltstack-002", manifest)
        self.assertEqual(2, len(contract["groups"]))

    def test_file_creation_uses_isolated_observed_volume_path(self) -> None:
        manifest = {"unauthorized_file_creation": "vuln-02-write.py"}
        flags = {
            "oracle_scope": {
                "unauthorized_file_creation": {
                    "target_filename": "write-proof",
                    "search_folders": ["/legacy/location"],
                }
            }
        }

        config = oracle_specs.build_runtime_config("saltstack-002", manifest, flags)

        self.assertEqual(
            "/tmp/dojo-file-creation/write-proof",
            config["file_creations"][0]["path"],
        )

    def test_vite_trigger_is_an_extra_check(self) -> None:
        manifest = {"unauthorized_file_access": "vuln-01-read.py"}
        contract = oracle_specs.build_contract("vite-003", manifest)
        self.assertIn("trigger_seen", contract["oracles"][0]["required_checks"])

    def test_runtime_config_removes_static_secret(self) -> None:
        manifest = {"other": "vuln-01-bypass.py"}
        flags = {
            "oracle_scope": {"other": {"description": "test"}},
            "other": {"path": "/run/task/flag", "value": "private"},
        }
        config = oracle_specs.build_runtime_config("task-001", manifest, flags)
        self.assertNotIn("private", repr(config))
        self.assertEqual("/run/task/flag", config["file_seeds"][0]["path"])

    def test_database_uses_password_environment(self) -> None:
        manifest = {"unauthorized_database_read": "vuln-01-read.py"}
        flags = {
            "oracle_scope": {
                "unauthorized_database_read": [
                    {
                        "vuln_secret": {
                            "row_filters": {"id": 1},
                            "columns_in_scope": ["value"],
                        }
                    }
                ]
            }
        }
        config = oracle_specs.build_runtime_config("django-003", manifest, flags)
        database = config["databases"][0]
        self.assertEqual("DOJO_DB_PASSWORD", database["password_env"])
        self.assertEqual("vuln_secret", database["table"])

    def test_auth_probe_preserves_live_response_marker(self) -> None:
        manifest = {"authentication_bypass": "vuln-01-bypass.py"}
        flags = {
            "authentication_bypass": {
                "path": "/",
                "header": "x-middleware-subrequest",
                "response_contains": "Protected Control Panel",
            },
            "oracle_scope": {"authentication_bypass": ["admin"]},
        }
        config = oracle_specs.build_runtime_config("next-js-001", manifest, flags)
        self.assertEqual(
            "Protected Control Panel",
            config["auth_probes"][0]["response_marker"],
        )
        self.assertIn(
            "unauthenticated_rejected",
            config["contract"]["oracles"][0]["required_checks"],
        )


if __name__ == "__main__":
    unittest.main()
