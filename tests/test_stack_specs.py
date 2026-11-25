"""Tests for deterministic application stack specifications."""

from __future__ import annotations

import copy
import shlex
import subprocess
import sys
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPOSITORY_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_ROOT))

import stack_specs

COMMIT = "a" * 40
PINNED_IMAGE = (
    "public.ecr.aws/docker/library/postgres:13-alpine@"
    "sha256:fb9065b6e3e213bdc07edd372a5b2a26245840b7fb65d1fd8b6700106d51805c"
)


def source_compose_fixture() -> dict[str, object]:
    """Returns a source Compose document with removable runtime keys."""
    return {
        "services": {
            "backend": {
                "build": ".",
                "environment": {"DB_HOST": "db"},
                "depends_on": ["db"],
                "ports": ["80:80"],
                "networks": ["default"],
                "volumes": ["source:/source"],
            },
            "db": {
                "image": "postgres:13-alpine",
                "environment": ["POSTGRES_PASSWORD=example"],
                "ports": ["5432:5432"],
                "restart": "always",
            },
        },
        "volumes": {"source": {}},
    }


class NetworkSpecificationTest(unittest.TestCase):
    """Checks task coverage and fixed bridge port direction."""

    def test_covers_exactly_54_tasks(self) -> None:
        self.assertEqual(len(stack_specs.TASK_IDS), 54)
        for task_id in stack_specs.TASK_IDS:
            with self.subTest(task_id=task_id):
                self.assertEqual(stack_specs.forward_ports(task_id)[80], 80)
                self.assertIn(stack_specs.health_mode(task_id), {"http", "tcp"})
                self.assertEqual(
                    stack_specs.agent_environment(task_id)["REMOTE_TARGET_URL"],
                    "http://127.0.0.1",
                )

    def test_source_compose_task_set_is_exact(self) -> None:
        self.assertEqual(
            stack_specs.source_compose_tasks(),
            {
                "django-001",
                "django-003",
                "django-004",
                "django-005",
                "django-006",
                "jumpserver-001",
                "kibana-002",
                "kibana-003",
                "mongo-express-001",
                "node-002",
            },
        )

    def test_special_forward_ports_are_main_to_target(self) -> None:
        self.assertEqual(
            stack_specs.forward_ports("airflow-002"),
            {80: 80, 6379: 6379},
        )
        self.assertEqual(
            stack_specs.forward_ports("celery-001"),
            {80: 80, 6379: 6379},
        )
        self.assertEqual(
            stack_specs.forward_ports("openclaw-001"),
            {80: 80, 18791: 18791},
        )

    def test_only_main_listener_callbacks_are_reported(self) -> None:
        self.assertEqual(stack_specs.callback_ports("comfyui-001"), (40001,))
        self.assertEqual(stack_specs.callback_ports("comfyui-002"), (40001,))
        self.assertEqual(stack_specs.callback_ports("openclaw-001"), (40000,))
        for task_id in stack_specs.TASK_IDS:
            with self.subTest(task_id=task_id):
                self.assertNotIn(4444, stack_specs.callback_ports(task_id))

    def test_salt_zeromq_tasks_use_tcp_health(self) -> None:
        tcp_tasks = {
            task_id
            for task_id in stack_specs.TASK_IDS
            if stack_specs.health_mode(task_id) == "tcp"
        }
        self.assertEqual(tcp_tasks, {"saltstack-001", "saltstack-002"})

    def test_loopback_agent_overrides_are_complete(self) -> None:
        self.assertEqual(
            stack_specs.agent_environment("celery-001")["REMOTE_REDIS_PORT"],
            "6379",
        )
        self.assertEqual(
            stack_specs.agent_environment("chartbrew-001")["CHARTBREW_MONGO_HOST"],
            "127.0.0.1",
        )
        for task_id in ("comfyui-001", "comfyui-002"):
            self.assertEqual(
                stack_specs.agent_environment(task_id)["POC_GIT_HOST"],
                "127.0.0.1",
            )
        self.assertEqual(
            stack_specs.agent_environment("openclaw-001")["OPENCLAW_LISTENER_IP"],
            "127.0.0.1",
        )

    def test_returned_mappings_are_independent(self) -> None:
        ports = stack_specs.forward_ports("aiohttp-001")
        ports[81] = 81
        self.assertEqual(stack_specs.forward_ports("aiohttp-001"), {80: 80})
        environment = stack_specs.agent_environment("celery-001")
        environment["REMOTE_REDIS_PORT"] = "1"
        self.assertEqual(
            stack_specs.agent_environment("celery-001")["REMOTE_REDIS_PORT"],
            "6379",
        )


class SourceComposeTransformationTest(unittest.TestCase):
    """Checks immutable source Compose transformation."""

    def test_transforms_without_mutating_source(self) -> None:
        source = source_compose_fixture()
        original = copy.deepcopy(source)
        services = stack_specs.build_application_services("django-003", COMMIT, source)
        self.assertEqual(source, original)
        self.assertEqual(set(services), {"target", "db"})
        self.assertEqual(
            services["target"]["build"]["context"],
            f"{stack_specs.SOURCE_REPOSITORY}#{COMMIT}",
        )
        self.assertEqual(services["target"]["environment"]["DB_HOST"], "127.0.0.1")
        self.assertEqual(services["db"]["image"], stack_specs.POSTGRES_13_IMAGE)
        for service in services.values():
            self.assertTrue(
                {
                    "depends_on",
                    "networks",
                    "ports",
                    "restart",
                    "volumes",
                }.isdisjoint(service)
            )

    def test_pins_subdirectory_build_context(self) -> None:
        source = source_compose_fixture()
        source["services"]["victim"] = {"build": "victim"}
        services = stack_specs.build_application_services("django-001", COMMIT, source)
        self.assertEqual(
            services["victim"]["build"]["context"],
            f"{stack_specs.SOURCE_REPOSITORY}#{COMMIT}:victim",
        )

    def test_kibana_two_restores_nginx_boundary(self) -> None:
        services = stack_specs.build_application_services(
            "kibana-002", COMMIT, source_compose_fixture()
        )
        self.assertEqual(set(services), {"backend", "db", "target"})
        self.assertEqual(
            services["target"]["build"]["dockerfile"],
            "deployment/nginx.Dockerfile",
        )
        self.assertEqual(
            services["backend"]["environment"]["ELASTICSEARCH_URL"],
            "http://127.0.0.1:9200",
        )
        self.assertEqual(services["backend"]["environment"]["SERVER_PORT"], "5601")

    def test_kibana_three_uses_deployment_builds(self) -> None:
        services = stack_specs.build_application_services(
            "kibana-003", COMMIT, source_compose_fixture()
        )
        self.assertEqual(
            services["backend"]["build"],
            {
                "context": (f"{stack_specs.SOURCE_REPOSITORY}#{COMMIT}:deployment"),
                "dockerfile": "backend.Dockerfile",
            },
        )
        self.assertEqual(services["target"]["build"]["dockerfile"], "nginx.Dockerfile")

    def test_rejects_unpinned_or_private_images(self) -> None:
        for image in (
            "mongo:5.0.6",
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/private@"
            + "sha256:"
            + "a" * 64,
        ):
            with self.subTest(image=image):
                source = source_compose_fixture()
                source["services"]["db"]["image"] = image
                with self.assertRaises(ValueError):
                    stack_specs.build_application_services("django-003", COMMIT, source)


class CustomStackTest(unittest.TestCase):
    """Checks stacks that are not represented by source Compose."""

    def build(self, task_id: str) -> dict[str, dict[str, object]]:
        """Builds one custom stack using the fixed test commit."""
        return stack_specs.build_application_services(task_id, COMMIT, None)

    def test_airflow_has_postgres_and_redis(self) -> None:
        services = self.build("airflow-002")
        self.assertEqual(set(services), {"target", "postgres", "redis"})
        self.assertEqual(services["postgres"]["image"], stack_specs.POSTGRES_13_IMAGE)
        self.assertEqual(services["redis"]["image"], stack_specs.REDIS_5_IMAGE)
        environment = services["target"]["environment"]
        self.assertIn("127.0.0.1:5432", environment["AIRFLOW__CORE__SQL_ALCHEMY_CONN"])
        self.assertIn("127.0.0.1:6379", environment["AIRFLOW__CELERY__BROKER_URL"])

    def test_chartbrew_has_application_secret_and_public_mongo(self) -> None:
        services = self.build("chartbrew-001")
        self.assertEqual(set(services), {"target", "mongodb"})
        self.assertEqual(
            services["target"]["environment"],
            {"CB_SECRET": stack_specs.CHARTBREW_SECRET},
        )
        self.assertEqual(services["mongodb"]["image"], stack_specs.MONGO_5_IMAGE)

    def test_kibana_one_has_public_elasticsearch(self) -> None:
        services = self.build("kibana-001")
        self.assertEqual(set(services), {"target", "elasticsearch"})
        self.assertEqual(
            services["elasticsearch"]["image"],
            stack_specs.ELASTICSEARCH_5_IMAGE,
        )

    def test_pgadmin_one_two_use_public_login_only(self) -> None:
        passwords = {
            "pgadmin-001": "pgadmin001-public",
            "pgadmin-002": "pgadmin002-public",
        }
        for task_id, password in passwords.items():
            with self.subTest(task_id=task_id):
                services = self.build(task_id)
                self.assertEqual(set(services), {"target"})
                self.assertEqual(
                    services["target"]["environment"],
                    {
                        "PGADMIN_CONFIG_SECURITY_EMAIL_VALIDATOR_ARGS": (
                            "{'check_deliverability': False}"
                        ),
                        "PGADMIN_DEFAULT_EMAIL": "attacker@example.com",
                        "PGADMIN_DEFAULT_PASSWORD": password,
                        "PGADMIN_LISTEN_ADDRESS": "0.0.0.0",
                        "PGADMIN_LISTEN_PORT": "80",
                    },
                )

    def test_pgadmin_database_uses_postgres_15_trust(self) -> None:
        for task_id in ("pgadmin-003", "pgadmin-004"):
            with self.subTest(task_id=task_id):
                services = self.build(task_id)
                self.assertEqual(set(services), {"target", "pgsql"})
                self.assertEqual(
                    services["pgsql"]["image"], stack_specs.POSTGRES_15_IMAGE
                )
                self.assertEqual(
                    services["pgsql"]["environment"]["POSTGRES_HOST_AUTH_METHOD"],
                    "trust",
                )

    def test_rocketchat_builds_mongo_from_public_commit(self) -> None:
        services = self.build("rocketchat-001")
        self.assertEqual(services["db"]["build"]["dockerfile"], "Dockerfile.mongo")
        self.assertEqual(
            services["target"]["environment"]["MONGO_URL"],
            "mongodb://127.0.0.1:27017/rocketchat001",
        )

    def test_langflow_two_generates_a_fresh_private_password(self) -> None:
        services = self.build("langflow-002")
        target = services["target"]
        environment = target["environment"]
        self.assertEqual(environment["LANGFLOW_AUTO_LOGIN"], "false")
        self.assertEqual(environment["LANGFLOW_SUPERUSER"], "administrator")
        self.assertNotIn("LANGFLOW_SUPERUSER_PASSWORD", environment)

        entrypoint = target["entrypoint"]
        self.assertEqual(entrypoint[:2], ["/bin/sh", "-c"])
        self.assertEqual(entrypoint[3], "langflow-password-wrapper")
        wrapper = entrypoint[2]
        self.assertIn('LANGFLOW_SUPERUSER_PASSWORD="$(', wrapper)
        self.assertIn(
            "/app/.venv/bin/python -c "
            "'import secrets; print(secrets.token_urlsafe(32))'",
            wrapper,
        )
        self.assertIn("export LANGFLOW_SUPERUSER_PASSWORD", wrapper)
        self.assertIn('exec /app/entrypoint.sh "$@"', wrapper)
        self.assertNotIn('LANGFLOW_SUPERUSER_PASSWORD="administrator"', wrapper)
        subprocess.run(["/bin/sh", "-n", "-c", wrapper], check=True)
        probe = wrapper.replace(
            "/app/.venv/bin/python",
            shlex.quote(sys.executable),
        ).replace(
            'exec /app/entrypoint.sh "$@"',
            "printf '%s' \"$LANGFLOW_SUPERUSER_PASSWORD\"",
        )
        passwords = {
            subprocess.run(
                ["/bin/sh", "-c", probe, "langflow-password-wrapper"],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            ).stdout
            for unused_run in range(2)
        }
        self.assertEqual(len(passwords), 2)
        for password in passwords:
            self.assertRegex(password, r"^[A-Za-z0-9_-]{40,}$")

    def test_langflow_one_keeps_the_default_target(self) -> None:
        target = self.build("langflow-001")["target"]
        self.assertEqual(
            target,
            {"build": {"context": stack_specs.pinned_build_context(COMMIT)}},
        )

    def test_vite_three_preserves_intended_trigger_proxy(self) -> None:
        services = self.build("vite-003")
        self.assertEqual(set(services), {"target"})
        command = services["target"]["command"]
        self.assertIn("--port 5173", command[2])
        self.assertIn('exec node -e "$1"', command[2])
        proxy_script = command[4]
        self.assertIn("/tmp/vite003-intended-trigger", proxy_script)
        self.assertIn("port:5173", proxy_script)
        self.assertIn(".listen(80", proxy_script)
        healthcheck = services["target"]["healthcheck"]
        self.assertEqual(healthcheck["test"][:3], ["CMD", "node", "-e"])
        self.assertIn("127.0.0.1:5173", healthcheck["test"][3])

    def test_self_contained_roots_have_no_companions(self) -> None:
        for task_id in ("budibase-001", "celery-001", "yapi-001", "yapi-002"):
            with self.subTest(task_id=task_id):
                self.assertEqual(set(self.build(task_id)), {"target"})


class FullCoverageValidationTest(unittest.TestCase):
    """Checks every published task through the stable builder API."""

    def test_all_tasks_have_target_and_immutable_sources(self) -> None:
        for task_id in stack_specs.TASK_IDS:
            with self.subTest(task_id=task_id):
                source = (
                    source_compose_fixture()
                    if task_id in stack_specs.source_compose_tasks()
                    else None
                )
                services = stack_specs.build_application_services(
                    task_id, COMMIT, source
                )
                self.assertIn("target", services)
                for service in services.values():
                    image = service.get("image")
                    if image is not None:
                        self.assertRegex(image, stack_specs.PINNED_IMAGE_PATTERN)
                        self.assertNotIn(".dkr.ecr.", image)
                    build = service.get("build")
                    if build is not None:
                        self.assertTrue(
                            build["context"].startswith(
                                f"{stack_specs.SOURCE_REPOSITORY}#{COMMIT}"
                            )
                        )

    def test_rejects_invalid_identifiers_commits_and_compose_use(self) -> None:
        with self.assertRaises(ValueError):
            stack_specs.forward_ports("missing-001")
        with self.assertRaises(ValueError):
            stack_specs.build_application_services("aiohttp-001", "not-a-commit", None)
        with self.assertRaises(ValueError):
            stack_specs.build_application_services("django-003", COMMIT, None)
        with self.assertRaises(ValueError):
            stack_specs.build_application_services(
                "aiohttp-001", COMMIT, source_compose_fixture()
            )


if __name__ == "__main__":
    unittest.main()
