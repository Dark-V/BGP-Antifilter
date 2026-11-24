import os
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bgp_antifilter import updater_server


class UpdaterServerTests(unittest.TestCase):
    def test_portainer_keeps_image_updates_in_portainer(self):
        with mock.patch.dict(os.environ, {"PORTAINER_MANAGED": "1"}):
            enabled, reason = updater_server.health_status()
        self.assertFalse(enabled)
        self.assertIn("Portainer", reason)

    def test_validate_version_accepts_plain_and_v_prefixed_values(self):
        self.assertEqual(updater_server.validate_version("0.2.6"), "0.2.6")
        self.assertEqual(updater_server.validate_version("v0.2.7"), "0.2.7")

    def test_validate_version_rejects_invalid_format(self):
        with self.assertRaises(ValueError):
            updater_server.validate_version("latest")

    def test_update_env_version_replaces_existing_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("FOO=bar\nBGP_ANTIFILTER_VERSION=0.2.5\n", encoding="utf-8")

            updater_server.update_env_version(path, "0.2.6")

            self.assertEqual(
                path.read_text(encoding="utf-8"),
                "FOO=bar\nBGP_ANTIFILTER_VERSION=0.2.6\n",
            )

    def test_update_env_version_appends_missing_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("FOO=bar\n", encoding="utf-8")

            updater_server.update_env_version(path, "0.2.6")

            self.assertEqual(
                path.read_text(encoding="utf-8"),
                "FOO=bar\n\nBGP_ANTIFILTER_VERSION=0.2.6\n",
            )

    def test_configured_version_prefers_env_value_over_workspace_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            version_file = Path(tmp) / "VERSION"
            env_file.write_text("BGP_ANTIFILTER_VERSION=v0.2.5\n", encoding="utf-8")
            version_file.write_text("0.3.2\n", encoding="utf-8")

            with mock.patch.object(updater_server, "ENV_FILE", env_file):
                with mock.patch.object(updater_server, "VERSION_FILE", version_file):
                    self.assertEqual(updater_server.configured_version(), "0.2.5")

    def test_configured_version_falls_back_to_workspace_version_for_invalid_env_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            version_file = Path(tmp) / "VERSION"
            env_file.write_text("BGP_ANTIFILTER_VERSION=latest\n", encoding="utf-8")
            version_file.write_text("0.3.2\n", encoding="utf-8")

            with mock.patch.object(updater_server, "ENV_FILE", env_file):
                with mock.patch.object(updater_server, "VERSION_FILE", version_file):
                    self.assertEqual(updater_server.configured_version(), "0.3.2")

    def test_configured_version_setting_is_empty_when_env_has_no_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("MY_AS=64500\n", encoding="utf-8")

            with mock.patch.object(updater_server, "ENV_FILE", env_file):
                self.assertEqual(updater_server.configured_version_setting(), "")

    def test_private_env_reads_only_pin_from_verified_own_container(self):
        with mock.patch.object(Path, "read_text", side_effect=PermissionError("private .env")), \
             mock.patch.object(updater_server, "deployment_context", return_value={"container": "a" * 64}), \
             mock.patch.object(updater_server, "run_docker", return_value=json.dumps(
                 {"workspace_exists": True, "compose_exists": True, "version": "1.0.4"})) as docker:
            self.assertEqual(updater_server.configured_version_setting(), "1.0.4")
        docker.assert_called_once_with("exec", "--user", "0:0", "a" * 64,
                                       "python3", "-m", "bgp_antifilter.updater_server", "--read-update-metadata")

    def test_private_env_probe_requires_verified_container_and_semver_output(self):
        with mock.patch.object(Path, "read_text", side_effect=PermissionError("private .env")), \
             mock.patch.object(updater_server, "deployment_context", side_effect=RuntimeError("unknown current container")), \
             mock.patch.object(updater_server, "run_docker") as docker:
            with self.assertRaisesRegex(RuntimeError, "metadata probe failed.*unknown current container"):
                updater_server.configured_version_setting()
            docker.assert_not_called()
        with mock.patch.object(Path, "read_text", side_effect=PermissionError("private .env")), \
             mock.patch.object(updater_server, "deployment_context", return_value={"container": "a" * 64}), \
             mock.patch.object(updater_server, "run_docker", return_value=json.dumps(
                 {"workspace_exists": True, "compose_exists": True, "version": "1.0.4\nUNEXPECTED=value"})):
            with self.assertRaisesRegex(RuntimeError, "MAJOR.MINOR.PATCH"):
                updater_server.configured_version_setting()

    def test_version_pin_helper_does_not_emit_other_env_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("ADMIN_PASSWORD=not-public\nBGP_ANTIFILTER_VERSION=v1.0.4\n", encoding="utf-8")
            import sys
            result = subprocess.run(
                [sys.executable, "-m", "bgp_antifilter.updater_server", "--read-update-metadata"],
                env={**os.environ, "ENV_FILE": str(path), "WORKSPACE_DIR": tmp, "COMPOSE_FILE": str(path.parent / "absent.yaml")},
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {"workspace_exists": True, "compose_exists": False, "version": "1.0.4"})
            self.assertEqual(result.stderr, "")

    def test_health_status_reports_private_env_probe_failure(self):
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.dict(os.environ, {"PORTAINER_MANAGED": "0"}), \
             mock.patch.object(updater_server, "update_metadata",
                               side_effect=RuntimeError("cannot read update metadata from workspace: metadata probe failed")):
            ok, error = updater_server.health_status()
        self.assertFalse(ok)
        self.assertIn("metadata probe failed", error)
        self.assertNotIn("local dev", error)

    def test_private_workspace_uses_metadata_without_changing_permissions(self):
        metadata = {"workspace_exists": True, "compose_exists": True, "version": "1.0.4"}
        with mock.patch.object(updater_server, "local_update_metadata", side_effect=PermissionError("private workspace")), \
             mock.patch.object(updater_server, "deployment_context", return_value={"container": "a" * 64}), \
             mock.patch.object(updater_server, "run_docker", return_value=json.dumps(metadata)), \
             mock.patch.object(updater_server.os, "chmod") as chmod:
            self.assertEqual(updater_server.update_metadata(), metadata)
            chmod.assert_not_called()
        with mock.patch.object(updater_server, "local_update_metadata", side_effect=PermissionError("private workspace")), \
             mock.patch.object(updater_server, "deployment_context", return_value={"container": "a" * 64}), \
             mock.patch.object(updater_server, "run_docker", side_effect=FileNotFoundError("docker unavailable")):
            with self.assertRaisesRegex(RuntimeError, "metadata probe failed.*docker unavailable"):
                updater_server.update_metadata()

    @unittest.skipUnless(os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0,
                         "requires root to exercise writes for another uid")
    def test_root_updater_preserves_private_env_owner_and_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("BGP_ANTIFILTER_VERSION=1.0.3\n", encoding="utf-8")
            os.chown(path, 10001, 10001)
            path.chmod(0o600)
            updater_server.update_env_version(path, "1.0.4")
            self.assertEqual((path.stat().st_uid, path.stat().st_gid, path.stat().st_mode & 0o777),
                             (10001, 10001, 0o600))

    def test_compose_project_name_reads_top_level_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose_file = Path(tmp) / "docker-compose.yml"
            compose_file.write_text('name: "bgp-antifilter"\nservices: {}\n', encoding="utf-8")

            self.assertEqual(updater_server.compose_project_name(compose_file), "bgp-antifilter")

    def test_strip_top_level_name_removes_only_project_name(self):
        source = "name: bgp-antifilter\n\nservices:\n  app:\n    environment:\n      APP_NAME: demo\n"
        stripped = updater_server.strip_top_level_name(source)

        self.assertTrue(stripped.startswith("services:\n"))
        self.assertIn("APP_NAME: demo", stripped)
        self.assertNotIn("name: bgp-antifilter", stripped)

    def test_sanitize_legacy_compose_text_removes_enable_ipv4(self):
        source = (
            "name: bgp-antifilter\n\n"
            "services: {}\n"
            "networks:\n"
            "  default:\n"
            "    enable_ipv4: true\n"
            "    enable_ipv6: false\n"
        )

        sanitized = updater_server.sanitize_legacy_compose_text(source)

        self.assertTrue(sanitized.startswith("services: {}\n"))
        self.assertNotIn("name: bgp-antifilter", sanitized)
        self.assertNotIn("enable_ipv4", sanitized)
        self.assertIn("enable_ipv6: false", sanitized)

    def test_health_status_requires_docker_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            env_file = workspace / ".env"
            compose_file = workspace / "docker-compose.yml"
            env_file.write_text("BGP_ANTIFILTER_VERSION=0.3.2\n", encoding="utf-8")
            compose_file.write_text("services: {}\n", encoding="utf-8")

            real_exists = Path.exists

            def exists_side_effect(path_obj):
                if path_obj == Path("/var/run/docker.sock"):
                    return False
                return real_exists(path_obj)

            with mock.patch.object(updater_server, "WORKSPACE_DIR", workspace):
                with mock.patch.object(updater_server, "ENV_FILE", env_file):
                    with mock.patch.object(updater_server, "COMPOSE_FILE", compose_file):
                        with mock.patch.object(updater_server.shutil, "which", return_value="docker-compose"):
                            with mock.patch.object(Path, "exists", autospec=True, side_effect=exists_side_effect):
                                ok, error = updater_server.health_status()

        self.assertFalse(ok)
        self.assertIn("docker socket", error)

    def test_health_status_rejects_local_dev_mode_without_version_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            env_file = workspace / ".env"
            compose_file = workspace / "docker-compose.yml"
            env_file.write_text("MY_AS=64500\n", encoding="utf-8")
            compose_file.write_text("services: {}\n", encoding="utf-8")

            with mock.patch.object(updater_server, "WORKSPACE_DIR", workspace):
                with mock.patch.object(updater_server, "ENV_FILE", env_file):
                    with mock.patch.object(updater_server, "COMPOSE_FILE", compose_file):
                        ok, error = updater_server.health_status()

        self.assertFalse(ok)
        self.assertIn("self-update is disabled for local dev builds", error)

    def test_compose_base_command_uses_docker_compose_v2_when_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose_file = Path(tmp) / "docker-compose.yml"
            compose_file.write_text("name: bgp-antifilter\nservices: {}\n", encoding="utf-8")

            completed = subprocess.CompletedProcess(args=["docker", "compose", "version"], returncode=0, stdout="", stderr="")

            with mock.patch.object(updater_server, "COMPOSE_FILE", compose_file):
                with mock.patch.object(updater_server.shutil, "which", side_effect=lambda cmd: {"docker": "docker", "docker-compose": "docker-compose"}.get(cmd)):
                    with mock.patch.object(updater_server.subprocess, "run", return_value=completed):
                        command, cleanup_path = updater_server.compose_base_command()

        self.assertEqual(command, ["docker", "compose", "--env-file", str(updater_server.ENV_FILE), "-f", str(compose_file)])
        self.assertIsNone(cleanup_path)

    def test_compose_base_command_falls_back_to_legacy_compose_with_project_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose_file = Path(tmp) / "docker-compose.yml"
            compose_file.write_text(
                "name: bgp-antifilter\n"
                "services: {}\n"
                "networks:\n"
                "  default:\n"
                "    enable_ipv4: true\n"
                "    enable_ipv6: false\n",
                encoding="utf-8",
            )

            completed = subprocess.CompletedProcess(args=["docker", "compose", "version"], returncode=1, stdout="", stderr="missing")

            with mock.patch.object(updater_server, "COMPOSE_FILE", compose_file):
                with mock.patch.object(updater_server.shutil, "which", side_effect=lambda cmd: {"docker": "docker", "docker-compose": "docker-compose"}.get(cmd)):
                    with mock.patch.object(updater_server.subprocess, "run", return_value=completed):
                        command, cleanup_path = updater_server.compose_base_command()

                        self.assertEqual(command[:5], ["docker-compose", "--env-file", str(updater_server.ENV_FILE), "-p", "bgp-antifilter"])
                        self.assertEqual(command[5], "-f")
                        self.assertIsNotNone(cleanup_path)
                        self.assertTrue(cleanup_path.exists())
                        self.assertEqual(
                            cleanup_path.read_text(encoding="utf-8"),
                            "services: {}\nnetworks:\n  default:\n    enable_ipv6: false\n",
                        )

                        cleanup_path.unlink(missing_ok=True)

    def test_independent_worker_restarts_self_service_with_legacy_compose(self):
        with mock.patch.object(updater_server, "uses_legacy_docker_compose", return_value=True):
            with mock.patch.object(updater_server, "COMPOSE_SERVICES", ("bgp-antifilter", "metrics")):
                with mock.patch.object(updater_server, "SELF_SERVICE", "metrics"):
                    self.assertEqual(updater_server.restart_services_for_update(), ("bgp-antifilter", "metrics"))

    def test_recreate_services_uses_rm_then_up(self):
        calls = []

        def fake_run_compose(*args, timeout=1800):
            calls.append(args)
            return {"ok": True, "stderr": "", "stdout": "", "returncode": 0}

        with mock.patch.object(updater_server, "run_compose", side_effect=fake_run_compose):
            result = updater_server.recreate_services("bgp-antifilter")

        self.assertTrue(result["ok"])
        self.assertEqual(calls, [("rm", "-f", "-s", "bgp-antifilter"), ("up", "-d", "--no-build", "bgp-antifilter")])

    def test_reconcile_runtime_marks_restart_as_completed_after_version_switch(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime_file = Path(tmp) / "update-runtime.json"
            runtime_file.write_text(
                '{'
                '"active": true,'
                '"stage": "restarting",'
                '"target_version": "0.3.0",'
                '"current_version": "0.2.9"'
                '}',
                encoding="utf-8",
            )

            with mock.patch.object(updater_server, "UPDATE_RUNTIME_FILE", runtime_file):
                payload = updater_server.reconcile_runtime("0.3.0")

        self.assertFalse(payload["active"])
        self.assertEqual(payload["stage"], "completed")
        self.assertTrue(payload["success"])
        self.assertEqual(payload["current_version"], "0.3.0")

    def test_reconcile_runtime_marks_any_active_stage_completed_when_target_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime_file = Path(tmp) / "update-runtime.json"
            runtime_file.write_text(
                '{'
                '"active": true,'
                '"stage": "pulling",'
                '"target_version": "0.3.1",'
                '"current_version": "0.3.0"'
                '}',
                encoding="utf-8",
            )

            with mock.patch.object(updater_server, "UPDATE_RUNTIME_FILE", runtime_file):
                payload = updater_server.reconcile_runtime("0.3.1")

        self.assertFalse(payload["active"])
        self.assertEqual(payload["stage"], "completed")
        self.assertTrue(payload["success"])
        self.assertEqual(payload["current_version"], "0.3.1")

    def test_reconcile_runtime_clears_failed_status_after_external_upgrade_to_target_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime_file = Path(tmp) / "update-runtime.json"
            runtime_file.write_text(
                '{'
                '"active": false,'
                '"stage": "failed",'
                '"target_version": "0.3.4",'
                '"current_version": "0.3.3",'
                '"success": false,'
                '"error": "docker compose up failed",'
                '"rollback": {"ok": false, "error": "rollback failed"}'
                '}',
                encoding="utf-8",
            )

            with mock.patch.object(updater_server, "UPDATE_RUNTIME_FILE", runtime_file):
                payload = updater_server.reconcile_runtime("0.3.4")

        self.assertFalse(payload["active"])
        self.assertEqual(payload["stage"], "completed")
        self.assertTrue(payload["success"])
        self.assertEqual(payload["current_version"], "0.3.4")
        self.assertEqual(payload["error"], "")
        self.assertEqual(payload["rollback"], {})

    @mock.patch.object(updater_server, "uses_legacy_docker_compose", return_value=False)
    def test_apply_update_rolls_back_to_version_from_env_file(self, _legacy):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            version_file = Path(tmp) / "VERSION"
            runtime_file = Path(tmp) / "update-runtime.json"
            env_file.write_text("BGP_ANTIFILTER_VERSION=0.2.8\n", encoding="utf-8")
            version_file.write_text("0.3.2\n", encoding="utf-8")

            compose_calls = []

            def fake_run_compose(*args, timeout=1800):
                compose_calls.append(args)
                if args and args[0] == "pull":
                    return {"ok": False, "stderr": "pull failed", "stdout": "", "returncode": 1}
                return {"ok": True, "stderr": "", "stdout": "", "returncode": 0}

            with mock.patch.object(updater_server, "ENV_FILE", env_file):
                with mock.patch.object(updater_server, "VERSION_FILE", version_file):
                    with mock.patch.object(updater_server, "UPDATE_RUNTIME_FILE", runtime_file):
                        with mock.patch.object(updater_server, "COMPOSE_SERVICES", ("bgp-antifilter",)):
                            with mock.patch.object(updater_server, "run_compose", side_effect=fake_run_compose):
                                updater_server.apply_update("0.3.3")

            self.assertEqual(compose_calls[0], ("pull", *updater_server.COMPOSE_SERVICES))
            self.assertEqual(len(compose_calls), 1, "pull failure must leave the running application alone")
            self.assertIn("BGP_ANTIFILTER_VERSION=0.2.8\n", env_file.read_text(encoding="utf-8"))
            runtime = updater_server.read_json(runtime_file, {})
            self.assertFalse(runtime["success"])
            self.assertTrue(runtime["rollback"]["ok"])
            self.assertEqual(runtime["rollback"]["version"], "0.2.8")

    @mock.patch.object(updater_server, "wait_for_services")
    def test_apply_update_uses_legacy_recreate_flow_for_all_services(self, wait):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            version_file = Path(tmp) / "VERSION"
            runtime_file = Path(tmp) / "update-runtime.json"
            env_file.write_text("BGP_ANTIFILTER_VERSION=0.2.8\n", encoding="utf-8")
            version_file.write_text("0.3.2\n", encoding="utf-8")

            compose_calls = []

            def fake_run_compose(*args, timeout=1800):
                compose_calls.append(args)
                return {"ok": True, "stderr": "", "stdout": "", "returncode": 0}

            with mock.patch.object(updater_server, "ENV_FILE", env_file):
                with mock.patch.object(updater_server, "VERSION_FILE", version_file):
                    with mock.patch.object(updater_server, "UPDATE_RUNTIME_FILE", runtime_file):
                        with mock.patch.object(updater_server, "COMPOSE_SERVICES", ("bgp-antifilter", "metrics")):
                            with mock.patch.object(updater_server, "SELF_SERVICE", "metrics"):
                                with mock.patch.object(updater_server, "uses_legacy_docker_compose", return_value=True):
                                    with mock.patch.object(updater_server, "run_compose", side_effect=fake_run_compose):
                                        updater_server.apply_update("0.3.3")

            self.assertEqual(
                compose_calls,
                [
                    ("pull", "bgp-antifilter", "metrics"),
                    ("rm", "-f", "-s", "bgp-antifilter", "metrics"),
                    ("up", "-d", "--no-build", "bgp-antifilter", "metrics"),
                ],
            )
            runtime = updater_server.read_json(runtime_file, {})
            self.assertTrue(runtime["success"])
            self.assertEqual(runtime["current_version"], "0.3.3")

    def test_start_update_reports_current_version_from_env_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            version_file = Path(tmp) / "VERSION"
            env_file.write_text("BGP_ANTIFILTER_VERSION=0.2.8\n", encoding="utf-8")
            version_file.write_text("0.3.2\n", encoding="utf-8")

            context = {"container": "self-id", "image": "sha256:old", "project": "test",
                       "directory": "/srv/test", "worker": "test-image-updater"}
            with mock.patch.object(updater_server, "ENV_FILE", env_file), \
                 mock.patch.object(updater_server, "VERSION_FILE", version_file), \
                 mock.patch.object(updater_server, "UPDATE_RUNTIME_FILE", Path(tmp) / "update.json"), \
                 mock.patch.object(updater_server, "health_status", return_value=(True, "")), \
                 mock.patch.object(updater_server, "deployment_context", return_value=context), \
                 mock.patch.object(updater_server, "run_docker", return_value="worker-id") as docker:
                payload = updater_server.start_update("0.3.3")

            self.assertEqual(payload["current_version"], "0.2.8")
            self.assertEqual(payload["target_version"], "0.3.3")
            self.assertEqual(docker.call_args.args[:3], ("run", "-d", "--rm"))
            self.assertEqual(docker.call_args.args[docker.call_args.args.index("--user") + 1], "0:0")
            self.assertIn("sha256:old", docker.call_args.args)


if __name__ == "__main__":
    unittest.main()
