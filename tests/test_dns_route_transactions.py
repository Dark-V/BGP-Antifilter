"""DNS policy commits retain source provenance without making leases permanent."""
from contextlib import closing
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

from bgp_antifilter import live_routes
from bgp_antifilter.route_snapshot import confirmed_snapshot, make_snapshot, publish_checkpoint, read_confirmed, snapshot_path
from bgp_antifilter.route_transaction import RouteManager, operation_lock
from bgp_antifilter.state_store import read_state
from tests.admin_support import admin_application
from tests.test_live_routes import Publisher, policy, wait_for


class DNSRouteTransactions(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = admin_application(self.root)
        self.config = self.app.config
        self.publisher = Publisher()
        self.publisher.confirm_policy = mock.Mock()
        self.worker = live_routes.LiveRoutes(self.config.generated_dir, publisher=self.publisher, batch_seconds=0.005)
        self.addCleanup(self.worker.close)
        self.environment = {**os.environ, "DNS_PROXY_ENABLED": "1", "DNS_ROUTE_GRACE": "0"}
        self.manager = RouteManager(self.config, self.environment)
        self.grace = mock.patch.dict(os.environ, {"DNS_ROUTE_GRACE": "0"})
        self.grace.start()
        self.addCleanup(self.grace.stop)

    def snapshot(self, generation=1, routes=None):
        config = policy(generation)
        if routes is not None:
            config["routes"] = routes
        status = {"sources": [], "success": True, "updated_at_unix": int(time.time()), "duration_seconds": 0,
                  "routes": {"final": len(config["routes"]), "invalid": 0, "exclude_rules_applied": 0}}
        result = make_snapshot([ipaddress.IPv4Network(value) for value in config["routes"]], status, [])
        result["dns_policy"] = config
        return result

    def apply(self, snapshot):
        with mock.patch.object(self.manager, "generate", return_value=snapshot):
            self.manager.apply()

    def test_policy_confirmation_is_single_owner_and_static_checkpoint_is_immutable_between_updates(self):
        with mock.patch.object(self.manager, "configure", side_effect=AssertionError("no BIRD configure in DNS mode")), \
             mock.patch.object(self.manager, "publish", side_effect=AssertionError("only worker publishes")):
            self.apply(self.snapshot())
        self.publisher.confirm_policy.assert_called_once()
        before = snapshot_path(self.config.last_good_routes_file).read_bytes()
        self.worker.observe("cdn.example.test", [("1.1.1.1", 60)])
        self.worker.flush()
        self.assertIn("1.1.1.1/32", self.publisher.routes)
        self.assertEqual(before, snapshot_path(self.config.last_good_routes_file).read_bytes())
        self.assertNotIn("1.1.1.1", self.config.last_good_routes_file.read_text())
        self.apply(self.snapshot(2, ["192.0.2.0/24"]))
        self.assertEqual(read_confirmed(self.config.last_good_routes_file)["prefixes"], ["192.0.2.0/24"])
        self.assertIn("1.1.1.1/32", self.publisher.routes)

    def test_empty_base_can_publish_learned_routes_and_restart_without_expired_addresses(self):
        self.apply(self.snapshot(routes=[]))
        self.assertTrue(read_confirmed(self.config.last_good_routes_file)["status"]["apply_success"])
        self.worker.observe("cdn.example.test", [("1.1.1.1", 60)])
        self.worker.flush()
        self.worker.close()
        with closing(sqlite3.connect(self.config.generated_dir / "dns-cache.sqlite3")) as db:
            db.execute("UPDATE leases SET expiry=0")
            db.commit()
        publisher = Publisher()
        restarted = live_routes.LiveRoutes(self.config.generated_dir, publisher=publisher, batch_seconds=0.005)
        self.addCleanup(restarted.close)
        restarted.flush()
        self.assertEqual(publisher.routes, set())
        self.assertEqual(restarted.lease_count, 0)
        self.assertEqual(read_confirmed(self.config.last_good_routes_file)["prefixes"], [])

    def test_failed_bird_confirmation_rolls_back_policy_and_checkpoint(self):
        self.apply(self.snapshot())
        self.worker.observe("cdn.example.test", [("1.1.1.1", 60)])
        self.worker.flush()
        before = snapshot_path(self.config.last_good_routes_file).read_bytes()
        routes = set(self.publisher.routes)
        self.publisher.confirm_policy.side_effect = RuntimeError("BIRD rejected policy")
        with self.assertRaisesRegex(RuntimeError, "BIRD rejected"):
            self.apply(self.snapshot(2, ["192.0.2.0/24"]))
        self.assertEqual(self.publisher.routes, routes)
        self.assertEqual(self.worker.policy["generation"], 1)
        self.assertEqual(snapshot_path(self.config.last_good_routes_file).read_bytes(), before)
        self.assertFalse(read_state(self.config.status_file)["apply_success"])
        with closing(sqlite3.connect(self.config.generated_dir / "dns-cache.sqlite3")) as db:
            persisted = json.loads(db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()[0])
        self.assertEqual(persisted["generation"], 1)

    def test_partial_checkpoint_failure_restores_files_and_durable_policy(self):
        self.apply(self.snapshot())
        before = snapshot_path(self.config.last_good_routes_file).read_bytes()
        original = live_routes.publish_checkpoint

        def broken(snapshot, paths):
            original(snapshot, paths)
            raise OSError("checkpoint disk failure")

        with mock.patch.object(live_routes, "publish_checkpoint", side_effect=broken):
            with self.assertRaisesRegex(RuntimeError, "checkpoint disk failure"):
                self.apply(self.snapshot(2, ["192.0.2.0/24"]))
        self.assertFalse((self.config.generated_dir / "dns-policy.pending.json").exists())
        self.assertEqual(snapshot_path(self.config.last_good_routes_file).read_bytes(), before)
        self.assertEqual(self.publisher.routes, {"93.184.216.0/24"})
        self.worker.close()
        publisher = Publisher()
        restarted = live_routes.LiveRoutes(self.config.generated_dir, publisher=publisher, batch_seconds=0.005)
        self.addCleanup(restarted.close)
        restarted.flush()
        self.assertEqual(restarted.policy["generation"], 1)
        self.assertEqual(read_confirmed(self.config.last_good_routes_file)["dns_policy"]["generation"], 1)

    def test_deadline_expiring_during_file_publication_rolls_back_before_commit(self):
        self.apply(self.snapshot())
        before = {path: path.read_bytes() for path in (
            self.config.routes_file, self.config.last_good_routes_file, snapshot_path(self.config.last_good_routes_file),
            self.config.status_file, self.config.metrics_file)}
        candidate = self.snapshot(2, ["192.0.2.0/24"])
        path = self.root / "delayed-policy.json"
        path.write_text(json.dumps(candidate["dns_policy"]))
        publication = {key: str(getattr(self.config, key)) for key in
                       ("routes_file", "last_good_routes_file", "status_file", "metrics_file")}
        entered, release = threading.Event(), threading.Event()
        original = live_routes.publish_checkpoint

        def delayed(snapshot, paths):
            original(snapshot, paths)
            entered.set()
            self.assertTrue(release.wait(2))

        with mock.patch.object(live_routes, "publish_checkpoint", side_effect=delayed):
            try:
                with self.assertRaises(TimeoutError):
                    live_routes.install_policy(path, self.config.generated_dir, timeout=0.2,
                                              snapshot=candidate, publication=publication)
                self.assertTrue(entered.is_set())
            finally:
                release.set()
            ack = self.config.generated_dir / "dns-policy.applied.json"
            wait_for(lambda: read_state(ack).get("generation") == 2)
            self.assertFalse(read_state(ack)["success"])
        self.assertEqual(self.worker.policy["generation"], 1)
        self.assertEqual(self.publisher.routes, {"93.184.216.0/24"})
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        self.assertFalse((self.config.generated_dir / "dns-policy.pending.json").exists())
        with closing(sqlite3.connect(self.config.generated_dir / "dns-cache.sqlite3")) as db:
            persisted = json.loads(db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()[0])
        self.assertEqual(persisted["generation"], 1)

    def assert_static_takeover(self, routes):
        self.apply(self.snapshot())
        self.worker.observe("cdn.example.test", [("1.1.1.1", 60)], targets=[("edge.other.test", 60)])
        self.worker.flush()
        self.worker.close()
        static = self.snapshot(2, routes)
        del static["dns_policy"]
        manager = RouteManager(self.config, {**self.environment, "DNS_PROXY_ENABLED": "0"})
        with mock.patch.object(manager, "generate", return_value=static), mock.patch.object(manager, "configure"):
            manager.apply()
        checkpoint = snapshot_path(self.config.last_good_routes_file).read_bytes()

        # Both the first enable and another restart before regeneration must
        # retain the newer static checkpoint without reviving old DNS rules.
        for _ in range(2):
            publisher = Publisher()
            restarted = live_routes.LiveRoutes(self.config.generated_dir, publisher, batch_seconds=0.005)
            self.addCleanup(restarted.close)
            restarted.flush()
            self.assertIsNone(restarted.policy)
            self.assertEqual(publisher.routes, set(routes))
            self.assertEqual(snapshot_path(self.config.last_good_routes_file).read_bytes(), checkpoint)
            self.assertEqual(restarted.lease_count, 1)
            self.assertEqual(restarted.alias_count, 1)
            self.assertFalse((self.config.generated_dir / "dns-policy.json").exists())
            with closing(sqlite3.connect(self.config.generated_dir / "dns-cache.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM metadata WHERE key IN ('policy','checkpoint')").fetchone()[0], 0)
            restarted.close()

        publisher = Publisher()
        restarted = live_routes.LiveRoutes(self.config.generated_dir, publisher, batch_seconds=0.005)
        self.addCleanup(restarted.close)
        restarted.flush()
        self.apply(self.snapshot(3, routes))
        restarted.flush()
        self.assertIn("1.1.1.1/32", publisher.routes)
        restarted.observe("edge.other.test", [("1.0.0.1", 60)])
        restarted.flush()
        self.assertIn("1.0.0.1/32", publisher.routes)

    def test_reenable_keeps_new_static_checkpoint_and_reclassifies_retained_leases(self):
        self.assert_static_takeover(["192.0.2.0/24"])

    def test_same_prefix_static_update_still_replaces_old_dns_policy(self):
        self.assert_static_takeover(["93.184.216.0/24"])

    def test_committed_sqlite_policy_wins_over_uncommitted_dns_file_mirrors(self):
        self.apply(self.snapshot())
        self.worker.close()
        candidate = confirmed_snapshot(self.snapshot(2, ["192.0.2.0/24"]))
        publication = {key: str(getattr(self.config, key)) for key in
                       ("routes_file", "last_good_routes_file", "status_file", "metrics_file")}
        publish_checkpoint(candidate, publication)
        live_routes.write_json(self.config.generated_dir / "dns-policy.json", candidate["dns_policy"])
        publisher = Publisher()
        restarted = live_routes.LiveRoutes(self.config.generated_dir, publisher, batch_seconds=0.005)
        self.addCleanup(restarted.close)
        restarted.flush()
        self.assertEqual(publisher.routes, {"93.184.216.0/24"})
        self.assertEqual(restarted.policy["generation"], 1)
        self.assertEqual(read_confirmed(self.config.last_good_routes_file)["dns_policy"]["generation"], 1)

    def test_confirmed_dns_checkpoint_recovers_missing_sqlite_metadata(self):
        self.apply(self.snapshot())
        self.worker.close()
        with closing(sqlite3.connect(self.config.generated_dir / "dns-cache.sqlite3")) as db:
            db.execute("DELETE FROM metadata")
            db.commit()
        (self.config.generated_dir / "dns-policy.json").unlink()
        publisher = Publisher()
        restarted = live_routes.LiveRoutes(self.config.generated_dir, publisher, batch_seconds=0.005)
        self.addCleanup(restarted.close)
        restarted.flush()
        self.assertEqual(publisher.routes, {"93.184.216.0/24"})
        self.assertEqual(restarted.policy["generation"], 1)
        self.assertEqual(read_confirmed(self.config.last_good_routes_file)["dns_policy"]["generation"], 1)

    def test_dns_observations_continue_while_static_generation_holds_operation_lock(self):
        self.apply(self.snapshot())
        with operation_lock(self.config):
            receipt = self.worker.observe("cdn.example.test", [("1.1.1.1", 60)], receipt=True)
            self.assertTrue(receipt.result(timeout=1).expected["1.1.1.1"])
        self.assertIn("1.1.1.1/32", self.publisher.routes)

    def test_preview_is_stale_after_policy_only_change(self):
        self.apply(self.snapshot())
        with mock.patch.object(self.manager, "generate", return_value=self.snapshot(2)):
            preview = self.manager.create_preview()
        changed = self.snapshot(3)
        changed["dns_policy"]["include_domains"] = ["other.test"]
        self.apply(changed)
        with self.assertRaisesRegex(ValueError, "stale"):
            self.manager.read_preview(preview["id"])

    def test_startup_does_not_confirm_a_policy_until_the_worker_accepts_it(self):
        with mock.patch.object(self.manager, "generate", return_value=self.snapshot(routes=[])):
            self.manager.prepare()
        self.assertFalse(self.config.last_good_routes_file.exists())
        self.manager.confirm_startup()
        self.assertTrue(read_confirmed(self.config.last_good_routes_file)["status"]["apply_success"])
        self.assertFalse((self.config.generated_dir / "routes.prepared.json").exists())

    def test_runtime_heartbeat_has_no_dns_names_and_stops_cleanly(self):
        self.apply(self.snapshot())
        self.worker.observe("cdn.example.test", [("1.1.1.1", 60)])
        self.worker.flush()
        path = self.config.generated_dir / "dns-runtime.json"
        wait_for(lambda: read_state(path).get("dynamic_routes") == 1)
        state = read_state(path)
        self.assertTrue(state["routes_ready"])
        self.assertFalse(state["ready"])
        self.assertEqual(state["last_error"], "DNS readiness has not been checked yet")
        self.assertNotIn("example.test", path.read_text())
        self.assertNotIn("1.1.1.1", path.read_text())
        self.worker.close()
        self.assertFalse(read_state(path)["running"])

    def test_lost_ack_does_not_report_a_committed_policy_as_failed(self):
        original = live_routes.write_json

        def drop_ack(path, value):
            if Path(path).name == "dns-policy.applied.json":
                raise OSError("ACK disk failure")
            return original(path, value)

        with mock.patch.object(live_routes, "write_json", side_effect=drop_ack):
            self.apply(self.snapshot())
        self.assertTrue(read_confirmed(self.config.last_good_routes_file)["status"]["apply_success"])
        self.assertEqual(self.worker.policy["generation"], 1)

    def test_expired_policy_request_cannot_apply_later(self):
        self.apply(self.snapshot())
        candidate = self.snapshot(2, ["192.0.2.0/24"])
        path = self.config.generated_dir / "dns-policy.pending.json"
        live_routes.write_json(path, {"policy": candidate["dns_policy"], "snapshot": candidate,
                                     "deadline_unix": time.time() - 1})
        ack = self.config.generated_dir / "dns-policy.applied.json"
        wait_for(lambda: read_state(ack).get("generation") == 2)
        self.assertFalse(read_state(ack)["success"])
        self.assertEqual(self.worker.policy["generation"], 1)
        self.assertEqual(self.publisher.routes, {"93.184.216.0/24"})


if __name__ == "__main__":
    unittest.main()
