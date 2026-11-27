import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from bgp_antifilter import runtime_permissions as permissions
from bgp_antifilter.runtime_paths import GENERATED_PATH_SPECS


class PermissionFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = self.root / "config"
        self.generated = self.root / "generated"
        self.bird = self.root / "etc" / "bird" / "bird.conf"
        self.environment = {
            **{name: str(self.generated / Path(default).name)
               for key, (name, default) in GENERATED_PATH_SPECS.items() if key != "generated_dir"},
            "GENERATED_DIR": str(self.generated), "CONFIG_DIR": str(self.config),
            "LAST_GOOD_ROUTES_FILE": str(self.generated / "routes.last-good.conf"),
            "UPDATE_LOCK_DIR": str(self.generated / "update.lock"),
            "STATE_DIR": str(self.root / "run" / "app"), "BIRD_CONFIG": str(self.bird),
            "LEGACY_BIRD_DIR": str(self.root / "old-bird"),
        }
        self.system = (self.root / "run" / "bird", self.root / "log" / "supervisor")
        self.patch = mock.patch.object(permissions, "SYSTEM_DIRECTORIES", self.system)
        self.patch.start()
        self.addCleanup(self.patch.stop)


class PermissionPathsTests(PermissionFixture, unittest.TestCase):
    def test_custom_settings_lists_and_generated_sidecars_are_included(self):
        settings = self.generated / "settings.json"
        projection = self.root / "secrets" / "custom.env"
        custom_list = self.root / "sources" / "custom.txt"
        checkpoint = self.root / "routes" / "checkpoint.conf"
        self.environment.update(SETTINGS_FILE=str(settings), SETTINGS_ENV_FILE=str(projection),
                                LISTS_FILE=str(custom_list), LAST_GOOD_ROUTES_FILE=str(checkpoint))
        trees, files, private, bird, lock = permissions.permission_paths(self.environment)
        self.assertIn(self.generated / "list-backups", trees)
        self.assertTrue({settings, projection, custom_list, checkpoint, checkpoint.with_suffix(".json"),
                         checkpoint.with_suffix(".json.lock")} <= files)
        self.assertEqual(private, {settings, projection})
        self.assertEqual(bird, self.bird)
        self.assertEqual(lock, self.generated / "update.lock")
        self.assertNotIn(self.root / "workspace", trees)

    def test_shared_directories_and_relative_or_parent_paths_are_rejected(self):
        with mock.patch.object(permissions, "SHARED_DIRECTORIES", {self.root}):
            for path in (str(self.root), "relative/config", str(self.root / ".." / "config")):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    permissions.permission_paths({**self.environment, "CONFIG_DIR": path})

    def test_root_ids_are_not_accepted_as_the_application_user(self):
        for uid, gid in ((0, 10001), (10001, 0), (-1, 10001), (10001, 2 ** 31)):
            with self.subTest(uid=uid, gid=gid), self.assertRaises(ValueError), \
                 mock.patch.object(permissions.Ownership, "directory") as change:
                permissions.prepare_runtime_permissions(self.environment, uid=uid, gid=gid)
            change.assert_not_called()


class StandardStreamTests(unittest.TestCase):
    def test_only_fifo_ownership_changes_and_other_output_targets_are_preserved(self):
        for mode in (stat.S_IFREG, stat.S_IFCHR, stat.S_IFSOCK, stat.S_IFIFO):
            for uid in (0, 10001):
                info = SimpleNamespace(st_mode=mode | 0o600, st_uid=uid)
                with self.subTest(mode=mode, uid=uid), \
                     mock.patch.object(permissions.os, "fstat", return_value=info) as inspect, \
                     mock.patch.object(permissions.os, "fchown", create=True) as change:
                    permissions.prepare_standard_streams()
                self.assertEqual(inspect.call_args_list, [mock.call(1), mock.call(2)])
                expected = [mock.call(1, 10001, 10001), mock.call(2, 10001, 10001)] if mode == stat.S_IFIFO and uid == 0 else []
                self.assertEqual(change.call_args_list, expected)

    @unittest.skipUnless(sys.platform == "linux" and getattr(os, "geteuid", lambda: -1)() == 0,
                         "Linux root is required to reopen a pipe after changing UID")
    def test_root_created_output_pipes_can_be_reopened_only_after_owner_migration(self):
        script = """
import os, sys
from bgp_antifilter.runtime_permissions import prepare_standard_streams
if sys.argv[1] == 'prepare':
    prepare_standard_streams()
os.setgroups([])
os.setgid(10001)
os.setuid(10001)
for descriptor in (1, 2):
    try:
        with open(f'/proc/self/fd/{descriptor}', 'w') as output:
            output.write(f'reopened{descriptor}\\n')
    except PermissionError:
        os.write(descriptor, f'denied{descriptor}\\n'.encode())
"""
        for mode, prefix in (("unchanged", "denied"), ("prepare", "reopened")):
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable, "-c", script, mode],
                                        cwd=Path(__file__).resolve().parents[1],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout, prefix + "1\n")
                self.assertEqual(result.stderr, prefix + "2\n")


@unittest.skipUnless(os.name == "posix", "Linux descriptor-based ownership preparation")
class RuntimeOwnershipTests(PermissionFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.uid, self.gid = os.geteuid() or 10001, os.getegid() or 10001

    def prepare(self):
        permissions.prepare_runtime_permissions(self.environment, uid=self.uid, gid=self.gid)

    def put(self, path, text="existing", mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(mode)
        return path

    def test_existing_private_files_database_and_cache_keep_contents(self):
        files = [self.put(self.config / "settings.json", "{\"values\":{}}", 0o644),
                 self.put(self.config / "settings.env", "HTTP_PROXY_PASSWORD='secret'\n", 0o640),
                 self.put(self.generated / "settings.env", "legacy", 0o644),
                 self.put(self.generated / "config-imports" / "preview.json", "{}", 0o644),
                 self.put(self.config / "config-backups" / "backup.json", "{}", 0o644),
                 self.put(self.generated / "dns-cache.sqlite3"),
                 self.put(self.generated / "dns-cache.sqlite3-wal"),
                 self.put(self.generated / "dns-cache.sqlite3-shm"),
                 self.put(self.generated / "cache" / "source.txt")]
        expected = {path: path.read_bytes() for path in files}
        self.prepare()
        self.prepare()
        for path in files:
            self.assertEqual(path.read_bytes(), expected[path])
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (self.uid, self.gid))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_only_bird_config_is_precreated_and_shared_parent_keeps_owner(self):
        self.bird.parent.mkdir(parents=True)
        parent_owner = self.bird.parent.stat().st_uid, self.bird.parent.stat().st_gid
        self.prepare()
        self.assertEqual(self.bird.read_bytes(), b"")
        self.assertEqual((self.bird.stat().st_uid, self.bird.stat().st_gid), (self.uid, self.gid))
        self.assertEqual((self.bird.parent.stat().st_uid, self.bird.parent.stat().st_gid), parent_owner)
        for path in (self.config / "settings.json", self.config / "settings.env",
                     self.config / "lists.txt", self.generated / "update.lock"):
            self.assertFalse(path.exists(), str(path))

    @unittest.skipUnless(os.name == "posix" and getattr(os, "geteuid", lambda: -1)() == 0,
                         "root is required to exercise an inaccessible parent after changing UID")
    def test_application_owned_config_still_requires_traversable_root_owned_parent(self):
        self.root.chmod(0o755)
        parent = self.bird.parent
        parent.mkdir(parents=True)
        parent.chmod(0o700)
        config = parent / "config"
        self.environment["CONFIG_DIR"] = str(config)
        self.prepare()
        self.assertEqual(config.stat().st_uid, self.uid)
        self.assertEqual(parent.stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
        script = """
import os, sys
from pathlib import Path
directory = Path(sys.argv[1])
os.setgroups([])
os.setgid(10001)
os.setuid(10001)
try:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'probe').write_text('ready')
except PermissionError:
    print('parent is not traversable')
    raise SystemExit(3)
print('ready')
"""
        for mode, status, output in ((0o700, 3, "parent is not traversable"), (0o755, 0, "ready")):
            with self.subTest(parent_mode=oct(mode)):
                # The image fixes its own /etc/bird mode; ownership preparation
                # must not silently loosen arbitrary custom parent directories.
                parent.chmod(mode)
                result = subprocess.run([sys.executable, "-c", script, str(config)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip(), output)
                self.assertEqual(parent.stat().st_uid, 0)

    def test_custom_parent_is_writable_without_changing_sibling_files(self):
        custom = self.root / "custom" / "secret.env"
        self.environment["SETTINGS_ENV_FILE"] = str(custom)
        self.put(custom, "secret", 0o644)
        sibling = self.put(custom.parent / "unrelated.txt", "private", 0o400)
        original = sibling.stat()
        self.prepare()
        self.assertEqual(stat.S_IMODE(custom.stat().st_mode), 0o600)
        self.assertEqual(custom.stat().st_uid, self.uid)
        self.assertEqual(custom.parent.stat().st_uid, self.uid)
        self.assertEqual((sibling.stat().st_uid, sibling.stat().st_gid, sibling.stat().st_mode),
                         (original.st_uid, original.st_gid, original.st_mode))

    def test_custom_legacy_config_and_old_list_are_readable_after_migration(self):
        legacy = self.root / "legacy-config"
        self.environment["LEGACY_CONFIG_DIR"] = str(legacy)
        settings = self.put(legacy / "settings.json", '{"values":{}}')
        legacy_list = self.put(Path(self.environment["LEGACY_BIRD_DIR"]) / "lists.txt", "https://example.test/routes.txt")
        sibling = self.put(legacy_list.parent / "unrelated", mode=0o400)
        before = sibling.stat()
        self.prepare()
        for path in (settings, legacy_list):
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (self.uid, self.gid))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual((sibling.stat().st_uid, sibling.stat().st_gid, sibling.stat().st_mode),
                         (before.st_uid, before.st_gid, before.st_mode))

    def test_nested_symlinks_do_not_change_external_files(self):
        external = self.put(self.root / "outside" / "secret", "unchanged", 0o400)
        before = external.stat()
        self.config.mkdir()
        (self.config / "linked-dir").symlink_to(external.parent, target_is_directory=True)
        (self.config / "linked-file").symlink_to(external)
        self.prepare()
        self.assertEqual(external.read_text(), "unchanged")
        self.assertEqual((external.stat().st_uid, external.stat().st_gid, external.stat().st_mode),
                         (before.st_uid, before.st_gid, before.st_mode))

    def test_explicit_file_symlink_and_directory_ancestor_are_rejected(self):
        external = self.put(self.root / "outside" / "secret", "unchanged", 0o400)
        self.config.mkdir()
        target = self.config / "settings.env"
        target.symlink_to(external)
        with self.assertRaises(OSError):
            self.prepare()
        target.unlink()
        link = self.root / "linked-parent"
        link.symlink_to(external.parent, target_is_directory=True)
        self.environment["SETTINGS_ENV_FILE"] = str(link / "secret")
        with self.assertRaises(OSError):
            self.prepare()
        self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o400)
        self.assertEqual(external.read_text(), "unchanged")

    def test_hard_links_are_rejected_before_ownership_or_modes_change(self):
        external = self.put(self.root / "outside" / "secret", "unchanged", 0o400)
        before = external.stat()
        self.config.mkdir()
        os.link(external, self.config / "linked-file")
        with self.assertRaisesRegex(ValueError, "hard-linked"):
            self.prepare()
        self.assertEqual((external.stat().st_uid, external.stat().st_gid, external.stat().st_mode),
                         (before.st_uid, before.st_gid, before.st_mode))

    @unittest.skipUnless(os.name == "posix" and getattr(os, "geteuid", lambda: -1)() == 0,
                         "root is required to exercise the final UID transition")
    def test_legacy_migration_and_sqlite_wal_work_after_dropping_uid(self):
        self.root.chmod(0o755)
        self.put(self.generated / "settings.json", '{"values":{"FETCH_TIMEOUT":"12"}}')
        self.put(self.generated / "settings.env", "FETCH_TIMEOUT=12\n")
        self.put(self.generated / "config" / "lists.txt", "https://example.test/routes.txt\n")
        self.environment.update(DEFAULT_CONFIG_DIR=str(self.root / "defaults"), LEGACY_BIRD_DIR=str(self.bird.parent))
        database = self.generated / "dns-cache.sqlite3"
        connection = sqlite3.connect(database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE lease (address TEXT)")
        connection.commit()
        for path in self.generated.glob("dns-cache.sqlite3*"):
            path.chmod(0o600)
        self.prepare()

        def drop_uid():
            os.setgroups([])
            os.setgid(self.gid)
            os.setuid(self.uid)

        script = """
import json, os, sqlite3
from pathlib import Path
from bgp_antifilter.config_migration import prepare_user_config
from bgp_antifilter.admin.storage import write_text_atomic
paths = prepare_user_config()
assert 'FETCH_TIMEOUT=12' in paths['settings_env_file'].read_text()
assert 'example.test' in (paths['config_dir'] / 'lists.txt').read_text()
write_text_atomic(paths['settings_env_file'], 'FETCH_TIMEOUT=20\\n', mode=0o600)
with sqlite3.connect(Path(os.environ['GENERATED_DIR']) / 'dns-cache.sqlite3') as db:
    db.execute("INSERT INTO lease VALUES ('192.0.2.1')")
Path(os.environ['BIRD_CONFIG']).write_text('router id 192.0.2.1;\\n')
"""
        result = subprocess.run([sys.executable, "-c", script], env={**os.environ, **self.environment},
                                cwd=Path(__file__).resolve().parents[1], preexec_fn=drop_uid,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(connection.execute("SELECT address FROM lease").fetchall(), [("192.0.2.1",)])
        self.assertEqual(stat.S_IMODE((self.config / "settings.env").stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
