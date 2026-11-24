"""Prepare persistent application files before dropping container privileges."""

import argparse
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import stat

from .runtime_paths import GENERATED_PATH_SPECS, LIST_FILE_SPECS, config_paths, list_paths


SYSTEM_DIRECTORIES = (Path("/run/bird"), Path("/run/bgp-antifilter"), Path("/var/log/supervisor"))
SHARED_DIRECTORIES = frozenset(Path(path) for path in (
    "/", "/etc", "/run", "/var", "/var/lib", "/var/log", "/tmp", "/usr",
    "/bin", "/sbin", "/lib", "/lib64", "/home", "/root", "/opt", "/mnt", "/media", "/srv",
))


def absolute_path(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"runtime path must be absolute and contain no '..': {path}")
    return path


def permission_paths(environ=None):
    environ = os.environ if environ is None else environ
    config = config_paths(environ)
    generated = {key: Path(environ.get(name, default))
                 for key, (name, default) in GENERATED_PATH_SPECS.items()}
    trees = {config["config_dir"], config["list_backup_dir"], generated["generated_dir"],
             generated["cache_dir"], Path(environ.get("STATE_DIR", "/run/bgp-antifilter")),
             *SYSTEM_DIRECTORIES}
    if "LEGACY_CONFIG_DIR" in environ:
        trees.add(Path(environ["LEGACY_CONFIG_DIR"]))
    files = {*list_paths(environ).values(), config["settings_file"], config["settings_env_file"],
             *(path for key, path in generated.items() if key not in {"generated_dir", "cache_dir"})}
    last_good = Path(environ.get("LAST_GOOD_ROUTES_FILE", "/etc/bird/generated/routes.last-good.conf"))
    files.update((last_good, last_good.with_suffix(".json")))
    # Persistent sidecar locks can also belong to the old root process.
    files.update(path.with_name(path.name + ".lock") for path in tuple(files))
    bird_config = Path(environ.get("BIRD_CONFIG", "/etc/bird/bird.conf"))
    lock = Path(environ.get("UPDATE_LOCK_DIR", "/etc/bird/generated/update.lock"))
    private = {config["settings_file"], config["settings_env_file"]}
    paths = trees | files | private | {bird_config, lock}
    for path in paths:
        absolute_path(path)
    if trees & SHARED_DIRECTORIES:
        raise ValueError("runtime data directories must not be shared system directories")
    return trees, files, private, bird_config, lock


class Ownership:
    def __init__(self, uid, gid, private):
        self.uid, self.gid, self.private = uid, gid, private

    def update(self, descriptor, path, *, directory=False):
        info = os.fstat(descriptor)
        if not directory and info.st_nlink > 1:
            raise ValueError(f"refusing to change ownership of a hard-linked runtime file: {path}")
        private = (path in self.private or path.name in {"settings.json", "settings.env"}
                   or any(part in {"config-imports", "config-backups"} for part in path.parts))
        mode = 0o600 if private and not directory else stat.S_IMODE(info.st_mode) & 0o777
        mode |= 0o700 if directory else 0o600
        if (info.st_uid, info.st_gid) != (self.uid, self.gid):
            os.fchown(descriptor, self.uid, self.gid)
        if stat.S_IMODE(info.st_mode) != mode:
            os.fchmod(descriptor, mode)

    @contextmanager
    def open_directory(self, path):
        # Resolve every component through descriptors. O_NOFOLLOW on the final
        # file alone would still follow a replaced parent directory symlink.
        path = absolute_path(path)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(path.anchor, flags)
        current = Path(path.anchor)
        try:
            for part in path.parts[1:]:
                current /= part
                created = False
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    os.mkdir(part, mode=0o755, dir_fd=descriptor)
                    child = os.open(part, flags, dir_fd=descriptor)
                    created = True
                os.close(descriptor)
                descriptor = child
                if created:
                    self.update(descriptor, current, directory=True)
            yield descriptor
        finally:
            os.close(descriptor)

    def walk(self, descriptor, path):
        self.update(descriptor, path, directory=True)
        for name in os.listdir(descriptor):
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            child_path = path / name
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    self.walk(child, child_path)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                self.open_file(descriptor, name, child_path)
            # Symlinks and stale sockets/FIFOs are never opened or traversed.

    def directory(self, path, *, recursive=False):
        if path in SHARED_DIRECTORIES:
            raise ValueError(f"refusing to change ownership of a shared system directory: {path}")
        with self.open_directory(path) as descriptor:
            if recursive:
                self.walk(descriptor, path)
            else:
                self.update(descriptor, path, directory=True)

    def open_file(self, parent, name, path, *, create=False):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if create:
            flags |= os.O_CREAT
        try:
            descriptor = os.open(name, flags, 0o644, dir_fd=parent)
        except FileNotFoundError:
            if create:
                raise
            return
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError(f"runtime file must be a regular file: {path}")
            self.update(descriptor, path)
        finally:
            os.close(descriptor)

    def file(self, path, *, create=False, writable_parent=True):
        with self.open_directory(path.parent) as descriptor:
            # Custom file paths need atomic replacement in their own directory,
            # but /etc and other shared parents must keep their original owner.
            if writable_parent and path.parent not in SHARED_DIRECTORIES:
                self.update(descriptor, path.parent, directory=True)
            self.open_file(descriptor, path.name, path, create=create)


def prepare_runtime_permissions(environ=None, *, uid=10001, gid=10001):
    if not 0 < uid < 2 ** 31 or not 0 < gid < 2 ** 31:
        raise ValueError("runtime uid and gid must be positive non-root IDs")
    trees, files, private, bird_config, lock = permission_paths(environ)
    owner = Ownership(uid, gid, private)
    for path in sorted(trees, key=lambda item: (len(item.parts), str(item))):
        owner.directory(path, recursive=not any(parent in trees for parent in path.parents))
    for path in sorted(files):
        owner.file(path)
    # The legacy lock is a directory. Do not create it on a clean startup.
    try:
        lock.lstat()
    except FileNotFoundError:
        if lock.parent not in SHARED_DIRECTORIES:
            owner.directory(lock.parent)
    else:
        owner.directory(lock, recursive=True)
    # render-bird writes this file in place; /etc/bird stays root-owned.
    owner.file(bird_config, create=True, writable_parent=False)
    environ = os.environ if environ is None else environ
    legacy_bird = absolute_path(environ.get("LEGACY_BIRD_DIR", "/etc/bird"))
    for _name, default in LIST_FILE_SPECS.values():
        source = legacy_bird / Path(default).name
        if os.path.lexists(source):
            owner.file(source, writable_parent=False)


def prepare_standard_streams(*, uid=10001, gid=10001):
    # Supervisor reopens /dev/fd/1 and /dev/fd/2 for child logs. A pipe inherited
    # from Docker is writable through the old descriptor, but reopening its
    # inode after setuid still requires permission from the pipe's owner.
    for descriptor in (1, 2):
        try:
            info = os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        if stat.S_ISFIFO(info.st_mode) and info.st_uid != uid:
            os.fchown(descriptor, uid, gid)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uid", type=int, default=10001)
    parser.add_argument("--gid", type=int, default=10001)
    args = parser.parse_args(argv)
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("runtime ownership preparation requires root on Linux")
    try:
        prepare_runtime_permissions(uid=args.uid, gid=args.gid)
        prepare_standard_streams(uid=args.uid, gid=args.gid)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Cannot prepare runtime permissions: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
