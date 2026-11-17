"""Shared advisory lock for route generation and legacy lock cleanup."""
from contextlib import contextmanager
import errno
import os


class UpdateLockBusy(RuntimeError):
    pass


@contextmanager
def acquire(legacy_dir, *, create=True):
    path = legacy_dir.with_name(legacy_dir.name + ".flock")
    # Never unlink this file. Processes must lock the same inode.
    with path.open("a+b" if create else "r+b") as handle:
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            raise UpdateLockBusy("A route update is running") from exc
        yield


def active(legacy_dir):
    try:
        with acquire(legacy_dir, create=False):
            return False
    except FileNotFoundError:
        return False
    except UpdateLockBusy:
        return True
