"""Admin file helpers; runtime JSON transactions use state_store separately."""

import errno
import json
import os


def json_load(path, default):
    try:
        with path.open(encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return default


def text_load(path):
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def write_text_atomic(path, text, *, mode=None):
    def write(target):
        if mode is None:
            target.write_text(text, encoding="utf-8", newline="\n")
            return
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as file:
            if os.name != "nt":
                os.fchmod(file.fileno(), mode)
            file.write(text)

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    write(tmp)
    try:
        tmp.replace(path)
    except OSError as exc:
        if exc.errno not in (errno.EBUSY, errno.EACCES, errno.EPERM):
            raise
        tmp.unlink(missing_ok=True)
        write(path)


def append_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as file:
        file.write(text)


def tail_text(path, max_bytes=250_000):
    try:
        with path.open("rb") as file:
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(max(0, size - max_bytes))
            data = file.read()
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")
