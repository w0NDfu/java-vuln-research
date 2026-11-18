"""Immutable receipts and cross-platform single-writer locks."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as out:
        json.dump(value, out, ensure_ascii=False, indent=2, allow_nan=False)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, path)


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def tree_hash(root):
    root = Path(root)
    return digest([(p.relative_to(root).as_posix(), file_hash(p))
                   for p in sorted(root.rglob("*")) if p.is_file()
                   and not {".git", "__pycache__", ".pytest_cache"}.intersection(p.relative_to(root).parts)
                   and p.suffix != ".pyc"])


def inside(root, relative):
    root = Path(root).resolve()
    path = (root / relative).resolve()
    if path == root or not path.is_relative_to(root):
        raise ValueError("Path must be a file strictly inside its declared root")
    return path


@contextlib.contextmanager
def lock(path):
    """OS releases lock on crash; stale files do not falsely block continuation."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as out:
        if os.name == "nt":
            import msvcrt
            if path.stat().st_size == 0:
                out.write(b"0"); out.flush()
            out.seek(0)
            msvcrt.locking(out.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(out.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == "nt":
                out.seek(0); msvcrt.locking(out.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(out.fileno(), fcntl.LOCK_UN)
