"""Collection-time cache for behaviour-derived tool selection.

``tests/_tool_classes._select_entries`` decides which tools a ``member=`` / ``eligible=``
property applies to by calling every candidate against the fake upstream. That is
roughly 90,000 tool calls and about 97% of the suite's collection time, and every
pytest process repeats it: each xdist worker, the ``--collect-only`` step and every
shard.

The result is a pure function of the code, the installed packages and the test
environment, so it is computed once and reused:

* The cache file is named by a fingerprint of every tracked or unignored file in the
  checkout (contents, not mtimes), the Python version, every installed distribution and
  version, and the environment (minus volatile names such as ``PYTEST_*`` and per-step
  Actions variables; values are only hashed, never stored). Any change gives a new file,
  so a stale selection can never be read.
* Inside one file, a selection is keyed by a stable description of its candidates,
  predicates (qualified name, code, closure values and defaults), argument names and axis
  values. A predicate or value without a stable description (its ``repr`` shows a
  memory address) is not cached and is computed as before.
* A hit returns the same entries, in the same order, as the computation it replaces;
  collected node IDs are unchanged. Errors are never cached.
* The first process takes an exclusive lock and keeps it while it collects; xdist
  workers that start at the same time wait and then read the finished file instead of
  repeating the work.

``UNIFI_TEST_SELECTION_CACHE=0`` turns the cache off; ``UNIFI_TEST_SELECTION_CACHE_DIR``
moves it (default ``.pytest_cache/unifi-selection`` under the repository root). The
directory is safe to delete at any time.
"""

from __future__ import annotations

import functools
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path
from typing import Any

try:  # POSIX only; elsewhere the cache works without the cross-process lock.
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parent.parent
FORMAT = 1


class _Unstable(Exception):
    """A value has no description that is stable across processes."""


_OWN_PREFIX = "UNIFI_TEST_SELECTION_"
# Environment names that change between processes of one run without changing any
# selection. Everything else in the environment is part of the fingerprint: the code reads
# UNIFI_*, MCP_* and FASTMCP_* (and libraries read more), and collection runs before the
# hermetic-env fixture. A volatile name missing here only costs a cache miss.
_VOLATILE_PREFIXES = (
    _OWN_PREFIX,
    "PYTEST_",  # PYTEST_CURRENT_TEST, PYTEST_XDIST_* (per worker)
    "COV_CORE_",  # pytest-cov subprocess support
    "COVERAGE_",  # coverage patch = subprocess (COVERAGE_PROCESS_CONFIG in every covered run)
    "GITHUB_",  # per-step files and ids in Actions
    "RUNNER_",
    "ACTIONS_",
    "SSH_",
    "TERM_SESSION_",
    "ITERM_",
    "TMUX",
    "XDG_SESSION_",
    # Per-build values of a hosted CI runner (build id, start time, the container's
    # credential and metadata endpoints).
    "CODEBUILD_",
    "ECS_CONTAINER_METADATA_",
    "AWS_CONTAINER_",
    # A runner host's package-index and toolchain mirrors.
    "PIP_",
    "UV_",
    "RUSTUP_",
    # A shard job's own coordinates (K, N, output directory, install time): the selection is
    # computed before, and independent of, the shard it runs.
    "SHARD_",
)
# Per hosted slot: each CI job, each shard of a sharded suite, runs in its own slot.
_VOLATILE_SUFFIXES = ("_SLOT",)
_VOLATILE_NAMES = frozenset(
    {
        "PWD",
        "OLDPWD",
        "SHLVL",
        "_",
        "COLUMNS",
        "LINES",
        "INVOCATION_ID",
        "JOURNAL_STREAM",
        # Per container: each CI job, each shard of a sharded suite.
        "HOSTNAME",
    }
)
_PRUNE_AFTER_S = 7 * 24 * 3600
# Only files this module writes: <fingerprint>.json, <fingerprint>.lock and the
# <fingerprint>.<random>.tmp files of an interrupted write.
_OWN_FILE = re.compile(r"[0-9a-f]{64}(\.json|\.lock|\.[^/]*\.tmp)")


def _fingerprint_env() -> list[tuple[str, str]]:
    return sorted(
        (k, v)
        for k, v in os.environ.items()
        if k not in _VOLATILE_NAMES
        and not k.startswith(_VOLATILE_PREFIXES)
        and not k.endswith(_VOLATILE_SUFFIXES)
    )


def enabled() -> bool:
    return os.environ.get("UNIFI_TEST_SELECTION_CACHE", "1") != "0"


def cache_dir() -> Path:
    override = os.environ.get("UNIFI_TEST_SELECTION_CACHE_DIR")
    return Path(override) if override else ROOT / ".pytest_cache" / "unifi-selection"


def _files() -> list[str]:
    git = shutil.which("git")
    try:
        if git is None:
            raise OSError("git not found")
        out = subprocess.run(  # noqa: S603 - fixed argv, resolved git
            [git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout
        return sorted({p for p in out.decode("utf-8", "surrogateescape").split("\0") if p})
    except (OSError, subprocess.CalledProcessError):
        found = []
        for base, dirs, names in os.walk(ROOT):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d != "__pycache__")
            for name in names:
                if not name.endswith((".pyc", ".pyo")):
                    found.append(os.path.relpath(os.path.join(base, name), ROOT))
        return sorted(found)


@functools.cache
def fingerprint() -> str:
    """Everything a selection can depend on, outside the selection call itself."""
    h = hashlib.sha256()
    h.update(f"format={FORMAT}\0python={sys.version}\0".encode())
    for dist in sorted(
        f"{d.metadata['Name']}=={d.version}" for d in importlib.metadata.distributions()
    ):
        h.update(f"dist={dist}\0".encode())
    for key, value in _fingerprint_env():
        h.update(f"env={key}={value}\0".encode("utf-8", "surrogateescape"))
    for rel in _files():
        path = ROOT / rel
        try:
            data = path.read_bytes()
        except (FileNotFoundError, IsADirectoryError):
            data = b"\0<missing>\0"
        h.update(f"file={rel}\0{len(data)}\0".encode())
        h.update(data)
    return h.hexdigest()


def _code(code: types.CodeType, depth: int) -> str:
    """The identity of a function body: first line, bytecode, names and constants.

    Two functions made by one factory share a qualified name (``f.<locals>.<lambda>``)
    and can close over the same values; only their code tells them apart.
    """
    if depth > 6:
        raise _Unstable("too deep")
    consts = [
        _code(c, depth + 1) if isinstance(c, types.CodeType) else _stable(c, depth + 1)
        for c in code.co_consts
    ]
    raw = "\0".join(
        [str(code.co_firstlineno), code.co_code.hex(), ",".join(code.co_names), *consts]
    )
    return hashlib.sha256(raw.encode("utf-8", "surrogateescape")).hexdigest()


def _stable(obj: Any, depth: int = 0) -> str:
    """A description of ``obj`` that is the same in every process, or ``_Unstable``."""
    if depth > 6:
        raise _Unstable("too deep")
    if obj is None or isinstance(obj, bool | int | float | complex | str | bytes):
        return f"{type(obj).__name__}:{obj!r}"
    if isinstance(obj, tuple | list):
        inner = ",".join(_stable(v, depth + 1) for v in obj)
        return f"{type(obj).__name__}[{inner}]"
    if isinstance(obj, set | frozenset):
        return f"{type(obj).__name__}{{{','.join(sorted(_stable(v, depth + 1) for v in obj))}}}"
    if isinstance(obj, dict):
        items = sorted(f"{_stable(k, depth + 1)}:{_stable(v, depth + 1)}" for k, v in obj.items())
        return f"{type(obj).__name__}{{{','.join(items)}}}"
    if isinstance(obj, functools.partial):
        return (
            f"partial({_stable(obj.func, depth + 1)},{_stable(obj.args, depth + 1)},"
            f"{_stable(obj.keywords, depth + 1)})"
        )
    if isinstance(obj, types.MethodType):
        return f"method({_stable(obj.__func__, depth + 1)},{_stable(obj.__self__, depth + 1)})"
    if isinstance(obj, types.FunctionType):
        if not obj.__closure__ and (
            "<lambda>" in obj.__qualname__ or "<locals>" in obj.__qualname__
        ):
            # Two such functions can share a name with different bodies; only the closure
            # values would tell them apart, and there are none.
            raise _Unstable(obj.__qualname__)
        cells = []
        for cell in obj.__closure__ or ():
            try:
                cells.append(_stable(cell.cell_contents, depth + 1))
            except ValueError:  # empty cell
                cells.append("<empty>")
        return (
            f"fn({obj.__module__}.{obj.__qualname__};"
            f"code={_code(obj.__code__, depth + 1)};"
            f"cells={','.join(cells)};"
            f"defaults={_stable(obj.__defaults__, depth + 1)};"
            f"kwdefaults={_stable(obj.__kwdefaults__, depth + 1)})"
        )
    if isinstance(obj, type | types.BuiltinFunctionType | types.ModuleType):
        name = getattr(obj, "__qualname__", getattr(obj, "__name__", ""))
        if "<locals>" in name:  # a class made at run time: its name does not identify it
            raise _Unstable(name)
        return f"{type(obj).__name__}({getattr(obj, '__module__', '')}.{name})"
    text = repr(obj)
    if " at 0x" in text or "object at" in text or "id='" in text:
        raise _Unstable(text)
    return f"{type(obj).__module__}.{type(obj).__qualname__}:{text}"


def key(entries: list[Any], member: Any, eligible: Any, argnames: Any, axes: Any) -> str | None:
    """The cache key of one selection, or ``None`` when it cannot be described stably."""
    try:
        text = "\0".join(
            [
                _stable(list(entries)),
                _stable(member),
                _stable(eligible),
                _stable(tuple(argnames)),
                _stable(axes),
            ]
        )
    except _Unstable:
        return None
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


class _Store:
    def __init__(self) -> None:
        self.loaded = False
        self.data: dict[str, dict[str, Any]] = {}
        self.new: dict[str, dict[str, Any]] = {}
        self.lock_fd: int | None = None
        self.path: Path | None = None

    def _load(self) -> None:
        if self.loaded:
            return
        self.loaded = True
        try:
            directory = cache_dir()
            directory.mkdir(parents=True, exist_ok=True)
            self.path = directory / f"{fingerprint()}.json"
            if fcntl is not None:
                fd = os.open(directory / f"{fingerprint()}.lock", os.O_RDWR | os.O_CREAT, 0o644)
                # Blocks while another process is producing this file, then reads it.
                fcntl.flock(fd, fcntl.LOCK_EX)
                self.lock_fd = fd
            self._read()
            if self.data:
                # In use: keep it out of other fingerprints' pruning.
                os.utime(self.path)
            if self.data and self.lock_fd is not None:
                # Warm: nothing to produce, so let other processes in at once.
                self._unlock()
        except OSError:
            self.path = None
            self._unlock()

    def _read(self) -> None:
        if self.path is None:
            return
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return
        if isinstance(raw, dict) and raw.get("format") == FORMAT:
            selections = raw.get("selections")
            if isinstance(selections, dict):
                self.data = selections

    def _unlock(self) -> None:
        if self.lock_fd is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            finally:
                try:
                    os.close(self.lock_fd)
                finally:
                    self.lock_fd = None

    def get(self, k: str, n: int) -> list[int] | None:
        self._load()
        hit = self.new.get(k) or self.data.get(k)
        if not hit or hit.get("n") != n:
            return None
        picked = hit.get("selected")
        if not isinstance(picked, list) or not all(
            isinstance(i, int) and 0 <= i < n for i in picked
        ):
            return None
        return picked

    def put(self, k: str, n: int, selected: list[int]) -> None:
        self._load()
        self.new[k] = {"n": n, "selected": selected}

    def _prune(self) -> None:
        """Remove this module's files of other fingerprints unused for a week."""
        if self.path is None:
            return
        now = time.time()
        keep = {self.path.name, self.path.with_suffix(".lock").name}
        for old in self.path.parent.iterdir():
            if old.name in keep or not _OWN_FILE.fullmatch(old.name):
                continue
            try:
                if now - old.stat().st_mtime > _PRUNE_AFTER_S:
                    old.unlink()
            except OSError:
                pass

    def flush(self) -> None:
        """Merge new selections into the file (atomically) and release the lock."""
        try:
            if self.new and self.path is not None:
                if fcntl is not None and self.lock_fd is None:
                    fd = os.open(self.path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT, 0o644)
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    self.lock_fd = fd
                self.data = {}
                self._read()
                merged = {**self.data, **self.new}
                fd, tmp = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f"{self.path.stem}.", suffix=".tmp"
                )
                with os.fdopen(fd, "w") as fh:
                    json.dump({"format": FORMAT, "selections": merged}, fh, sort_keys=True)
                os.replace(tmp, self.path)
                self.data, self.new = merged, {}
                self._prune()
        except OSError:
            pass
        finally:
            self._unlock()


_STORE = _Store()


def get(k: str, n: int) -> list[int] | None:
    """The selected indices recorded for ``k`` over ``n`` candidates, or ``None``."""
    return _STORE.get(k, n) if enabled() else None


def put(k: str, n: int, selected: list[int]) -> None:
    if enabled():
        _STORE.put(k, n, selected)


def flush() -> None:
    """Called at the end of collection (``tests/conftest.py``)."""
    if enabled():
        _STORE.flush()
