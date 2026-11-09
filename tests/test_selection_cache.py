"""tests/_selection_cache: stable keys, round trip, and no caching outside collection."""

from __future__ import annotations

import functools

import pytest

from tests import _selection_cache, _tool_catalog, _tool_classes


def _make(threshold: int):
    def member(name: str) -> bool:
        return len(name) > threshold

    return member


def test_key_is_stable_and_separates_closure_values():
    entries = ["a", "bb", "ccc"]
    k1 = _selection_cache.key(entries, _make(1), None, ("name",), None)
    assert k1 == _selection_cache.key(list(entries), _make(1), None, ("name",), None)
    assert k1 != _selection_cache.key(entries, _make(2), None, ("name",), None)
    assert k1 != _selection_cache.key(entries[:2], _make(1), None, ("name",), None)
    assert k1 != _selection_cache.key(entries, _make(1), None, ("name",), {"status": 500})
    part = functools.partial(_make(1))
    assert _selection_cache.key(entries, part, None, ("name",), None) is not None


def _pair(threshold: int):
    return (lambda name: len(name) > threshold), (lambda name: len(name) <= threshold)


def test_key_separates_functions_that_share_a_name_and_closure():
    longer, shorter = _pair(1)
    assert longer.__qualname__ == shorter.__qualname__
    k_longer = _selection_cache.key(["a", "bb"], longer, None, ("name",), None)
    k_shorter = _selection_cache.key(["a", "bb"], shorter, None, ("name",), None)
    assert k_longer is not None and k_shorter is not None
    assert k_longer != k_shorter
    assert k_longer == _selection_cache.key(["a", "bb"], _pair(1)[0], None, ("name",), None)


def test_unstable_values_are_not_cached():
    class Opaque:
        pass

    assert _selection_cache.key(["a"], None, None, ("name",), {"x": Opaque()}) is None
    assert _selection_cache.key(["a"], None, None, ("name",), {"x": Opaque}) is None


def test_round_trip_through_a_fresh_store(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_TEST_SELECTION_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(_selection_cache, "_STORE", _selection_cache._Store())
    _selection_cache.put("k", 3, [0, 2])
    assert _selection_cache.get("k", 3) == [0, 2]
    _selection_cache.flush()
    assert len(list(tmp_path.glob("*.json"))) == 1

    monkeypatch.setattr(_selection_cache, "_STORE", _selection_cache._Store())
    assert _selection_cache.get("k", 3) == [0, 2]
    assert _selection_cache.get("k", 4) is None  # candidate count must match
    assert _selection_cache.get("other", 3) is None


def test_disabled_cache_never_hits(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_TEST_SELECTION_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("UNIFI_TEST_SELECTION_CACHE", "0")
    monkeypatch.setattr(_selection_cache, "_STORE", _selection_cache._Store())
    _selection_cache.put("k", 1, [0])
    assert _selection_cache.get("k", 1) is None


# Module level, so the predicate key does not change as calls are recorded (a closure over
# a changing list is, correctly, a different key on each call).
_CALLS: list[str] = []


def eligible(name: str) -> bool:
    _CALLS.append(name)
    return name != "bb"


@pytest.mark.parametrize("generating", [False, True])
def test_selection_result_is_identical_with_and_without_cache(generating, tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_TEST_SELECTION_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(_selection_cache, "_STORE", _selection_cache._Store())
    monkeypatch.setattr(_tool_catalog, "GENERATING", generating)
    _CALLS.clear()
    first = _tool_classes._select_entries(["a", "bb", "ccc"], eligible=eligible)
    second = _tool_classes._select_entries(["a", "bb", "ccc"], eligible=eligible)
    assert first == second == ["a", "ccc"]
    _selection_cache.flush()
    # Outside collection every call evaluates; during collection the second is a hit.
    assert len(_CALLS) == (3 if generating else 6)


def test_fingerprint_covers_the_environment_but_not_volatile_names(monkeypatch, tmp_path):
    # Other workers and suite-output logs can change the real checkout between hashes.
    # Keep this environment comparison on a private, stable source inventory.
    source = tmp_path / "source.py"
    source.write_text("original source\n")
    monkeypatch.setattr(_selection_cache, "ROOT", tmp_path)

    def fresh() -> str:
        _selection_cache.fingerprint.cache_clear()
        return _selection_cache.fingerprint()

    try:
        base = fresh()
        monkeypatch.setenv("MCP_HOST_ORIGIN_PROTECTION", "off")
        assert fresh() != base
        first = fresh()
        monkeypatch.setenv("FASTMCP_TRANSPORT", "sse")
        changed = fresh()
        assert changed != first
        monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw7")
        monkeypatch.setenv("UNIFI_TEST_SELECTION_CACHE_DIR", "/elsewhere")
        assert fresh() == changed
        # Isolation must preserve the file-content invalidation contract too.
        source.write_text("changed source\n")
        assert fresh() != changed
    finally:
        monkeypatch.undo()
        _selection_cache.fingerprint.cache_clear()


def test_anonymous_functions_without_a_closure_are_not_cached():
    def outer():
        def inner(name: str) -> bool:
            return bool(name)

        return inner

    assert _selection_cache.key(["a"], lambda name: True, None, ("name",), None) is None
    assert _selection_cache.key(["a"], outer(), None, ("name",), None) is None


def test_prune_removes_only_old_files_of_this_module(tmp_path, monkeypatch):
    import os
    import time

    monkeypatch.setenv("UNIFI_TEST_SELECTION_CACHE_DIR", str(tmp_path))
    old = time.time() - 30 * 24 * 3600
    stale = [tmp_path / f"{'a' * 64}.json", tmp_path / f"{'a' * 64}.lock"]
    foreign = [tmp_path / "notes.json", tmp_path / "other.lock", tmp_path / "x.tmp"]
    for path in stale + foreign:
        path.write_text("{}")
        os.utime(path, (old, old))
    monkeypatch.setattr(_selection_cache, "_STORE", _selection_cache._Store())
    _selection_cache.put("k", 1, [0])
    _selection_cache.flush()
    assert not any(p.exists() for p in stale)
    assert all(p.exists() for p in foreign)
    assert len(list(tmp_path.glob("*.json"))) == 2  # the current file and notes.json
