"""Call-secret caches end with their scope and long secret forms remain compact."""

from __future__ import annotations

import asyncio
import gc
import hashlib
import tracemalloc
import weakref

import pytest

from unifi_fabric import secret_scrub as product


class Secret(str):
    """A synthetic string whose lifetime can be observed without logging it."""


def _key(size, index=0):
    return Secret(
        "".join(hashlib.sha256(f"{index}:{n}".encode()).hexdigest() for n in range(size // 64 + 1))[
            :size
        ]
    )


@pytest.mark.parametrize("warm_configured_cache", (False, True))
def test_call_secret_and_derived_caches_are_released_with_scope(warm_configured_cache):
    key = _key(640)
    key_ref = weakref.ref(key)
    if warm_configured_cache:
        assert product._token_char("%41") == "A"
    tokens = dict(product._TOKEN_CHARS)
    with product.secret_scope([key]):
        state = product._call_secrets.get()
        state_ref = weakref.ref(state)
        text = f"%41 before {key} after " + "x" * 5000
        expected = "%41 before *** after " + "x" * 5000
        assert product.scrub(text, [key]) == expected
        assert product.scrub_bytes(text.encode(), [key]) == expected.encode()
        assert state.derived_cache
        assert state.outcomes
        assert state.token_chars
        del state, text
    del key
    gc.collect()
    assert state_ref() is None
    assert key_ref() is None
    assert product._TOKEN_CHARS == tokens


async def test_inherited_child_keeps_scope_until_its_work_finishes():
    started, release = asyncio.Event(), asyncio.Event()
    key = _key(640)

    async def child():
        started.set()
        await release.wait()
        assert product.scrub(f"before {key} after", [key]) == "before *** after"
        assert product._call_secrets.get().derived_cache

    with product.secret_scope([key]):
        state_ref = weakref.ref(product._call_secrets.get())
        task = asyncio.create_task(child())
        await started.wait()
    assert state_ref() is not None
    release.set()
    await task
    del task
    await asyncio.sleep(0)
    gc.collect()
    assert state_ref() is None


def test_distinct_long_call_secrets_have_linear_working_memory():
    peaks = []
    for size in (160, 640):
        gc.collect()
        tracemalloc.start()
        try:
            for index in range(4):
                key = _key(size, index)
                with product.secret_scope([key]):
                    # UTF-16 forms carry many separator characters. The entire form
                    # still matches; no substring table or earlier call stays alive.
                    encoded = key.encode("utf-16-le").decode("latin-1")
                    assert product.scrub(encoded, [key]) == "***"
                    assert product.scrub(f"%41 {key} %42", [key]) == "%41 *** %42"
                del key, encoded
            peaks.append(tracemalloc.get_traced_memory()[1])
        finally:
            tracemalloc.stop()
    # Four times as much secret text permits linear growth plus fixed bookkeeping.
    # Eager separator-substring expansion instead copies cubic character volume.
    assert peaks[1] < 6 * peaks[0] + 64 * 1024, peaks


@pytest.mark.parametrize("size", (160, 640))
def test_join_search_visits_actual_occurrences_once(size):
    calls = 0

    class ObservedForm(str):
        def find(self, *args):
            nonlocal calls
            calls += 1
            return super().find(*args)

    form = ObservedForm("x" + "\0a" * size + "y")
    assert product._join_pairs((form,), "\0") == {("x", "a"), ("a", "a")}
    assert calls == size + 1
