"""History helpers validate types and preserve upstream data when adding hints."""

from __future__ import annotations

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools._history_common import (
    MILLISECONDS_HINT_AT,
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    translate_host_not_found,
    with_warnings,
)


@pytest.mark.parametrize("value", [-1, 0, 1, MILLISECONDS_HINT_AT, 10**30])
def test_integer_epochs_are_forwarded_even_outside_warning_bounds(value):
    assert require_epoch_seconds(value, "start") == value
    assert seconds_to_millis(value) == value * 1000


@pytest.mark.parametrize("value", [True, False, None, 1.0, "123", [], {}])
def test_non_integer_epochs_are_refused_with_argument_name(value):
    with pytest.raises(ValueError, match="'start' must be an integer epoch-seconds"):
        require_epoch_seconds(value, "start")


def test_warning_boundaries_and_omitted_or_non_integer_arguments():
    values = dict(
        negative=-1,
        zero=0,
        below=MILLISECONDS_HINT_AT - 1,
        boundary=MILLISECONDS_HINT_AT,
        above=MILLISECONDS_HINT_AT + 1,
        omitted=None,
        boolean=True,
        text="123",
        floating=1.0,
    )
    warnings = epoch_warnings(**values)
    assert [(w["argument"], w["value"], w["code"]) for w in warnings] == [
        ("negative", -1, "EPOCH_SECONDS_NEGATIVE"),
        ("boundary", MILLISECONDS_HINT_AT, "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS"),
        ("above", MILLISECONDS_HINT_AT + 1, "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS"),
    ]
    # Most callers multiply seconds by 1000 before sending, so "sent as given" would be
    # false: the message says the value was not rescaled and still took the usual unit.
    assert all("multiplied by 1000" in w["message"] for w in warnings)
    assert not any("as given" in w["message"] for w in warnings)


@pytest.mark.parametrize("result", [{"data": []}, [], "upstream", None, 123])
def test_no_warnings_returns_original_object(result):
    assert with_warnings(result, []) is result


def test_array_warning_keeps_all_records_and_array_identity():
    records = [{"id": "one"}, {"id": "two", "value": None}]
    warnings = epoch_warnings(start=-1)
    result = with_warnings(records, warnings)
    assert result == {"result": records, "_warnings": warnings}
    assert result["result"] is records


def test_warning_collision_preserves_upstream_and_existing_wrapper_bucket():
    original = {"data": [], "_warnings": ["upstream"], "_wrapperFields": {"kept": True}}
    warnings = epoch_warnings(start=-1)
    result = with_warnings(original, warnings)
    assert result["_warnings"] == ["upstream"]
    assert result["_wrapperFields"] == {"kept": True}
    assert result["_wrapperFields_2"] == {"_warnings": warnings}
    assert "_wrapperFields_2" not in original


@pytest.mark.parametrize("result", [None, "upstream", 1])
def test_scalar_with_warnings_is_preserved(result):
    assert with_warnings(result, epoch_warnings(start=-1)) is result


@pytest.mark.parametrize("message", ["HTTP 403: host not found", "HTTP 403: forbidden"])
def test_host_hint_retains_upstream_reason(message):
    error = UniFiConnectionError(message)
    result = translate_host_not_found(error, "host-1")
    assert str(result).startswith(message)
    assert "'host-1'" in str(result) and "list_hosts" in str(result)


@pytest.mark.parametrize(
    "message", ["HTTP 403: other", "HTTP 4030: forbidden", "HTTP 500: host not found"]
)
def test_other_errors_are_unchanged(message):
    error = UniFiConnectionError(message)
    assert translate_host_not_found(error, "host-1") is error
