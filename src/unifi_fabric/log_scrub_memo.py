"""Byte-bounded completed-log-text memo, isolated from scrubber decoding."""

from __future__ import annotations

import logging
import threading
import weakref
from collections import OrderedDict
from collections.abc import Callable

_MAX_BYTES = 256 * 1024
# Weak references avoid adding raw-text memo state to serialized LogRecords.
_Key = tuple[int, tuple[str, ...], str]
_entries: OrderedDict[_Key, tuple[str, int, weakref.ReferenceType[logging.LogRecord]]] = (
    OrderedDict()
)
_bytes = 0
_lock = threading.RLock()


def _remove_record(record_id: int, ref: weakref.ReferenceType[logging.LogRecord]) -> None:
    global _bytes
    with _lock:
        for key in list(_entries):
            if key[0] == record_id and _entries[key][2] is ref:
                _bytes -= _entries.pop(key)[1]


def _size(values: tuple[str, ...], text: str, output: str) -> int:
    # Include keys and output, plus a conservative allowance for entry bookkeeping.
    return 512 + sum(len(v.encode("utf-8", "surrogatepass")) for v in (*values, text, output))


def scrub_record_text(
    record: logging.LogRecord,
    text: str,
    values: tuple[str, ...],
    scrubber: Callable[[str, tuple[str, ...]], str],
    *,
    cacheable: bool = True,
) -> str:
    """Memoize only success; (values, output) is the successful scrub's fixpoint.

    Cache is process-wide byte-capped LRU but keys isolate every individual record.
    Integer identity plus a checked weak reference avoids caller hash/equality code.
    Withheld records and raised scrubs never populate the memo.
    """
    global _bytes
    if not cacheable:
        return scrubber(text, values)
    record_id = id(record)
    ref = weakref.ref(record, lambda dead: _remove_record(record_id, dead))
    key = (record_id, values, text)
    with _lock:
        entry = _entries.get(key)
        if entry is not None:
            if entry[2]() is record:
                _entries.move_to_end(key)
                return entry[0]
            # A dead record identity can be reused; never return its cached text.
            _bytes -= _entries.pop(key)[1]
    output = scrubber(text, values)
    if "<log record withheld:" in output or "diagnostic withheld" in output:
        return output
    with _lock:
        for source in dict.fromkeys((text, output)):
            item = (record_id, values, source)
            size = _size(values, source, output)
            if size > _MAX_BYTES:
                continue
            previous = _entries.pop(item, None)
            if previous is not None:
                _bytes -= previous[1]
            while _entries and _bytes + size > _MAX_BYTES:
                _bytes -= _entries.popitem(last=False)[1][1]
            _entries[item] = (output, size, ref)
            _bytes += size
    return output
