#!/usr/bin/env python3
"""Deterministic cold-call old/new differential; synthetic data only, no live IO.

Run from repo with its locked venv. No input/output content is printed on failures;
reproduce by fixed seed and case label. Oracle corpus means all default fast/shallow
cases and pinned fixture/regression cases, not the opt-in 210,000-case slow corpus.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import random
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(REPO), str(REPO / "src")]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def oracle_cases():
    from tests import scrub_fuzz
    from tests import test_secret_scrub_oracle as suite

    for group in ("CAPTURED", "AT2_BOUND", "EXACT_128"):
        for i, case in enumerate(getattr(suite, group)):
            yield f"fixture:{group}:{i}", case["text"], case["secrets"]
    for i, (text, values) in enumerate(suite.PRESERVED):
        yield f"preserved:{i}", text, values
    regressions = suite.REGRESSIONS + suite.CHAIN_REGRESSIONS + scrub_fuzz.REPORTED
    for i, (text, value) in enumerate(regressions):
        yield f"regression:{i}", text, [value]
    for depth in (0, 1, 7, 8, 9, 10, 20, 64):
        for suffix in ("41", "20A!", "20***A!"):
            yield f"depth:{depth}:{suffix}", "%" + "25" * depth + suffix, ["A", "A!", "***"]
    # Mask markers can form short-token boundaries, join fragments, or themselves be
    # secret syntax. Each case checks the complete fixed-point product output.
    for i, (text, secrets) in enumerate(
        [
            ("abcSECRETxyz", ["SECRET", "abc", "xyz"]),
            ("%4SECRET1", ["SECRET", "A", "*"]),
            ("\\x4SECRET1", ["SECRET", "A", "***"]),
            ("&amSECRETp;A", ["SECRET", "&A", "*"]),
            ("aLONGSYNTHETICKEYz", ["LONGSYNTHETICKEY", "a", "z"]),
            ("a***b", ["***", "a", "b"]),
            ("KEY", []),
            ("", ["KEY"]),
        ]
    ):
        yield f"boundary:{i}", text, secrets
    long_value = "SyntheticLongKey012345"
    percent = "".join(f"%{ord(char):02x}" for char in long_value)
    for i, (text, values) in enumerate(
        [
            ("plain " + long_value + " plain", [long_value]),
            (percent, [long_value]),
            (percent + "%25", [long_value]),
            ("%25" + percent, [long_value]),
            ("prefix!" + percent + "!suffix", [long_value]),
            ("prefix" + long_value + "suffix", [long_value]),
            (long_value[:10] + "".join(f"%{ord(c):02x}" for c in long_value[10:]), [long_value]),
            (percent + " " + long_value, [long_value]),
            (percent + "!" + percent, [long_value]),
            ("%4" + long_value + "1", [long_value]),
            ("\\x4" + long_value + "1", [long_value]),
            ("&am" + long_value + "p;", [long_value]),
            ("%25 " + long_value + " %25", [long_value]),
            (long_value + "*" + long_value, [long_value]),
        ]
    ):
        yield f"long_fixed_point:{i}", text, values
    for corpus in ("fast", "shallow"):
        seeds, count, kwargs, _ = suite.CORPORA[corpus]
        for seed in seeds:
            rng = random.Random(seed)  # noqa: S311 - deterministic synthetic corpus
            for i in range(count):
                text, values = scrub_fuzz.case(rng, **kwargs)
                yield f"oracle:{corpus}:{seed}:{i}", text, values


def random_cases(count, seed):
    from tests import scrub_fuzz

    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic corpus
    atoms = (
        "%25",
        "%41",
        "%u0041",
        r"\x41",
        r"\u005c",
        "&#65;",
        "&amp;",
        "&#x25;",
        r"\134",
        "%",
        "\\",
        "&#",
        "25",
        "41",
        "0",
        "!",
        " ",
    )
    for i in range(count):
        depth = 1 + i % 10
        text, values = scrub_fuzz.case(rng, max_depth=depth, chain_units=5 + i % 35)
        # Always escape-dense; vary regions and joins on both sides of fuzz material.
        prefix = "".join(rng.choice(atoms) for _ in range(rng.randrange(8, 33)))
        suffix = "".join(rng.choice(atoms) for _ in range(rng.randrange(8, 33)))
        if i % 5 == 0:
            value = rng.choice(("A", "K!", "***", "SyntheticLongKey012345", "é", "😀"))
            values = [*values, value]
            text += " " + scrub_fuzz.encode(rng, value, depth) + " "
        # Half the random corpus has only long, star-free secrets so it exercises
        # the guarded fixed-point fast path as well as its partial-region fallback.
        if i % 4 in (0, 1):
            value = "Synthetic" + "".join(
                rng.choice("abcXYZ0123456789") for _ in range(rng.randrange(8, 25))
            )
            values = [value]
            if i % 4 == 0:
                text += " " + (value if i % 8 == 0 else scrub_fuzz.encode(rng, value, depth)) + " "
        yield f"random:{seed}:{i}", prefix + text + suffix, values


def cold(module, operation, data, values):
    # Every operation gets an independent holder and no inherited/global outcome.
    module._memo_clear()
    with module.secret_scope(values):
        module._memo_clear()
        return getattr(module, operation)(data, values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--old", type=Path, required=True, help="Path to the baseline secret_scrub.py module"
    )
    parser.add_argument("--random-count", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=17400317)
    parser.add_argument("--limit", type=int, default=0, help="Smoke-test first N cases only")
    parser.add_argument(
        "--describe", action="store_true", help="Count corpus without executing scrubber"
    )
    args = parser.parse_args()
    old_path = args.old.resolve()
    new_path = REPO / "src" / "unifi_fabric" / "secret_scrub.py"
    cases = list(oracle_cases())
    oracle_count = len(cases)
    cases.extend(random_cases(args.random_count, args.seed))
    corpus_hash = hashlib.sha256()
    for label, text, values in cases:
        corpus_hash.update(json.dumps([label, text, values], ensure_ascii=True).encode())
        corpus_hash.update(b"\n")
    summary = {
        "oracle_cases": oracle_count,
        "random_cases": args.random_count,
        "seed": args.seed,
        "corpus_sha256": corpus_hash.hexdigest(),
        "total_cases": len(cases),
        "operations_per_case": 4,
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    if args.describe:
        print(json.dumps(summary, sort_keys=True))
        return
    old = load_module("lane_r_old_secret_scrub", old_path)
    import unifi_fabric.secret_scrub as new

    summary["old_source_sha256"] = hashlib.sha256(old_path.read_bytes()).hexdigest()
    summary["new_source_sha256"] = hashlib.sha256(new_path.read_bytes()).hexdigest()
    start = time.monotonic()
    tested = 0
    for index, (label, text, values) in enumerate(cases):
        if args.limit and index >= args.limit:
            break
        # Non-UTF8 bytes bracket selected bodies to exercise byte-preserving paths.
        raw = text.encode("utf-8")
        if index % 7 == 0:
            raw = b"\xff\x00" + raw + b"\x80\xfe"
        for operation, data in (
            ("scrub", text),
            ("scrub_bytes", raw),
            ("contains_secret", text),
            ("contains_secret", raw),
        ):
            before = cold(old, operation, data, values)
            after = cold(new, operation, data, values)
            if type(before) is not type(after) or before != after:
                summary.update(
                    status="FAIL",
                    case=label,
                    operation=operation,
                    input_type=type(data).__name__,
                    tested=tested,
                    elapsed_seconds=round(time.monotonic() - start, 3),
                )
                print(json.dumps(summary, sort_keys=True), flush=True)
                raise AssertionError(
                    f"Differential mismatch at {label} {operation} {type(data).__name__}; "
                    "synthetic input reproducible from seed"
                )
        tested += 1
        if tested % 1000 == 0:
            print(
                json.dumps(
                    {"progress": tested, "elapsed_seconds": round(time.monotonic() - start, 3)}
                ),
                flush=True,
            )
    summary.update(
        status="PASS",
        tested=tested,
        comparisons=tested * 4,
        elapsed_seconds=round(time.monotonic() - start, 3),
    )
    print(json.dumps(summary, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
