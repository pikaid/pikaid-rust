#!/usr/bin/env python3
"""Independent pikaid conformance oracle and case generator.

This script deliberately contains no Rust code and does not import, execute or
inspect the implementation under test.  Every expected value is derived from
the pikaid 1.0.4 arithmetic:

    text = base36(timestamp, width 7) + base36(randomness, width 19)
    bin  = timestamp.to_bytes(5, "big") + randomness.to_bytes(12, "big")

The generated table is committed as ``tests/vectors/oracle-cases.json`` so the
Rust test suite and the external packaged-crate consumer execute exactly the
same pinned values.  A deterministic PRNG implemented below (not Python's
``random`` module) keeps the file byte-identical across Python versions.

Usage:

    python3 scripts/generate_oracle_cases.py            # rewrite the table
    python3 scripts/generate_oracle_cases.py --check    # fail if it differs

Exit status is non-zero on an arithmetic contradiction or a stale table.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
MAX_TIMESTAMP = 36**7 - 1  # 78_364_164_095
TWO96 = 1 << 96
BASE36_POW19 = 36**19  # 371_319_292_745_659_279_662_190_166_016
DEFAULT_TABLE = Path(__file__).resolve().parent.parent / "tests" / "vectors" / "oracle-cases.json"


def base36(value: int, width: int) -> str:
    """Fixed-width lowercase Base36 with left-zero padding."""
    if value < 0:
        raise ValueError("negative values are not representable")
    digits = []
    remaining = value
    for _ in range(width):
        remaining, digit = divmod(remaining, 36)
        digits.append(ALPHABET[digit])
    if remaining:
        raise ValueError(f"{value} does not fit in {width} Base36 digits")
    return "".join(reversed(digits))


def encode(timestamp: int, randomness: int) -> dict:
    if not 0 <= timestamp <= MAX_TIMESTAMP:
        raise ValueError("timestamp outside 0..36^7-1")
    if not 0 <= randomness < TWO96:
        raise ValueError("randomness outside 0..2^96-1")
    entropy_hex = randomness.to_bytes(12, "big").hex()
    return {
        "timestamp": timestamp,
        "entropy_hex": entropy_hex,
        "id": base36(timestamp, 7) + base36(randomness, 19),
        "bin_hex": timestamp.to_bytes(5, "big").hex() + entropy_hex,
    }


class SplitMix64:
    """Version-independent deterministic PRNG (only for test inputs)."""

    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFF_FFFF_FFFF_FFFF

    def next_u64(self) -> int:
        self.state = (self.state + 0x9E37_79B9_7F4A_7C15) & 0xFFFF_FFFF_FFFF_FFFF
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58_476D_1CE4_E5B9) & 0xFFFF_FFFF_FFFF_FFFF
        z = ((z ^ (z >> 27)) * 0x94D0_49BB_1331_11EB) & 0xFFFF_FFFF_FFFF_FFFF
        return (z ^ (z >> 31)) & 0xFFFF_FFFF_FFFF_FFFF

    def below(self, bound: int) -> int:
        if bound <= 0:
            raise ValueError("bound must be positive")
        return self.next_u64() % bound

    def u96(self) -> int:
        return (self.next_u64() << 32) ^ (self.next_u64() >> 32)


def build_payload() -> dict:
    # Anchor cases from specification 1.0.4 and the brief.  Each pair is
    # (name, timestamp, randomness).
    anchors = [
        ("all-zero", 0, 0),
        ("zero-ts-unit-entropy", 0, 1),
        ("zero-ts-max-entropy", 0, TWO96 - 1),
        ("unit-ts-zero-entropy", 1, 0),
        ("unit-ts-unit-entropy", 1, 1),
        ("unit-ts-max-entropy", 1, TWO96 - 1),
        ("max-ts-zero-entropy", MAX_TIMESTAMP, 0),
        ("max-ts-unit-entropy", MAX_TIMESTAMP, 1),
        ("max-ts-max-entropy", MAX_TIMESTAMP, TWO96 - 1),
        ("last-six-digit-timestamp", 36**6 - 1, 0),
        ("first-seven-digit-timestamp", 36**6, 0),
        ("last-six-digit-timestamp-max-entropy", 36**6 - 1, TWO96 - 1),
        ("first-seven-digit-timestamp-max-entropy", 36**6, TWO96 - 1),
        # Fixed real-world timestamp with fixed leading-zero randomness.
        ("real-world-leading-zero-entropy", 1_700_000_000, 0x0011_2233_4455_6677_8899_AABB),
        ("real-world-zero-entropy", 1_700_000_000, 0),
        ("real-world-all-ff-entropy", 1_700_000_000, TWO96 - 1),
        ("real-world-near-min-entropy", 1_700_000_000, 1),
        # Randomness with a leading zero byte but a large remainder.
        ("leading-zero-byte", 0, 0x00FF_FFFF_FFFF_FFFF_FFFF_FFFF),
        ("leading-two-zero-bytes", 1, 0x0000_FFFF_FFFF_FFFF_FFFF_FFFF),
        # Adjacent timestamps, ascending.
        ("ascending-0", 1_700_000_000, 0),
        ("ascending-1", 1_700_000_001, 0),
        ("ascending-2", 1_700_000_002, 0xFF),
        ("ascending-3", 1_700_000_003, TWO96 - 1),
        # Adjacent timestamps, descending input order but sorted expectations.
        ("descending-0", 1_700_000_100, 0),
        ("descending-1", 1_700_000_099, 0),
        ("descending-2", 1_700_000_098, 0xFF),
        ("descending-3", 1_700_000_097, TWO96 - 1),
        # Same second: ordering is by randomness, not generation order.
        ("same-second-low", 1_700_000_200, 0),
        ("same-second-mid", 1_700_000_200, 1 << 95),
        ("same-second-high", 1_700_000_200, TWO96 - 1),
    ]

    cases = []
    seen = set()
    for name, timestamp, randomness in anchors:
        if name in seen:
            raise AssertionError(f"duplicate case name {name}")
        seen.add(name)
        cases.append({"name": name, **encode(timestamp, randomness)})

    # Seeded pseudo-random spread.  Pure-integer SplitMix64 keeps this stable
    # across Python versions so `--check` can enforce a byte-identical table.
    rng = SplitMix64(0x5EED_1DCA_5EED_1DCA)
    for index in range(300):
        timestamp = rng.below(MAX_TIMESTAMP + 1)
        randomness = rng.u96()
        cases.append({"name": f"seeded-{index:03d}", **encode(timestamp, randomness)})

    # Verify the shipped official fixture with the same independent arithmetic.
    fixture_path = Path(__file__).resolve().parent.parent / "tests" / "vectors" / "pikaid-v1.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    fixture_names = []
    for vector in fixture["valid"]:
        derived = encode(int(vector["timestamp"]), int(vector["entropy_hex"], 16))
        if derived["id"] != vector["id"] or derived["bin_hex"] != vector["bin_hex"]:
            raise AssertionError(f"official fixture mismatch: {vector['name']}")
        fixture_names.append(vector["name"])
        cases.append({"name": f"official-{vector['name']}", **derived})

    # Ordering expectation: timestamp, then unsigned randomness.
    ordered = sorted(cases, key=lambda case: (case["timestamp"], int(case["entropy_hex"], 16)))
    if [case["name"] for case in sorted(cases, key=lambda case: case["id"])] != [
        case["name"] for case in ordered
    ]:
        raise AssertionError("text order disagrees with numeric order")
    if [case["name"] for case in sorted(cases, key=lambda case: case["bin_hex"])] != [
        case["name"] for case in ordered
    ]:
        raise AssertionError("binary order disagrees with numeric order")

    overflow_suffix = base36(TWO96, 19)
    if int(overflow_suffix, 36) != TWO96:
        raise AssertionError("2^96 did not encode to 19 Base36 digits")
    if BASE36_POW19 - 1 <= TWO96:
        raise AssertionError("36^19-1 must exceed 2^96")

    invalid_strings = [
        {"name": "empty", "id": "", "error": "length"},
        {"name": "length-1", "id": "0", "error": "length"},
        {"name": "length-25", "id": "0" * 25, "error": "length"},
        {"name": "length-27", "id": "0" * 27, "error": "length"},
        {"name": "length-1000", "id": "0" * 1000, "error": "length"},
        {"name": "uppercase-first", "id": "A" + "0" * 25, "error": "character"},
        {"name": "uppercase-middle", "id": "000000A" + "0" * 19, "error": "character"},
        {"name": "uppercase-last", "id": "0" * 25 + "Z", "error": "character"},
        {"name": "dash", "id": "000000-" + "0" * 19, "error": "character"},
        {"name": "plus", "id": "+000000" + "0" * 19, "error": "character"},
        {"name": "leading-space", "id": " " + "0" * 25, "error": "character"},
        {"name": "trailing-space", "id": "0" * 25 + " ", "error": "character"},
        {"name": "internal-space", "id": "0000000 " + "0" * 18, "error": "character"},
        {"name": "nul", "id": "0" * 25 + "\u0000", "error": "character"},
        {"name": "crlf", "id": "0" * 24 + "\r\n", "error": "character"},
        {"name": "newline", "id": "0" * 25 + "\n", "error": "character"},
        {"name": "non-ascii-e-acute", "id": "0" * 24 + "\u00e9", "error": "character"},
        {"name": "zero-width-space", "id": "0" * 23 + "\u200b", "error": "character"},
        {"name": "fullwidth-digit", "id": "0" * 25 + "\uff10", "error": "length"},
        {"name": "entropy-2-pow-96", "id": "0000000" + overflow_suffix, "error": "overflow"},
        {"name": "entropy-36-pow-19-minus-1", "id": "0000000" + "z" * 19, "error": "overflow"},
        {"name": "entropy-36-pow-19-minus-2", "id": "0000000" + base36(BASE36_POW19 - 2, 19), "error": "overflow"},
    ]

    max_plus_one_bin = (MAX_TIMESTAMP + 1).to_bytes(5, "big").hex() + "00" * 12
    invalid_binaries = [
        {"name": "empty", "bin_hex": "", "error": "length"},
        {"name": "length-1", "bin_hex": "00", "error": "length"},
        {"name": "length-16", "bin_hex": "00" * 16, "error": "length"},
        {"name": "length-18", "bin_hex": "00" * 18, "error": "length"},
        {"name": "length-1000", "bin_hex": "00" * 1000, "error": "length"},
        {"name": "timestamp-max-plus-one", "bin_hex": max_plus_one_bin, "error": "timestamp"},
        {"name": "timestamp-40-bit-max", "bin_hex": "ff" * 5 + "00" * 12, "error": "timestamp"},
        {"name": "timestamp-40-bit-max-entropy", "bin_hex": "ff" * 5 + "ff" * 12, "error": "timestamp"},
    ]

    return {
        "meta": {
            "spec_revision": "1.0.4",
            "spec_commit": "17014d76f568c3ac9f9ce2927c1a018fdbc36d1d",
            "official_fixture": "pikaid-php v1.2.0",
            "official_fixture_commit": "e3f843edeb5157a5d2d25196cac0d69580810a95",
            "official_fixture_names": fixture_names,
            "max_timestamp": MAX_TIMESTAMP,
            "max_timestamp_utc": "4453-04-05T15:21:35Z",
            "two96": str(TWO96),
            "base36_pow19": str(BASE36_POW19),
            "string_length": 26,
            "binary_length": 17,
            "generator": "scripts/generate_oracle_cases.py",
        },
        "valid": cases,
        "ordering": [case["name"] for case in ordered],
        "invalid": {"string": invalid_strings, "binary": invalid_binaries},
    }


def serialize(payload: dict) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=True) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify that the committed table equals freshly derived values",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_TABLE)
    args = parser.parse_args(argv)

    rendered = serialize(build_payload())
    if args.check:
        if not args.output.exists():
            print(f"missing oracle table: {args.output}", file=sys.stderr)
            return 1
        current = args.output.read_text(encoding="utf-8")
        if current != rendered:
            print(f"oracle table is stale: {args.output}", file=sys.stderr)
            return 1
        print(f"oracle table is current: {args.output}")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
