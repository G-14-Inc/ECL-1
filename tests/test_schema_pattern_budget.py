"""Keep the supported OTLP bytes grammar while avoiding per-group regex state.

Robert F. Tilley Jr.; G-14, Inc.
"""
import itertools
import json
from pathlib import Path
import re
import tracemalloc

import pytest

from ecl_verify.resources import validator_for
from ecl_verify.schema_patterns import pattern_matches, python_pattern

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/ecl-binding-otel-export-v1.schema.json").read_text())
PATTERN = SCHEMA["$defs"]["anyValue"]["properties"]["bytesValue"]["pattern"]


def test_otlp_bytes_pattern_exact_short_domain():
    # The published expression is the oracle; the long-input optimization must
    # retain its padding, alphabet, empty-string and exact-end behavior.
    oracle = re.compile(python_pattern(PATTERN))
    for length in range(8):
        for members in itertools.product("A=!\n", repeat=length):
            value = "".join(members)
            assert pattern_matches(PATTERN, value) is (oracle.search(value) is not None), repr(value)
    for length in range(1, 9):
        for position in range(length):
            for character in "+/_-z09\r\u2028\u2029":
                value = "A" * position + character + "A" * (length - position - 1)
                for suffix in ["", "=", "==", "==="]:
                    text = value + suffix
                    assert pattern_matches(PATTERN, text) is (oracle.search(text) is not None), repr(text)


@pytest.mark.parametrize("tail,valid", [("", True), ("!", False)])
def test_otlp_bytes_pattern_bounded_auxiliary_allocation(tail, valid):
    # 256 KiB is far below the parser default. A repeated four-byte group used
    # over 10 MiB of regex state here; the equivalent check needs no per-group stack.
    value = "A" * 262144 + tail
    pattern_matches(PATTERN, "AAAA")
    tracemalloc.start()
    try:
        result = pattern_matches(PATTERN, value)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result is valid
    assert peak < 65536, peak


@pytest.mark.parametrize("tail,valid", [("", True), ("!", False)])
def test_otlp_large_bytes_reaches_public_record_validator(tail, valid):
    record = json.loads((ROOT / "tests/fixtures/export-authority-boundaries/otel-unrelated-url-bytes-control.json").read_text())
    record["log_record"]["attributes"][-1]["value"] = {"bytesValue": "A" * 262144 + tail}
    assert validator_for("https://externalcontrollayer.ai/ns/schema/binding/otel-export/1").is_valid(record) is valid
