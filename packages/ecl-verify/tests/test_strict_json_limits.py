"""Declared limits of strict JSON and of the archive reader (IE1-028, IE1-029, IE1-037).

A strict parser that compares its value and nesting limits only after the whole input is built
spends memory in proportion to the input on a refusal under a budget of 8 values, and a limit of
NaN or infinity passes every comparison. These tests hold the parser to its declared limits: each
limit is an integer of at least 1, checked by type before any input is read; a refusal costs
memory that follows the limits, not the input; and the order of IE1-037 still decides the finding,
check 2 (the grammar) before check 3 (the limits) wherever each defect lies in the text.
"""

from __future__ import annotations

import enum
import struct
import tracemalloc
from collections.abc import Callable
from decimal import Decimal
from fractions import Fraction
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from ecl_verify.canonical import (
    CONFIGURATION_INVALID,
    DUPLICATE_MEMBERS,
    GRAMMAR_NESTING_BOUND,
    MAX_JSON_BYTES_CEILING,
    MAX_JSON_DEPTH_CEILING,
    MAX_JSON_NODES_CEILING,
    RESOURCE_LIMIT,
    RESTRICTED_NUMBERS,
    STRICT_SYNTAX,
    CanonicalizationError,
    _validate_value_limits,
    canonicalize,
    load_json_strict,
    loads_json_strict,
)
from ecl_verify.offline import (
    OfflinePackageError,
    OfflineResourceLimits,
    verify_zip_members,
)

# The memory a refusal may cost when the declared limits are small: a constant, far below the
# inputs below (one to three megabytes), which a parse that builds the value exceeds many times.
SMALL = 64 * 1024


class Eight(enum.IntEnum):
    VALUE = 8


def finding(data: str | bytes, **limits: Any) -> str:
    """The finding of a refusal, or "accepted"."""
    try:
        loads_json_strict(data, **limits)
    except CanonicalizationError as error:
        return error.finding_id
    return "accepted"


def peak(call: Callable[[], object]) -> int:
    """The peak traced allocation while `call` runs, whatever it raises."""
    tracemalloc.start()
    try:
        call()
    except (CanonicalizationError, OfflinePackageError):
        pass
    finally:
        _, highest = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    return highest


# --- IE1-028: each limit is an integer of at least 1, checked by type --------------------------

INVALID_LIMITS = [
    pytest.param(float("nan"), id="nan"),
    pytest.param(float("inf"), id="infinity"),
    pytest.param(float("-inf"), id="negative-infinity"),
    pytest.param(8.0, id="integral-float"),
    pytest.param(8.5, id="fraction"),
    pytest.param(True, id="bool"),
    pytest.param(0, id="zero"),
    pytest.param(-1, id="negative"),
    pytest.param(-(10**5000), id="huge-negative"),
    pytest.param("8", id="text"),
    pytest.param(None, id="none"),
    pytest.param(Decimal(8), id="decimal"),
    pytest.param(Fraction(8), id="exact-fraction"),
    pytest.param(Eight.VALUE, id="int-subclass"),
]


@pytest.mark.parametrize("name", ["max_bytes", "max_depth", "max_nodes"])
@pytest.mark.parametrize("value", INVALID_LIMITS)
def test_a_limit_that_is_not_an_integer_of_at_least_one_is_refused(name: str, value: Any) -> None:
    with pytest.raises(CanonicalizationError, match=f"limit {name}") as caught:
        loads_json_strict(b"[0,1,2]", **{name: value})
    assert caught.value.finding_id == CONFIGURATION_INVALID


@pytest.mark.parametrize("value", INVALID_LIMITS)
def test_the_limits_are_refused_before_the_input_is_read(value: Any) -> None:
    """Even input that fails check 1 or check 2 is refused for the configuration first."""
    for data in (b"[" * 100, b"\xff", b"x" * 100):
        with pytest.raises(CanonicalizationError, match="limit max_nodes") as caught:
            loads_json_strict(data, max_nodes=value, max_bytes=8)
        assert caught.value.finding_id == CONFIGURATION_INVALID


@pytest.mark.parametrize("value", INVALID_LIMITS)
def test_the_canonicalizer_and_the_file_reader_check_their_limits_too(
    value: Any, tmp_path: Path
) -> None:
    with pytest.raises(CanonicalizationError) as caught:
        _validate_value_limits([1], max_depth=value)
    assert caught.value.finding_id == CONFIGURATION_INVALID
    path = tmp_path / "value.json"
    path.write_bytes(b"[1]")
    with pytest.raises(CanonicalizationError) as caught:
        load_json_strict(path, max_bytes=value)
    assert caught.value.finding_id == CONFIGURATION_INVALID


CEILINGS = {
    "max_bytes": MAX_JSON_BYTES_CEILING,
    "max_depth": MAX_JSON_DEPTH_CEILING,
    "max_nodes": MAX_JSON_NODES_CEILING,
}


def test_the_ceilings_of_the_limits_are_as_declared() -> None:
    """IE1-028 : 2,147,483,647 bytes, 4,096 levels of nesting, 100,000,000 values."""
    assert CEILINGS == {"max_bytes": 2_147_483_647, "max_depth": 4_096, "max_nodes": 100_000_000}


@pytest.mark.parametrize("name", ["max_bytes", "max_depth", "max_nodes"])
def test_a_limit_at_its_ceiling_is_accepted_and_one_above_it_is_a_configuration_error(
    name: str,
) -> None:
    assert loads_json_strict(b"[0,1,2]", **{name: CEILINGS[name]}) == [0, 1, 2]
    for value in (CEILINGS[name] + 1, 2**53, 2**53 + 1, 10**30):
        with pytest.raises(CanonicalizationError, match=f"limit {name}") as caught:
            loads_json_strict(b"[0,1,2]", **{name: value})
        assert caught.value.finding_id == CONFIGURATION_INVALID


def test_the_canonicalizer_refuses_a_value_limit_above_its_ceiling() -> None:
    with pytest.raises(CanonicalizationError, match="limit max_nodes") as caught:
        _validate_value_limits([1], max_nodes=MAX_JSON_NODES_CEILING + 1)
    assert caught.value.finding_id == CONFIGURATION_INVALID
    _validate_value_limits([1], max_depth=MAX_JSON_DEPTH_CEILING, max_nodes=MAX_JSON_NODES_CEILING)


@pytest.mark.parametrize(
    "name", [f.name for f in OfflineResourceLimits.__dataclass_fields__.values()]
)
@pytest.mark.parametrize("value", [float("nan"), float("inf"), 8.0, True, 0, -1])
def test_an_archive_limit_that_is_not_an_integer_of_at_least_one_is_refused(
    name: str, value: Any
) -> None:
    limits = OfflineResourceLimits(**{name: value})
    with pytest.raises(OfflinePackageError, match=name) as caught:
        verify_zip_members(b"PK", limits=limits)
    assert caught.value.code == CONFIGURATION_INVALID


# --- IE1-029: a refusal costs memory that follows the limits ------------------------------------


def flat_array(count: int, tail: bytes = b"") -> bytes:
    return b"[" + b"0," * (count - 1) + b"0" + tail + b"]"


def test_a_refusal_under_a_small_value_limit_does_not_build_the_input() -> None:
    """An input of 500,000 values under a limit of 8 must not cost memory in proportion to its
    size; traced allocation is slow, so these inputs are smaller, and the cost must not grow with
    them.
    """
    costs = []
    for count in (1_000, 20_000):
        data = flat_array(count)
        assert finding(data, max_nodes=8) == RESOURCE_LIMIT
        costs.append(peak(partial(loads_json_strict, data, max_nodes=8)))
    assert max(costs) < SMALL
    assert costs[1] - costs[0] < 4096
    assert finding(flat_array(500_000), max_nodes=8) == RESOURCE_LIMIT


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(flat_array(20_000, b","), id="array-with-a-late-grammar-error"),
        pytest.param(
            b"{" + b",".join(b'"m%d":0' % index for index in range(10_000)) + b"}",
            id="object",
        ),
        pytest.param(b"[" + b",".join([b'"' + b"x" * 30 + b'"'] * 10_000) + b"]", id="strings"),
        pytest.param(
            ("[" + ",".join(['"\u00e9\U0001f600"'] * 10_000) + "]").encode(), id="non-ascii"
        ),
    ],
)
def test_the_grammar_check_after_a_limit_keeps_nothing(data: bytes) -> None:
    assert peak(lambda: loads_json_strict(data, max_nodes=8)) < SMALL


def test_the_nesting_check_keeps_one_byte_for_each_open_container() -> None:
    for depth in (5_000, 50_000):
        data = b"[" * depth + b"]" * depth
        assert finding(data, max_depth=8) == RESOURCE_LIMIT
        assert peak(partial(loads_json_strict, data, max_depth=8)) < SMALL


def test_a_file_over_the_byte_limit_is_refused_without_being_read(tmp_path: Path) -> None:
    path = tmp_path / "large.json"
    with path.open("wb") as handle:
        handle.truncate(1 << 30)
    with pytest.raises(CanonicalizationError, match="byte budget") as caught:
        load_json_strict(path, max_bytes=1024)
    assert caught.value.finding_id == RESOURCE_LIMIT
    assert peak(lambda: load_json_strict(path, max_bytes=1024)) < SMALL


def test_text_beyond_the_byte_limit_in_code_points_is_not_encoded() -> None:
    text = "[" + "0," * 500_000 + "0]"
    assert peak(lambda: loads_json_strict(text, max_bytes=1024)) < SMALL


# --- IE1-037: the order of the checks decides the finding --------------------------------------

# Each case: the input, the declared limits, and the finding of IE1-037 (or "accepted").
ORDER = [
    pytest.param(flat_array(20), {"max_nodes": 8}, RESOURCE_LIMIT, id="values-over-the-limit"),
    pytest.param(
        flat_array(20, b","), {"max_nodes": 8}, STRICT_SYNTAX, id="values-over-then-syntax"
    ),
    pytest.param(
        b"[0,0,0,0,0,0,0,0,0,0] x", {"max_nodes": 8}, STRICT_SYNTAX, id="values-over-then-extra"
    ),
    pytest.param(b"[[[[[[]]]]]]", {"max_depth": 4}, RESOURCE_LIMIT, id="depth-over-the-limit"),
    pytest.param(b"[[[[[[]]]]]]]", {"max_depth": 4}, STRICT_SYNTAX, id="depth-over-then-syntax"),
    pytest.param(b"[[[[[[", {"max_depth": 4}, STRICT_SYNTAX, id="depth-over-unterminated"),
    pytest.param(
        b'[1.5,"\\uffff",{"a":1,"a":2},0,0,0,0,0,0,0]',
        {"max_nodes": 8},
        RESOURCE_LIMIT,
        id="defects-of-checks-4-to-6-then-values-over",
    ),
    pytest.param(
        b'[0,0,0,0,0,0,0,0,0,"\xff"]',
        {"max_nodes": 8},
        STRICT_SYNTAX,
        id="values-over-then-bad-utf8",
    ),
    pytest.param(b"[0,0,0,0,0,0,0,0,0,NaN]", {"max_nodes": 8}, STRICT_SYNTAX, id="values-over-nan"),
    pytest.param(flat_array(8), {"max_nodes": 9}, "accepted", id="values-at-the-limit"),
    pytest.param(b"[[[[[]]]]]", {"max_depth": 4}, "accepted", id="depth-at-the-limit"),
    pytest.param(b"[" * 40 + b"]" * 40 + b"x", {"max_bytes": 16}, RESOURCE_LIMIT, id="bytes-first"),
    pytest.param(
        b'{"a":1.5,"a":"\\ud800"}', {}, STRICT_SYNTAX, id="scalar-before-duplicate-and-number"
    ),
    pytest.param(b'{"a":1.5,"a":2}', {}, DUPLICATE_MEMBERS, id="duplicate-before-number"),
    pytest.param(b'[1.5,-0,{"b":1}]', {}, RESTRICTED_NUMBERS, id="number"),
]


@pytest.mark.parametrize(("data", "limits", "expected"), ORDER)
def test_the_order_of_the_checks_decides_the_finding(
    data: bytes, limits: dict[str, int], expected: str
) -> None:
    assert finding(data, **limits) == expected
    if b"\xff" not in data:
        assert finding(data.decode("utf-8"), **limits) == expected


def nested(depth: int, tail: bytes = b"") -> bytes:
    """`depth` nested arrays: the innermost is a value at depth `depth` - 1."""
    return b"[" * depth + b"]" * depth + tail


def test_the_grammar_is_read_to_the_parsers_own_nesting_bound() -> None:
    """Every consumer reads the grammar of an input nested no deeper than 10,000 levels; deeper
    than that and than its nesting limit, the parser may stop, as a resource limit (check 2)."""
    assert GRAMMAR_NESTING_BOUND == 10_000
    assert finding(nested(GRAMMAR_NESTING_BOUND + 1, b"x")) == STRICT_SYNTAX
    assert finding(nested(GRAMMAR_NESTING_BOUND + 2, b"x")) == RESOURCE_LIMIT
    assert finding(nested(GRAMMAR_NESTING_BOUND + 2)) == RESOURCE_LIMIT
    # The nesting ceiling of 4,096 is below the bound, so the bound is always 10,000 levels: an
    # input nested to the ceiling is built, one level deeper is refused at check 3, and a grammar
    # error below the bound still decides.
    assert finding(nested(4_097), max_depth=4_096, max_nodes=5_000) == "accepted"
    assert finding(nested(4_098), max_depth=4_096, max_nodes=5_000) == RESOURCE_LIMIT
    assert finding(nested(4_098, b"x"), max_depth=4_096, max_nodes=5_000) == STRICT_SYNTAX


def test_a_value_within_the_limits_is_built_whatever_the_limits() -> None:
    value = {"a": [1, {"b": None}, "é"], "c": True}
    data = canonicalize(value)
    assert loads_json_strict(data, max_nodes=7, max_depth=3) == value
    assert finding(data, max_nodes=6) == RESOURCE_LIMIT
    assert finding(data, max_depth=2) == RESOURCE_LIMIT


# --- IE1-029: the archive reader holds no more entries than its member limit -------------------


def central_directory(count: int, *, corrupt_after: int | None = None) -> bytes:
    """An archive of `count` central directory entries named "a" and an end record; with
    `corrupt_after`, the entry after that many has a bad signature."""
    entry = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            (3 << 8) | 20,
            20,
            0,
            0,
            0,
            33,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0o100644 << 16,
            0,
        )
        + b"a"
    )
    entries = [entry] * count
    if corrupt_after is not None:
        entries[corrupt_after] = b"XXXX" + entry[4:]
    directory = b"".join(entries)
    end = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, count & 0xFFFF, count & 0xFFFF, len(directory), 0, 0
    )
    return directory + end


def test_an_archive_over_the_member_limit_is_refused_before_its_entries_are_read() -> None:
    """An archive of 100,000 directory entries under a member limit of 10 cost 42 MB before; this
    one has 20,000, which the archive library would hold as 20,000 entry objects."""
    data = central_directory(20_000)
    limits = OfflineResourceLimits(max_member_count=10)
    with pytest.raises(OfflinePackageError, match="member count") as caught:
        verify_zip_members(data, limits=limits)
    assert caught.value.code == RESOURCE_LIMIT
    assert peak(lambda: verify_zip_members(data, limits=limits)) < SMALL


def test_a_directory_that_cannot_be_read_is_refused_as_such_even_beyond_the_member_limit() -> None:
    """The whole directory is read before the member count is compared, as before."""
    data = central_directory(30, corrupt_after=25)
    with pytest.raises(OfflinePackageError, match="malformed archive") as caught:
        verify_zip_members(data, limits=OfflineResourceLimits(max_member_count=10))
    assert caught.value.code == "ecl.error.semantic-invalid.v1"
