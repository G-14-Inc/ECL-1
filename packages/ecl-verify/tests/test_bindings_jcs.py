"""RFC 8785 canonical JSON for the content the binding profiles digest (ecl_verify.bindings.jcs).

The known answers are those of RFC 8785: the number samples of Appendix B, given as IEEE 754
bit patterns, the serialization example of section 3.2.2 and the sorting example of section
3.2.3. ECL's own objects keep the restricted profile of IE1-001; these tests pin the full scheme
that MCP, ACS and AARM content needs.
"""

from __future__ import annotations

import struct

import pytest

from ecl_verify.bindings import jcs
from ecl_verify.canonical import canonicalize as restricted

# RFC 8785 Appendix B: the IEEE 754 double, as hexadecimal bits, and its serialization.
NUMBER_SAMPLES = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]
BACKSLASH = "\\"


@pytest.mark.parametrize(("bits", "expected"), NUMBER_SAMPLES)
def test_number_samples_of_appendix_b(bits: str, expected: str) -> None:
    value = struct.unpack(">d", bytes.fromhex(bits))[0]
    assert jcs.number(value) == expected
    assert jcs.canonicalize(value) == expected.encode()


@pytest.mark.parametrize("bits", ["7fffffffffffffff", "7ff0000000000000", "fff0000000000000"])
def test_nan_and_the_infinities_have_no_form(bits: str) -> None:
    with pytest.raises(jcs.JcsError):
        jcs.number(struct.unpack(">d", bytes.fromhex(bits))[0])


def test_serialization_example_of_section_3_2_2() -> None:
    # The string of the example as RFC 8785 writes it: \u20ac$\u000F\u000aA'\u0042\u0022\u005c
    escaped = "".join(
        piece if len(piece) == 1 else BACKSLASH + piece
        for piece in ("u20ac", "$", "u000F", "u000a", "A", "'", "u0042", "u0022", "u005c")
    )
    text = (
        '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
        f' "string": "{escaped}{BACKSLASH}{BACKSLASH}{BACKSLASH}"{BACKSLASH}/",'
        ' "literals": [null, true, false]}'
    )
    expected = (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert jcs.canonicalize(jcs.loads(text)).decode() == expected


def test_sorting_example_of_section_3_2_3() -> None:
    value = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    order = list(jcs.loads(jcs.canonicalize(value)).values())
    assert order == [
        "Carriage Return",
        "One",
        "Control",
        "Latin Small Letter O With Diaeresis",
        "Euro Sign",
        "Emoji: Grinning Face",
        "Hebrew Letter Dalet With Dagesh",
    ]


def test_integers_beyond_two_to_the_53_round_as_doubles() -> None:
    assert jcs.canonicalize(2**53 + 1) == b"9007199254740992"
    assert jcs.canonicalize(2**68) == b"295147905179352830000"
    assert jcs.canonicalize(-(2**53)) == b"-9007199254740992"
    with pytest.raises(jcs.JcsError):
        jcs.canonicalize(10**400)


def test_restricted_values_canonicalize_alike() -> None:
    value = {"b": [1, "two", None, True], "a": {"z": -3, "y": "é\n"}}
    assert jcs.canonicalize(value) == restricted(value)


@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1, "a": 2}',
        '{"a": NaN}',
        '{"a": Infinity}',
        '{"a": 1e400}',
        "﻿{}",
        '{"a": "\\ud800"}',
    ],
)
def test_loads_refuses_what_is_not_i_json(text: str) -> None:
    with pytest.raises(jcs.JcsError):
        jcs.loads(text)


def test_loads_keeps_floats_and_digest_names_the_suite() -> None:
    value = jcs.loads('{"price": 1.50, "count": 3}')
    assert value == {"price": 1.5, "count": 3}
    assert jcs.canonicalize(value) == b'{"count":3,"price":1.5}'
    assert jcs.digest(value)["algorithm"] == "ecl.digest.sha-256.v1"
    assert len(jcs.digest(value)["value"]) == 64


@pytest.mark.parametrize("value", [{1: "x"}, {"a": {1, 2}}, {"a": b"x"}, ["\ud800"]])
def test_values_without_a_json_form_are_refused(value: object) -> None:
    with pytest.raises(jcs.JcsError):
        jcs.canonicalize(value)
