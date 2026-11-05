"""Refusal probes for ECMA anchors while retaining unpatterned string data."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import SplitResult

import pytest
from jsonschema import Draft202012Validator

import ecl_verify.schema as schema_formats
from ecl_verify.resources import validator_for
from ecl_verify.schema_patterns import python_pattern
from ecl_verify.trust import TrustPolicy, TrustPolicyError

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    ("authority", "valid"),
    [
        ("example.test", True),
        ("[::1]", True),
        ("[2001:db8::1]:443", True),
        ("[::ffff:192.0.2.1]", True),
        ("[fe80::1%25eth0]", True),
        ("[v1.future]", True),
        ("[externalcontrollayer.ai]", False),
        ("[127.0.0.1]", False),
        ("[::1]suffix", False),
        ("[broken", False),
        ("user[info]@example.test", False),
    ],
)
def test_ip_literal_validation_does_not_depend_on_urlsplit_patch_level(
    monkeypatch: pytest.MonkeyPatch, authority: str, valid: bool
) -> None:
    # Python 3.10.8 splits a bracketed DNS name without rejecting it. Preserve the
    # required refusal even when the host parser supplies no IP-literal validation.
    monkeypatch.setattr(
        schema_formats,
        "urlsplit",
        lambda _value: SplitResult("https", authority, "/profile", "", ""),
    )
    assert (
        schema_formats.ecl_format_checker().conforms("https://" + authority + "/profile", "uri")
        is valid
    )


def test_trailing_newline_fails_in_referenced_pattern() -> None:
    data = json.loads(
        (ROOT / "conformance/suites/trust-policy/trust-policy-valid.json").read_bytes()
    )
    data["version"] = "1\n"
    with pytest.raises(TrustPolicyError) as caught:
        TrustPolicy.load(json.dumps(data).encode())
    assert caught.value.code == "ecl.error.schema-invalid.v1"
    data["version"] = "1"
    data["revocations"][0]["reason"] = "unpatterned text\n"
    assert len(TrustPolicy.load(json.dumps(data).encode()).keys) == 2


def test_control_exposes_python_dollar_difference() -> None:
    assert Draft202012Validator({"pattern": "^[0-9]+$"}).is_valid("1\n")
    assert not re.search(python_pattern("^[0-9]+$"), "1\n")
    assert re.search(python_pattern(r"^[.$]+\$$"), ".$$")
    assert not re.search(python_pattern("^.+$"), "x\r")
    assert not re.search(python_pattern("^.+$"), "x\u2028")
    assert (
        validator_for("https://externalcontrollayer.ai/ns/schema/common/1")
        .evolve(schema={"$ref": "#/$defs/asciiToken"})
        .is_valid("1")
    )
