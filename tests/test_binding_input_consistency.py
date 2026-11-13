"""Known telemetry digest exposures and encoded binding inputs retain their profile checks."""
import base64
import copy
import json
from pathlib import Path

import pytest
from ecl_verify.bindings import binding_findings, jcs, otel
from ecl_verify.canonical import loads_json_strict
from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/binding-input-consistency"
CASES = json.loads((FIXTURES / "manifest.json").read_text())["cases"]
SEGMENTS = json.loads((FIXTURES / "strict-segments.json").read_text())["cases"]
KEYS = otel.load_export_keys((FIXTURES / "export-keys.json").read_bytes())
NONCHARACTERS = list(range(0xFDD0, 0xFDF0)) + [plane * 65536 + tail for plane in range(17) for tail in (65534, 65535)]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_binding_input_record(case):
    # The parsed-input entrypoint also receives deliberately schema-invalid objects.
    value = json.loads((FIXTURES / case["file"]).read_text())
    original = copy.deepcopy(value)
    errors = list(validator_for(case["schema"]).iter_errors(value))
    found = [] if errors else binding_findings(value, export_keys=KEYS)
    rules = ["ecl.error.schema-invalid.v1"] if errors else sorted({item.rule_id for item in found})
    assert rules == case["expected_rules"], (found, [error.message for error in errors])
    assert value == original


@pytest.mark.parametrize("case", SEGMENTS, ids=lambda case: case["id"])
def test_jws_segment_strict_profile(case):
    try:
        loads_json_strict(base64.b64decode(case["base64"]))
        result = "accept"
    except ValueError as error:
        result = "duplicate" if "duplicate" in str(error).lower() or "repeat" in str(error).lower() else "strict"
    assert result == case["expected"]


@pytest.mark.parametrize("codepoint", NONCHARACTERS, ids=lambda cp: f"U+{cp:04X}")
@pytest.mark.parametrize("slot", ["key", "value"])
def test_jcs_refuses_i_json_noncharacters(codepoint, slot):
    value = {chr(codepoint): 1} if slot == "key" else {"a": chr(codepoint)}
    with pytest.raises(jcs.JcsError):
        jcs.canonicalize(value)
    for escaped in (False, True):
        with pytest.raises(jcs.JcsError):
            jcs.loads(json.dumps(value, ensure_ascii=escaped))


def test_jcs_keeps_valid_scalars_fractions_and_utf16_order():
    value = {"\ue000": 1, "\U00010000": 2, "scalar": "\U0001f511", "values": [1.5, -0.0, 1e21, 1e-7]}
    assert jcs.canonicalize(value).decode() == '{"scalar":"🔑","values":[1.5,0,1e+21,1e-7],"𐀀":2,"":1}'


@pytest.mark.parametrize("key_id", ["k", "k" * 256, "🔑" * 129, "🔑" * 256])
def test_export_key_identifier_uses_codepoints(key_id):
    assert otel.ExportKey(key_id, bytes(range(32))).key_id == key_id


@pytest.mark.parametrize("key_id", ["", "k" * 257, "🔑" * 257])
def test_export_key_identifier_refuses_outside_supported_range(key_id):
    with pytest.raises(ValueError):
        otel.ExportKey(key_id, bytes(range(32)))


def test_missing_after_snapshot_has_a_controlled_direct_finding():
    value = json.loads((FIXTURES / "missing-after-otel-valid-failed-export-evidence-unchanged.json").read_text())
    assert otel.EXPORT_RULE in {finding.rule_id for finding in otel.check(value, KEYS)}
