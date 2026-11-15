"""Telemetry representation and sender-constraint boundaries.

Robert F. Tilley Jr.; G-14, Inc. All keys and records are synthetic.
"""
from pathlib import Path
import copy
import json
import pytest
from ecl_verify.bindings import binding_findings, otel
from ecl_verify.canonical import loads_json_strict
from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/export-authority-boundaries"
CASES = json.loads((FIXTURES / "manifest.json").read_text())["cases"]
KEYS = otel.load_export_keys((FIXTURES / "export-keys.json").read_bytes())

@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_export_authority_boundary(case):
    value = loads_json_strict((FIXTURES / case["file"]).read_bytes())
    original = copy.deepcopy(value)
    errors = list(validator_for(case["schema"]).iter_errors(value))
    assert not errors, [error.message for error in errors]
    findings = binding_findings(value, export_keys=KEYS)
    assert sorted({finding.rule_id for finding in findings}) == case["expected_rules"], findings
    assert value == original
