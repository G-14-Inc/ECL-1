"""Parsed retained counters and bounds keep their mathematical integer meaning.

Robert F. Tilley Jr.; G-14, Inc.
"""
import json
from pathlib import Path
import pytest
from ecl_verify.bindings import binding_findings
from ecl_verify.resources import schema_is_valid

ROOT = Path(__file__).resolve().parents[3]
CASES = json.loads((ROOT / "tests/fixtures/binding-host-integers/cases.json").read_text())

def replace(value, path, replacement):
    at = value
    for key in path[:-1]:
        at = at[key]
    at[path[-1]] = replacement

def check(case, value):
    assert schema_is_valid(case["schema"], value) is case["schema_valid"]
    if not case["schema_valid"]:
        # The Python rule-only API requires schema validation by its caller.
        return [("ecl.error.schema-invalid.v1", "/")]
    findings = sorted((f.rule_id, f.path) for f in binding_findings(value))
    assert set(case["required"]) <= {rule for rule, _ in findings}
    if case["clean"]:
        assert findings == []
    return findings

@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_parsed_binding_integer_representation(case):
    value = json.loads((ROOT / case["fixture"]).read_text())
    for change in case["prepare"]:
        replace(value, change["path"], change["value"])
    baseline = check(case, value) if case["schema_valid"] else None
    operand = (float(case["host_value"]) if case["host_kind"] == "whole-float"
               else case["host_value"])
    replace(value, case["field_path"], operand)
    before = json.dumps(value, sort_keys=True)
    found = check(case, value)
    assert json.dumps(value, sort_keys=True) == before
    if baseline is not None:
        assert found == baseline
