"""Schema-backed semantics use mathematical integer operands without mutating inputs."""
import copy
import json
import math
from pathlib import Path
import pytest
from ecl_verify.resources import _semantics, object_findings
from ecl_verify.semantic_numbers import schema_int
from ecl_verify.decision_basis_checks import timing_coverage

ROOT = Path(__file__).resolve().parents[3]
CASES = json.loads((ROOT / "tests/fixtures/semantic-host-integers/cases.json").read_text())

def whole_floats(value):
    if type(value) is int:
        return float(value)
    if isinstance(value, list):
        return [whole_floats(item) for item in value]
    if isinstance(value, dict):
        return {key: whole_floats(item) for key, item in value.items()}
    return value

@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_schema_integer_findings_are_representation_independent(case):
    observed = []
    for value in (copy.deepcopy(case["value"]), whole_floats(case["value"])):
        # JSON text distinguishes 1 from 1.0; Python mapping equality does not.
        before = json.dumps(value, sort_keys=True)
        findings = (object_findings(value) if case["api"] == "object"
                    else _semantics().validate(value))
        assert json.dumps(value, sort_keys=True) == before
        keys = sorted((f.rule_id, f.path) for f in findings)
        assert set(case["required"]) <= {rule for rule, _ in keys}
        if case["clean"]:
            assert keys == []
        observed.append(keys)
    assert observed[0] == observed[1]

@pytest.mark.parametrize("value", [True, False, 1.5, math.nan, math.inf, -math.inf,
                                  float(2**53), "1", None])
def test_schema_integer_operand_refuses_other_host_values(value):
    assert schema_int(value) is None

@pytest.mark.parametrize("value", [0.0, -0.0, 1.0, -1.0, float(2**53 - 1)])
def test_schema_integer_operand_reads_bounded_whole_floats(value):
    assert schema_int(value) == int(value)

@pytest.mark.parametrize("case", json.loads((ROOT / "tests/fixtures/decision-input-timing/helper-cases.json").read_text()), ids=lambda c:c["id"])
def test_timing_coverage_retains_whole_float_constraints(case):
    value = whole_floats(case["register"])
    before = json.dumps(value, sort_keys=True)
    assert list(timing_coverage(case["basis"], value, "ecl.action.ai-proposed-operation.v1",
                evaluated_at="2026-09-29T10:00:00Z")) == case["expected"]
    assert json.dumps(value, sort_keys=True) == before

@pytest.mark.parametrize("bad_version", [True, 1.5, "1"])
def test_object_api_refuses_noninteger_extension_versions(bad_version):
    value = copy.deepcopy(CASES[1]["value"])
    value["extensions"][-1]["version"] = bad_version
    assert any(f.rule_id == "ecl.error.schema-invalid.v1" for f in object_findings(value))


@pytest.mark.parametrize("protocol,version,expected", [
    ("EBMP-2", 1, True), ("EBMP-2", 1.0, True), ("DCMP-2", 1.0, False),
    ("EBMP-2", 2.0, False), ("EBMP-2", True, False), ("EBMP-2", 1.5, False),
])
def test_shared_extension_selector_reads_integer_versions(protocol, version, expected):
    from ecl_verify.extension_selection import interpreted_extension
    value = {"protocol": protocol}
    occurrence = {"id": "ecl.ext.outcome-reason.v1", "version": version}
    before = json.dumps(occurrence, sort_keys=True)
    assert interpreted_extension(value, occurrence) is expected
    assert json.dumps(occurrence, sort_keys=True) == before
