"""MCP retained observations must remain consistent even when dispatch was refused."""
import json
from pathlib import Path

import pytest

from ecl_verify.bindings.mcp import check, refusal_cause
from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/mcp-retained-evidence-regressions/manifest.json").read_bytes())
VALIDATOR = validator_for(MANIFEST["schema"])


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["id"])
def test_mcp_retained_evidence(case):
    record = json.loads((ROOT / case["path"]).read_bytes())
    before = json.dumps(record, sort_keys=True)
    errors = list(VALIDATOR.iter_errors(record))
    assert (not errors) == case["schema_valid"], errors
    findings = [] if errors else check(record)
    rules = {"ecl.error.schema-invalid.v1"} if errors else {finding.rule_id for finding in findings}
    assert (not errors and not findings) == case["accepted"], findings
    assert set(case["expected_rules"]) == rules, findings
    assert json.dumps(record, sort_keys=True) == before


def test_malformed_discharge_keeps_obligation_refusal_precedence():
    record = json.loads((ROOT / "tests/fixtures/mcp-record-consistency/clock-intrinsic-proof-failure-control.json").read_bytes())
    assert refusal_cause(record) == (
        "obligation-unproven", "ecl.error.obligation-unproven.v1",
        record["decision_request"]["message_id"],
    )
    findings = check(record)
    assert {item.rule_id for item in findings} == {"ecl.rule.mcp-obligations-discharged.v1"}
