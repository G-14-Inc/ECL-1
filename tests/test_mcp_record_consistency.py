"""MCP retained evidence agrees with release, recovery and refusal rules."""
import copy
import json
from pathlib import Path
import pytest
from ecl_verify.bindings import mcp
from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parent / "fixtures/mcp-record-consistency"
CASES = json.loads((ROOT / "manifest.json").read_text())["cases"]

@pytest.mark.parametrize("case", CASES, ids=lambda row: row["id"])
def test_mcp_record_consistency(case):
    value = json.loads((ROOT / case["file"]).read_text())
    before = copy.deepcopy(value)
    schema_errors = list(validator_for(mcp.EXCHANGE_SCHEMA).iter_errors(value))
    findings = mcp.check(value)
    assert (not schema_errors) == case["schema_valid"], [e.message for e in schema_errors]
    assert (not schema_errors and not findings) == case["accepted"], (schema_errors, findings)
    assert (not findings) == case["direct_accepted"], findings
    if not case["direct_accepted"]:
        assert case["required_direct_rule"] in {f.rule_id for f in findings}
    assert value == before
