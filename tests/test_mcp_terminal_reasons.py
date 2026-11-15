"""MCP terminals retain active outcome reasons consistent with the refused action."""
import json
from pathlib import Path

import pytest

from ecl_verify.bindings.mcp import check, refusal_cause
from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/mcp-terminal-reasons/manifest.json").read_bytes())
VALIDATOR = validator_for(MANIFEST["schema"])


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["id"])
def test_mcp_terminal_reasons(case):
    record = json.loads((ROOT / case["path"]).read_bytes())
    before = json.dumps(record, sort_keys=True)
    errors = list(VALIDATOR.iter_errors(record))
    assert (not errors) == case["schema_valid"], errors
    findings = [] if errors else check(record)
    rules = {"ecl.error.schema-invalid.v1"} if errors else {finding.rule_id for finding in findings}
    assert (not errors and not findings) == case["accepted"], findings
    assert set(case["expected_rules"]) == rules, findings
    assert json.dumps(record, sort_keys=True) == before

