"""MCP stage progression and retained completion must agree across the record."""
import json
from pathlib import Path

import pytest

from ecl_verify.bindings.mcp import check
from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/mcp-release-progress-regressions/manifest.json").read_bytes())
VALIDATOR = validator_for(MANIFEST["schema"])


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["id"])
def test_mcp_release_progress(case):
    record = json.loads((ROOT / case["path"]).read_bytes())
    errors = list(VALIDATOR.iter_errors(record))
    assert not errors, [error.message for error in errors]
    findings = check(record)
    rules = {finding.rule_id for finding in findings}
    assert (not rules) == case["valid"], findings
    assert set(case["expected_rules"]) <= rules, findings
