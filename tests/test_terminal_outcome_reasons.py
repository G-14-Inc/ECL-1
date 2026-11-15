"""AARM terminal outcome reasons satisfy the response-independent EBMP2-056 clauses."""
import json
from pathlib import Path

import pytest

from ecl_verify.bindings.aarm import check
from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/terminal-outcome-reasons/manifest.json").read_bytes())
VALIDATOR = validator_for(MANIFEST["schema"])


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["id"])
def test_aarm_terminal_outcome_reasons(case):
    record = json.loads((ROOT / case["path"]).read_bytes())
    before = json.dumps(record, sort_keys=True)
    errors = list(VALIDATOR.iter_errors(record))
    assert (not errors) == case["schema_valid"], errors
    findings = [] if errors else check(record)
    rules = {"ecl.error.schema-invalid.v1"} if errors else {finding.rule_id for finding in findings}
    assert (not errors and not findings) == case["accepted"], findings
    assert set(case["expected_rules"]) == rules, findings
    assert json.dumps(record, sort_keys=True) == before



@pytest.mark.parametrize("case", MANIFEST["helper_cases"], ids=lambda case: case["id"])
def test_paired_terminal_outcome_reasons(case):
    from ecl_verify.bindings.terminal_reason import terminal_reason_findings
    terminal = json.loads((ROOT / case["path"]).read_bytes())["terminal"]
    before = json.dumps(terminal, sort_keys=True)
    found = terminal_reason_findings(terminal, response_outcome=case["response_outcome"], paired=case["paired"])
    assert {item.rule_id for item in found} == set(case["expected_rules"]), found
    assert all(item.path == "/extensions" for item in found)
    assert json.dumps(terminal, sort_keys=True) == before
