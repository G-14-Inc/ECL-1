"""A session entry is unique; an originating step may have an intent extension."""
import json
from pathlib import Path
import pytest
from ecl_verify.bindings.acs import check
from ecl_verify.resources import validator_for
from scripts.generate_acs_context_identity import build

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/acs-context-identity.json").read_bytes())

@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["id"])
def test_acs_context_identity(case):
    value = case["record"]; before = json.dumps(value, sort_keys=True)
    assert not list(validator_for(MANIFEST["schema"]).iter_errors(value))
    found = check(value)
    assert sorted({item.rule_id for item in found}) == case["expected_rules"], found
    assert json.dumps(value, sort_keys=True) == before

def test_acs_context_identity_reconstructs():
    assert build() == MANIFEST
