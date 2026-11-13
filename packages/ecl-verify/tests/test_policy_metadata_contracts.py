"""Policy and generated-metadata schema contracts."""
import json
from pathlib import Path
import pytest
from ecl_verify.resources import validator_for
ROOT = Path(__file__).resolve().parents[3]
CASES = json.loads((ROOT / "tests/fixtures/policy-metadata-contracts.json").read_text())
@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_policy_metadata_contracts(case):
    assert validator_for(case["schema"]).is_valid(case["value"]) == case["valid"]
