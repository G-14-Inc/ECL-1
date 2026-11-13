"""MG1-010 first-cause reasons preserve decision states and recovery uncertainty."""
import hashlib
import json
from pathlib import Path

import pytest

from ecl_verify.bindings.mcp import check
from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "tests/fixtures/mcp-multicause-reasons/manifest.json").read_bytes())
VALIDATOR = validator_for(MANIFEST["schema"])


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["id"])
def test_mcp_multicause_terminal_reason(case):
    data = (ROOT / case["path"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == case["sha256"]
    record = json.loads(data)
    before = json.dumps(record, sort_keys=True)
    assert record["terminal"]["event"]["state"] == case["expected_state"]
    errors = list(VALIDATOR.iter_errors(record))
    assert (not errors) == case["schema_valid"], errors
    found = [] if errors else check(record)
    rules = {"ecl.error.schema-invalid.v1"} if errors else {item.rule_id for item in found}
    assert sorted(rules) == case["expected_rules"], found
    assert (not errors and not found) == case["accepted"], found
    if not case["accepted"]:
        assert all(item.path == "/terminal/extensions" for item in found), found
    assert json.dumps(record, sort_keys=True) == before
