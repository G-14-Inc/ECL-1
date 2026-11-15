"""ACS record completeness regressions. Robert F. Tilley Jr.; G-14, Inc."""
import json
from pathlib import Path

import pytest

from ecl_verify.bindings import binding_findings
from ecl_verify.resources import validator_for

FIXTURES = Path(__file__).resolve().parent / "fixtures/acs-record-completeness/cases.json"
MANIFEST = json.loads(FIXTURES.read_text())


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda case: case["case"])
def test_acs_record_completeness(case):
    record = case["record"]
    direct = binding_findings(record)
    assert sorted({item.rule_id for item in direct}) == case["expected_direct_rules"], direct
    for path in case["required_direct_paths"]:
        assert any(item.path == path for item in direct), (path, direct)
    errors = list(validator_for(MANIFEST["schema"]).iter_errors(record))
    public = ["ecl.error.schema-invalid.v1"] if errors else sorted({item.rule_id for item in direct})
    assert public == case["expected_public_rules"], (direct, [error.message for error in errors])
