"""OAuth presentation records reject ambiguous configured key identifiers."""
import json
from pathlib import Path
import pytest
from ecl_verify.bindings import binding_findings, RECORD_SCHEMAS
from ecl_verify.resources import validator_for

CASES = json.loads((Path(__file__).resolve().parent / "fixtures/oauth-key-selection/cases.json").read_text())

@pytest.mark.parametrize("row", CASES, ids=lambda row: row["name"])
def test_configured_oauth_key_selection(row):
    record = row["record"]
    assert validator_for(RECORD_SCHEMAS[record["schema_version"]]).is_valid(record)
    actual = sorted({finding.rule_id for finding in binding_findings(record)})
    assert actual == row["expected_rules"]
