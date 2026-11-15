"""Complete synthetic record controls for the MCP public-review repairs."""
import json
from pathlib import Path
import pytest
from ecl_verify.bindings.mcp import check
from ecl_verify.resources import validator_for
ROOT=Path(__file__).resolve().parents[1]
MANIFEST=json.loads((ROOT/'tests/fixtures/mcp-public-review-repairs/manifest.json').read_text())
VALIDATOR=validator_for(MANIFEST['schema'])

@pytest.mark.parametrize('case',MANIFEST['cases'],ids=lambda c:c['id'])
def test_mcp_complete_record(case):
    record=json.loads((ROOT/case['path']).read_text())
    schema_errors=list(VALIDATOR.iter_errors(record))
    findings=[] if schema_errors else check(record)
    rules=['ecl.error.schema-invalid.v1'] if schema_errors else [f.rule_id for f in findings]
    assert (not rules)==case['valid'], (rules,findings,[e.message for e in schema_errors])
    if case['expected_rule']:
        assert case['expected_rule'] in rules,(rules,findings)
