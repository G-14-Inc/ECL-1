"""The migrated MCP corpus preserves exact primary and secondary findings."""
import json
import sys
from pathlib import Path
import pytest
from ecl_verify.bindings.mcp import check
from ecl_verify.resources import validator_for
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.run_conformance import registered_errors, rule_precedence, select_findings
PRECEDENCE=rule_precedence(ROOT)
ERRORS=registered_errors(ROOT)
CASES=[c for c in json.loads((ROOT/'conformance/suites/mcp-gateway/manifest.json').read_text())['vectors'] if c['stage']=='binding']
VALIDATOR=validator_for('https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1')
@pytest.mark.parametrize('case',CASES,ids=lambda c:c['id'])
def test_active_mcp_corpus(case):
    record=json.loads((ROOT/case['path']).read_text())
    errors=list(VALIDATOR.iter_errors(record));findings=[] if errors else check(record)
    rules={'ecl.error.schema-invalid.v1'} if errors else {f.rule_id for f in findings}
    assert (not rules)==(case['expected']=='pass'),(rules,findings,[e.message for e in errors])
    assert select_findings(list(rules),PRECEDENCE,ERRORS)==(case.get('expected_primary_id'),case.get('expected_secondary_ids',[])),(rules,findings)
