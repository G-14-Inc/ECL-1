"""Portable assessment/deployment declarations and the federated timing comparison."""
import json
from pathlib import Path
import pytest
from ecl_verify.canonical import loads_json_strict
from ecl_verify.resources import validator_for,_semantics
ROOT=Path(__file__).resolve().parents[1]
ROWS=[row for suite in ('claim-deployment-contract','deployment-timing-case') for row in json.loads((ROOT/'conformance/suites'/suite/'manifest.json').read_text())['vectors']]
RULE='ecl.rule.deployment-timing-case-consistent.v1'
@pytest.mark.parametrize('row',ROWS,ids=lambda r:r['id'])
def test_document_contract(row):
    value=loads_json_strict((ROOT/row['path']).read_bytes())
    actual={'ecl.error.schema-invalid.v1'} if list(validator_for(row['schema']).iter_errors(value)) else set()
    actual.update(f.rule_id for f in _semantics().validate(value) if f.rule_id==RULE)
    assert actual==({row['expected_primary_id'],*row['expected_secondary_ids']} if row['expected']=='fail' else set())

@pytest.mark.parametrize('invalid',[True,'1',None,1.5,float('nan'),float('inf')])
def test_parsed_document_timing_types(invalid):
    value=json.loads((ROOT/'conformance/suites/document-coverage/deployment-valid-federated-example.json').read_text())
    value['timing_case']['federated_exchange_seconds']=invalid
    assert list(validator_for('https://externalcontrollayer.ai/ns/schema/deployment-profile/1').iter_errors(value))
    assert RULE not in {f.rule_id for f in _semantics().validate(value)}
