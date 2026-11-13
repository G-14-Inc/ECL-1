"""Semantic diagnostics retain independent findings and fail-open scope is explicit."""
import json
from pathlib import Path
import pytest
from ecl_verify.resources import _semantics
from ecl_verify.semantic_rc4 import validate_safe_state_profile
ROOT=Path(__file__).resolve().parents[1]/'tests/fixtures/core-contract-regressions'
CASES=json.loads((ROOT/'manifest.json').read_text())['cases']
@pytest.mark.parametrize('case',CASES,ids=lambda c:c['id'])
def test_core_contract(case):
    value=json.loads((ROOT/case['file']).read_text())
    if case['mutation']=='fractional_parameter': value['action']['parameters']={'number':1.5}
    before=json.dumps(value,sort_keys=True)
    found=validate_safe_state_profile(value) if case['kind']=='safe-state' else _semantics().validate(value)
    rules={x.rule_id for x in found}
    assert set(case['required'])<=rules,found
    assert not set(case['absent'])&rules,found
    assert json.dumps(value,sort_keys=True)==before
