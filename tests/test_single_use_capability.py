"""The supported single-use domain is enforced by acceptance helpers, before release."""
import json
import os
from pathlib import Path
import pytest
from ecl_verify.canonical import loads_json_strict
from ecl_verify.binding import BindingError, check_response_binding, check_event_binding, check_authority_event_binding
from ecl_verify.bindings import oauth, mcp

ROOT=Path(os.environ.get('ECL_CAPABILITY_FIXTURES',str(Path(__file__).resolve().parents[1]/'tests/fixtures/single-use-capability')))
CASES=json.loads((ROOT/'manifest.json').read_text())['cases']
def code(call):
    try:call()
    except BindingError as error:return error.code
    return None

@pytest.mark.parametrize('case',CASES,ids=lambda case:case['id'])
def test_single_use_capability(case):
    record=loads_json_strict((ROOT/case['file']).read_bytes())
    if case['kind']=='pair':
        assert code(lambda:check_response_binding(record['request'],record['response']))==case['expected']
    elif case['kind']=='event':
        assert code(lambda:check_event_binding(record['released'],request=record['request'],response=record['response']))==case['expected']
        assert code(lambda:check_authority_event_binding(record['consumed'],response=record['response']))==case['authority_expected']
    elif case['kind']=='oauth':
        found=oauth.presentation_problems(record)
        assert (found[0][2] if found else None)==case['expected'],found
        refused=oauth.refusal_problems(record)
        assert (refused[0][2] if refused else None)==case.get('refusal_expected',case['expected']),refused
    elif case['kind']=='mcp':
        found=mcp.check(record)
        if case['expected'] is None:
            assert not found,found
            assert mcp.refusal_cause(record) is None
        else:
            assert case['expected'] in {f.rule_id for f in found},found
            assert mcp.refusal_cause(record)[0]=='decision-invalid'
    else:raise AssertionError(case['kind'])
