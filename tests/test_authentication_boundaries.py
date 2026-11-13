"""Authentication record regressions. Robert F. Tilley Jr.; G-14, Inc."""
"""Authenticated claims and exchange records preserve their profile-specific boundaries."""
import json
from pathlib import Path
import pytest
from ecl_verify.bindings import binding_findings, acs
from ecl_verify.canonical import loads_json_strict
from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/authentication-boundaries'
CASES = json.loads((FIXTURES / 'manifest.json').read_text())['cases']

@pytest.mark.parametrize('case', CASES, ids=lambda case: case['case'])
def test_authentication_record(case):
    record = loads_json_strict((FIXTURES / case['path']).read_bytes())
    errors = list(validator_for(case['schema']).iter_errors(record))
    found = [] if errors else binding_findings(record)
    rules = ['ecl.error.schema-invalid.v1'] if errors else sorted({item.rule_id for item in found})
    assert rules == case['expected_rules'], (found, [error.message for error in errors])
    if 'message' in case:
        assert any(item.message == case['message'] for item in found)
    for path in case.get('required_paths', []):
        assert any(item.path == path for item in found)

def test_native_defer_zero_is_a_valid_immediate_deadline():
    record = json.loads((FIXTURES / 'acs-defer-zero-denied-control.json').read_text())
    assert acs.deadline(record, 'defer') == 1790758800080000000
