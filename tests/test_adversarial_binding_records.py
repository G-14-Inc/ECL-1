"""Cross-profile records must enforce the same content and event contracts as their components."""
import json
from pathlib import Path
import pytest
from ecl_verify.canonical import loads_json_strict
from ecl_verify.bindings import binding_findings
from ecl_verify.resources import validator_for

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/adversarial-bindings'
CASES = json.loads((FIXTURES / 'manifest.json').read_text())['cases']

@pytest.mark.parametrize('case', CASES, ids=lambda case: case['id'])
def test_adversarial_binding_record(case):
    record = loads_json_strict((FIXTURES / case['file']).read_bytes())
    errors = list(validator_for(case['schema']).iter_errors(record))
    found = [] if errors else binding_findings(record)
    rules = ['ecl.error.schema-invalid.v1'] if errors else sorted({item.rule_id for item in found})
    assert rules == case['expected_rules'], (found, [error.message for error in errors])
