"""Wire schema boundaries, readable adapter rules and supported wrapper extensions."""
from pathlib import Path
import json
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'packages/ecl-verify/src')]
from ecl_verify.resources import validator_for
from ecl_verify.semantic import SemanticValidator
from ecl_verify.bindings import binding_findings
from ecl_verify.bundle_verification import verify_bundle, primary_finding
from ecl_verify.trust import TrustPolicy

CASES = json.loads((ROOT / 'tests/fixtures/schema-contract-boundaries.json').read_text())

@pytest.mark.parametrize('case', CASES, ids=lambda c: c['id'])
def test_schema_contract_boundary(case):
    value = case['value']
    if case['lane'] == 'bundle':
        policy = TrustPolicy.load((ROOT / 'conformance/fixtures/evidence/trust-policy.json').read_bytes())
        report = verify_bundle(value, policy, now='2026-10-01T00:00:00Z')
        assert (report.verdict, primary_finding(report)) == (case['verdict'], case['primary'])
        return
    validator = validator_for(case['schema'].split('#')[0])
    if '#' in case['schema']:
        validator = validator.evolve(schema={'$ref': case['schema']})
    assert validator.is_valid(value) is case['valid']
    if case['lane'] == 'adapter':
        ids = sorted({f.rule_id for f in SemanticValidator(set()).validate(value)})
        assert ids == case['rules']
    elif case['lane'] == 'binding' and case['valid']:
        assert not binding_findings(value)
