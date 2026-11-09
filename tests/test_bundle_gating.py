"""Exercise complete findings, including failures suppressed by prescribed gates."""
from pathlib import Path
import json, sys
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'packages/ecl-verify/src'))
from ecl_verify.bundle_verification import verify_bundle, report_to_json
from ecl_verify.trust import TrustPolicy
MANIFEST=json.loads((ROOT/'tests/fixtures/bundle-gating/expected.json').read_text())

@pytest.mark.parametrize('case', MANIFEST['cases'], ids=lambda case:case['id'])
def test_full_findings(case):
    bundle=json.loads((ROOT/case['path']).read_text())
    policy=TrustPolicy.load((ROOT/MANIFEST['trust_policy']).read_bytes())
    report=report_to_json(verify_bundle(bundle,policy,now=MANIFEST['evaluated_at']))
    assert report['verdict']==case['expected_verdict']
    assert report['findings']==case['expected_findings'],case['rationale']


TRUST_CASES=json.loads((ROOT/'tests/fixtures/bundle-gating/trust-dependencies.json').read_text())

@pytest.mark.parametrize('case', TRUST_CASES['cases'], ids=lambda case:case['id'])
def test_signer_trust_dependencies(case):
    value=json.loads((ROOT/case['path']).read_text())
    bundle={'schema_version':'ecl_evidence_bundle_v1','envelopes':[value]} if case['wrap_envelope'] else value
    policy=TrustPolicy.load((ROOT/TRUST_CASES['trust_policy']).read_bytes())
    report=report_to_json(verify_bundle(bundle,policy,now=TRUST_CASES['evaluated_at']))
    assert report['verdict']==case['expected_verdict']
    signers=[{key:dep[key] for key in ('key_id','historical','current')}
             for dep in report['trust_dependencies'] if dep['role']=='signer']
    assert signers==case['expected_dependencies']
