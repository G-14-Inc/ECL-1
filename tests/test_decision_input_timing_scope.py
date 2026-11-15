"""Optional recorded times produce explicit timing coverage, without changing bundle validity."""
import json
from pathlib import Path
import pytest
from ecl_verify.bundle_verification import verify_bundle
from ecl_verify.decision_basis_checks import timing_coverage
from ecl_verify.trust import TrustPolicy
ROOT=Path(__file__).resolve().parents[1]/'tests/fixtures/decision-input-timing'
MANIFEST=json.loads((ROOT/'manifest.json').read_text())
POLICY=TrustPolicy.load((ROOT/'policy.json').read_bytes())
SCOPE='decision-input-timing'
@pytest.mark.parametrize('row',MANIFEST['cases'],ids=lambda r:r['id'])
def test_recorded_input_timing_scope(row):
    b=json.loads((ROOT/row['bundle']).read_text())
    reg=json.loads((ROOT/row['register']).read_text()) if row['register'] else None
    report=verify_bundle(b,POLICY,now=MANIFEST['now'],register=reg)
    assert report.verdict==row['verdict'],report.findings
    assert (SCOPE in report.scope.established)==(row['scope']=='established')
    assert (SCOPE in report.scope.not_established)==(row['scope'] in ('missing','not-established'))
    assert report.scope.reasons.get(SCOPE)==('input-times-not-recorded' if row['scope']=='missing' else None)
    assert 'recorded-times-true' not in report.scope.established
    if row['scope']=='established':assert report.scope.checks[SCOPE]['objects']==[1]
@pytest.mark.parametrize('row',json.loads((ROOT/'helper-cases.json').read_text()),ids=lambda r:r['id'])
def test_timing_operand_applicability(row):
    assert list(timing_coverage(row['basis'],row['register'],'ecl.action.ai-proposed-operation.v1',evaluated_at='2026-09-29T10:00:00Z'))==row['expected']
