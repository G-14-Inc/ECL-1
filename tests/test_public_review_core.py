"""Regression tests for repaired bundle claims, ordering and package boundaries."""
import json
from pathlib import Path
import pytest
from ecl_verify.bundle_verification import verify_bundle, report_to_json
from ecl_verify.package_verification import verify_offline_package
from ecl_verify.trust import TrustPolicy
ROOT=Path(__file__).resolve().parents[1]
CASES=json.loads((ROOT/'tests/fixtures/core-public-review-repairs/manifest.json').read_bytes())['cases']
def run_case(case):
 policy=TrustPolicy.load((ROOT/case['policy']).read_bytes())
 options={'now':case['now'],'history':tuple(TrustPolicy.load((ROOT/p).read_bytes()) for p in case.get('history',[])),'require_trusted_time':case.get('require_trusted_time',False)}
 raw=(ROOT/case['file']).read_bytes()
 report=verify_offline_package(raw,policy,**options) if case['kind']=='package' else verify_bundle(json.loads(raw),policy,**options)
 return report_to_json(report)
def assert_case(case,result):
 assert result['verdict']==case['expected_verdict'], result
 if 'expected_primary' in case: assert result['primary']==case['expected_primary'],result
 for value in case.get('scope_present',[]):assert value in result['scope']['established'],result['scope']
 for value in case.get('scope_absent',[]):assert value not in result['scope']['established'],result['scope']
 if case.get('expected_dependency_code'):assert any(d['historical']==case['expected_dependency_code'] for d in result['trust_dependencies']),result['trust_dependencies']
 assert result['response_clock_skew_seconds']==0
@pytest.mark.parametrize('case',CASES,ids=[c['id'] for c in CASES])
def test_public_review_core(case):assert_case(case,run_case(case))
def test_reference_profiles_reject_nonzero_skew():
 case=CASES[0];policy=TrustPolicy.load((ROOT/case['policy']).read_bytes())
 with pytest.raises(ValueError,match='zero'):
  verify_bundle({},policy,now=case['now'],response_clock_skew_seconds=1)
