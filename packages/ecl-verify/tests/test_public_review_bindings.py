"""Regressions for public-review binding and safe-state repairs."""
from dataclasses import replace
from itertools import combinations
import json
from pathlib import Path
import pytest
from ecl_verify.bindings import binding_findings
from ecl_verify.resources import validator_for
from ecl_verify.safe_state import ActionSafeStatePolicy, FailOpenAuthorization, DISPOSITION_PRECEDENCE, decide_safe_state
from ecl_verify.semantic_rc4 import CLASSIFICATION_RULE, validate_safe_state_profile

ROOT=Path(__file__).resolve().parents[3]
MANIFEST=json.loads((ROOT/'conformance/suites/repair-bindings/manifest.json').read_text())

@pytest.mark.parametrize('vector',MANIFEST['vectors'],ids=lambda v:v['id'])
def test_repaired_binding_corpus(vector):
    value=json.loads((ROOT/vector['path']).read_text())
    errors=list(validator_for(vector['schema']).iter_errors(value))
    findings=([] if errors else binding_findings(value)) if vector['stage']=='binding' else validate_safe_state_profile(value)
    actual=({'ecl.error.schema-invalid.v1'} if errors else set()) | {f.rule_id for f in findings}
    expected=set([vector['expected_primary_id'],*vector['expected_secondary_ids']]) if vector['expected']=='fail' else set()
    assert actual==expected, (errors, findings)


def policy(expiry='2026-09-30T09:00:00Z'):
    return ActionSafeStatePolicy('ecl.action.ai-proposed-operation.v1','fail_open','restricted','degraded','quarantine',('read_health',),
        fail_open_authorization=FailOpenAuthorization('urn:example:owner','bounded advisory outage',expiry,'ecl.evidence.standard.v1',('urn:example:dependency:advisory',)))

@pytest.mark.parametrize('expiry,expected',[
    ('2026-09-30T09:00:00Z','fail_closed'),
    ('2026-09-30T09:00:00.000000500Z','fail_open'),
    ('2026-09-30T09:00:00.000001Z','fail_open'),
])
def test_fail_open_expiry_preserves_nanoseconds(expiry,expected):
    assert decide_safe_state(['deadline_exceeded'],policy(expiry),evaluated_at='2026-09-30T09:00:00Z',failed_advisory_dependencies=('urn:example:dependency:advisory',),required_proof_available=True).disposition==expected

@pytest.mark.parametrize('current',[policy(),policy('2026-09-30T09:00:01Z'),replace(policy(),fail_open_authorization=None),replace(policy('2026-09-30T09:00:01Z'),irreversible_risk_requires_fail_closed=True)])
def test_more_failures_never_weaken_disposition(current):
    failures=('deadline_exceeded','dependency_unavailable','dependency_stale','evidence_buffer_exhausted','emergency_halt')
    sets=[frozenset(items) for count in range(1,len(failures)+1) for items in combinations(failures,count)]
    results={items:decide_safe_state(items,current,evaluated_at='2026-09-30T09:00:00Z',failed_advisory_dependencies=('urn:example:dependency:advisory',),required_proof_available=True) for items in sets}
    for before in sets:
        for after in sets:
            if before<=after:
                assert DISPOSITION_PRECEDENCE[results[after].disposition]>=DISPOSITION_PRECEDENCE[results[before].disposition]
    if current.fail_open_authorization is None or current.fail_open_authorization.expires_at=='2026-09-30T09:00:00Z':
        assert results[frozenset(('deadline_exceeded','dependency_stale'))].permitted_operations==()


def test_healthy_operation_is_not_a_failure_decision():
    with pytest.raises(ValueError,match='at least one failure'):
        decide_safe_state([],policy(),evaluated_at='2026-09-30T09:00:00Z',failed_advisory_dependencies=('urn:example:dependency:advisory',),required_proof_available=True)


def test_direct_safe_state_api_rejects_advisory_proof_contradiction():
    value=json.loads((ROOT/'conformance/suites/repair-bindings/repair-safe-state-advisory-required-proof.json').read_text())
    assert CLASSIFICATION_RULE in {f.rule_id for f in validate_safe_state_profile(value)}
