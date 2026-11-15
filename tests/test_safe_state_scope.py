"""Fail-open exceptions require named advisory scope and intact required proof."""
from dataclasses import replace
import pytest
from ecl_verify.safe_state import ActionSafeStatePolicy, FailOpenAuthorization, SafeStateError, decide_safe_state
AT='2026-09-30T09:00:00Z'
DEP='urn:example:dependency:advisory'
AUTH=FailOpenAuthorization('urn:example:owner','Advisory monitor unavailable','2026-09-30T09:01:00Z','ecl.evidence.standard.v1',(DEP,))
POLICY=ActionSafeStatePolicy('ecl.action.ai-proposed-operation.v1','fail_open','fail_open','fail_open','fail_open',(),fail_open_authorization=AUTH)
def decide(failures=('dependency_unavailable',),policy=POLICY,**kwargs):
    return decide_safe_state(failures,policy,evaluated_at=AT,**kwargs)
@pytest.mark.parametrize('proof',[None,False])
def test_unknown_or_absent_required_proof_never_opens(proof):
    assert decide(failed_advisory_dependencies=(DEP,),required_proof_available=proof).disposition=='fail_closed'
@pytest.mark.parametrize('names',[(),('urn:example:unknown',),(DEP,'urn:example:unknown')])
def test_all_failed_dependencies_must_be_named_and_covered(names):
    assert decide(failed_advisory_dependencies=names,required_proof_available=True).disposition=='fail_closed'
@pytest.mark.parametrize('failure',['deadline_exceeded','dependency_unavailable','dependency_stale','evidence_buffer_exhausted'])
def test_noncritical_advisory_failures_can_open_with_intact_proof(failure):
    assert decide((failure,),failed_advisory_dependencies=(DEP,),required_proof_available=True).disposition=='fail_open'
@pytest.mark.parametrize('failure,expected',[('missing_pre_release_evidence','fail_closed'),('missing_policy','fail_closed'),('quarantine','quarantine'),('emergency_halt','emergency_halt')])
def test_stronger_state_survives_scoped_exception(failure,expected):
    assert decide(('dependency_unavailable',failure),failed_advisory_dependencies=(DEP,),required_proof_available=True).disposition==expected
@pytest.mark.parametrize('proof',[0,1,'false',[],{}])
def test_proof_declaration_is_boolean(proof):
    with pytest.raises(SafeStateError):decide(failed_advisory_dependencies=(DEP,),required_proof_available=proof)
@pytest.mark.parametrize('field',['irreversible_risk_requires_fail_closed','law_or_contract_requires_fail_closed'])
@pytest.mark.parametrize('invalid',[0,1,'false',None])
def test_policy_declarations_are_booleans(field,invalid):
    with pytest.raises(SafeStateError):decide(policy=replace(POLICY,**{field:invalid}))
@pytest.mark.parametrize('names',[(DEP,DEP),('',),(' ',),(1,),[DEP],DEP])
def test_failed_dependency_identity_domain(names):
    with pytest.raises(SafeStateError):decide(failed_advisory_dependencies=names,required_proof_available=True)
@pytest.mark.parametrize('names',[(DEP,DEP),('',),(1,),[DEP]])
def test_authorization_identity_domain(names):
    with pytest.raises(SafeStateError):decide(policy=replace(POLICY,fail_open_authorization=replace(AUTH,covered_advisory_dependencies=names)))
@pytest.mark.parametrize('field',['owner','rationale','evidence_profile'])
@pytest.mark.parametrize('invalid',['',True])
def test_authorization_declarations_are_nonempty_text(field,invalid):
    with pytest.raises(SafeStateError):decide(policy=replace(POLICY,fail_open_authorization=replace(AUTH,**{field:invalid})))
def test_missing_proof_overrides_restricted_policy():
    assert decide(policy=replace(POLICY,dependency_disposition='restricted'),required_proof_available=False).disposition=='fail_closed'
def test_invalid_unused_time_and_disposition_are_rejected():
    with pytest.raises(SafeStateError):decide_safe_state(['missing_policy'],POLICY,evaluated_at='bad')
    with pytest.raises(SafeStateError):decide(('missing_policy',),replace(POLICY,timeout_disposition='nonsense'))
def test_unscoped_legacy_authorization_cannot_open():
    assert decide(policy=replace(POLICY,fail_open_authorization=replace(AUTH,covered_advisory_dependencies=())),failed_advisory_dependencies=(DEP,),required_proof_available=True).disposition=='fail_closed'
