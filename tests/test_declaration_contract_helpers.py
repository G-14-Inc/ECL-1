"""Typed declarations cannot bypass assessment, timing or recovery requirements."""
from dataclasses import replace
from pathlib import Path
import runpy
import pytest
from ecl_verify.claims import AssessmentOutcome,ClaimError,PublicClaim
from ecl_verify.deployment import DeclaredTimingCase,DeploymentError,DEFAULT_TIMING
from ecl_verify.safe_state import RecoveryEvidence,recovery_is_complete,SafeStateError
ROOT=Path(__file__).resolve().parents[1]
FACTORIES=runpy.run_path(str(ROOT/'tests/test_adversarial_claim_consistency.py'))

@pytest.mark.parametrize('level,valid',[(1,'A'),(1,'B'),(1,'C'),(2,'B'),(2,'C'),(3,'B'),(3,'C'),(4,'C')])
def test_boundary_independence_controls(level,valid):
    replace(FACTORIES['boundary'](),claimed_level=level,independence_class=valid).validate()
@pytest.mark.parametrize('level,invalid',[(2,'A'),(3,'A'),(4,'A'),(4,'B'),(1,'INVALID'),(1,None),(1,False),(1,[])])
def test_boundary_independence_cannot_be_lowered(level,invalid):
    with pytest.raises(ClaimError):replace(FACTORIES['boundary'](),claimed_level=level,independence_class=invalid).validate()
def test_included_and_excluded_paths_are_disjoint():
    boundary=FACTORIES['boundary']()
    with pytest.raises(ClaimError):replace(boundary,negative_boundary_paths=boundary.included_effect_paths).validate()
    replace(boundary,claim_class='bounded-action-class-mediation',included_effect_paths=frozenset({'tool:payment'}),negative_boundary_paths=frozenset({'tool:wire'})).validate()
@pytest.mark.parametrize('digest',['z'*64,'A'*64,42,None,['a']*64,'a'*63,'a'*65])
def test_artifact_hashes_are_lowercase_sha256(digest):
    with pytest.raises(ClaimError):replace(FACTORIES['package'](),artifact_hashes={'item':digest}).validate()
def test_lowercase_artifact_hash_control():replace(FACTORIES['package'](),artifact_hashes={'item':'abcdef0123456789'*4}).validate()
def claim(state):
    return PublicClaim('urn:test:soi',2,'assessment_only','bounded-action-class-mediation','B','1',('DCMP-2',),(),'2026-11-10T00:00:00Z',(),framework_name='Example',mapping_packet_id='urn:test:packet',obligation_slice='slice',residual_gap='gap',mapping_validation_state=state)
@pytest.mark.parametrize('state',['draft','internally_reviewed','independently_reviewed','owner_validated'])
def test_mapping_state_controls(state):claim(state).validate()
@pytest.mark.parametrize('state',['certified',False,0,{},[]])
def test_mapping_state_has_registered_domain(state):
    with pytest.raises(ClaimError):claim(state).validate()
def test_general_observation_preserves_minor_caveats():
    AssessmentOutcome({'EA-01':'fail'},{'f1':'minor','note':'observation'},'full_conformance','not_evaluated',{'EA-01':'f1'}).validate()
    AssessmentOutcome({'EA-01':'pass'},{'note':'observation'},'full_conformance','not_evaluated').validate()
    with pytest.raises(ClaimError):AssessmentOutcome({'EA-01':'fail'},{'note':'observation'},'assessment_only','not_evaluated',{'EA-01':'note'}).validate()
def timing(level=2):return DeclaredTimingCase(level,*DEFAULT_TIMING[level],None,(),None,None,level>=3)
@pytest.mark.parametrize('level',[1,2,3,4])
def test_timing_default_and_federated_boundaries(level):
    value=timing(level);value.validate();replace(value,federated_exchange_seconds=0).validate();replace(value,federated_exchange_seconds=value.connected_revocation_seconds).validate()
    with pytest.raises(DeploymentError):replace(value,federated_exchange_seconds=value.connected_revocation_seconds+1).validate()
@pytest.mark.parametrize('field',['connected_revocation_seconds','offline_staleness_seconds','evidence_export_seconds','federated_exchange_seconds'])
@pytest.mark.parametrize('invalid',[-1,True,False,'0',1.5,float('nan'),float('inf')])
def test_timing_interval_domain(field,invalid):
    with pytest.raises(DeploymentError):replace(timing(),**{field:invalid}).validate()
@pytest.mark.parametrize('invalid',[0,5,True,2.0,'2',None])
def test_timing_level_domain(invalid):
    with pytest.raises(DeploymentError):replace(timing(),level=invalid).validate()
@pytest.mark.parametrize('invalid',[None,False,0,'false',{},[]])
def test_l3_trusted_order_is_explicit(invalid):
    with pytest.raises(DeploymentError):replace(timing(3),trusted_time_or_secure_monotonic=invalid).validate()
FLAGS=('policy_epochs_reconciled','revocations_reconciled','consumed_authorities_reconciled','buffered_evidence_reconciled','clock_discontinuities_reconciled')
def recovery():return RecoveryEvidence(True,True,True,True,True)
@pytest.mark.parametrize('field',FLAGS)
@pytest.mark.parametrize('invalid',['false',0,1,None,[],{}])
def test_recovery_requires_boolean_declarations(field,invalid):
    with pytest.raises(SafeStateError):recovery_is_complete(replace(recovery(),**{field:invalid}))
@pytest.mark.parametrize('field',FLAGS)
def test_unreconciled_frontier_stays_incomplete(field):assert recovery_is_complete(replace(recovery(),**{field:False})) is False
@pytest.mark.parametrize('invalid',[None,False,0,'',[],('','id'),(False,),({},)])
def test_recovery_effect_identity_domain(invalid):
    with pytest.raises(SafeStateError):recovery_is_complete(replace(recovery(),unresolved_effect_ids=invalid))
def test_recovery_controls():
    assert recovery_is_complete(recovery()) is True
    assert recovery_is_complete(replace(recovery(),unresolved_effect_ids=('urn:test:effect',))) is False
