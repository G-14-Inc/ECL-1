"""Contract and context regressions; graph tests do not assert signed-bundle validity."""
from pathlib import Path
from dataclasses import replace
import json
import pytest
from ecl_verify.resources import validator_for
from ecl_verify.bundle import analyze_bundle
from ecl_verify.claims import ActionRegisterEntry,PublicClaim,MappingPacket,AssessmentOutcome,ClaimError
R=Path(__file__).resolve().parents[1]
CASES=json.loads((R/'conformance/suites/repair-contracts/manifest.json').read_text())['vectors']
@pytest.mark.parametrize('case',CASES,ids=[x['id'] for x in CASES])
def test_document_contract(case):
 errors=list(validator_for(case['schema']).iter_errors(json.loads((R/case['path']).read_text())))
 assert bool(errors)==(case['expected']=='fail'),[e.message for e in errors]
GRAPHS=json.loads((R/'tests/fixtures/repair-causal-context.json').read_text())
@pytest.mark.parametrize('case',GRAPHS,ids=[x['name'] for x in GRAPHS])
def test_parent_child_context(case):
 result=analyze_bundle(case['records'],check_context=True)
 assert result.status==case['status'],result
 assert set(case['required_findings']) <= {f.rule_id for f in result.findings}
 if case['status'] in ('complete','incomplete'): assert not result.findings

def test_pending_action_requires_capability_inventory():
 entry=ActionRegisterEntry('ecl.action.example.v1','consequential_pending_review','Awaiting classification',('urn:example:resource',),('urn:example:actor',),('example',),'soft',None,())
 with pytest.raises(ClaimError,match='capability'): entry.validate()
 replace(entry,capability_paths=('tool:example:write',)).validate()

@pytest.mark.parametrize('state',['draft','internally_reviewed','independently_reviewed','owner_validated'])
def test_mapping_states_match_published_enum(state):
 packet=MappingPacket('urn:example:mapping','1','Example','2026',{'one':'direct_runtime_support'},{'one':('FR-101',)},{'one':'Organizational obligations remain.'},('Defined boundary',),state,'2026-11-10T00:00:00Z');packet.validate()
 with pytest.raises(ClaimError):replace(packet,validation_state='internally_validated').validate()

def claim(level,status='conditional_conformance'):
 return PublicClaim('urn:example:soi',level,status,'bounded-action-class-mediation','C','1.0',('DCMP-2:2.0',),(),'2026-11-10T00:00:00Z',('Synthetic helper test',))
@pytest.mark.parametrize('level',[1,2,3,4])
def test_conditional_level_helper(level):
 if level in (2,3):claim(level).validate()
 else:
  with pytest.raises(ClaimError,match='conditional'):claim(level).validate()
def test_component_cannot_make_mediation_level_claim():
 with pytest.raises(ClaimError):replace(claim(1,'assessment_only'),boundary_class='component-or-profile-implementation').validate()
def test_assessment_does_not_force_procurement_decision():
 AssessmentOutcome({'FR-001':'pass'},{},'assessment_only','not_evaluated').validate()
