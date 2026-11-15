"""Deterministic public-review contract and causal-context regression fixtures."""
from pathlib import Path
import copy,json,hashlib,argparse
parser=argparse.ArgumentParser();parser.add_argument("--check",action="store_true");CHECK=parser.parse_args().check
ROOT=Path(__file__).resolve().parents[1]
J=lambda p:json.loads((ROOT/p).read_text())
def save(p,v):
 dest=ROOT/p;raw=(json.dumps(v,indent=2,ensure_ascii=False)+'\n').encode()
 if CHECK:
  if not dest.exists() or dest.read_bytes()!=raw:raise RuntimeError('stale generated fixture: '+p)
 else:dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
suite='conformance/suites/repair-contracts';vectors=[]
def doc(name,value,schema,reqs,failed=False):
 p=suite+'/'+name+'.json';save(p,value);v={'id':name,'path':p,'stage':'document','schema':schema,'expected':'fail' if failed else 'pass','expected_primary_id':'ecl.error.schema-invalid.v1' if failed else None,'expected_secondary_ids':[],'requirement_ids':reqs,'covers':[],'source':{'kind':'authored','generator':'scripts/generate_repair_contract_vectors.py','mutation':'Synthetic contract-shape regression; no actual deployment or assessment claim.'}}
 if failed:v['negates']=reqs
 else:v.pop('expected_primary_id')
 vectors.append(v)
ref={'uri':'urn:example:component:artifact','version':'0.1-review','digest':{'algorithm':'ecl.digest.sha-256.v1','value':'ab'*32}}
component={'schema_version':'ecl_component_implementation_report_v1','report_id':'urn:example:report:component','component':{'name':'Example offline verifier','version':'0.1-review','artifact':ref},'version_set':{'core_version':'1.0','profile_versions':['TRUST-POLICY-1:1.0']},'capabilities':['envelope verification'],'applicable_requirements':[{'requirement_id':'IE1-040','applicability':'Envelope verification is implemented.','result':'pass','evidence_refs':[ref['uri']]}],'evidence':[ref],'limitations':['Synthetic document-shape example. No deployment has been assessed.']}
uri='https://externalcontrollayer.ai/ns/schema/component-implementation-report/1'
doc('component-valid-scoped-report',component,uri,['ECL1N-0009'])
for key,value in [('level','L1'),('status','full_conformance')]:
 v=copy.deepcopy(component);v[key]=value;doc('component-invalid-'+key+'-claim',v,uri,['ECL1N-0009'],True)
v=copy.deepcopy(component);v['applicable_requirements'][0]['evidence_refs']=[];doc('component-invalid-pass-without-evidence',v,uri,['ECL1N-0009'],True)
v=copy.deepcopy(component);v['applicable_requirements'][0]['result']='not_assessed';v['applicable_requirements'][0]['evidence_refs']=[];doc('component-valid-unassessed-requirement',v,uri,['ECL1N-0009'])
v=copy.deepcopy(component);v['applicable_requirements'][0]['result']='unknown';doc('component-invalid-result-enum',v,uri,['ECL1N-0009'],True)
# Exact schema-unit claims are checked by the recovered denominator attribution tool.
component_units=[uri+'##root',uri+'#/properties/applicable_requirements/items/properties/result/enum#enum',uri+'#/properties/applicable_requirements/items/allOf/0/if#if[0]',uri+'#/properties/applicable_requirements/items/allOf/0/if/properties/result/enum#enum']
for vector in vectors:
 if vector['id']=='component-valid-scoped-report':vector['covers']=component_units
 elif vector['id']=='component-invalid-pass-without-evidence':vector['covers']=[component_units[0],*component_units[2:]]
 elif vector['id']=='component-invalid-result-enum':vector['covers']=component_units[:2]
base=J('conformance/suites/document-coverage/claim-valid-published-example.json');schema='https://externalcontrollayer.ai/ns/schema/conformance-claim/1'
v=copy.deepcopy(base);v['boundary_class']='component-or-profile-implementation';doc('claim-invalid-component-level',v,schema,['ECL1N-0073'],True)
v=J('conformance/suites/document-coverage/claim-valid-conditional-l3-class-c.json');v['level']=1;doc('claim-invalid-conditional-l1',v,schema,['ECL1N-0077'],True)
save(suite+'/manifest.json',{'candidate_version':'1.0','schema_version':'ecl_conformance_vector_manifest_v3','suite':'repair-contracts','vectors':vectors})
# Low-level causal graph fixtures use the same context option as signed bundle analysis.
template=J('conformance/vectors/bundles/valid-cross-workflow-sequence.json')['records'][0]
from ecl_verify.canonical import object_digest
def record(n,w,seq,pre=(),parent=None):
 r=copy.deepcopy(template);r['object_id']='urn:example:repair:record:'+n;r['workflow']={'workflow_id':'urn:example:repair:wf:'+w,'root_trace_id':'urn:example:repair:trace:join','attempt':1,'sequence':seq,'causal_predecessors':[{'id':p['object_id'],'digest':{'algorithm':'ecl.digest.sha-256.v1','value':object_digest(p)},'relation':'ecl.relation.follows.v1'} for p in pre]}
 if parent:r['workflow']['parent_workflow_id']='urn:example:repair:wf:'+parent
 r['event']['evidence_boundary']='Synthetic graph-context fixture; no actual execution or delegation claim.'
 return r
start=record('start','parent',1);a=record('a','a',1,[start],'parent');b=record('b','b',1,[start],'parent');join=record('join','parent',2,[a,b]);same=record('same','parent',2,[start]);alien=record('alien','alien',1,[start]);sibling=record('sibling','b',2,[a],'parent');badroot=copy.deepcopy(join);badroot['workflow']['root_trace_id']='urn:example:other:trace';back=record('back','parent',1,[same]);badparent=copy.deepcopy(a);badparent['workflow']['parent_workflow_id']='urn:example:other:parent'
graphs=[('parent-to-children',[start,a,b],'complete',[]),('children-to-parent-join',[start,a,b,join],'complete',[]),('same-workflow',[start,same],'complete',[]),('missing-child',[start,a,join],'incomplete',[]),('unrelated',[start,alien],'indeterminate',['ecl.rule.bundle-causal-context-consistent.v1']),('sibling-edge',[start,a,sibling],'indeterminate',['ecl.rule.bundle-causal-context-consistent.v1']),('wrong-root',[start,a,b,badroot],'indeterminate',['ecl.rule.bundle-causal-context-consistent.v1']),('backward-sequence',[start,same,back],'indeterminate',['ecl.rule.bundle-causal-sequence-monotonic.v1']),('wrong-parent',[start,badparent],'indeterminate',['ecl.rule.bundle-causal-context-consistent.v1'])]
save('tests/fixtures/repair-causal-context.json',[{'name':n,'records':rs,'status':status,'required_findings':codes} for n,rs,status,codes in graphs])
