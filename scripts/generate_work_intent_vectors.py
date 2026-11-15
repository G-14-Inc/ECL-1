"""Reproduce safe-state declaration and work-intent contract controls."""
from __future__ import annotations
import argparse,copy,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'packages/ecl-verify/src'))
from coverage_denominator import attribution_for,schema_units
NS='https://externalcontrollayer.ai/ns/schema/'
ERROR='ecl.error.schema-invalid.v1'
ACTION='ecl.rule.action-class-policy-unambiguous.v1'
CONTEXT='ecl.rule.work-intent-context-consistent.v1'
SELF='ecl.rule.message-cannot-cause-itself.v1'
EXPIRY='ecl.rule.expiry-after-issue.v1'
GENERATOR='scripts/generate_work_intent_vectors.py'
SUITES=('safe-state-declaration-contract','work-intent-contract')
def encoded(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def build(root):
    def read(path):return json.loads((root/path).read_bytes())
    sp='conformance/suites/strict-failure/strict-failure-valid-unclaimed-advisory-fail-open.json';wp='conformance/suites/document-coverage/work-intent-valid.json'
    safe,intent=map(read,(sp,wp));outputs={};rows={name:[] for name in SUITES}
    def add(name,value,kind='intent',expected=(),requirements=(),covers=()):
        suite=SUITES[int(kind=='intent')];identifier=suite+'-'+name;path=Path('conformance/suites')/suite/(identifier+'.json');outputs[path]=encoded(value)
        row=dict(id=identifier,path=path.as_posix(),stage='document' if kind=='intent' else 'safe-state-profile',schema=NS+('work-intent' if kind=='intent' else 'safe-state-profile')+'/1',source=dict(kind='mutation',generator=GENERATOR,base_vector=wp if kind=='intent' else sp,mutation=name),expected='fail' if expected else 'pass',expected_secondary_ids=list(expected[1:]),requirement_ids=sorted(requirements),covers=list(covers))
        if expected:row.update(expected_primary_id=expected[0],negates=sorted(requirements))
        rows[suite].append(row)
    add('single-class-control',safe,'safe',requirements=['TS1-016'],covers=[ACTION])
    for label,same in [('identical',True),('conflicting',False)]:
        for reverse in (False,True):
            x=copy.deepcopy(safe);y=copy.deepcopy(x['action_classes'][0]);
            if not same:y['timeout_disposition']='emergency_halt'
            x['action_classes'].append(y)
            if reverse:x['action_classes'].reverse()
            add('duplicate-'+label+('-reversed' if reverse else ''),x,'safe',([ERROR,ACTION] if same else [ACTION]),['TS1-016'],[] if same else [ACTION])
    x=copy.deepcopy(safe);y=copy.deepcopy(x['action_classes'][0]);y['action_class']='ecl.action.test-distinct.v1';x['action_classes'].append(y);add('distinct-classes-control',x,'safe',requirements=['TS1-016'],covers=[ACTION])
    x=copy.deepcopy(safe);x['dependencies'][1]['id']=x['dependencies'][0]['id'];add('duplicate-dependency',x,'safe',['ecl.rule.dependency-classification-consistent.v1'],['TS1-033'])
    x=copy.deepcopy(safe);x['action_classes'][0]['timeout_disposition']='restricted';x['action_classes'][0]['restricted_operations']=[];add('empty-restricted-set-control',x,'safe',requirements=['TS1-020'])
    x=copy.deepcopy(safe);ac=x['action_classes'][0];ac['dependency_disposition']='fail_open';ac['fail_open_prohibited_conditions']=[];ac['fail_open_authorization']={'owner':'urn:example:owner:ops','rationale':'Covered diagnostic outage only; required proof remains valid.','expires_at':'2026-12-31T00:00:00Z','evidence_profile':'ecl.profile.audit.v1','covered_advisory_dependencies':[x['dependencies'][1]['id']]};add('empty-additional-prohibitions-control',x,'safe',requirements=['TS1-016','TS1-018','TS1-033'])
    add('root-control',intent,requirements=['DW1-002','DW1-006','DW1-015'],covers=[CONTEXT,SELF,EXPIRY])
    def causal(x,ident='urn:example:causal:delegation'):
        x['workflow']['causal_predecessors']=[{'id':ident,'digest':{'algorithm':'ecl.digest.sha-256.v1','value':'0'*64},'relation':'ecl.relation.follows.v1'}]
    x=copy.deepcopy(intent);causal(x,x['intent_id']);add('self-causation',x,expected=[SELF],requirements=['DW1-006'],covers=[SELF])
    for label,issued,expiry in [('equal',intent['issued_at'],intent['issued_at']),('reversed',intent['issued_at'],'2026-07-27T11:00:00Z'),('positive-nanosecond','2026-07-27T12:00:00.000000001Z','2026-07-27T12:00:00.000000002Z'),('reversed-nanosecond','2026-07-27T12:00:00.000000002Z','2026-07-27T12:00:00.000000001Z')]:
        x=copy.deepcopy(intent);x.update(issued_at=issued,expires_at=expiry);add('interval-'+label,x,expected=[] if label=='positive-nanosecond' else [EXPIRY],requirements=['DW1-015'],covers=[EXPIRY])
    for label in ['reference','context','both']:
        for has_cause in [False,True]:
            x=copy.deepcopy(intent)
            if label!='context':x['parent_workflow']={'uri':'urn:example:workflow:parent'}
            if label!='reference':x['workflow']['parent_workflow_id']='urn:example:workflow:parent'
            if has_cause:causal(x)
            # A secondary diagnostic is retained, but only a decisive rule witnesses
            # negative rule coverage. Schema units below attribute the no-cause cases.
            add('parent-'+label+('-control' if has_cause else '-no-cause'),x,expected=[] if has_cause else [ERROR,CONTEXT],requirements=['DW1-002'],covers=[CONTEXT] if has_cause else [])
        x=copy.deepcopy(intent);causal(x)
        if label!='context':x['parent_workflow']={'uri':x['workflow']['workflow_id']}
        if label!='reference':x['workflow']['parent_workflow_id']=x['workflow']['workflow_id']
        add('parent-'+label+'-self',x,expected=[CONTEXT],requirements=['DW1-002'],covers=[CONTEXT])
    x=copy.deepcopy(intent);causal(x);x['parent_workflow']={'uri':'urn:example:workflow:parent'};x['workflow']['parent_workflow_id']='urn:example:workflow:other';add('parent-disagreement',x,expected=[CONTEXT],requirements=['DW1-002'],covers=[CONTEXT])
    x=copy.deepcopy(x);x['expires_at']=x['issued_at'];causal(x,x['intent_id']);add('independent-rule-findings',x,expected=sorted([CONTEXT,SELF,EXPIRY]),requirements=['DW1-002','DW1-006','DW1-015'])
    x=copy.deepcopy(intent);causal(x);x['parent_workflow']={'uri':'urn:example:workflow:parent','digest':{'algorithm':'ecl.digest.sha-256.v1','value':'1'*64}};add('optional-parent-digest-control',x,requirements=['DW1-002'],covers=[CONTEXT])
    x=copy.deepcopy(intent);x['integrity_policy']={'required':False,'threshold':0,'accepted_suites':['ecl.sig.ed25519.v1'],'eligible_key_ids':[],'required_key_ids':[],'trust_policy':{'id':'urn:example:trust:policy','version':'1','digest':{'algorithm':'ecl.digest.sha-256.v1','value':'2'*64}}};add('optional-integrity-policy-control',x,requirements=['DW1-015'])
    for field,invalid in [('issued_at','2026-02-30T00:00:00Z'),('expires_at',None),('workflow',[]),('parent_workflow',False)]:
        x=copy.deepcopy(intent);x[field]=invalid;add('malformed-'+field.replace('_','-'),x,expected=[ERROR],requirements=['DW1-002','DW1-015'])
    # A carrying protocol never makes another protocol's extension interpretable.
    for name in ['runtime-configuration','control-change','aarm-receipt','decision-basis']:
        for critical in (False,True):
            x=copy.deepcopy(intent);x['extensions']=[{'id':'ecl.ext.'+name+'.v1','version':1,'critical':critical,'value':'malformed'}]
            add('inapplicable-'+name+('-critical' if critical else '-preserved'),x,expected=['ecl.rule.unknown-critical-extension-rejected.v1'] if critical else [],requirements=['XR1-006','XR1-007'])
    # Authored verdicts above; mutated schemas are used only for two-sided attribution.
    units=[u for u in schema_units(NS+'work-intent/1',read('schemas/ecl-work-intent-v1.schema.json')) if u['pointer'].startswith('/allOf/')]
    attr=attribution_for(root)
    for row in rows[SUITES[1]]:
        value=json.loads(outputs[Path(row['path'])]);row['covers']+= [u['id'] for u in units if attr.witnesses(u,row,value)]
    missing=[u['id']+':'+v for u in units for v in ['pass','fail'] if not any(r['expected']==v and u['id'] in r['covers'] for r in rows[SUITES[1]])]
    if missing:raise ValueError('missing schema-unit coverage: '+str(missing))
    for suite,vectors in rows.items():outputs[Path('conformance/suites')/suite/'manifest.json']=encoded(dict(schema_version='ecl_conformance_vector_manifest_v3',candidate_version='1.0',suite='ecl-1-v1.0-'+suite,vectors=sorted(vectors,key=lambda r:r['id'])))
    return outputs,dict(safe_state_vectors=len(rows[SUITES[0]]),work_intent_vectors=len(rows[SUITES[1]]),schema_units=len(units),missing_two_sided_attribution=missing)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--check',action='store_true');a=p.parse_args();out,receipt=build(a.root)
    for path,data in out.items():
        target=a.root/path
        if a.check:
            if not target.is_file() or target.read_bytes()!=data:raise SystemExit('stale work-intent control: '+str(path))
        else:target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    print(json.dumps({**receipt,'check':a.check}))
if __name__=='__main__':main()
