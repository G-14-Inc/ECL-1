from pathlib import Path
import base64,copy,hashlib,json,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
# Reproducible execution-evidence cases. Robert F. Tilley Jr.; G-14, Inc.
import argparse
parser=argparse.ArgumentParser(description="Reproduce signed execution evidence and report-scope regression cases.")
parser.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[1])
parser.add_argument("--check",action="store_true")
args=parser.parse_args();P=args.root.resolve();O=P/'tests/fixtures/execution-evidence-consistency'
if not args.check:O.mkdir(parents=True,exist_ok=True)
def emit(name,value):
    data=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode();path=O/name
    if args.check:
        if path.read_bytes()!=data:raise ValueError('stale execution evidence case: '+name)
    else:path.write_bytes(data)
sys.path.insert(0,str(P/'packages/ecl-verify/src'))
from ecl_verify.canonical import canonicalize,object_digest
from ecl_verify.integrity import signing_input
suite=P/'conformance/suites/evidence-bundle';base=json.loads((suite/'bundle-valid-succeeded.json').read_text());original=[json.loads(base64.b64decode(e['payload'])) for e in base['envelopes']]
policy=json.loads((suite/'trust-policy.json').read_text());emit('policy.json',policy)
keys={'urn:example:key:'+name:Ed25519PrivateKey.from_private_bytes(bytes(range(i,i+32))) for name,i in [('bundle-agent',0),('bundle-decision',1),('bundle-ep',2)]}
for e in policy['keys']:
    if e['key_id'] in keys:assert base64.b64encode(keys[e['key_id']].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()==e['public_key']
def cp(v):return copy.deepcopy(v)
def identity(p):return p.get('message_id',p.get('object_id'))
def digest(p):return {'algorithm':'ecl.digest.sha-256.v1','value':object_digest(p)}
def event(kind,state):
    p=cp(original[3]);p['object_id']='urn:example:execution-binding:'+kind;p['event_type']=kind;p['event']['state']=state;p['event'].pop('authority',None);p['event'].pop('release_guard_ms',None);return p
def setup(outcome='admit',prepared=False,running=False,consume=True,release=True,terminal='cancelled',late=False):
    req,resp=cp(original[:2])
    if outcome is None:resp=None
    elif outcome!='admit':
        resp['outcome']=outcome;resp.pop('authorization',None);resp['reasons']=[{'code':'ecl.reason.native-policy-disposition.v1','detail':'the policy did not permit it','retryable':False}]
        if outcome=='challenge':resp['challenge_id']='urn:example:challenge:approval'
    rows=[req]+([resp] if resp else [])
    if prepared:rows.append(event('release_prepared','prepared'))
    if consume:rows.append(cp(original[2]))
    if release:rows.append(cp(original[3]))
    if running:rows.append(event('execution_observed','running'))
    if terminal:
        t=cp(original[4]);t['event']['state']=terminal;t['event'].pop('authority',None);t['event']['side_effects']=[]
        if terminal in ['cancelled','timed_out','unknown']:t['event']['residual_state']='attempt stopped; no known residual effect'
        if terminal=='denied' and outcome in [None,'admit']:t['extensions']=[{'id':'ecl.ext.outcome-reason.v1','version':1,'critical':False,'value':{'code':'ecl.error.safe-state-required.v1'}}]
        rows.append(t)
    for i,p in enumerate(rows):
        p['workflow']['sequence']=i+1
        if 'event' in p:
            p['observed_at']='2026-09-29T20:00:00.000000Z' if late and p['event_type'] in ['execution_observed','execution_terminal'] else f'2026-09-29T10:00:00.{(i+1)*100000:06d}Z'
            if p['event']['kind']=='execution':
                if resp:p['event']['decision']={'uri':identity(resp),'digest':digest(resp)}
                else:p['event'].pop('decision',None)
        if i==0:p['workflow']['causal_predecessors']=[]
        else:
            prev=resp if p.get('event_type')=='authority_consumed' else rows[i-1]
            p['workflow']['causal_predecessors']=[{'id':identity(prev),'digest':digest(prev),'relation':'ecl.relation.responds-to.v1' if p.get('message_type')=='decision_response' else 'ecl.relation.follows.v1'}]
    return rows
def sign(rows):
    by_id={identity(p):p for p in rows}
    for _ in range(len(rows)+1):
        changed=False
        for p in rows:
            for e in p['workflow']['causal_predecessors']:
                if e['id'] in by_id:
                    new=digest(by_id[e['id']]);changed|=e['digest']!=new;e['digest']=new
            if 'event' in p and 'decision' in p['event']:
                ref=p['event']['decision'];new=digest(by_id[ref['uri']]);changed|=ref['digest']!=new;ref['digest']=new
        if not changed:break
    else:raise AssertionError('DAG rebinding did not converge')
    envs=[]
    for p in rows:
        source=0 if p.get('message_type')=='decision_request' else 1 if p.get('message_type')=='decision_response' else 3
        e=cp(base['envelopes'][source]);raw=canonicalize(p);e['payload']=base64.b64encode(raw).decode();e['payload_digest']['value']=hashlib.sha256(raw).hexdigest()
        for s in e['signatures']:s['signature']=base64.b64encode(keys[s['key_id']].sign(signing_input(e['payload_type'],raw))).decode()
        envs.append(e)
    return {'schema_version':base['schema_version'],'envelopes':envs}
cases=[]
def add(name,rows,note):
    b=sign(rows);emit(name+'.json',b)
    req=rows[0];resp=next((p for p in rows if p.get('message_type')=='decision_response'),None)
    events=[p for p in rows if p.get('event_type') in ['release_prepared','execution_observed']]
    invalid=(name.startswith(('running-no-','running-with-','running-missing-')) or '-foreign-' in name)
    incomplete=name in ['control-running-open-after-release','control-running-own-unresolved-predecessor','prepared-with-hold-response','prepared-with-challenge-response']
    verdict='invalid' if invalid else 'incomplete' if incomplete else 'verified'
    direct={e['event_type']: ('ecl.error.decision-binding-invalid.v1' if (e['event_type']+'-foreign-' in name or (e['event_type']=='execution_observed' and name.startswith('running-with-'))) else None) for e in events}
    cases.append({'id':name,'bundle':name+'.json','policy':'policy.json','note':note,'verdict':verdict,'primary':'ecl.error.decision-binding-invalid.v1' if invalid else 'ecl.error.causal-closure-incomplete.v1' if incomplete else None,'direct':direct})
add('control-running-after-expiry',setup(prepared=True,running=True,late=True),'Release occurs inside the authorization window; running/terminal later than expiry is allowed.')
for state in ['cancelled','timed_out']:
    add('running-no-release-or-consumption-'+state,setup(running=True,consume=False,release=False,terminal=state,late=True),'Running proves post-release execution although this terminal alone does not.')
for mode in ['deny',None]:
    label=mode or 'absent'
    add('running-with-'+label+'-response',setup(mode,running=True,consume=False,release=False,terminal=None),'Open attempt with running state but no admit.')
    add('prepared-with-'+label+'-response',setup(mode,prepared=True,consume=False,release=False,terminal='denied'),'Prepared before denied terminal; test declared generic versus MCP-specific obligation.')
add('control-denied-without-preparation',setup('deny',consume=False,release=False,terminal='denied'),'Valid non-release denial control.')
add('control-prepared-then-denied-at-enforcement',setup('admit',prepared=True,consume=False,release=False,terminal='denied'),'Post-admit/pre-release enforcement refusal remains valid.')
for kind in ['release_prepared','execution_observed']:
    for member,value in [('operation','records.delete'),('parameters_digest',{'algorithm':'ecl.digest.sha-256.v1','value':'44'*32}),('target',{'uri':'urn:example:foreign-target'})]:
        rows=setup(prepared=True,running=True);e=next(p for p in rows if p.get('event_type')==kind);e['event'][member]=value
        add(kind+'-foreign-'+member,rows,'One repeated action field differs from the request, with otherwise valid signed release evidence.')
    rows=setup(prepared=True,running=True);e=next(p for p in rows if p.get('event_type')==kind)
    for member in ['operation','parameters_digest','target']:e['event'][member]=cp(rows[0]['action'][member])
    add(kind+'-matching-repeats-control',rows,'All optional repeated action fields equal the request.')
add('control-running-open-after-release',setup(running=True,terminal=None),'Open attempt has bound consumption and release; incomplete only because terminal is absent.')
add('running-no-consumption',setup(running=True,consume=False),'Recorded release without consumption already has an independent refusal.')
add('running-no-release',setup(running=True,release=False),'Bound consumption alone cannot establish release.')
add('control-cancelled-before-release',setup(prepared=True,consume=False,release=False),'Cancelled without running or release can describe pre-release abort.')
for mode in ['hold','challenge']:
    add('running-with-'+mode+'-response',setup(mode,running=True,consume=False,release=False,terminal=None),'A non-admit cannot authorize an already-running attempt.')
    add('prepared-with-'+mode+'-response',setup(mode,prepared=True,consume=False,release=False,terminal=None),'Generic preparation versus an MCP-specific post-admit preparation rule.')
rows=setup(running=True,consume=False,release=False)
rows[2]['workflow']['causal_predecessors'].append({'id':'urn:example:unheld-release','digest':{'algorithm':'ecl.digest.sha-256.v1','value':'55'*32},'relation':'ecl.relation.follows.v1'})
add('control-running-own-unresolved-predecessor',rows,'The attempt itself names missing evidence, so its required release may be unheld; report remains incomplete.')
rows=setup(running=True,consume=False,release=False)
other=cp(original[0]);other['message_id']='urn:example:other-request';other['action']['action_id']='urn:example:other-action';other['workflow']['workflow_id']='urn:example:other-workflow';other['workflow']['root_trace_id']='urn:example:other-trace';other['workflow']['sequence']=1;other['workflow']['causal_predecessors']=[{'id':'urn:example:unheld-other','digest':{'algorithm':'ecl.digest.sha-256.v1','value':'66'*32},'relation':'ecl.relation.follows.v1'}];rows.append(other)
add('running-missing-release-unrelated-incomplete-attempt',rows,'An unrelated missing predecessor cannot waive missing release evidence for this closed attempt.')
for kind in ['release_prepared','execution_observed']:
    rows=setup(prepared=True,running=True);e=next(p for p in rows if p.get('event_type')==kind);e['event']['target']=cp(rows[0]['action']['target']);e['event']['target']['version']='after';e['event']['target']['digest']={'algorithm':'ecl.digest.sha-256.v1','value':'77'*32}
    add(kind+'-target-metadata-control',rows,'Only repeated target URI binds; target version and digest can change with effect.')
# A non-admitting response can close generic preparation without changing its
# already signed prefix; it never authorizes release or reuse of the attempt.
def prepared_completion(name,outcome,state,primary=None,mutation=None):
    rows=setup(outcome,prepared=True,consume=False,release=False,terminal=state)
    if mutation=='attempt':rows[-1]['event']['attempt_id']='urn:example:attempt:other'
    elif mutation=='after-terminal':
        again=cp(rows[2]);again['object_id']='urn:example:prepared-completion:prepared-again'
        again['workflow']['sequence']=5;again['observed_at']='2026-09-29T10:00:00.500000Z'
        again['workflow']['causal_predecessors']=[{'id':identity(rows[-1]),'digest':digest(rows[-1]),'relation':'ecl.relation.follows.v1'}]
        rows.append(again)
    bundle=sign(rows)
    prefix=json.loads((O/('prepared-with-'+outcome+'-response.json')).read_text())
    if bundle['envelopes'][:len(prefix['envelopes'])]!=prefix['envelopes']:
        raise AssertionError('completion changed an existing signed prefix')
    emit(name+'.json',bundle)
    cases.append({'id':name,'bundle':name+'.json','policy':'policy.json',
                  'note':'Appends to the unchanged generic prepared-'+outcome+' prefix; terminal binding, attempt identity and terminal finality remain enforced.',
                  'verdict':'invalid' if primary else 'verified','primary':primary,
                  'direct':{'release_prepared':None}})
prepared_completion('control-prepared-then-challenged','challenge','challenged')
prepared_completion('control-prepared-then-held','hold','held')
prepared_completion('prepared-challenge-wrong-held','challenge','held','ecl.error.decision-binding-invalid.v1')
prepared_completion('prepared-hold-wrong-challenged','hold','challenged','ecl.error.decision-binding-invalid.v1')
prepared_completion('prepared-challenge-changes-attempt','challenge','challenged','ecl.error.decision-binding-invalid.v1','attempt')
prepared_completion('prepared-after-challenged-terminal','challenge','challenged','ecl.rule.execution-state-transition-valid.v1','after-terminal')
scope_cases=[
    {'id':'control','remove':[]},
    {'id':'signer-historical-invalid','remove':['envelope-signatures','trusted-time']},
    {'id':'time-authority-historical-invalid','remove':['trusted-time']},
    {'id':'missing-trusted-time','remove':['trusted-time']},
    {'id':'envelope-historical-invalid','remove':['envelope-signatures','trusted-time']},
    {'id':'current-signer-invalid','remove':['current-trust']},
    {'id':'missing-signer-dependency','remove':['envelope-signatures']},
    {'id':'invalid-verdict','remove':'all'},
]
sources=['conformance/suites/evidence-bundle/'+name for name in ['bundle-valid-succeeded.json','trust-policy.json','bundle-valid-trusted-time.json','trust-policy-time-authority.json']]
manifest={'now':'2026-09-29T21:00:00Z','cases':cases,'reconstructed_scopes':scope_cases,'source_sha256':{name:hashlib.sha256((P/name).read_bytes()).hexdigest() for name in sources}}
emit('manifest.json',manifest)
print(len(cases),'signed cases; deterministic fixture keys verified against retained public policy')
