#!/usr/bin/env python3
"""Reproduce public-review binding and safe-state regression fixtures.

All keys are public deterministic test seeds. Existing synthetic ACS examples
are migrated only with --migrate-existing; no historical results are rewritten.
The new suite is separate so its manifest can be reviewed before integration.
"""
from __future__ import annotations
import argparse, base64, copy, hashlib, json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ecl_verify.bindings import acs, aarm, oauth, jcs, jose
from ecl_verify.canonical import canonicalize, object_digest

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'conformance/suites/repair-bindings'
SCHEMA='https://externalcontrollayer.ai/ns/schema/safe-state-profile/1'
INVALID='ecl.error.schema-invalid.v1'
BASIS='ecl.rule.decision-basis-one-way.v1'

def read(path): return json.loads((ROOT/path).read_text())
def encode(value): return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def basis(record, member='response'):
    return next(e['value'] for e in record[member]['extensions'] if e['id']=='ecl.ext.decision-basis.v1')
def migrate_signed(record):
    """Explicitly synthesize the current test request binding; not recovered real evidence."""
    g=record['guardian']; req=record['request']
    # This artificial tool-step envelope carries only the action, so derived_from=[] is accurate.
    params={'tool_name':req['action']['operation'],'arguments':copy.deepcopy(req['action']['parameters'])}
    g['request_params']=params; g['request_digest']=jcs.digest(params)
    g['authenticated_context']={'session_id':record['session_id'],'request_id':g['result']['request_id'],
        'method':record['hook'],'request_digest':jcs.digest(params),'dcmp_request_digest':jcs.digest(req)}
    head=None
    for entry in record.get('chain',[]):
        entry['previous_hash']=head
        if entry['step_id']==g['result']['request_id']: entry['request_hash']=g['request_digest']['value']
        entry['entry_hash']=acs.entry_hash(entry); head=entry['entry_hash']
    if head:
        g['result']['chain_hash']=head
        for ext in record['response']['extensions']:
            if ext['id']==acs.DECISION_EXTENSION:
                ext['value']['chain_hash']=head;ext['value']['request_hash']=g['request_digest']['value']
    return record

def migrate_existing():
    changed=[]
    for path in sorted((ROOT/'conformance/suites').glob('**/acs*.json')):
        if path.parent==OUT: continue
        record=json.loads(path.read_text())
        if record.get('schema_version')!='ecl_acs_exchange_v1': continue
        original=path.read_bytes()
        g=record['guardian']
        # These fixtures deliberately test the absent declaration and remain negative.
        if g.get('status')=='decided' and 'without-derivation' not in path.name:
            names=set()
            for item in record.get('inputs',[]):
                if item.get('guardian') is True and 'derived_from' not in item:
                    item['derived_from']=[]; names.add(item['input'])
            for member in ('response','modification_response'):
                if member not in record: continue
                for ext in record[member].get('extensions',[]):
                    if ext['id']=='ecl.ext.decision-basis.v1':
                        for item in ext['value'].get('inputs',[]):
                            if item['input'] in names and 'derived_from' not in item: item['derived_from']=[]
        if g.get('channel')=='signed':
            had_key='key_id' in g
            old_algorithm=g.get('request_digest',{}).get('algorithm')
            migrate_signed(record)
            if not had_key: g.pop('key_id',None)
            if old_algorithm and old_algorithm!='ecl.digest.sha-256.v1': g['request_digest']['algorithm']=old_algorithm
        new=encode(record)
        # Do not normalize unchanged fixtures merely for indentation or key order.
        if json.loads(original)!=record:
            path.write_bytes(new);changed.append({'path':path.relative_to(ROOT).as_posix(),
              'before_sha256':hashlib.sha256(original).hexdigest(),'after_sha256':hashlib.sha256(new).hexdigest(),
              'reason':'Synthetic ACS fixture migration for explicit derivation or signed request-content binding.'})
    return changed

issuer=Ed25519PrivateKey.from_private_bytes(bytes([44])*32)
sender=Ed25519PrivateKey.from_private_bytes(bytes([45])*32)
kid='urn:example:key:public-review-dpop-issuer'
def jwk(key,kid=None):
    value={'kty':'OKP','crv':'Ed25519','x':jose.b64url(key.public_key().public_bytes_raw())}
    if kid:value['kid']=kid
    return value

def jws(header,claims,key=None):
    body=jose.b64url(canonicalize(header))+'.'+jose.b64url(canonicalize(claims))
    signature=key.sign(body.encode()) if key else b'\x01'+bytes(63)
    return body+'.'+jose.b64url(signature)

def oauth_record(presenter=None, signer=sender, mutate=None, proof_change=None):
    r=read('conformance/suites/oauth-authority/oauth-valid-dpop-es256-accepted.json')
    if mutate:mutate(r)
    _, claims, _, _=jose.decode(r['token']);_, proof,_,_=jose.decode(r['presentation']['dpop_proof'])
    key=presenter or jwk(sender)
    r['issuer_keys']={'keys':[jwk(issuer,kid)]}
    entry=claims['authorization_details'][0]
    entry['use_policy']=r['response']['authorization']['use_policy'];entry['max_uses']=r['response']['authorization']['max_uses']
    if 'decision' in entry:entry['decision']['digest']['value']=object_digest(r['response'])
    claims['cnf']={'jkt':jose.thumbprint(key)}
    r['token']=jws({'alg':'EdDSA','kid':kid,'typ':'at+jwt'},claims,issuer)
    proof['ath']=jose.token_hash(r['token'])
    if proof_change:proof.update(proof_change)
    r['presentation']['dpop_proof']=jws({'alg':'EdDSA','jwk':key,'typ':'dpop+jwt'},proof,signer)
    return r

vectors=[]; files={}
def add(name,value,requirements,primary=None,secondary=(),schema=None,stage='binding',note=''):
    identifier='repair-'+name; path=f'conformance/suites/repair-bindings/{identifier}.json'
    schema=schema or {'ecl_oauth_presentation_v1':oauth.PRESENTATION_SCHEMA,'ecl_acs_exchange_v1':acs.EXCHANGE_SCHEMA,'ecl_aarm_exchange_v1':aarm.EXCHANGE_SCHEMA}[value['schema_version']]
    files[path]=encode(value)
    item={'id':identifier,'path':path,'schema':schema,'stage':stage,'requirement_ids':requirements,
      'expected':'fail' if primary else 'pass','expected_secondary_ids':list(secondary),'covers':[schema+'##root'] if primary in (None,INVALID) else [primary],
      'source':{'kind':'mutation','generator':'scripts/generate_repair_bindings_vectors.py','mutation':note or name.replace('-',' ')}}
    if primary:item.update(expected_primary_id=primary,negates=requirements)
    vectors.append(item)

def generate():
    base=read('conformance/suites/strict-failure/strict-failure-valid-profile.json')
    add('safe-state-all-frontiers',base,['TS1-014'],schema=SCHEMA,stage='safe-state-profile')
    for frontier in base['recovery']['required_frontiers']:
        r=copy.deepcopy(base);r['recovery']['required_frontiers'].remove(frontier)
        add('safe-state-missing-'+frontier.replace('_','-'),r,['TS1-014'],INVALID,schema=SCHEMA,stage='safe-state-profile')
    r=copy.deepcopy(base);r['dependencies'][0].update({'class':'advisory','supplies_required_proof':True,'loss_disposition':'fail_closed'})
    add('safe-state-advisory-required-proof',r,['TS1-031'],INVALID,secondary=['ecl.rule.dependency-classification-consistent.v1'],schema=SCHEMA,stage='safe-state-profile')
    for delivery in ('hot_path','cached','asynchronous'):
        r=copy.deepcopy(base);r['dependencies'][0].update({'class':delivery,'supplies_required_proof':True,'loss_disposition':'fail_closed'})
        add('safe-state-required-'+delivery.replace('_','-'),r,['TS1-031','TS1-032'],schema=SCHEMA,stage='safe-state-profile')

    add('oauth-ordinary-key',oauth_record(),['OA1-004','OA1-007'])
    for n in range(14):
        weak=read(f'conformance/suites/trust-policy/trust-policy-invalid-small-order-{n:02d}.json')['keys'][0]['public_key']
        key={'kty':'OKP','crv':'Ed25519','x':jose.b64url(base64.b64decode(weak))}
        add(f'oauth-small-order-{n:02d}',oauth_record(key,None),['OA1-004'],oauth.PRESENTATION_RULE)
    add('oauth-identity-new-jti',oauth_record({'kty':'OKP','crv':'Ed25519','x':jose.b64url(b'\x01'+bytes(31))},None,proof_change={'jti':'changed-without-a-private-key'}),['OA1-004'],oauth.PRESENTATION_RULE)
    add('oauth-ordinary-key-constant-signature',oauth_record(jwk(sender),None),['OA1-004'],oauth.PRESENTATION_RULE)
    r=oauth_record();a,b,c=r['token'].split('.');sig=bytearray(jose.b64url_decode(c));sig[0]^=1;r['token']=a+'.'+b+'.'+jose.b64url(bytes(sig))
    add('oauth-corrupt-issuer-signature',r,['OA1-007'],oauth.SIGNATURE_RULE,[oauth.PRESENTATION_RULE])
    for class_ in ('actor_supplied','judgment'):
        def mutation(r):
            item=basis(r)['inputs'][0];item['class']=class_;item['effect']='supports'
        add('oauth-'+class_.replace('_','-')+'-supports',oauth_record(mutate=mutation),['OA1-008','DCMP2-053'],BASIS)
    def no_basis(r):r['response']['extensions']=[e for e in r['response']['extensions'] if e['id']!='ecl.ext.decision-basis.v1']
    add('oauth-missing-basis',oauth_record(mutate=no_basis),['OA1-008','DCMP2-053'],BASIS)
    def critical(r):r['response']['extensions'].append({'id':'urn:example:unknown:critical','version':1,'critical':True,'value':{}})
    add('oauth-unknown-critical',oauth_record(mutate=critical),['OA1-008','XR1-006'],'ecl.rule.unknown-critical-extension-rejected.v1')
    def critical_request(r):
        r['request']['extensions'].append({'id':'urn:example:unknown:critical','version':1,'critical':True,'value':{}})
        r['response']['workflow']['causal_predecessors'][0]['digest']['value']=object_digest(r['request'])
    add('oauth-request-unknown-critical',oauth_record(mutate=critical_request),['OA1-008','XR1-006'],'ecl.rule.unknown-critical-extension-rejected.v1')
    # Same proof key, method, htu and jti as an earlier, different single-use authorization.
    # Cache retention is independent of the current authorization use count.
    def single_use_window(r):
        r['request']['authority_request']['use_policy']='single_use';r['response']['authorization'].update(use_policy='single_use',max_uses=1)
        r['response']['workflow']['causal_predecessors'][0]['digest']['value']=object_digest(r['request'])
        r['dpop_proof_window_seconds']=1
    r=oauth_record(mutate=single_use_window);proof=jose.decode(r['presentation']['dpop_proof'])[1]
    for name,at,count,seen,expected in [
      ('future-iat-first-use','2026-09-30T09:00:01Z',1,[],None),
      ('future-iat-retained','2026-09-30T09:00:02.500000Z',1,[proof['jti']],oauth.PRESENTATION_RULE),
      ('inclusive-endpoint-retained','2026-09-30T09:00:03Z',1,[proof['jti']],oauth.PRESENTATION_RULE),
      ('inclusive-endpoint-first-use','2026-09-30T09:00:03Z',1,[],None),
      ('after-endpoint','2026-09-30T09:00:03.000000001Z',1,[],oauth.PRESENTATION_RULE)]:
        v=copy.deepcopy(r);v['presentation'].update(presented_at=at,use_count=count,seen_dpop_jti=seen)
        add('oauth-'+name,v,['OA1-004','OA1-005'],expected,note='Single-use DPoP timing/replay case: '+name+'. Any seen jti comes from the distinct prior authorization in conformance/suites/single-use-policy/single-use-dpop-other-authorization-cache-control.json, under the same proof key, method and htu; the current authorization use_count is 1.')
    v=copy.deepcopy(r);v['presentation'].update(presented_at='2026-09-30T09:00:03Z',use_count=1,seen_dpop_jti=[proof['jti']]);v['result']={'accepted':False,'error':'ecl.error.replay.v1'}
    add('oauth-inclusive-endpoint-replay-refused',v,['OA1-004','OA1-011'],note='Correct replay refusal at the inclusive proof-cache endpoint. The seen jti belongs to the distinct prior authorization in conformance/suites/single-use-policy/single-use-dpop-other-authorization-cache-control.json, under the same proof key, method and htu; the current authorization use_count is 1.')
    r=read('conformance/suites/acs-binding/acs-valid-signed-guardian-names-key-and-request.json');migrate_signed(r)
    add('acs-signed-bound',r,['AC1-004','AC1-008'])
    for name,field,value in [('session','session_id','another-session'),('step','request_id','another-step'),('method','method','steps/memoryStore')]:
        v=copy.deepcopy(r);v['guardian']['authenticated_context'][field]=value
        add('acs-signed-wrong-'+name,v,['AC1-004'],acs.RECORD_RULE)
    for field in ('request_digest','dcmp_request_digest'):
        v=copy.deepcopy(r);v['guardian']['authenticated_context'][field]['value']='00'*32
        add('acs-signed-wrong-'+field.replace('_','-'),v,['AC1-004'],acs.RECORD_RULE)
    v=copy.deepcopy(r);v['guardian']['request_params']['arguments']['record_id']='substituted'
    add('acs-signed-substituted-params',v,['AC1-004'],acs.RECORD_RULE)
    v=copy.deepcopy(r);v['guardian']['request_params']={'params':v['guardian']['request_params']}
    add('acs-signed-envelope-domain',v,['AC1-004'],acs.RECORD_RULE)
    v=copy.deepcopy(r);v['chain'][-1].pop('request_hash');v['chain'][-1]['entry_hash']=acs.entry_hash(v['chain'][-1]);v['guardian']['result']['chain_hash']=v['chain'][-1]['entry_hash']
    for e in v['response']['extensions']:
        if e['id']==acs.DECISION_EXTENSION:e['value']['chain_hash']=v['chain'][-1]['entry_hash'];e['value'].pop('request_hash',None)
    add('acs-signed-no-chain-request-hash',v,['AC1-004','AC1-008'],acs.RECORD_RULE)
    v=copy.deepcopy(r);v['guardian'].pop('authenticated_context')
    add('acs-signed-no-context',v,['AC1-004'],INVALID)
    for class_ in ('verifiable','actor_supplied','judgment'):
        v=copy.deepcopy(r);item=next(i for i in v['inputs'] if i.get('guardian'));item['class']=class_;item.pop('derived_from')
        for i in basis(v)['inputs']:
            if i['input']==item['input']:i['class']=class_;i.pop('derived_from')
        add('acs-missing-derivation-'+class_.replace('_','-'),v,['AC1-004'],acs.JUDGMENT_RULE)
    r=read('conformance/suites/acs-binding/acs-valid-deterministic-guardian-over-session-context.json')
    add('acs-context-derivation-control',r,['AC1-004'])
    for name,missing,class_ in [('missing-actor',True,'actor_supplied'),('missing-judgment',True,'judgment'),('wrong-judgment',False,'judgment')]:
        v=copy.deepcopy(r);item=next(i for i in v['inputs'] if i.get('guardian'));item['class']=class_
        if missing:item.pop('derived_from')
        for i in basis(v)['inputs']:
            if i['input']==item['input']:
                i['class']=class_
                if missing:i.pop('derived_from')
        add('acs-context-'+name,v,['AC1-004'],acs.JUDGMENT_RULE)
    r=read('conformance/suites/aarm-binding/aarm-valid-allow-released.json')
    add('aarm-terminal-control',r,['AB1-007','AB1-009'])
    v=copy.deepcopy(r);v['terminal']['event_type']='execution_released';v['terminal']['event']['state']='released';v['terminal']['event']['release_guard_ms']=250
    add('aarm-release-in-terminal-slot',v,['AB1-007','AB1-009'],INVALID)
    v=copy.deepcopy(r);v['terminal']['event']['state']='released'
    add('aarm-nonterminal-state',v,['AB1-007','AB1-009'],INVALID)
    files['conformance/suites/repair-bindings/manifest.json']=encode({'schema_version':'ecl_conformance_vector_manifest_v3','candidate_version':'1.0','suite':'ecl-1-public-review-repair-bindings','vectors':vectors,'schema_shadowed_rules':[{'rule':'ecl.rule.dependency-classification-consistent.v1','vector':'repair-safe-state-advisory-required-proof','justification':'The safe-state schema conditional rejects every advisory dependency that supplies required proof, so this predicate is always secondary to schema invalidity in the complete stage. The direct semantic API still reports it; the conditional has separate attributed positive and negative schema witnesses.'}]})

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--check',action='store_true');ap.add_argument('--migrate-existing',action='store_true');args=ap.parse_args()
    if args.check and args.migrate_existing:ap.error('check and migration are separate operations')
    migrated=migrate_existing() if args.migrate_existing else []
    generate();differences=[]
    for relative,data in files.items():
        path=ROOT/relative
        if args.check:
            if not path.exists() or path.read_bytes()!=data:differences.append(relative)
        else:path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    print(json.dumps({'vectors':len(vectors),'differences':differences,'migrated':migrated},indent=2))
    if differences:raise SystemExit(1)
