#!/usr/bin/env python3
"""Reconstruct synthetic MCP regression records; never rewrite historical evidence.

Robert F. Tilley Jr.; G-14, Inc. Source templates remain in conformance/suites/mcp-gateway.
These are complete unsigned exchange-record tests, not new observations of old executions.
"""
from __future__ import annotations
import argparse, copy, hashlib, json
from datetime import datetime, timedelta, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DEST=Path('tests/fixtures/mcp-public-review-repairs')
SCHEMA='https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1'
BIND='ecl.ext.mcp-binding.v1'; DISCHARGE='ecl.ext.obligation-discharge.v1'

def digest(x):
    from ecl_verify.canonical import object_digest
    return {"algorithm":"ecl.digest.sha-256.v1","value":object_digest(x)}

def load(name): return json.loads((ROOT/'conformance/suites/mcp-gateway'/f'{name}.json').read_text())
def clone(d): return copy.deepcopy(d)
def stamp(t): return t.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
def parse(t): return datetime.fromisoformat(t.replace('Z','+00:00'))
def complete_synthetic_answer(d):
    """Add the authored answer observation to legacy synthetic controls only.

    The timestamp is the existing release-order control's synthetic observation,
    not a time inferred from a terminal, a return, or a historical execution.
    Existing observations, deliberate one-sided observations, and recovery stay intact.
    """
    values=[e['value'] for e in d.get('terminal',{}).get('extensions',[]) if e.get('id')==BIND]
    if (d.get('forwarded') is not None and d.get('server_response') is not None
            and d.get('recovery') is None and 'forward_completed_at' not in d['forwarded']
            and not any('forward_completed_at' in value for value in values)):
        observed='2026-09-30T09:00:00.380000Z'
        d['forwarded']['forward_completed_at']=observed
        for value in values:value['forward_completed_at']=observed
    return d

def observation(at):
    snapshot={'mode':'urn:example:mode:mcp-repair','scope':'urn:example:server:issues','status':'current'}
    return {'observed_at':at,'control_state':{'status':'current','reference':{'uri':'urn:example:control-snapshot:mcp-public-review-repair','digest':digest(snapshot)},'fresh_until':'2026-09-30T09:05:00.000000Z','halt':False,'quarantine':False,'revoked':False}}
def migrate(d):
    d=clone(d)
    if 'forwarded' in d or 'prepared' in d or 'released' in d:
        d.setdefault('release_guard_milliseconds',250)
        start=parse(d['decision']['response']['issued_at'])
        at=d.get('forwarded',{}).get('forwarded_at',d.get('released',{}).get('observed_at',stamp(start+timedelta(milliseconds=200))))
        initial=stamp(start+timedelta(milliseconds=100))
        if 'forwarded' in d:
            # Build missing events explicitly as new synthetic controls from their bound terminal.
            for name,kind,state,offset in [('prepared','release_prepared','prepared',-20),('released','execution_released','released',0)]:
                if name not in d:
                    e=clone(d['terminal']);e['event_type']=kind;e['observed_at']=stamp(parse(at)+timedelta(milliseconds=offset));e['event']['state']=state
                    e['event'].pop('side_effects',None);e['event'].pop('residual_state',None);e['extensions']=[]
                    if name=='released':e['event']['release_guard_ms']=d['release_guard_milliseconds']
                    e['object_id']='urn:example:synthetic-mcp-repair:'+d['decision_request']['action']['action_id'].split(':')[-1]+':'+name
                    d[name]=e
        if 'prepared' in d and parse(initial)>parse(d['prepared']['observed_at']): initial=stamp(parse(d['prepared']['observed_at'])-timedelta(milliseconds=10))
        d['release_observations']={'initial':observation(initial)}
        if 'released' in d or 'forwarded' in d:d['release_observations']['final']=observation(at)
    return complete_synthetic_answer(d)

def reasons(d,reason):
    ex=d['terminal']['extensions'];ex[:]=[e for e in ex if e['id']!='ecl.ext.outcome-reason.v1']
    ex.append({'id':'ecl.ext.outcome-reason.v1','version':1,'critical':False,'value':{'code':reason}})
def returned(d,cause,code,reason):
    d['returned']={'jsonrpc':'2.0','id':d['call']['id'],'error':{'code':code,'message':cause,'data':{'ecl':{'code':cause,'reason':reason,'request_id':d['decision_request']['message_id']}}}}
def refusal(d,cause,code,reason,consumed=True,keep_release=False):
    d=clone(d)
    for key in ['forwarded','server_response']:d.pop(key,None)
    if not keep_release:d.pop('released',None)
    if not consumed:d.pop('prepared',None);d['release_observations'].pop('final',None)
    e=d['terminal']['event'];e['state']='cancelled' if consumed else 'denied';e['side_effects']=[]
    if consumed:e['residual_state']='The gateway did not write the request to the server.'
    else:e.pop('authority',None);e.pop('residual_state',None)
    for ex in d['terminal']['extensions']:
        if ex['id']==BIND:
            for key in ['response_digest','forward_completed_at','released_after_valid_until']:ex['value'].pop(key,None)
    reasons(d,reason);returned(d,cause,code,reason)
    return d

def build():
    cases=[];outputs={}
    def add(name,d,valid,ids,rule=None):
        path=str(DEST/(name+'.json'));outputs[path]=d
        cases.append({'id':name,'path':path,'valid':valid,'root_ids':ids,'expected_rule':rule})
    base=migrate(load('mcp-valid-forwarded-release-order'));ob=migrate(load('mcp-valid-forwarded-obligations-discharged'))
    add('forward-complete-control',base,True,['ROOT-064','ROOT-079','ROOT-035'])
    add('obligations-complete-control',ob,True,['ROOT-001'])
    for suffix,until,valid in [('at-observation','2026-09-30T09:00:00.300000Z',False),('at-guard','2026-09-30T09:00:00.550000Z',False),('after-guard','2026-09-30T09:00:00.550001Z',True)]:
        d=clone(ob)
        for discharge in [d['obligation_discharge']]+[x['value'] for x in d['released']['extensions'] if x['id']==DISCHARGE]:
            for item in discharge['obligations']:
                if item['type']=='ecl.obligation.approval-record.v1':item['fresh_until']=until
        add('approval-'+suffix,d,valid,['ROOT-001'],'ecl.rule.mcp-obligations-discharged.v1' if not valid else None)
    d=migrate(load('mcp-valid-stale-proof-cancelled'));d['release_observations']['final']=observation('2026-09-30T09:00:05.010000Z');d['terminal']['observed_at']='2026-09-30T09:00:05.020000Z'
    add('stale-proof-explicit-observation',d,True,['ROOT-002'])
    for field in ['data','code']:
        bad=clone(d)
        if field=='data':bad['returned']['error'].pop('data')
        else:bad['returned']['error']['code']=-31001
        add('stale-proof-wrong-'+field,bad,False,['ROOT-002'],'ecl.rule.mcp-refusal-defined.v1')
    bad=clone(d);bad['release_observations'].pop('final');add('delayed-return-does-not-prove-staleness',bad,False,['ROOT-002'],'ecl.rule.mcp-refusal-defined.v1')
    for disposition in ['denied','held','challenged']:
        d=load('mcp-valid-'+disposition+'-refused');add(disposition+'-control',d,True,['ROOT-004'])
        d=clone(d);d.pop('terminal');add(disposition+'-missing-terminal',d,False,['ROOT-004'],'ecl.rule.mcp-result-bound.v1')
    for name in ['prepared','released','release_guard_milliseconds','release_observations']:
        d=clone(base);d.pop(name);add('forward-missing-'+name,d,False,['ROOT-064'],'ecl.error.schema-invalid.v1')
    for name in ['initial','final']:
        d=clone(base);d['release_observations'].pop(name);add('forward-missing-'+name+'-observation',d,False,['ROOT-035'],'ecl.error.schema-invalid.v1')
    for event in ['prepared','released']:
        for field in ['action','decision-digest','authority-digest','workflow','root-trace','attempt','event-type','attempt-id']:
            d=clone(base);e=d[event]
            if field=='action':e['event']['action_id']='urn:example:action:foreign'
            elif field=='decision-digest':e['event']['decision']['digest']['value']='0'*64
            elif field=='authority-digest':e['event']['authority']['digest']['value']='0'*64
            elif field=='workflow':e['workflow']['workflow_id']='urn:example:workflow:foreign'
            elif field=='root-trace':e['workflow']['root_trace_id']='urn:example:trace:foreign'
            elif field=='attempt':e['workflow']['attempt']=2
            elif field=='attempt-id':e['event']['attempt_id']='urn:example:attempt:foreign'
            else:e['event_type']='execution_terminal';e['event']['state']='succeeded';e['event'].pop('release_guard_ms',None)
            add(event+'-wrong-'+field,d,False,['ROOT-079'],'ecl.error.schema-invalid.v1' if field=='event-type' else 'ecl.rule.mcp-forward-requires-admit.v1')
    for consumed in [False,True]:
        for control in ['halt','quarantine','revoked','stale','unavailable']:
            reason='ecl.error.revoked.v1' if control=='revoked' else 'ecl.error.safe-state-required.v1'
            cause='control-blocked' if control in ['halt','quarantine','revoked'] else 'control-state-unusable'
            code=-31012 if cause=='control-blocked' else -31013
            d=refusal(base,cause,code,reason,consumed)
            state=d['release_observations']['final' if consumed else 'initial']['control_state']
            if control in ['stale','unavailable']:
                state['status']=control
                if control=='stale':state['fresh_until']='2026-09-30T09:00:00.400000Z'
                else:state.pop('fresh_until');state.pop('reference')
            else:state[control]=True
            name=('consumed-' if consumed else 'unconsumed-')+control
            add(name+'-refusal',d,True,['ROOT-035'])
            wrong=clone(d);wrong['returned']['error']['code']=-31001;add(name+'-wrong-code',wrong,False,['ROOT-035'],'ecl.rule.mcp-refusal-defined.v1')
            wrong=clone(base);wrong['release_observations']['final' if consumed else 'initial']['control_state']=clone(state)
            add(name+'-forwarded',wrong,False,['ROOT-035'],'ecl.rule.mcp-forward-requires-admit.v1')
    d=refusal(base,'control-blocked',-31012,'ecl.error.safe-state-required.v1',True,True);d['release_observations']['final']=observation('2026-09-30T09:00:00.350000Z');d['release_observations']['final']['control_state']['halt']=True
    add('halt-after-release-before-dispatch',d,True,['ROOT-035'])
    for suffix,until,valid in [('at-guard','2026-09-30T09:00:00.550000Z',False),('after-guard','2026-09-30T09:00:00.550001Z',True)]:
        d=clone(base);d['release_observations']['final']['control_state']['fresh_until']=until;add('control-freshness-'+suffix,d,valid,['ROOT-035'],None if valid else 'ecl.rule.mcp-forward-requires-admit.v1')
    for recovered in [False,True]:
        d=clone(base)
        if recovered:
            d['recovery']={'recovered_at':'2026-09-30T09:01:00.000000Z','classification':'outcome-recorded'};d.pop('returned');d.pop('returned_at')
        prefix='recovered-' if recovered else 'live-'
        add(prefix+'response-control',d,True,['ROOT-088'])
        for field in ['state','response-digest','completion','action']:
            bad=clone(d)
            if field=='state':bad['terminal']['event']['state']='failed'
            elif field=='action':bad['terminal']['event']['action_id']='urn:example:action:foreign'
            else:
                val=next(x['value'] for x in bad['terminal']['extensions'] if x['id']==BIND)
                if field=='response-digest':val['response_digest']['value']='0'*64
                else:val['forward_completed_at']='2026-09-30T09:00:00.390000Z'
            add(prefix+'wrong-'+field,bad,False,['ROOT-088'],'ecl.rule.mcp-result-bound.v1')
        if recovered:
            # The original terminal retains completion; retain that same observation
            # in forwarded even when the server response is unavailable at recovery.
            absent=clone(d);absent.pop('server_response');add('recovered-unavailable-server-response',absent,True,['ROOT-088'])
    d=migrate(load('mcp-valid-obligation-unproven-cancelled'));add('unproven-control',d,True,['ROOT-089'])
    duplicate=clone(d);response=duplicate['decision']['response'];response['obligations'].append(clone(response['obligations'][0]))
    for key in ['prepared','released','terminal']:
        if key in duplicate:duplicate[key]['event']['decision']['digest']=digest(response)
    add('duplicate-obligation-consumed-refusal',duplicate,False,['ROOT-089'],'ecl.rule.mcp-decision-failure-not-forwarded.v1')
    add('duplicate-obligation-refused-before-consumption',load('mcp-valid-duplicated-obligation-refused'),True,['ROOT-089'])
    for method in ['tasks/update','resources/read']:
        d=clone(base);d['call']['method']=method;d['forwarded']['request']['method']=method
        for ex in d['decision_request']['extensions']:
            if ex['id']==BIND:ex['value']['method']=method
        d['decision']['response']['workflow']['causal_predecessors'][0]['digest']=digest(d['decision_request'])
        for key in ['prepared','released','terminal']:d[key]['event']['decision']['digest']=digest(d['decision']['response'])
        add(method.replace('/','-')+'-cannot-forward',d,False,['ROOT-091'])
        d=load('mcp-valid-unmapped-method-refused');d['call']['method']=method;add(method.replace('/','-')+'-refused',d,True,['ROOT-091'])
    d=migrate(load('mcp-valid-forward-failed-unknown'));add('forward-failed-complete-control',d,True,['ROOT-002'])
    wrong=clone(d);wrong['returned']['error'].pop('data');add('forward-failed-missing-error-data',wrong,False,['ROOT-002'],'ecl.rule.mcp-result-bound.v1')
    d=clone(base);d['release_observations']['initial']['observed_at']='2026-09-30T09:00:00.000000Z';add('consumed-before-authority-valid',d,False,['ROOT-035'],'ecl.rule.mcp-forward-requires-admit.v1')
    d=migrate(load('mcp-valid-stale-proof-cancelled'));d['release_observations']['final']=observation('2026-09-30T09:00:05.010000Z');d['terminal']['observed_at']='2026-09-30T09:00:05.020000Z';reasons(d,'ecl.error.expired.v1');add('stale-proof-terminal-wrong-reason',d,False,['ROOT-002'],'ecl.rule.mcp-result-bound.v1')
    d=clone(base);d['prepared']['event']['operation']='issues.delete';add('prepared-wrong-repeated-operation',d,False,['ROOT-079'],'ecl.rule.mcp-forward-requires-admit.v1')
    d=clone(base);d['prepared']['event']['target']={'uri':'urn:example:target:foreign'};add('prepared-wrong-repeated-target',d,False,['ROOT-079'],'ecl.rule.mcp-forward-requires-admit.v1')
    d=refusal(base,'authorization-unusable',-31006,'ecl.error.clock-regressed.v1');d['release_observations']['final']['clock_regressed']=True;add('clock-comparison-explicit-failure',d,True,['ROOT-002','ROOT-035'])
    wrong=clone(d);wrong['release_observations']['final'].pop('clock_regressed');add('clock-failure-must-be-recorded',wrong,False,['ROOT-002'],'ecl.rule.mcp-refusal-defined.v1')
    wrong=clone(base);wrong['release_observations']['final']['clock_regressed']=True;add('clock-failure-cannot-forward',wrong,False,['ROOT-035'],'ecl.rule.mcp-forward-requires-admit.v1')
    wrong=clone(base);wrong['release_observations']['initial']['clock_regressed']=True;add('clock-marker-not-initial',wrong,False,['ROOT-035'],'ecl.error.schema-invalid.v1')
    wrong=clone(base);wrong['obligation_discharge']=clone(ob['obligation_discharge']);wrong['released']['extensions']=[clone(x) for x in ob['released']['extensions'] if x['id']==DISCHARGE];add('unrequested-discharge-cannot-hide',wrong,False,['ROOT-001'],'ecl.rule.mcp-obligations-discharged.v1')
    manifest={'schema':SCHEMA,'authors_and_producers':['Robert F. Tilley Jr.','G-14, Inc.'],'status':'synthetic reconstructed regression controls; no historical observation claim','signed_bundle_scope':False,'cases':cases}
    outputs[str(DEST/'manifest.json')]=manifest
    return outputs

def main():
    a=argparse.ArgumentParser();a.add_argument('--check',action='store_true');args=a.parse_args();different=[]
    for rel,value in build().items():
        text=json.dumps(value,indent=2,sort_keys=True)+'\n';path=ROOT/rel
        if not path.exists() or path.read_bytes()!=text.encode("utf-8"):
            different.append(rel)
            if not args.check:path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(text.encode("utf-8"))
    if args.check and different:raise SystemExit('generated fixtures differ: '+', '.join(different))
    print(json.dumps({'cases':len(build())-1,'changed_files':len(different)}))
if __name__=='__main__':main()
