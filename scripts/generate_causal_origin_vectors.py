"""Signed synthetic ROOT-037 child-origin controls using public deterministic fixture keys.

Robert F. Tilley Jr.; G-14, Inc. No historical record or operational observation is rewritten.
"""
from __future__ import annotations
import argparse
import base64
import copy
import hashlib
import json
import sys
from collections import deque
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packages/ecl-verify/src'))
from ecl_verify.canonical import canonicalize, object_digest
from ecl_verify.integrity import signing_input

DEST = Path('conformance/suites/public-review-causal-origin')
GRAPHS = Path('tests/fixtures/repair-causal-origin.json')
CONTEXT = 'ecl.rule.bundle-causal-context-consistent.v1'
DIGEST = 'ecl.rule.bundle-predecessor-digest-valid.v1'
SEQUENCE = 'ecl.rule.bundle-causal-sequence-monotonic.v1'
CLOSURE = 'ecl.error.causal-closure-incomplete.v1'
SCHEMA = 'https://externalcontrollayer.ai/ns/schema/evidence-bundle/1'
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
MISSING = 'urn:example:repair:missing-origin'

def clone(v): return copy.deepcopy(v)
def encoded(v): return (json.dumps(v, indent=2, sort_keys=True) + '\n').encode()
def reference(record):
    return {'id': record['object_id'], 'digest': {'algorithm': 'ecl.digest.sha-256.v1', 'value': object_digest(record)}, 'relation': 'ecl.relation.follows.v1'}
def missing_ref():
    return {'id': MISSING, 'digest': {'algorithm': 'ecl.digest.sha-256.v1', 'value': 'd' * 64}, 'relation': 'ecl.relation.follows.v1'}

def rebind(records, corrupt=()):
    """Topological rebinding, preserving specifically corrupted edges and absent references."""
    by_id = {r['object_id']: r for r in records}
    pending = {name: 0 for name in by_id}; successors = {}
    for name, record in by_id.items():
        for ref in record['workflow']['causal_predecessors']:
            if ref['id'] in by_id:
                pending[name] += 1
                successors.setdefault(ref['id'], []).append(name)
    ready = deque(name for name, n in pending.items() if n == 0); count = 0
    while ready:
        name = ready.popleft(); count += 1
        for ref in by_id[name]['workflow']['causal_predecessors']:
            if ref['id'] in by_id:
                ref['digest']['value'] = 'f' * 64 if (name, ref['id']) in corrupt else object_digest(by_id[ref['id']])
        for child in successors.get(name, ()):
            pending[child] -= 1
            if pending[child] == 0: ready.append(child)
    if count != len(records): raise ValueError('synthetic origin graph must be acyclic')
    return records

def build(root=ROOT):
    old = json.loads((root / 'tests/fixtures/repair-causal-context.json').read_bytes())
    graph = clone(next(c['records'] for c in old if c['name'] == 'children-to-parent-join'))
    envelope = json.loads((root / 'conformance/suites/evidence-bundle/bundle-valid-succeeded.json').read_bytes())['envelopes'][-1]
    payload = json.loads(base64.b64decode(envelope['payload']))
    for record in graph:
        for member in ['integrity_policy', 'producer', 'observed_at']: record[member] = clone(payload[member])
    start, first, sibling, join = graph
    join['workflow']['causal_predecessors'] = [reference(first)]
    base = [start, first, join]
    parent = start['workflow']['workflow_id']
    def indirect():
        s, a, j = clone(base)
        later = clone(a); later['object_id'] += '-next'; later['workflow']['sequence'] = 2
        later['workflow']['causal_predecessors'] = [reference(a)]
        j['workflow']['causal_predecessors'] = [reference(later)]
        return [s, a, later, j]
    cases=[]; outputs={}; vectors=[]
    def add(name, records, status='complete', rules=(), primary=None, external=(), corrupt=(), reverse=False):
        records = rebind(records, corrupt)
        if reverse: records.reverse()
        case_id = 'child-origin-' + name
        envs=[]
        for record in records:
            e=clone(envelope); raw=canonicalize(record)
            e['payload']=base64.b64encode(raw).decode(); e['payload_digest']['value']=hashlib.sha256(raw).hexdigest()
            e['signatures'][0]['signature']=base64.b64encode(KEY.sign(signing_input(e['payload_type'],raw))).decode()
            envs.append(e)
        bundle={'schema_version':'ecl_evidence_bundle_v1','envelopes':envs}
        path=str(DEST/(case_id+'.json')); outputs[Path(path)] = encoded(bundle)
        # The signed verifier never exempts missing origin material; only the direct graph API
        # exposes allowed_external_predecessors, exercised separately by these same records.
        absent=sorted({ref['id'] for r in records for ref in r['workflow']['causal_predecessors'] if not any(p['object_id']==ref['id'] for p in records)})
        verdict='invalid' if rules else 'incomplete' if absent else 'verified'
        primary=primary or (CONTEXT if CONTEXT in rules else rules[0] if rules else CLOSURE if absent else None)
        cases.append({'name':case_id,'records':records,'status':status,'expected_rules':sorted(set(rules)),'allowed_external_predecessors':list(external),'expected_unresolved':absent if status=='incomplete' else [],'bundle_path':path,'expected_verdict':verdict,'expected_primary':primary})
        v={'id':case_id,'path':path,'schema':SCHEMA,'stage':'evidence-bundle','expected':'pass' if verdict=='verified' else 'fail','expected_secondary_ids':[], 'expected_verdict':verdict,'evaluated_at':'2026-10-01T00:00:00Z','trust_policy_path':'conformance/suites/evidence-bundle/trust-policy.json','trust_policy_history_paths':[],'covers':[],'requirement_ids':['EBMP2-077','DW1-002'],'source':{'kind':'mutation','base_vector':'conformance/suites/evidence-bundle/bundle-valid-succeeded.json','generator':'scripts/generate_causal_origin_vectors.py','mutation':'ROOT-037 synthetic child-origin graph: '+name}}
        if primary: v['expected_primary_id']=primary
        negates=[]
        if CONTEXT in rules: negates += ['EBMP2-077','DW1-002']
        if DIGEST in rules: negates.append('EBMP2-024')
        if SEQUENCE in rules: negates.append('EBMP2-025')
        if verdict=='incomplete': negates += ['EBMP2-023','EBMP2-059']
        if negates:
            v['negates']=sorted(set(negates))
            v['requirement_ids']=sorted(set(v['requirement_ids']+negates))
        vectors.append(v)
    add('direct-control',clone(base))
    add('indirect-control',indirect())
    add('indirect-reversed-control',indirect(),reverse=True)
    fork=clone(graph);fork[-1]['workflow']['causal_predecessors']=[reference(fork[1]),reference(fork[2])];add('two-children-control',fork)
    d=clone(base);d[1]['workflow']['causal_predecessors']=[];add('absent-declaration',d,'indeterminate',[CONTEXT])
    d=clone(base);detached=clone(d[1]);detached['object_id']+='-detached';d[1]['workflow']['sequence']=2;d[1]['workflow']['causal_predecessors']=[];d.insert(1,detached);add('detached-correct-branch',d,'indeterminate',[CONTEXT])
    d=indirect();d[1]['workflow']['workflow_id']='urn:example:repair:wf:sibling';add('sibling-cannot-supply-origin',d,'indeterminate',[CONTEXT])
    d=clone(base);add('bad-origin-digest',d,'indeterminate',[DIGEST,CONTEXT],primary=DIGEST,corrupt={(d[1]['object_id'],d[0]['object_id'])})
    d=indirect();add('bad-progress-digest',d,'indeterminate',[DIGEST,CONTEXT],primary=DIGEST,corrupt={(d[2]['object_id'],d[1]['object_id'])})
    d=indirect();d[1]['workflow']['parent_workflow_id']='urn:example:wrong-parent';add('changed-parent',d,'indeterminate',[CONTEXT])
    d=indirect();d[1]['workflow']['parent_workflow_id']='urn:example:wrong-parent';d[2]['workflow']['causal_predecessors'].append(missing_ref());add('changed-parent-with-absent-branch',d,'incomplete',[CONTEXT])
    d=indirect();d[1]['workflow'].pop('parent_workflow_id');add('missing-parent-declaration',d,'indeterminate',[CONTEXT])
    d=clone(base);d[0]['workflow']['root_trace_id']='urn:example:wrong-root';add('origin-wrong-root',d,'indeterminate',[CONTEXT])
    d=clone(base);d[0]['workflow']['workflow_id']='urn:example:wrong-parent';add('origin-wrong-parent',d,'indeterminate',[CONTEXT])
    d=rebind(clone(base));missing=d[0]['object_id'];add('named-origin-unavailable',d[1:],'incomplete')
    d=rebind(clone(base));add('external-origin-unavailable',d[1:],'incomplete',external=[missing])
    d=rebind(indirect());missing=d[1]['object_id'];add('named-intermediate-unavailable',[d[0],d[2],d[3]],'incomplete')
    d=rebind(indirect());add('external-intermediate-unavailable',[d[0],d[2],d[3]],'incomplete',external=[missing])
    d=clone(base);d[1]['workflow']['causal_predecessors']=[];extra=clone(sibling);extra['workflow']['causal_predecessors']=[missing_ref()];d.insert(1,extra);add('unrelated-absence-cannot-excuse-orphan',d,'incomplete',[CONTEXT])
    d=clone(base);d[1]['workflow']['causal_predecessors'].append(missing_ref());add('held-origin-with-external-branch',d,external=[MISSING])
    d=indirect();d[2]['workflow']['attempt']=2;add('increasing-attempt-control',d)
    d=indirect();d[1]['workflow']['attempt']=2;add('backward-attempt',d,'indeterminate',[CONTEXT])
    d=indirect();d[2]['workflow']['sequence']=1;add('backward-sequence',d,'indeterminate',[SEQUENCE,CONTEXT])
    d=clone(base);d[1]['workflow']['causal_predecessors'].append(missing_ref());add('bad-digest-with-absent-branch',d,'incomplete',[DIGEST],primary=DIGEST,corrupt={(d[1]['object_id'],d[0]['object_id'])})
    d=clone(base);d[0]['workflow']['root_trace_id']='urn:example:wrong-root';d[1]['workflow']['causal_predecessors'].append(missing_ref());add('wrong-root-with-absent-branch',d,'incomplete',[CONTEXT])
    # Preserve the bounded independent review's additional branch controls as regressions.
    d=indirect();conflict=clone(d[1]);conflict['object_id']+='-conflict';conflict['workflow']['parent_workflow_id']='urn:example:wrong-parent';conflict['workflow']['causal_predecessors']=[];d[2]['workflow']['causal_predecessors'].append(reference(conflict));d.insert(2,conflict);add('held-origin-and-parent-conflict',d,'indeterminate',[CONTEXT])
    d=indirect();later=clone(d[2]);later['object_id']+='-again';later['workflow']['sequence']=3;later['workflow']['causal_predecessors']=[reference(d[2])];d[-1]['workflow']['causal_predecessors']=[reference(later)];d.insert(-1,later);add('nested-child-progression-control',d)
    d=indirect();grandchild=clone(d[1]);grandchild['object_id']+='-grandchild';grandchild['workflow']['workflow_id']='urn:example:repair:wf:grandchild';grandchild['workflow']['parent_workflow_id']=d[1]['workflow']['workflow_id'];grandchild['workflow']['causal_predecessors']=[reference(d[1])];d[2]['workflow']['causal_predecessors']=[reference(grandchild)];d.insert(2,grandchild);add('grandchild-route-cannot-supply-origin',d,'indeterminate',[CONTEXT])
    d=clone(graph);d[-1]['workflow']['causal_predecessors']=[reference(d[1]),reference(d[2])];d[2]['workflow']['causal_predecessors']=[];add('one-orphan-among-two-joins',d,'indeterminate',[CONTEXT])
    manifest={'schema_version':'ecl_conformance_vector_manifest_v3','candidate_version':'1.0','suite':'public-review-causal-origin','vectors':vectors}
    outputs[DEST/'manifest.json']=encoded(manifest)
    outputs[GRAPHS]=encoded(cases)
    return outputs

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    outputs=build();changed=[]
    for path,data in outputs.items():
        target=ROOT/path
        if not target.exists() or target.read_bytes()!=data:
            changed.append(str(path))
            if not args.check: target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    print(json.dumps({'vectors':len(outputs)-2,'changed':changed,'check':args.check}))
    if args.check and changed: raise SystemExit(1)
if __name__=='__main__':main()
