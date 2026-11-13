"""Reproduce ordered-envelope and manually specified scope regression vectors.

Envelope mutations intentionally retain the baseline signature: their required
refusals occur before signature evaluation. Scope oracles are fixed below from
EBMP2-076 and the inspected fixture object positions, not verifier output.
"""
from __future__ import annotations
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packages/ecl-verify/src'))
from ecl_verify.canonical import canonicalize

SUITE = Path('conformance/suites/repair-harness')
GENERATOR = 'scripts/generate_repair_harness_vectors.py'
ENVELOPE = 'https://externalcontrollayer.ai/ns/schema/integrity-envelope/1'
INTEGRITY = 'ecl.error.integrity-invalid.v1'
POLICY = 'ecl.error.signature-policy-invalid.v1'
CHECKS = {
    'envelope-signatures': ['envelope-integrity','time-not-after-evaluation','historical-signers','current-compromise-knowledge','trusted-time-countersignatures'],
    'current-trust': ['current-status'],
    'trusted-time': ['historical-signers','current-compromise-knowledge','trusted-time-countersignatures','trusted-time-coverage','attestation-signers'],
    'object-rules': ['object-schema','object-semantics','observation-kind','identifiers-unique','decision-basis-one-way'],
    'decision-basis-recorded': ['decision-basis-present'],
    'decision-basis-register': ['decision-basis-register'],
    'bindings': ['pairing','continuation-history','response-binding','event-binding','outcome-reasons'],
    'release-within-authority': ['release-window'],
    'causal-completeness': ['identifiers-unique','predecessors-resolved','predecessor-digests','graph-acyclic','causal-context','sequence-monotonic','state-transitions','terminal-per-request','attempt-authority-consumed'],
}
# Number of objects, request/response/event pair indexes, release participants.
# Index 2 is consumption: part of binding/causal checks, not released-attempts.
SCOPE_CASES = {
    'bundle-valid-succeeded-with-register': (5,[0,1,2,3,4],[0,1,3,4]),
    'bundle-valid-trusted-time': (5,[0,1,2,3,4],[0,1,3,4]),
    'bundle-valid-observation-signer-revoked-after-waiver': (6,[0,1,2,3,4],[0,1,3,4]),
    'bundle-incomplete-no-terminal': (4,[0,1,2,3],[0,1,3]),
    'bundle-invalid-signer-revoked-before-own-time': (5,[0,1,2,3,4],[0,1,3,4]),
    'bundle-valid-observation-corroborates': (6,[0,1,2,3,4],[0,1,3,4]),
    'bundle-valid-attestation-extra-signature-not-verifying': (5,[0,1,2,3,4],[0,1,3,4]),
}

def encoded(value):
    return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode('utf-8')

def build(root: Path):
    basepath = 'conformance/suites/envelope/envelope-valid-ed25519-signed.json'
    base = json.loads((root/basepath).read_bytes())
    payload = json.loads(base64.b64decode(base['payload']))
    outputs, vectors = {}, []
    def add(name, value, code=None, stage='envelope', row=None):
        identifier = 'repair-harness-' + name
        path = SUITE/(identifier+'.json')
        outputs[path] = encoded(value)
        if row is None:
            row = dict(stage=stage,schema=ENVELOPE,expected='fail' if code else 'pass',expected_secondary_ids=[],covers=[],requirement_ids=['IE1-040'],
                       source=dict(kind='mutation',base_vector=basepath,generator=GENERATOR,mutation=name))
            if code: row.update(expected_primary_id=code,negates=['IE1-040'])
        row = copy.deepcopy(row);row.update(id=identifier,path=path.as_posix())
        vectors.append(row)
    def wrap(value, media=None):
        envelope = copy.deepcopy(base);raw=canonicalize(value)
        envelope['payload']=base64.b64encode(raw).decode()
        envelope['payload_digest']['value']=hashlib.sha256(raw).hexdigest()
        if media is not None:envelope['payload_type']=media
        return envelope
    add('envelope-valid-control',base)
    add('envelope-array',wrap([]),INTEGRITY)
    add('envelope-scalar',wrap('not a protocol object'),INTEGRITY)
    missing=copy.deepcopy(payload);missing.pop('integrity_policy');missing.pop('issued_at')
    add('envelope-missing-policy-and-time',wrap(missing),INTEGRITY)
    mismatch=copy.deepcopy(payload);mismatch['protocol']='EBMP-2';mismatch.pop('issued_at')
    add('envelope-media-before-time',wrap(mismatch),INTEGRITY)
    oversized=wrap([]);oversized['signatures']*=33
    add('envelope-budget-before-payload',oversized,'ecl.error.schema-invalid.v1')
    no_time=copy.deepcopy(payload);no_time.pop('issued_at')
    add('envelope-missing-time',wrap(no_time),POLICY)
    list_limit=copy.deepcopy(no_time);list_limit['integrity_policy']['eligible_key_ids']=['urn:example:budget:'+str(i) for i in range(65)]
    add('envelope-policy-budget-before-time',wrap(list_limit),'ecl.error.resource-limit-exceeded.v1')
    invalid_time=copy.deepcopy(payload);invalid_time['issued_at']='2026-02-30T00:00:00Z'
    add('envelope-invalid-time',wrap(invalid_time),POLICY)
    threshold=copy.deepcopy(no_time);threshold['integrity_policy']['threshold']=0
    add('envelope-policy-before-time',wrap(threshold),POLICY)
    extra=wrap(no_time);extra['extensions']=[{'id':'urn:example:repair-harness:unknown','version':1,'critical':True,'value':{}}]
    add('envelope-extension-before-time',extra,'ecl.rule.unknown-critical-extension-rejected.v1')
    bad_signature=copy.deepcopy(base);bad_signature['signatures'][0]['signature']=base64.b64encode(bytes(64)).decode()
    add('envelope-invalid-signature-control',bad_signature,POLICY)

    manifests=json.loads((root/'conformance/suites/evidence-bundle/manifest.json').read_bytes())
    by_id={v['id']:v for v in manifests['vectors']}
    registry=json.loads((root/'registries/scope-checks.json').read_bytes())
    rules={v['item']:v['required_checks'] for v in registry['items']}
    if any(set(rules[item])!=set(checks) for item,checks in CHECKS.items()):
        raise ValueError('Scope check contract changed: review the manual oracle before regeneration')
    for original,(count,paired,released) in SCOPE_CASES.items():
        row=copy.deepcopy(by_id[original]);value=json.loads((root/row['path']).read_bytes())
        payloads=[json.loads(base64.b64decode(e['payload'])) for e in value['envelopes']+value.get('observations',[])]
        if len(payloads)!=count or payloads[0].get('message_type')!='decision_request' or payloads[1].get('message_type')!='decision_response':
            raise ValueError('Scope fixture object positions changed: '+original)
        expected=row['expected_scope'];expected['checks']={}
        for item in expected['established']:
            indexes = [1] if item.startswith('decision-basis-') else paired if item=='bindings' else released if item=='release-within-authority' else list(range(count))
            expected['checks'][item]={'checks':CHECKS[item],'objects':indexes}
        row['source']={'kind':'mutation','generator':GENERATOR,'base_vector':row['path'],'mutation':'Preserve the signed input; add a fixed oracle for supporting checks and exact object indexes.'}
        row['requirement_ids']=sorted(set(row['requirement_ids'])|{'EBMP2-076'})
        add('scope-'+original.removeprefix('bundle-'),value,row=row)
    manifest=dict(schema_version='ecl_conformance_vector_manifest_v3',candidate_version='1.0',suite='ecl-1-v1.0-repair-harness',
                  trust_policy_path='conformance/suites/envelope/trust-policy.json',vectors=sorted(vectors,key=lambda v:v['id']))
    outputs[SUITE/'manifest.json']=encoded(manifest)
    return outputs

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    outputs=build(args.root)
    for path,data in outputs.items():
        target=args.root/path
        if args.check:
            if not target.is_file() or target.read_bytes()!=data:raise SystemExit('stale repair harness fixture: '+str(path))
        else:target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    print(json.dumps({'vectors':len(outputs)-1,'check':args.check}))

if __name__=='__main__':main()
