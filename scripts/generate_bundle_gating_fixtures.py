"""Prepare signed multi-fault regression inputs without the private fixture library."""
from pathlib import Path
import argparse, base64, copy, hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
parser.add_argument('--check',action='store_true')
args = parser.parse_args()
S = args.root
out = S/'tests/fixtures/bundle-gating'
out.mkdir(parents=True,exist_ok=True)
sys.path.insert(0,str(S/'packages/ecl-verify/src'))
from ecl_verify.canonical import canonicalize, object_digest
from ecl_verify.integrity import signing_input

suite = S/'conformance/suites/evidence-bundle'
policy_document = json.loads((suite/'trust-policy.json').read_text())
# Public deterministic fixture seeds, confirmed against every corresponding
# released policy key before use. These have no production authority.
seeds = {'bundle-agent':0,'bundle-decision':1,'bundle-ep':2,'bundle-observer':3,
         'bundle-approval-service':50,'bundle-observer-other':51,'bundle-agent-observer':52}
keys = {'urn:example:key:'+name:Ed25519PrivateKey.from_private_bytes(bytes(range(start,start+32))) for name,start in seeds.items()}
for entry in policy_document['keys']:
    if entry['key_id'] in keys:
        if base64.b64encode(keys[entry['key_id']].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode() != entry['public_key']:
            raise ValueError('Public fixture key differs from the trust policy: ' + entry['key_id'])

def load(name):
    bundle = json.loads((suite/(name+'.json')).read_text())
    # Envelopes first, then observations: the mutations index envelopes by position.
    return bundle, [json.loads(base64.b64decode(e['payload'])) for e in bundle['envelopes']+bundle.get('observations',[])]

def signed(bundle, payloads):
    # Rebind only causal edges affected by a changed payload. Deliberate decision,
    # authority and proof digest faults remain exactly as the test specifies.
    by_id = {p.get('object_id',p.get('message_id')):p for p in payloads}
    for _ in range(len(payloads)):
        changed = False
        for p in payloads:
            for edge in p['workflow'].get('causal_predecessors',[]):
                target = by_id.get(edge['id'])
                if target is not None:
                    digest = object_digest(target)
                    if edge['digest']['value'] != digest:
                        edge['digest']['value'] = digest;changed=True
        if not changed:break
    else:raise AssertionError('Causal rebinding did not converge')
    for envelope,payload in zip(bundle['envelopes']+bundle.get('observations',[]),payloads):
        raw = canonicalize(payload)
        envelope['payload'] = base64.b64encode(raw).decode()
        envelope['payload_digest']['value'] = hashlib.sha256(raw).hexdigest()
        for entry in envelope['signatures']:
            if entry['suite_id'] != 'ecl.sig.ed25519.v1':
                raise ValueError('Unsupported fixture signature suite: ' + entry['suite_id'])
            entry['signature']=base64.b64encode(keys[entry['key_id']].sign(signing_input(envelope['payload_type'],raw))).decode()
    return bundle

cases=[]
expected = {c['id']:c for c in json.loads((out/'expected.json').read_text())['cases']} if args.check else {}
def add(name,base,mutate,rationale):
    bundle,payloads=load(base)
    mutate(bundle,payloads)
    fixture=signed(bundle,payloads)
    path=out/(name+'.json')
    content=(json.dumps(fixture,indent=2,sort_keys=True)+'\n').encode()
    if args.check:
        base_digest = hashlib.sha256((suite/(base+'.json')).read_bytes()).hexdigest()
        if expected[name]['base'] != base or expected[name]['base_sha256'] != base_digest:
            raise ValueError('Base suite fixture drifted: ' + base)
        if path.read_bytes() != content:
            raise ValueError('Stale full-finding fixture: ' + name)
    else:
        path.write_bytes(content)
    cases.append(name)

def core_digest(bundle,p):p[3]['event']['decision']['digest']['value']='f'*64
add('core-binding-gates-release-window','bundle-invalid-release-guard-reaches-valid-until',core_digest,
    'The release has both a wrong decision digest and an expired guard window. The core binding failure suppresses the window check; no expired finding should be emitted.')
def use_count(bundle,p):p[2]['event']['use_count']=2
add('cross-event-code-order','bundle-invalid-order-within-event-binding',use_count,
    'An invalid single-use consumption coexists with another event authority-digest fault and a release window fault. Decision-binding-invalid ranks before digest-mismatch and expired across events.')
def proof_gate(bundle,p):
    for extension in p[3]['extensions']:
        if extension['id']=='ecl.ext.obligation-discharge.v1':
            for entry in extension['value']['obligations']:
                entry['fresh_until']=p[3]['observed_at']
                # This target would fail the signer and type checks if the
                # wrong digest did not gate them. The control below proves it.
                entry['proof']['reference']=p[0]['message_id']
add('proof-digest-gates-proof-checks','bundle-invalid-discharge-carried-proof-other-digest',proof_gate,
    'Wrong digests name the actor-signed request as a proof while entry fresh_until is stale. Entry freshness still fails, but the signer/type proof/reference checks must be suppressed.')
def proof_control(bundle,p):
    proof_gate(bundle,p)
    for extension in p[3]['extensions']:
        if extension['id']=='ecl.ext.obligation-discharge.v1':
            for entry in extension['value']['obligations']:entry['proof']['digest']['value']=object_digest(p[0])
add('proof-digest-matching-control','bundle-invalid-discharge-carried-proof-other-digest',proof_control,
    'The same actor-signed request is named with its correct digest. Its signer and decision-message type failures must now be reported, alongside stale entry freshness.')
def no_consumption(bundle,p):
    p[3]['workflow']['causal_predecessors']=[copy.deepcopy(p[2]['workflow']['causal_predecessors'][0])]
    del p[2];del bundle['envelopes'][2]
add('stage8-binding-before-unproven','bundle-invalid-discharge-uncarried-proof-stale',no_consumption,
    'Removing the consumption and rebinding the release predecessor leaves a single-use release with stale uncarried proof. Stage-8 decision-binding-invalid ranks before obligation-unproven.')
print(f"Bundle gating fixtures: {len(cases)} {'checked' if args.check else 'generated'}; expected.json is maintained separately.")
