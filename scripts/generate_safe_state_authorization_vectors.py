"""Reproduce the four schema-coverage fail-open authorization controls."""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE='conformance/suites/strict-failure/strict-failure-valid-unclaimed-advisory-fail-open.json'
GENERATOR='scripts/generate_safe_state_authorization_vectors.py'
FIELDS={'timeout':'timeout_disposition','dependency':'dependency_disposition','stale-dependency':'stale_dependency_disposition','buffer-exhaustion':'buffer_exhaustion_disposition'}
def build(root):
    base=json.loads((root/BASE).read_text());outputs={}
    for label,field in FIELDS.items():
        value=copy.deepcopy(base);entry=value['action_classes'][0];entry[field]='fail_open'
        entry['fail_open_authorization']={
            'owner':'urn:example:owner:payments-risk',
            'rationale':'An explicit fail-open decision for this action class, owned, expiring, and evidenced.',
            'expires_at':'2026-10-31T00:00:00.000000Z',
            'evidence_profile':'ecl.evidence.standard.v1',
            'covered_advisory_dependencies':['urn:example:dependency:diagnostic-telemetry'],
        }
        outputs[Path(f'conformance/suites/schema-coverage/safe-state-valid-{label}-fail-open-authorized.json')]=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
    return outputs

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    outputs=build(args.root)
    for path,data in outputs.items():
        target=args.root/path
        if args.check:
            if target.read_bytes()!=data:raise SystemExit('stale authorization control: '+str(path))
        else:target.write_bytes(data)
    print(json.dumps({'vectors':len(outputs),'check':args.check}))
if __name__=='__main__':main()
