#!/usr/bin/env python3
"""Explicit synthetic migration of active MCP records, preserving original input bytes.

Robert F. Tilley Jr.; G-14, Inc. Does not invent historical evidence or sign records.
The pinned retained fixture is the default baseline. An optional --baseline-dir
must match it exactly; neither mode seeds inputs from the outputs.
"""
from __future__ import annotations
import argparse, copy, hashlib, io, json, sys, zipfile
from datetime import timedelta
from pathlib import Path
from generate_mcp_public_review_repairs import ROOT, BIND, migrate, observation, stamp, parse, digest, complete_synthetic_answer
from ecl_verify.bindings.mcp import check, EXCHANGE_SCHEMA
from ecl_verify.resources import validator_for
from generate_binding_input_migration import migrate_mcp, OLD_PATH, NEGATIVE_PATH, POSITIVE_PATH
sys.path.insert(0,str(ROOT))
from scripts.run_conformance import registered_errors, rule_precedence, select_findings

def clone(v):return copy.deepcopy(v)
def sha(b):return hashlib.sha256(b).hexdigest()
def encode(v):return (json.dumps(v,indent=2,sort_keys=True)+'\n').encode()
def delta(old,changed,new):
    if old==changed:return clone(new)
    if isinstance(old,dict) and isinstance(changed,dict) and isinstance(new,dict):
        out=clone(new)
        for key in old.keys()-changed.keys():out.pop(key,None)
        for key,value in changed.items():out[key]=delta(old[key],value,new.get(key,old[key])) if key in old else clone(value)
        return out
    if isinstance(old,list) and isinstance(changed,list) and isinstance(new,list) and len(old)==len(changed)==len(new):return [delta(a,b,c) for a,b,c in zip(old,changed,new)]
    return clone(changed)

def build(originals,manifest):
    by_path={c['path']:c for c in manifest['vectors']};built={};notes={}
    seed=originals['conformance/suites/mcp-gateway/mcp-valid-forwarded-release-order.json']
    def complete(d,original):
        d=clone(d)
        if d.get('forwarded') is not None:
            response=d.get('decision',{}).get('response') or {};req=d.get('decision_request') or seed['decision_request']
            at=d['forwarded']['forwarded_at'];guard=d.setdefault('release_guard_milliseconds',250)
            start=parse(response.get('issued_at',req['issued_at']))
            initial=stamp(start+timedelta(milliseconds=10))
            for name,kind,state,offset in [('prepared','release_prepared','prepared',-10),('released','execution_released','released',0)]:
                if name not in d:
                    e=clone(d.get('terminal') or seed['terminal']);e['event_type']=kind;e['event']['state']=state;e['observed_at']=stamp(parse(at)+timedelta(milliseconds=offset));e['extensions']=[]
                    e['event'].pop('side_effects',None);e['event'].pop('residual_state',None)
                    if name=='released':e['event']['release_guard_ms']=guard
                    else:e['event'].pop('release_guard_ms',None)
                    e['object_id']='urn:example:synthetic-mcp-migration:'+sha(encode(req))[:24]+':'+name
                    d[name]=e
                # Newly reconstructed common events bind the mutated request/response too.
                if name not in original:
                    e=d[name]
                    e['workflow']=clone(req['workflow']);e['workflow']['sequence']=4 if name=='prepared' else 5
                    e['event']['action_id']=req['action']['action_id']
                    if d.get('terminal',{}).get('event',{}).get('attempt_id'):e['event']['attempt_id']=d['terminal']['event']['attempt_id']
                    if response:
                        e['event']['decision']={'uri':response['message_id'],'digest':digest(response)}
                    else:e['event'].pop('decision',None)
                    if response.get('authorization'):
                        e['event']['authority']={'uri':response['authorization']['authorization_id'],'digest':digest(response['authorization'])}
                    else:e['event'].pop('authority',None)
            if parse(initial)>parse(d['prepared']['observed_at']):initial=stamp(parse(d['prepared']['observed_at'])-timedelta(milliseconds=1))
            d.setdefault('release_observations',{'initial':observation(initial),'final':observation(d['released']['observed_at'])})
            if 'terminal' in d and 'released' not in original:
                d['terminal']['workflow']['sequence']=6
                d['terminal']['workflow']['causal_predecessors']=[{'id':d['released']['object_id'],'digest':digest(d['released']),'relation':'ecl.relation.follows.v1'}]
        return complete_synthetic_answer(d)
    def one(path):
        if path in built:return built[path]
        original=originals[path];entry=by_path.get(path,{})
        if original.get('schema_version')!='ecl_mcp_gateway_exchange_v1':built[path]=clone(original);return built[path]
        base=entry.get('source',{}).get('base_vector')
        if entry.get('expected')=='fail' and base in originals:
            d=delta(originals[base],original,one(base));d=complete(d,original)
            notes[path]='Synthetic reconstruction: add common release/control evidence from migrated positive base, preserving the original targeted mutation.'
        else:
            # Existing complete event records retain their fields; legacy forward records receive
            # explicitly reconstructed new preparation/release records and control observations.
            if 'forwarded' in original:d=complete(original,original)
            else:d=migrate(original)
            note='Synthetic reconstruction of explicit release/control observations and any missing preparation/release evidence; not historical observation.'
            reason=d.get('returned',{}).get('error',{}).get('data',{}).get('ecl',{}).get('reason')
            if reason in ('ecl.error.expired.v1','ecl.error.clock-regressed.v1','ecl.error.obligation-unproven.v1') and d.get('decision',{}).get('status')=='answered' and d['decision']['response'].get('outcome')=='admit':
                resp=d['decision']['response'];consumed='prepared' in d or 'released' in d
                if reason=='ecl.error.obligation-unproven.v1' and d.get('obligation_discharge'):
                    failed=min(parse(e['fresh_until']) for e in d['obligation_discharge']['obligations'] if 'fresh_until' in e)-timedelta(milliseconds=d['release_guard_milliseconds'])
                elif reason=='ecl.error.clock-regressed.v1':failed=parse(d['prepared']['observed_at'])+timedelta(milliseconds=10)
                elif reason=='ecl.error.expired.v1' and 'released' in d:
                    failed=None # existing release/terminal gap is the recorded guard-exceeded case
                elif reason=='ecl.error.expired.v1':
                    d.setdefault('release_guard_milliseconds',250)
                    failed=parse(resp['authorization']['valid_until'])-timedelta(milliseconds=d['release_guard_milliseconds'])
                else:failed=None
                if failed is not None:
                    if consumed:d.setdefault('release_observations',{})['final']=observation(stamp(failed))
                    else:d['release_observations']={'initial':observation(stamp(failed))}
                    if reason=='ecl.error.clock-regressed.v1':d['release_observations']['final']['clock_regressed']=True
                    if 'terminal' in d:d['terminal']['observed_at']=stamp(failed+timedelta(milliseconds=10))
                    d['returned_at']=stamp(max(parse(d.get('returned_at',stamp(failed))),failed+timedelta(milliseconds=20)))
                    note+=' Reconstruct failed comparison explicitly and order terminal/return after it; do not infer failed observation from old returned_at.'
            notes[path]=note
        built[path]=d;return d
    for path in originals:one(path)
    return built,notes

BASELINE_ARCHIVE = "scripts/fixtures/mcp-reconstruction-baseline.zip"
BASELINE_SHA256 = "3db76edb06f8b0fca976893fae6205cf42011552252517e808d344c9069b3d92"
# These negative cases retain their defects and complete finding sets. The
# registered terminal-state rule precedes the MCP-specific rules. This fixed
# migration is an oracle, not a refresh from the implementation's current output.
APPROVED_EXPECTATIONS = {
 'mcp-invalid-recovered-admit-denied-without-reason': {
     'expected_primary_id': 'ecl.rule.mcp-result-bound.v1',
     'expected_secondary_ids': ['ecl.error.semantic-invalid.v1']},
 'mcp-invalid-refusal-not-first-cause': {
     'expected_primary_id': 'ecl.rule.mcp-refusal-defined.v1',
     'expected_secondary_ids': ['ecl.rule.mcp-result-bound.v1']},
 'mcp-invalid-live-cancelled-no-residual': {'expected_primary_id': 'ecl.rule.terminal-execution-state-consistent.v1',
                                            'expected_secondary_ids': ['ecl.rule.mcp-result-bound.v1']},
 'mcp-invalid-recorded-denied-wrong-state': {'expected_primary_id': 'ecl.rule.terminal-execution-state-consistent.v1',
                                             'expected_secondary_ids': ['ecl.rule.mcp-result-bound.v1']},
 'mcp-invalid-recovered-challenged-as-cancelled': {'expected_primary_id': 'ecl.rule.terminal-execution-state-consistent.v1',
                                                   'expected_secondary_ids': ['ecl.rule.mcp-result-bound.v1']},
 'mcp-invalid-recovered-denied-as-cancelled': {'expected_primary_id': 'ecl.rule.terminal-execution-state-consistent.v1',
                                               'expected_secondary_ids': ['ecl.rule.mcp-result-bound.v1']},
 'mcp-invalid-recovered-held-as-cancelled': {'expected_primary_id': 'ecl.rule.terminal-execution-state-consistent.v1',
                                             'expected_secondary_ids': ['ecl.rule.mcp-result-bound.v1']},
 'mcp-invalid-recovered-unverified-as-cancelled': {'expected_primary_id': 'ecl.rule.terminal-execution-state-consistent.v1',
                                                   'expected_secondary_ids': ['ecl.rule.mcp-decision-failure-not-forwarded.v1',
                                                                              'ecl.rule.mcp-result-bound.v1']}}

def baseline_inputs(directory=None):
    raw = (ROOT / BASELINE_ARCHIVE).read_bytes()
    if sha(raw) != BASELINE_SHA256:
        raise ValueError("retained MCP baseline archive does not match its pin")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        if len(names) != 140 or len(set(names)) != len(names) or "manifest.json" not in names:
            raise ValueError("invalid retained MCP baseline members")
        if any(Path(name).name != name or not name.endswith(".json") for name in names):
            raise ValueError("invalid retained MCP baseline path")
        expected = {name: archive.read(name) for name in names}
    if directory is not None:
        if not directory.is_dir():
            raise ValueError("baseline directory must already contain the retained inputs")
        paths = {p.name: p for p in directory.glob("*.json")}
        if paths.keys() != expected.keys() or any(paths[n].read_bytes() != b for n, b in expected.items()):
            raise ValueError("baseline directory differs from the independently pinned inputs")
    return expected


def reconstructed_suite(inputs):
    manifest = json.loads(inputs["manifest.json"])
    originals = {"conformance/suites/mcp-gateway/" + name: json.loads(data)
                 for name, data in inputs.items() if name != "manifest.json"}
    values, notes = build(originals, manifest)
    migrate_mcp(manifest, values, notes)
    for identifier, changes in APPROVED_EXPECTATIONS.items():
        rows = [row for row in manifest["vectors"] if row["id"] == identifier]
        if len(rows) != 1:
            raise ValueError("expected one retained diagnostic migration: " + identifier)
        rows[0].update(clone(changes))
    return manifest, values, notes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-dir", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    inputs = baseline_inputs(args.baseline_dir)
    manifest, values, notes = reconstructed_suite(inputs)
    validator = validator_for(EXCHANGE_SCHEMA)
    precedence, error_codes = rule_precedence(ROOT), registered_errors(ROOT)
    rows, unexpected = [], []
    for entry in manifest["vectors"]:
        path, value = entry["path"], values[entry["path"]]
        if entry["stage"] == "binding":
            errors = list(validator.iter_errors(value))
            found = [] if errors else check(value)
            rules = sorted(set(["ecl.error.schema-invalid.v1"] if errors else [f.rule_id for f in found]))
            primary, secondary = select_findings(rules, precedence, error_codes)
            wanted = (entry.get("expected_primary_id"), entry.get("expected_secondary_ids", []))
            if (not rules) != (entry["expected"] == "pass") or (primary, secondary) != wanted:
                unexpected.append({"id": entry["id"], "actual_rules": rules,
                                   "expected_primary_id": wanted[0], "expected_secondary_ids": wanted[1]})
        else:
            rules = None  # Original protocol rows are reproduced, not relabeled as binding checks.
        original_name = Path(path).name
        if original_name not in inputs and path in (NEGATIVE_PATH, POSITIVE_PATH):
            original_name = Path(OLD_PATH).name
        before, after = inputs[original_name], encode(value)
        rows.append({"id": entry["id"], "path": path, "before_sha256": sha(before),
                     "after_sha256": sha(after), "changed": before != after,
                     "expected": entry["expected"], "actual_rules": rules,
                     "rationale": notes.get(path, "unchanged protocol fixture")})
    outputs = {path: encode(value) for path, value in values.items()}
    outputs["conformance/suites/mcp-gateway/manifest.json"] = encode(manifest)
    drift = [path for path, content in outputs.items()
             if not (ROOT / path).is_file() or (ROOT / path).read_bytes() != content]
    retired = [OLD_PATH] if (ROOT / OLD_PATH).exists() else []
    written = False
    if args.write and not unexpected:
        for path, content in outputs.items():
            (ROOT / path).parent.mkdir(parents=True, exist_ok=True)
            (ROOT / path).write_bytes(content)
        for path in retired:
            (ROOT / path).unlink()
        written = True
    report = {"authors_and_producers": ["Robert F. Tilley Jr.", "G-14, Inc."],
              "status": "synthetic corpus reconstruction; exact baseline retained",
              "baseline_archive": BASELINE_ARCHIVE, "baseline_sha256": BASELINE_SHA256,
              "baseline_directory": str(args.baseline_dir) if args.baseline_dir else None,
              "written": written, "records": rows, "unexpected": unexpected,
              "drifted_files": drift, "retired_paths": retired,
              "approved_expectations": APPROVED_EXPECTATIONS,
              "manifest_sha256": sha(outputs["conformance/suites/mcp-gateway/manifest.json"]),
              "signed_records_modified": False,
              "reference_gateway": "No MCP reference gateway implementation is present in this source distribution."}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"records": len(rows), "binding_records": sum(r["actual_rules"] is not None for r in rows),
                      "unexpected": len(unexpected), "differing_files": len(drift),
                      "retired_paths": retired, "written": written}))
    if unexpected or (args.check and (drift or retired)):
        raise SystemExit("MCP reconstruction differs from its fixed inputs or expectations")

if __name__ == "__main__":
    main()
