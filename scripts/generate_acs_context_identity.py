"""ACS entry identity controls. Robert F. Tilley Jr.; G-14, Inc."""
from pathlib import Path
import argparse, copy, hashlib, json
from ecl_verify.bindings import jcs

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests/fixtures/acs-context-identity.json"

def build():
    base = json.loads((ROOT / "conformance/suites/repair-bindings/repair-acs-signed-bound.json").read_bytes())
    cases = [{"id": "original-control", "record": base, "expected_rules": []}]
    for duplicate in (False, True):
        for repeated_step in (False, True):
            value = copy.deepcopy(base)
            previous = value["chain"][-1]
            entry = copy.deepcopy(previous)
            entry["previous_hash"] = previous["entry_hash"]
            if not duplicate: entry["entry_id"] = "urn:example:entry:later"
            if not repeated_step: entry["step_id"] = "urn:example:step:later"
            else: entry["step_type"] = "intent_extension"
            entry.pop("request_hash", None)
            content = {k:v for k,v in entry.items() if k not in ("entry_hash", "previous_hash")}
            entry["entry_hash"] = hashlib.sha256(jcs.canonicalize(content) + bytes.fromhex(previous["entry_hash"])).hexdigest()
            value["chain"].append(entry)
            cases.append({"id": ("duplicate-entry" if duplicate else "distinct-entry") + ("-repeated-step" if repeated_step else "-distinct-step"), "record": value, "expected_rules": ["ecl.rule.acs-decision-recorded.v1"] if duplicate else []})
    return {"authors_and_producers": ["Robert F. Tilley Jr.", "G-14, Inc."], "schema": "https://externalcontrollayer.ai/ns/schema/binding/acs-exchange/1", "basis": "Pinned ACS ContextEntry entry_id is unique within the session. Instrument section 9.1 permits an intent_extension to retain the originating ASK step_id. These are synthetic chain-validation fixtures, not an approver execution trace.", "cases": cases}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--check", action="store_true"); args = parser.parse_args()
    data = (json.dumps(build(), indent=2, sort_keys=True) + "\n").encode()
    if args.check:
        if not TARGET.is_file() or TARGET.read_bytes() != data: raise SystemExit("ACS identity fixtures differ")
    else: TARGET.write_bytes(data)
