"""Reproduce the isolated negative witness for both supported ECL object alternatives.

Robert F. Tilley Jr.; G-14, Inc. These are synthetic conformance records.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITE = Path("conformance/suites/otel-export")
IDENTIFIER = "otel-invalid-object-not-ecl"
BASE = SUITE / "otel-valid-admit-response-exported.json"
GENERATOR = "scripts/generate_otel_schema_witness.py"
# Reviewed oracle, separate from the output manifest. Other rows remain caller-owned.
EXPECTED_ROW = {'covers': ['https://externalcontrollayer.ai/ns/schema/binding/otel-export/1##root',
            'https://externalcontrollayer.ai/ns/schema/binding/otel-export/1#/$defs/eclObject/oneOf#oneOf[0]',
            'https://externalcontrollayer.ai/ns/schema/binding/otel-export/1#/$defs/eclObject/oneOf#oneOf[1]'],
 'expected': 'fail',
 'expected_primary_id': 'ecl.error.schema-invalid.v1',
 'expected_secondary_ids': [],
 'id': 'otel-invalid-object-not-ecl',
 'negates': ['OE1-009'],
 'path': 'conformance/suites/otel-export/otel-invalid-object-not-ecl.json',
 'requirement_ids': ['OE1-009'],
 'schema': 'https://externalcontrollayer.ai/ns/schema/binding/otel-export/1',
 'source': {'base_vector': 'conformance/suites/otel-export/otel-valid-admit-response-exported.json',
            'generator': 'scripts/generate_otel_schema_witness.py',
            'kind': 'mutation',
            'mutation': 'Replace the before and after snapshots with the same incomplete DCMP '
                        'object, isolating the supported ECL-object alternatives.'},
 'stage': 'binding'}


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def build(root=ROOT):
    value = json.loads((root / BASE).read_bytes())
    value["object"] = {"protocol": "DCMP-2", "message_type": "decision_response"}
    # Keep the required after-snapshot and the equality of the two snapshots.
    # Both objects fail the shared eclObject union. Relaxing either alternative
    # alone then admits them, without a separate missing-member failure.
    value["evidence_after"] = copy.deepcopy(value["object"])
    manifest_path = SUITE / "manifest.json"
    manifest = json.loads((root / manifest_path).read_bytes())
    matches = [row for row in manifest["vectors"] if row["id"] == IDENTIFIER]
    if len(matches) != 1:
        raise ValueError("expected one existing non-ECL-object witness")
    matches[0].clear()
    matches[0].update(copy.deepcopy(EXPECTED_ROW))
    return {SUITE / (IDENTIFIER + ".json"): encoded(value), manifest_path: encoded(manifest)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = build(args.root)
    stale = [str(path) for path, data in outputs.items() if not (args.root / path).is_file() or (args.root / path).read_bytes() != data]
    if args.check:
        if stale:
            raise SystemExit("stale OTEL schema witness: " + ", ".join(stale))
    else:
        for path, data in outputs.items():
            (args.root / path).write_bytes(data)
    print(json.dumps({"files": len(outputs), "check": args.check, "differences": stale}))


if __name__ == "__main__":
    main()
