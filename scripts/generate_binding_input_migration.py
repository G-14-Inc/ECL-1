#!/usr/bin/env python3
"""Exact I-JSON and telemetry corpus migrations, with retained negative payload bytes.

Robert F. Tilley Jr.; G-14, Inc. No signatures or historical observations are created.
Run --check after --write; --baseline-dir optionally verifies the retired MCP payload bytes.
"""
from __future__ import annotations
import argparse, base64, copy, hashlib, json
from pathlib import Path
from ecl_verify.bindings import jcs

ROOT = Path(__file__).resolve().parents[1]
SUITE = 'conformance/suites/mcp-gateway/'
OLD_ID = 'mcp-valid-noncharacter-id-forwarded'
NEGATIVE_ID = 'mcp-invalid-encoded-noncharacter-id-forwarded'
POSITIVE_ID = 'mcp-valid-supplementary-id-forwarded'
OLD_PATH = SUITE + OLD_ID + '.json'
NEGATIVE_PATH = SUITE + NEGATIVE_ID + '.json'
POSITIVE_PATH = SUITE + POSITIVE_ID + '.json'
GENERATOR = 'scripts/generate_binding_input_migration.py'
MATCH = 'ecl.rule.otel-record-matches-object.v1'
MINIMIZED = 'ecl.rule.otel-record-minimized.v1'
SCHEMA_INVALID = 'ecl.error.schema-invalid.v1'

# Exact accepted migration oracles; corpus metadata is not its own oracle.
RETAINED_NEGATIVE_SHA256 = 'abc3f8d3185c77511dc715a817e9f45631e320bb8091b751a0f768ae5675b890'
EXPECTED_MCP_ROWS = {'mcp-invalid-encoded-noncharacter-id-forwarded': {'covers': [],
                                                   'expected': 'fail',
                                                   'expected_primary_id': 'ecl.error.schema-invalid.v1',
                                                   'expected_secondary_ids': [],
                                                   'id': 'mcp-invalid-encoded-noncharacter-id-forwarded',
                                                   'negates': ['MG1-012'],
                                                   'path': 'conformance/suites/mcp-gateway/mcp-invalid-encoded-noncharacter-id-forwarded.json',
                                                   'requirement_ids': ['MG1-005', 'MG1-010', 'MG1-012'],
                                                   'schema': 'https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1',
                                                   'source': {'generator': 'scripts/generate_binding_input_migration.py',
                                                              'kind': 'authored'},
                                                   'stage': 'binding'},
 'mcp-valid-supplementary-id-forwarded': {'covers': ['https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1##root'],
                                          'expected': 'pass',
                                          'expected_secondary_ids': [],
                                          'id': 'mcp-valid-supplementary-id-forwarded',
                                          'path': 'conformance/suites/mcp-gateway/mcp-valid-supplementary-id-forwarded.json',
                                          'requirement_ids': ['MG1-005', 'MG1-010', 'MG1-012'],
                                          'schema': 'https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1',
                                          'source': {'base_vector': 'conformance/suites/mcp-gateway/mcp-invalid-encoded-noncharacter-id-forwarded.json',
                                                     'generator': 'scripts/generate_binding_input_migration.py',
                                                     'kind': 'mutation',
                                                     'mutation': 'replace the forbidden JSON-RPC ID '
                                                                 'with a valid supplementary scalar in '
                                                                 'every message and recompute the '
                                                                 'terminal response digest'},
                                          'stage': 'binding'}}
EXPECTED_OTEL_ROW = {'covers': [],
 'expected': 'fail',
 'expected_primary_id': 'ecl.rule.otel-record-matches-object.v1',
 'expected_secondary_ids': ['ecl.rule.otel-record-minimized.v1'],
 'id': 'otel-invalid-body-undeclared',
 'negates': ['OE1-004', 'OE1-005'],
 'path': 'conformance/suites/otel-export/otel-invalid-body-undeclared.json',
 'requirement_ids': ['OE1-004', 'OE1-005'],
 'schema': 'https://externalcontrollayer.ai/ns/schema/binding/otel-export/1',
 'source': {'base_vector': 'conformance/suites/otel-export/otel-valid-terminal-event-exported.json',
            'generator': 'scripts/generate_otel_export_vectors.py',
            'kind': 'mutation',
            'mutation': 'export the whole event as an undeclared body'},
 'stage': 'binding'}


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def supplementary_control(value):
    result = copy.deepcopy(value)
    for parent, field in [(result, 'call'), (result['forwarded'], 'request'), (result, 'returned'), (result, 'server_response')]:
        held = parent[field]
        if not isinstance(held, dict) or set(held) != {'rfc8785'}:
            raise ValueError('the retained negative has no encoded content at ' + field)
        # Intentionally decode the retired invalid-I-JSON input as generic JSON to repair it.
        decoded = json.loads(base64.b64decode(held['rfc8785'], validate=True))
        if decoded.get('id') != '\uffff':
            raise ValueError('the retained negative does not have its original noncharacter ID')
        decoded['id'] = '\U0001f511'
        jcs.canonicalize(decoded)  # The corrected content must now have a valid RFC 8785 form.
        parent[field] = decoded  # All remaining values fit the restricted profile.
    for extension in result['terminal']['extensions']:
        if extension['id'] == 'ecl.ext.mcp-binding.v1':
            extension['value']['response_digest'] = jcs.digest(result['server_response'])
    return result


def migrate_mcp(manifest, values, notes):
    """Apply only this accepted post-migration to an older retained MCP reconstruction."""
    entries = manifest['vectors']
    old = next((entry for entry in entries if entry['id'] == OLD_ID), None)
    if old is None:
        return
    negative = copy.deepcopy(old)
    negative.update(id=NEGATIVE_ID, path=NEGATIVE_PATH, expected='fail', expected_primary_id=SCHEMA_INVALID,
                    expected_secondary_ids=[], covers=[], negates=['MG1-012'],
                    source={'kind':'authored', 'generator':GENERATOR})
    positive = copy.deepcopy(old)
    positive.update(id=POSITIVE_ID, path=POSITIVE_PATH, expected='pass', expected_secondary_ids=[],
                    source={'kind':'mutation', 'generator':GENERATOR, 'base_vector':NEGATIVE_PATH,
                            'mutation':'replace the forbidden JSON-RPC ID with a valid supplementary scalar in every message and recompute the terminal response digest'})
    positive.pop('expected_primary_id', None)
    positive.pop('negates', None)
    # The new positive is direct JSON; the dedicated encoded-fraction controls retain MG1-012 coverage.
    positive['covers'] = [item for item in positive.get('covers', []) if '/oneOf#oneOf[1]' not in item]
    index = entries.index(old)
    entries[index:index + 1] = [negative, positive]
    original = values.pop(OLD_PATH)
    values[NEGATIVE_PATH] = copy.deepcopy(original)
    values[POSITIVE_PATH] = supplementary_control(original)
    notes.pop(OLD_PATH, None)
    notes[NEGATIVE_PATH] = 'Preserve the original noncharacter payload as an explicit I-JSON refusal; RFC 8785 cannot admit it by encoding.'
    notes[POSITIVE_PATH] = 'Synthetic valid supplementary-ID control, with unchanged authorization and correctly recomputed terminal response digest.'


def retained_source_path(path, baseline):
    candidate = baseline / Path(path).name
    if not candidate.exists() and path in (NEGATIVE_PATH, POSITIVE_PATH):
        return baseline / Path(OLD_PATH).name
    return candidate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--baseline-dir', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    mcp_path = ROOT / SUITE / 'manifest.json'
    manifest = json.loads(mcp_path.read_bytes())
    input_path = ROOT / (OLD_PATH if (ROOT / OLD_PATH).exists() else NEGATIVE_PATH)
    retained = input_path.read_bytes()
    if hashlib.sha256(retained).hexdigest() != RETAINED_NEGATIVE_SHA256:
        raise SystemExit('retained negative differs from the approved original bytes')
    if args.baseline_dir:
        baseline = args.baseline_dir / Path(OLD_PATH).name
        if baseline.read_bytes() != retained:
            raise SystemExit('retained negative differs from the approved original bytes')
    values = {OLD_PATH: json.loads(retained)}
    notes = {}
    if any(entry['id'] == OLD_ID for entry in manifest['vectors']):
        migrate_mcp(manifest, values, notes)
    else:
        values = {NEGATIVE_PATH: json.loads(retained), POSITIVE_PATH: supplementary_control(json.loads(retained))}
    for name, expected in EXPECTED_MCP_ROWS.items():
        matches = [i for i, row in enumerate(manifest['vectors']) if row['id'] == name]
        if len(matches) != 1:
            raise SystemExit('missing or duplicate migrated MCP vector: ' + name)
        manifest['vectors'][matches[0]] = copy.deepcopy(expected)
    otel_path = ROOT / 'conformance/suites/otel-export/manifest.json'
    otel_manifest = json.loads(otel_path.read_bytes())
    matches = [i for i, row in enumerate(otel_manifest['vectors']) if row['id'] == EXPECTED_OTEL_ROW['id']]
    if len(matches) != 1:
        raise SystemExit('missing or duplicate migrated OTel vector')
    # Registered precedence 862 (matching) precedes 864 (minimization).
    # Preserve both requirement attributions and the complete accepted oracle.
    otel_manifest['vectors'][matches[0]] = copy.deepcopy(EXPECTED_OTEL_ROW)
    outputs = {str(mcp_path.relative_to(ROOT)):encode(manifest), str(otel_path.relative_to(ROOT)):encode(otel_manifest),
               NEGATIVE_PATH:retained, POSITIVE_PATH:encode(values[POSITIVE_PATH])}
    drift = [path for path,data in outputs.items() if not (ROOT/path).exists() or (ROOT/path).read_bytes()!=data]
    if (ROOT/OLD_PATH).exists(): drift.append(OLD_PATH)
    if args.write:
        for path,data in outputs.items(): (ROOT/path).write_bytes(data)
        (ROOT/OLD_PATH).unlink(missing_ok=True)
    report = {'authors_and_producers':['Robert F. Tilley Jr.','G-14, Inc.'], 'drift':drift, 'written':args.write,
              'retained_negative_sha256':hashlib.sha256(retained).hexdigest(),
              'outputs':{path:hashlib.sha256(data).hexdigest() for path,data in outputs.items()},
              'otel_payload_unchanged':True, 'otel_primary_precedence':{MATCH:862, MINIMIZED:864}}
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
    if args.check and drift: raise SystemExit('binding input migration differs from generated output')

if __name__=='__main__':main()
