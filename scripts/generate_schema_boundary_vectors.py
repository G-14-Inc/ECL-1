"""Reproduce schema dispatch and namespace regression controls.

Robert F. Tilley Jr.; G-14, Inc.
"""
from pathlib import Path
import copy
import argparse
import json

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
S = args.root
read = lambda p: json.loads((S / p).read_text())
request = read("conformance/vectors/dcmp-2/valid-decision-request.json")
register = read("conformance/suites/document-coverage/register-valid-published-example.json")
cases = []
ns = "ecl.rule.extension-namespace-allocated.v1"
for identifier, reserved in [
    ("https://externalcontrollayer.ai/audit", True),
    ("HTTPS://EXTERNALCONTROLLAYER.AI/audit", True),
    ("https://user:pass@externalcontrollayer.ai:443/audit", True),
    ("https://user@user@externalcontrollayer.ai/audit", True),
    ("http://externalcontrollayer.ai:abc/audit", True),
    ("https://externalcontrollayer%2eai/audit", True),
    ("https://%65xternalcontrollayer.ai/audit", True),
    ("https://externalcontrollayer.ai.example.com/audit", False),
    ("https://externalcontrollayer.ai@example.com/audit", False),
    ("https://example.com/externalcontrollayer.ai", False),
    ("urn:example:extension", False),
    ("com.example.audit.v1", False),
]:
    v = copy.deepcopy(request)
    v["extensions"] = [{"id": identifier, "version": 1, "critical": False, "value": {}}]
    cases.append(dict(name="namespace-"+str(len(cases)), identifier=identifier, value=v,
                      schema="https://externalcontrollayer.ai/ns/schema/dcmp/2",
                      expected_schema=not reserved, expected_rules=[ns] if reserved else []))
for records in [None, [], {}, [{"object_id": "urn:example:unrelated"}]]:
    v = copy.deepcopy(register)
    v["entries"].append(copy.deepcopy(v["entries"][0]))
    if records is not None:
        v["records"] = records
    cases.append(dict(name="register-records-"+str(len(cases)), value=v,
                      schema="https://externalcontrollayer.ai/ns/schema/action-register/1",
                      expected_schema=records is None,
                      expected_rules=["ecl.rule.register-declarations-consistent.v1"]))
for records in [[], {}, [{"object_id": "urn:example:unrelated"}]]:
    v = {"protocol": "ECL-WI-1", "object_id": "urn:example:self",
         "workflow": {"causal_predecessors": [{"id": "urn:example:self"}]}, "records": records}
    cases.append(dict(name="work-intent-records-"+str(len(cases)), value=v,
                      schema=None, expected_rules=["ecl.rule.message-cannot-cause-itself.v1"]))
for value in [{"protocol": "unknown", "records": []}]:
    cases.append(dict(name="untyped-records-"+str(len(cases)), value=value, schema=None, expected_rules=[]))
# XR1-017 is a reservation comparison over an IE1-038 URI. Malformed URI
# inputs remain schema failures, without parser normalization adding a reservation.
for name, identifier, uri_valid, reserved in [
    ('bracketed-userinfo', 'https://a[b]@externalcontrollayer.ai/audit', False, False),
    ('tab-in-host', 'https://externalcontrollayer.\tai/audit', False, False),
    ('cr-in-host', 'https://externalcontrollayer.\rai/audit', False, False),
    ('lf-in-host', 'https://externalcontrollayer.\nai/audit', False, False),
    ('leading-space', ' https://externalcontrollayer.ai/audit', False, False),
    ('leading-tab', '\thttps://externalcontrollayer.ai/audit', False, False),
    ('leading-null', '\x00https://externalcontrollayer.ai/audit', False, False),
    ('leading-unit-separator', '\x1fhttps://externalcontrollayer.ai/audit', False, False),
    ('trailing-tab-in-path', 'https://externalcontrollayer.ai/audit\t', False, False),
    ('space-in-path', 'https://externalcontrollayer.ai/a udit', False, False),
    ('bad-percent-in-path', 'https://externalcontrollayer.ai/%Q0', False, False),
    ('backslash-in-userinfo', 'https://a\\b@externalcontrollayer.ai/audit', False, False),
    ('nonascii-in-path', 'https://externalcontrollayer.ai/café', False, False),
    ('del-in-path', 'https://externalcontrollayer.ai/a\x7f', False, False),
    ('bad-percent-in-host', 'https://externalcontrollayer%Q0ai/audit', False, False),
    ('open-bracket-in-userinfo', 'https://a[b@externalcontrollayer.ai/audit', False, False),
    ('terminal-dot', 'https://externalcontrollayer.ai./audit', True, True),
    ('escaped-terminal-dot', 'https://externalcontrollayer.ai%2E/audit', True, True),
    ('escaped-userinfo-brackets', 'https://a%5Bb%5D@externalcontrollayer.ai/audit', True, True),
    ('brackets-only-in-path', 'https://externalcontrollayer.ai/[a]', True, True),
    ('brackets-only-in-query', 'https://externalcontrollayer.ai/audit?q=[a]', True, True),
    ('percent-encoded-control-in-path', 'https://externalcontrollayer.ai/%09', True, True),
    ('percent-encoded-utf8-in-path', 'https://externalcontrollayer.ai/caf%C3%A9', True, True),
    ('nonreserved-host', 'https://example.com/audit', True, False),
    ('subdomain-neighbor', 'https://sub.externalcontrollayer.ai/audit', True, False),
    ('two-terminal-dots', 'https://externalcontrollayer.ai../audit', True, False),
    ('repeated-encoding', 'https://externalcontrollayer%252eai/audit', True, False),
    ('reserved-character-host-escape', 'https://externalcontrollayer%2fai/audit', True, False),
    ('non-http-scheme', 'ftp://externalcontrollayer.ai/audit', True, False),
    ('empty-authority-path', 'http:/externalcontrollayer.ai/audit', True, False),
    ('ipv6-neighbor', 'https://[::1]/audit', True, False),
    ('invalid-nonreserved-leading-space', ' https://example.com/audit', False, False),
    ('invalid-nonreserved-userinfo-bracket', 'https://a[b]@example.com/audit', False, False),
]:
    v = copy.deepcopy(request)
    v["extensions"] = [{"id": identifier, "version": 1, "critical": False, "value": {}}]
    cases.append(dict(name="namespace-"+name, identifier=identifier, value=v,
                      schema="https://externalcontrollayer.ai/ns/schema/dcmp/2",
                      expected_schema=uri_valid and not reserved,
                      expected_rules=[ns] if reserved else []))
# ECL-WI-1 uses intent_id before the legacy message_id/object_id fallback.
for name, predecessor, object_id, self_reference in [
    ("intent-id-self-reference", "urn:example:self", "urn:example:other", True),
    ("intent-id-nonself-neighbor", "urn:example:other", None, False),
    ("intent-id-before-object-id", "urn:example:other", "urn:example:other", False),
]:
    v = {"protocol": "ECL-WI-1", "intent_id": "urn:example:self",
         "workflow": {"causal_predecessors": [{"id": predecessor}]}}
    if object_id is not None:
        v["object_id"] = object_id
    cases.append(dict(name="work-intent-"+name, value=v, schema=None,
                      expected_rules=["ecl.rule.message-cannot-cause-itself.v1"] if self_reference else []))
dest = S / "tests/fixtures/schema-boundaries.json"
content = json.dumps(cases, indent=2)+"\n"
manifest_path = S / "conformance/manifest.json"
manifest = json.loads(manifest_path.read_text())
# The current complete duplicate-ID oracle, independent of mutable input rows.
expected = {'covers': [],
 'expected': 'fail',
 'expected_primary_id': 'ecl.rule.bundle-object-identifiers-unique.v1',
 'expected_secondary_ids': [],
 'id': 'ebmp2-invalid-duplicate-object-id',
 'negates': ['DCMP2-039', 'DCMP2-043', 'EBMP2-002', 'EBMP2-032'],
 'path': 'conformance/vectors/bundles/invalid-duplicate-object-id.json',
 'requirement_ids': ['DCMP2-039', 'DCMP2-043', 'EBMP2-002', 'EBMP2-032'],
 'source': {'base_vector': 'conformance/vectors/ebmp-2/valid-execution-terminal.json',
            'generator': 'scripts/generate_foundation_vectors.py',
            'kind': 'mutation',
            'mutation': 'duplicate one immutable object identifier'},
 'stage': 'bundle'}
matches = [i for i, row in enumerate(manifest['vectors']) if row['id'] == expected['id']]
if len(matches) != 1:
    raise SystemExit('missing or duplicate duplicate-ID vector')
manifest['vectors'][matches[0]] = expected
outputs = {dest: content, manifest_path: json.dumps(manifest, indent=2)+"\n"}
if args.check:
    drift = [str(path.relative_to(S)) for path, data in outputs.items() if not path.is_file() or path.read_text() != data]
    if drift:
        raise SystemExit("Generated schema boundary drift: " + ", ".join(drift))
else:
    for path, data in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
print(f"Schema boundary controls: {len(cases)}; exact duplicate-ID oracle migration checked")
