#!/usr/bin/env python3
"""Deterministic telemetry and OAuth boundary regression records.

All records and signing/export keys are synthetic public test material.
Robert F. Tilley Jr.; G-14, Inc.
"""
from pathlib import Path
import argparse
import base64
import copy
import importlib.util
import json

from ecl_verify.bindings import jose, oauth, otel

ROOT = Path(__file__).resolve().parents[1]
SUITE = Path("tests/fixtures/export-authority-boundaries")

def build(root=ROOT):
    files, cases = {}, []
    def read(path): return json.loads((root / path).read_bytes())
    def add(name, record, expected, requirements):
        schema = otel.EXPORT_SCHEMA if record["schema_version"] == otel.EXPORT_VERSION else oauth.PRESENTATION_SCHEMA
        files[SUITE / (name + ".json")] = record
        cases.append({"id": name, "file": name + ".json", "schema": schema,
                      "expected_rules": sorted(expected), "requirement_ids": requirements})
    keys_data = read(Path("tests/fixtures/binding-input-consistency/export-keys.json"))
    keys = otel.load_export_keys(json.dumps(keys_data).encode())
    files[SUITE / "export-keys.json"] = keys_data
    def attribute(record, name):
        return next(row for row in record["log_record"]["attributes"] if row["key"] == name)
    def refresh(record):
        record["evidence_after"] = copy.deepcopy(record["object"])
        key = keys[attribute(record, otel.KEY_ID)["value"]["stringValue"]]
        attribute(record, otel.OBJECT_DIGEST)["value"] = {"stringValue": key.digest(record["object"])}

    base = read(Path("tests/fixtures/binding-input-consistency/declared-custom-correlation-object-raw-bytes.json"))
    raw = b"\xfb\xff" + bytes.fromhex(otel.object_digest_hex(base["object"])) + b"\x00"
    standard = base64.b64encode(raw).decode()
    encodings = {"standard-padded": standard, "standard-unpadded": standard.rstrip("="),
                 "url-padded": base64.urlsafe_b64encode(raw).decode(),
                 "url-unpadded": base64.urlsafe_b64encode(raw).decode().rstrip("="),
                 "mixed-padded": standard.replace("+", "-")}
    assert "+" in standard and "/" in standard
    for name, encoded in encodings.items():
        record = copy.deepcopy(base)
        attribute(record, "custom.correlation")["value"] = {"bytesValue": encoded}
        add("otel-digest-" + name, record, [otel.MATCH_RULE], ["OE1-004", "OE1-007"])
    record = copy.deepcopy(base)
    hex_bytes = b"\xfb\xff" + otel.object_digest_hex(base["object"]).encode()
    attribute(record, "custom.correlation")["value"] = {"bytesValue": base64.urlsafe_b64encode(hex_bytes).decode()}
    add("otel-digest-url-hex-bytes", record, [otel.MATCH_RULE], ["OE1-004", "OE1-007"])
    record = copy.deepcopy(base)
    attribute(record, "custom.correlation")["value"] = {"bytesValue": base64.urlsafe_b64encode(b"\xfb\xffunrelated").decode()}
    add("otel-unrelated-url-bytes-control", record, [], ["OE1-004", "OE1-007"])
    for name, payload, expected in [("digest", raw, [otel.MATCH_RULE]), ("unrelated", b"\xfb\xffunrelated", [])]:
        record = copy.deepcopy(base)
        record["log_record"]["attributes"] = [row for row in record["log_record"]["attributes"] if row["key"] != "custom.correlation"]
        record["declared_attributes"] = [{"name": "body", "data_class": "synthetic-boundary-test"}]
        record["log_record"]["body"] = {"arrayValue": {"values": [{"kvlistValue": {"values": [{"key": "nested", "value": {"bytesValue": base64.urlsafe_b64encode(payload).decode().rstrip("=")}}]}}]}}
        add("otel-nested-url-" + name, record, expected, ["OE1-004", "OE1-005", "OE1-007"])

    source = Path("conformance/suites/otel-export/otel-valid-admit-response-exported.json")
    base = read(source)
    slots = [("ecl.policy.id", ("policy", "id")), ("ecl.object.id", ("message_id",)),
             ("ecl.decision.id", ("decision_id",)), ("ecl.authorization.id", ("authorization", "authorization_id")),
             ("ecl.request.id", ("request_id",)), ("ecl.workflow.id", ("workflow", "workflow_id")),
             ("ecl.workflow.root_trace_id", ("workflow", "root_trace_id")), ("ecl.issuer.id", ("issuer", "id"))]
    for slot, parts in slots:
        record = copy.deepcopy(base)
        identifier = "https://externalcontrollayer.ai/ns/test/sha256/" + record["object"]["policy"]["digest"]["value"]
        owner = record["object"]
        for part in parts[:-1]: owner = owner[part]
        owner[parts[-1]] = identifier
        attribute(record, slot)["value"] = {"stringValue": identifier}
        refresh(record)
        add("otel-table-" + slot.replace(".", "-"), record, [], ["OE1-003", "OE1-004"])
        if slot == "ecl.policy.id":
            for location in ["extra", "body", "wrong-slot"]:
                bad = copy.deepcopy(record)
                if location == "extra":
                    bad.setdefault("declared_attributes", []).append({"name": "custom.copy", "data_class": "synthetic-boundary-test"})
                    bad["log_record"]["attributes"].append({"key": "custom.copy", "value": {"stringValue": identifier}})
                elif location == "body":
                    bad.setdefault("declared_attributes", []).append({"name": "body", "data_class": "synthetic-boundary-test"})
                    bad["log_record"]["body"] = {"stringValue": identifier}
                else:
                    attribute(bad, "ecl.issuer.id")["value"] = {"stringValue": identifier}
                add("otel-table-identifier-copy-" + location, bad, [otel.MATCH_RULE], ["OE1-003", "OE1-004"])
    for file, slot, parts, digest_parts in [
        ("otel-valid-terminal-event-exported.json", "ecl.event.decision_id", ("event", "decision", "uri"), ("event", "decision", "digest", "value")),
        ("otel-valid-request-event-exported.json", "ecl.request.id", ("event", "request", "uri"), ("event", "request", "digest", "value")),
    ]:
        record = read(Path("conformance/suites/otel-export") / file)
        digest = record["object"]
        for part in digest_parts: digest = digest[part]
        identifier = "https://externalcontrollayer.ai/ns/test/sha256/" + digest
        owner = record["object"]
        for part in parts[:-1]: owner = owner[part]
        owner[parts[-1]] = identifier; attribute(record, slot)["value"] = {"stringValue": identifier}; refresh(record)
        add("otel-event-table-" + slot.replace(".", "-"), record, [], ["OE1-003", "OE1-004"])
    for slot, parts in [("ecl.action.id", ("event", "action_id")), ("ecl.producer.id", ("producer", "id")), ("ecl.evidence.bundle", ())]:
        record = read(Path("conformance/suites/otel-export/otel-valid-terminal-event-exported.json"))
        identifier = "https://externalcontrollayer.ai/ns/test/sha256/" + record["object"]["event"]["decision"]["digest"]["value"]
        if parts:
            owner = record["object"]
            for part in parts[:-1]: owner = owner[part]
            owner[parts[-1]] = identifier
        else:
            record["bundle_id"] = identifier
        attribute(record, slot)["value"] = {"stringValue": identifier}; refresh(record)
        add("otel-event-table-" + slot.replace(".", "-"), record, [], ["OE1-003", "OE1-004"])
    record = copy.deepcopy(base)
    record["object"]["policy"]["version"] = record["object"]["policy"]["digest"]["value"]
    attribute(record, "ecl.policy.version")["value"] = {"stringValue": record["object"]["policy"]["version"]}
    refresh(record)
    add("otel-nonidentifier-table-digest-refused", record, [otel.MATCH_RULE], ["OE1-004"])

    spec = importlib.util.spec_from_file_location("boundary_signed_fixtures", root / "scripts/generate_repair_bindings_vectors.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); module.ROOT = root
    def resign(record, confirmation):
        header, claims, _, _ = jose.decode(record["token"])
        claims["cnf"] = confirmation
        record["token"] = module.jws(header, claims, module.issuer)
    certificate = jose.b64url(bytes(range(32)))
    base = module.oauth_record()
    resign(base, {"x5t#S256": certificate})
    base["presentation"].pop("dpop_proof")
    base["presentation"]["client_certificate_sha256"] = certificate
    add("oauth-mtls-control", copy.deepcopy(base), [], ["OA1-004"])
    record = copy.deepcopy(base); record["presentation"]["use_count"] = 2
    record["result"] = {"accepted": False, "error": "ecl.error.replay.v1"}
    add("oauth-mtls-replay-refusal-control", record, [], ["OA1-004", "OA1-011"])
    for extra, extra_value in [("jkt", certificate), ("jkt-null", None), ("other", "unregistered")]:
        record = copy.deepcopy(base)
        confirmation = {"x5t#S256": certificate, "jkt" if extra == "jkt-null" else extra: extra_value}
        resign(record, confirmation)
        add("oauth-cnf-" + extra + "-accepted", copy.deepcopy(record), [oauth.ISSUE_RULE, oauth.PRESENTATION_RULE], ["OA1-004"])
        record["presentation"]["use_count"] = 2
        record["result"] = {"accepted": False, "error": "ecl.error.integrity-invalid.v1"}
        add("oauth-cnf-" + extra + "-integrity-before-replay", copy.deepcopy(record), [oauth.ISSUE_RULE], ["OA1-004", "OA1-011"])
        record["result"]["error"] = "ecl.error.replay.v1"
        add("oauth-cnf-" + extra + "-wrong-replay-refusal", record, [oauth.ISSUE_RULE, oauth.REFUSAL_RULE], ["OA1-004", "OA1-011"])
    record = module.oauth_record()
    _, claims, _, _ = jose.decode(record["token"])
    resign(record, {**claims["cnf"], "other": "unregistered"})
    header, proof, _, _ = jose.decode(record["presentation"]["dpop_proof"])
    proof["ath"] = jose.token_hash(record["token"])
    record["presentation"]["dpop_proof"] = module.jws(header, proof, module.sender)
    add("oauth-cnf-dpop-extra-accepted", copy.deepcopy(record), [oauth.ISSUE_RULE, oauth.PRESENTATION_RULE], ["OA1-004"])
    record["presentation"]["target"] = "urn:example:wrong-target"
    record["result"] = {"accepted": False, "error": "ecl.error.integrity-invalid.v1"}
    add("oauth-cnf-dpop-extra-integrity-before-scope", record, [oauth.ISSUE_RULE], ["OA1-004", "OA1-011"])
    for name, uri, target in [
        ("normal-spelling", "HTTPS://EXAMPLE.com:443/a/../b%2f?x=1#part", "https://EXAMPLE.com:443/a/../b%2f"),
        ("https-single-slash", "https:/v1/action?x=1", "https:/v1/action"),
        ("https-empty-authority", "https:///v1/action?x=1", "https:///v1/action"),
        ("custom-empty-authority", "custom:///v1/action?x=1", "custom:///v1/action"),
        ("custom-single-slash", "custom:/v1/action?x=1", "custom:/v1/action"),
    ]:
        record = module.oauth_record(proof_change={"htu": target})
        record["presentation"]["uri"] = uri
        add("oauth-htu-" + name, record, [], ["OA1-004"])
        if name in ["https-single-slash", "custom-empty-authority"]:
            wrong = "https:///v1/action" if name == "https-single-slash" else "custom:/v1/action"
            record = module.oauth_record(proof_change={"htu": wrong}); record["presentation"]["uri"] = uri
            add("oauth-htu-" + name + "-changed-spelling", record, [oauth.PRESENTATION_RULE], ["OA1-004"])
    files[SUITE / "manifest.json"] = {"cases": cases}
    return {path: (json.dumps(value, indent=2, sort_keys=True) + "\n").encode() for path, value in files.items()}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--check", action="store_true"); args = parser.parse_args()
    for relative, content in build().items():
        target = ROOT / relative
        if args.check:
            if not target.is_file() or target.read_bytes() != content: raise SystemExit("stale boundary fixture: " + str(relative))
        else:
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(content)
