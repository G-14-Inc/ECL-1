"""Focused regressions for the adjudicated public-review primitive repairs.

All signing keys below are public deterministic test material.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ecl_verify.bindings import RECORD_SCHEMAS, binding_findings
from ecl_verify.canonical import canonicalize, object_digest
from ecl_verify.extensions import (
    ExtensionDescriptor, ExtensionError, ExtensionOccurrence, PrivateExtension, process_extensions,
)
from ecl_verify.integrity import (
    IntegrityError, VerificationContext, VerificationKey, signing_input, verify_envelope,
)
from ecl_verify.resources import _limit_exceeded, _semantics, object_findings, registry_document, schema_registry, validator_for
from ecl_verify.schema import _valid_absolute_uri, ecl_format_checker, rfc3339_utc_nanoseconds
from ecl_verify.schema_patterns import schema_validator

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = "ecl.error.schema-invalid.v1"
RESOURCE = "ecl.error.resource-limit-exceeded.v1"
UNIQUE = "ecl.rule.extension-identifiers-unique.v1"
UNKNOWN = "ecl.rule.unknown-critical-extension-rejected.v1"
NAMESPACE = "ecl.rule.extension-namespace-allocated.v1"
VERSION = "ecl.rule.extension-single-version.v1"
POLICY = "ecl.rule.integrity-threshold-consistent.v1"
COUPLING = "ecl.rule.coupling-results-permit-admit.v1"
EXTENSION_VALUE = "ecl.rule.extension-value-valid.v1"
TAG = "com.example.audit-tag.v1"
SUITE = "ecl.sig.ed25519.v1"
KEY_ID = "urn:example:key:public-review"
MEDIA = "application/vnd.ecl.dcmp+json"


def fixture(path):
    return json.loads((ROOT / path).read_text())


def request():
    return fixture("conformance/vectors/dcmp-2/valid-decision-request.json")


def occurrence(identifier=TAG, version=1, critical=False):
    return {"id": identifier, "version": version, "critical": critical, "value": {}}


def rules(value):
    return {finding.rule_id for finding in _semantics().validate(value)}


def complete_binding(path):
    """Retain AARM/ACS controls; reconstruct the full MCP release evidence control."""
    if not path.startswith("mcp-gateway/"):
        return fixture("conformance/suites/" + path)
    value = fixture("conformance/suites/mcp-gateway/mcp-valid-forwarded-release-order.json")
    state = {"status": "current", "reference": {"uri": "urn:example:control-snapshot:mcp-repair",
        "digest": {"algorithm": "ecl.digest.sha-256.v1", "value": "a" * 64}},
        "fresh_until": "2026-09-30T09:01:00.000000Z", "halt": False, "quarantine": False, "revoked": False}
    value["release_observations"] = {
        "initial": {"observed_at": "2026-09-30T09:00:00.200000Z", "control_state": copy.deepcopy(state)},
        "final": {"observed_at": "2026-09-30T09:00:00.300000Z", "control_state": copy.deepcopy(state)},
    }
    return value


class PrimitiveRepairs(unittest.TestCase):
    def test_root025_old_limits_and_exact_boundaries(self):
        for depth, width in [(0, 0), (20, 0), (40, 0), (130, 0), (0, 10_001)]:
            value = request()
            parameters = {"values": [0] * width}
            for _ in range(depth):
                parameters = {"nested": parameters}
            value["action"]["parameters"] = parameters
            value["action"]["parameters_digest"]["value"] = object_digest(parameters)
            with self.subTest(depth=depth, width=width):
                self.assertEqual(object_findings(value), [])
        self.assertIsNone(_limit_exceeded({"a": [0]}, max_depth=2, max_nodes=3))
        self.assertIn("depth", _limit_exceeded({"a": [0]}, max_depth=1, max_nodes=3))
        self.assertIn("node", _limit_exceeded({"a": [0]}, max_depth=2, max_nodes=2))
        self.assertEqual({f.rule_id for f in object_findings(request(), max_nodes=1)}, {RESOURCE})
        self.assertEqual({f.rule_id for f in object_findings(request(), max_depth=True)}, {"ecl.error.configuration-invalid.v1"})

    def test_root016_private_namespace_helpers_and_complete_objects(self):
        allowed = [TAG, "urn:example:audit:v1", "https://example.com/audit", "https://externalcontrollayer.ai@example.com/audit"]
        denied = ["ecl.unallocated.v1", "https://externalcontrollayer.ai/audit", "HTTPS://EXTERNALCONTROLLAYER.AI/audit", "https://user@externalcontrollayer.ai:443/audit"]
        for identifier in allowed + denied:
            with self.subTest(identifier=identifier):
                helper = PrivateExtension(identifier, False, True)
                value = request()
                value["extensions"] = [occurrence(identifier)]
                if identifier in denied:
                    with self.assertRaises(ExtensionError):
                        helper.validate_namespace()
                    self.assertIn(NAMESPACE, rules(value))
                    self.assertTrue(object_findings(value))
                else:
                    helper.validate_namespace()
                    self.assertEqual(object_findings(value), [])

    def test_root026_authority_brackets(self):
        for uri in ["https://user[info]@[::1]/profile", "https://[v1.[a]/profile", "https://[::1]:[80]/profile"]:
            self.assertFalse(_valid_absolute_uri(uri), uri)
        for uri in ["https://[::1]/profile", "https://user:info@[::1]:80/profile", "https://[v1.a]/profile", "https://[fe80::1%25eth0]/profile"]:
            self.assertTrue(_valid_absolute_uri(uri), uri)
        self.assertFalse(_valid_absolute_uri("//example.com/profile"))

    def test_root027_typed_extension_rules_keep_later_findings(self):
        value = request()
        value["extensions"] = [None, occurrence(version=True), occurrence(), occurrence(), occurrence("urn:example:unknown", critical=True)]
        self.assertEqual(rules(value), {UNIQUE, UNKNOWN})
        self.assertIn(SCHEMA, {f.rule_id for f in object_findings(value)})
        value["extensions"] = [occurrence(version=True), occurrence(), occurrence("urn:example:unknown", critical="false")]
        self.assertEqual(rules(value), set())
        for member in ["required", "threshold"]:
            value = request()
            value["integrity_policy"] = {"required": True, "threshold": 1}
            del value["integrity_policy"][member]
            self.assertNotIn(POLICY, rules(value))
        value["integrity_policy"] = {"required": True, "threshold": 0, "eligible_key_ids": None}
        self.assertIn(POLICY, rules(value))  # Independent typed required/threshold relation survives.

    def test_root027_malformed_coupling_outcome_retains_blocker(self):
        value = fixture("conformance/suites/aarm-binding/aarm-valid-allow-released.json")["response"]
        for malformed in [[], {}]:
            target = copy.deepcopy(value)
            target["extensions"].append({"id": "ecl.ext.consequence-coupling.v1", "version": 1, "critical": False,
                "value": {"budget_result": {"outcome": malformed}, "blocker_reason": "ecl.reason.denied.v1"}})
            found = _semantics().validate(target)
            self.assertIn(EXTENSION_VALUE, {f.rule_id for f in found})
            self.assertIn(COUPLING, {f.rule_id for f in found})
            self.assertNotIn(SCHEMA, {f.rule_id for f in found})
            self.assertTrue(any(f.rule_id == COUPLING and f.path.endswith("/blocker_reason") for f in found))

    def test_root056_binding_records_return_findings(self):
        for path, nested in [("aarm-binding/aarm-valid-allow-released.json", False), ("acs-binding/acs-valid-allow-released.json", False), ("mcp-gateway/mcp-valid-forwarded-on-admit.json", True)]:
            original = complete_binding(path)
            baseline = binding_findings(original)
            self.assertEqual(baseline, [])
            for input_class in [[], {}, "review_invalid_class"]:
                value = copy.deepcopy(original)
                response = value["decision"]["response"] if nested else value["response"]
                basis = next(e["value"] for e in response["extensions"] if e["id"] == "ecl.ext.decision-basis.v1")
                basis["inputs"][0]["class"] = input_class
                self.assertTrue(validator_for(RECORD_SCHEMAS[value["schema_version"]]).is_valid(value))
                found = binding_findings(value)
                self.assertTrue(found)
                self.assertTrue(any(EXTENSION_VALUE in f.message or f.rule_id == EXTENSION_VALUE for f in found), found)

    def test_root074_incident_ecmascript_whitespace(self):
        document = fixture("schemas/ecl-incident-scenario-v1.schema.json")
        schema = schema_validator({"$ref": document["$id"] + "#/$defs/uri"}, registry=schema_registry(), format_checker=ecl_format_checker())
        for char, accepted in [("x", True), (" ", False), ("\u0085", True), ("\u00a0", False), ("\u2028", False), ("\ufeff", False)]:
            self.assertEqual(schema.is_valid("urn:example:" + char), accepted, repr(char))

    def test_root070_calendar_controls(self):
        for value in ["2026-10-00T00:00:00Z", "2026-01-00T00:00:00Z", "2025-02-29T00:00:00Z", "2026-04-31T00:00:00Z"]:
            with self.assertRaises(ValueError):
                rfc3339_utc_nanoseconds(value)
        for value in ["2026-09-30T00:00:00Z", "2024-02-29T00:00:00Z", "2000-02-29T00:00:00Z"]:
            rfc3339_utc_nanoseconds(value)

    def test_root078_only_active_descriptors_are_known(self):
        for status in ["active", "deprecated", "prohibited", "superseded", "reserved", None]:
            descriptor = ExtensionDescriptor("ecl.ext.test.v1", 1, ("DCMP-2",), ("extensions",), "urn:example:interpretation", "private", status or "active", "additive", False)
            registry = {} if status is None else {(descriptor.identifier, 1): descriptor}
            for critical in [False, True]:
                value = ExtensionOccurrence(descriptor.identifier, 1, critical, {"test": True})
                if status != "active" and critical:
                    with self.assertRaisesRegex(ExtensionError, "unknown critical"):
                        process_extensions([value], registry=registry, object_type="DCMP-2")
                else:
                    result = process_extensions([value], registry=registry, object_type="DCMP-2")
                    self.assertEqual(len(result.known), int(status == "active"))
                    self.assertEqual(len(result.preserved_unknown_noncritical), int(status != "active"))


class EnvelopeRepairs(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.from_private_bytes(bytes([44]) * 32)
        self.context = VerificationContext("urn:example:policy:review", "1", "ab" * 32, 1,
            "2026-11-09T00:00:00Z", "ecl.time.issued-at.v1", "ecl.revocation.offline-bundle.v1", (SUITE,))
        self.key = VerificationKey(KEY_ID, SUITE, self.private.public_key(), role_purposes=("ecl.purpose.decision-request.v1",))
        self.payload = request()
        self.payload["integrity_policy"] = {"required": True, "threshold": 1, "accepted_suites": [SUITE], "eligible_key_ids": [], "required_key_ids": [],
            "verification_time_policy": self.context.verification_time_policy, "revocation_policy": self.context.revocation_policy,
            "trust_policy": {"id": self.context.trust_policy_id, "version": "1", "epoch": 1, "digest": {"algorithm": "ecl.digest.sha-256.v1", "value": "ab" * 32}}}

    def sign(self, payload=None):
        raw = canonicalize(self.payload if payload is None else payload)
        return {"envelope_version": "ECL-IE-1", "payload_type": MEDIA, "payload": base64.b64encode(raw).decode(),
            "payload_digest": {"algorithm": "ecl.digest.sha-256.v1", "value": hashlib.sha256(raw).hexdigest()},
            "signatures": [{"key_id": KEY_ID, "suite_id": SUITE, "signature": base64.b64encode(self.private.sign(signing_input(MEDIA, raw))).decode()}]}

    def verify(self, envelope):
        return verify_envelope(envelope, {KEY_ID: self.key}, self.context)

    def refused(self, envelope, code):
        with self.assertRaises(IntegrityError) as caught:
            self.verify(envelope)
        self.assertEqual(caught.exception.code, code)

    def test_root015_optional_lists_and_invalid_present_values(self):
        self.verify(self.sign())
        for member in ["eligible_key_ids", "required_key_ids"]:
            value = copy.deepcopy(self.payload)
            del value["integrity_policy"][member]
            self.verify(self.sign(value))
            for invalid in [None, "", [KEY_ID, KEY_ID], [1]]:
                value["integrity_policy"][member] = invalid
                self.refused(self.sign(value), "ecl.error.signature-policy-invalid.v1")

    def test_root032_unknown_dcmp_role_is_ineligible(self):
        self.verify(self.sign())
        for kind in [None, "review_unknown", "control"]:
            value = copy.deepcopy(self.payload)
            if kind is None:
                del value["message_type"]
            else:
                value["message_type"] = kind
            self.refused(self.sign(value), "ecl.error.signature-policy-invalid.v1")

    def test_root071_outer_extensions_and_precedence(self):
        base = self.sign()
        self.verify(base)
        allowed = copy.deepcopy(base)
        allowed["extensions"] = [occurrence()]
        self.verify(allowed)
        for entries, code in [([occurrence(critical=True)], UNKNOWN), ([occurrence(), occurrence()], UNIQUE), ([occurrence(), occurrence(version=2)], VERSION), ([occurrence(), occurrence(), occurrence("urn:example:unknown", critical=True)], UNKNOWN)]:
            target = copy.deepcopy(base)
            target["extensions"] = entries
            self.assertEqual(target["payload"], base["payload"])
            self.assertEqual(target["signatures"], base["signatures"])
            self.refused(target, code)
        target["payload_digest"]["value"] = "00" * 32
        self.refused(target, "ecl.error.integrity-invalid.v1")
        target["signatures"] *= 33
        self.refused(target, RESOURCE)
        invalid_policy = copy.deepcopy(self.payload)
        invalid_policy["integrity_policy"]["required"] = False
        target = self.sign(invalid_policy)
        target["extensions"] = [occurrence(critical=True)]
        self.refused(target, UNKNOWN)

    def test_root081_work_intent_document_policy_findings(self):
        applicable = {e["id"] for e in registry_document("semantic-rules")["entries"] if "ECL-WI-1" in e["attributes"]["applies_to"]}
        original = fixture("conformance/suites/document-coverage/work-intent-valid.json")
        policy = self.payload["integrity_policy"]
        for current, expected in [(None, set()), (policy, set()), ({**policy, "threshold": 0}, {POLICY}),
            ({**policy, "eligible_key_ids": ["urn:example:key:eligible"], "required_key_ids": ["urn:example:key:required"]}, {POLICY})]:
            value = copy.deepcopy(original)
            if current is not None:
                value["integrity_policy"] = current
            self.assertTrue(validator_for("https://externalcontrollayer.ai/ns/schema/work-intent/1").is_valid(value))
            self.assertEqual({f.rule_id for f in _semantics().validate(value) if f.rule_id in applicable}, expected)
        original["extensions"] = [occurrence(critical=True)]
        self.assertEqual({f.rule_id for f in _semantics().validate(original) if f.rule_id in applicable}, {UNKNOWN})


if __name__ == "__main__":
    unittest.main()
