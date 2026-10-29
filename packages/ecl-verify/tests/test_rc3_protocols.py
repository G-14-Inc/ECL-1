from __future__ import annotations

import base64
import copy
import hashlib
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "ecl-verify" / "src"))

from ecl_verify.canonical import (  # noqa: E402
    CanonicalizationError,
    canonicalize,
    load_json_strict,
    loads_json_strict,
    object_id,
)
from ecl_verify.integrity import (  # noqa: E402
    IntegrityError,
    VerificationContext,
    VerificationKey,
    decode_canonical_json_payload,
    signing_input,
    verify_envelope,
)
from ecl_verify.semantic import SemanticValidator  # noqa: E402
from ecl_verify.schema import ecl_format_checker  # noqa: E402


SCHEMA_PATHS = {
    "https://externalcontrollayer.ai/ns/schema/common/1": ROOT / "schemas" / "ecl-common-v1.schema.json",
    "https://externalcontrollayer.ai/ns/schema/integrity-envelope/1": ROOT
    / "schemas"
    / "ecl-integrity-envelope-v1.schema.json",
    "https://externalcontrollayer.ai/ns/schema/dcmp/2": ROOT / "schemas" / "dcmp-2.schema.json",
    "https://externalcontrollayer.ai/ns/schema/ebmp/2": ROOT / "schemas" / "ebmp-2.schema.json",
}


def schema_registry() -> tuple[dict[str, dict], Registry]:
    schemas = {
        uri: load_json_strict(path) for uri, path in SCHEMA_PATHS.items()
    }
    registry = Registry()
    for uri, schema in schemas.items():
        registry = registry.with_resource(uri, Resource.from_contents(schema))
    return schemas, registry


def vector(relative: str) -> dict:
    value = load_json_strict(ROOT / "conformance" / "vectors" / relative)
    assert isinstance(value, dict)
    return value


class Rc3ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas, cls.registry = schema_registry()
        extensions = load_json_strict(ROOT / "registries" / "extensions.json")
        cls.semantic = SemanticValidator(
            item["id"] for item in extensions["entries"]
        )

    def validator(self, uri: str) -> Draft202012Validator:
        return Draft202012Validator(
            self.schemas[uri],
            registry=self.registry,
            format_checker=ecl_format_checker(),
        )

    def assert_schema_valid(self, uri: str, instance: dict) -> None:
        errors = sorted(
            self.validator(uri).iter_errors(instance),
            key=lambda item: (list(item.absolute_path), item.message),
        )
        self.assertEqual([], [error.message for error in errors])

    @staticmethod
    def verification_context(payload: dict) -> VerificationContext:
        policy = payload["integrity_policy"]
        trust = policy["trust_policy"]
        return VerificationContext(
            trust_policy_id=trust["id"],
            trust_policy_version=trust["version"],
            trust_policy_digest=trust["digest"]["value"],
            trust_policy_epoch=trust["epoch"],
            evaluated_at=payload["issued_at"],
            verification_time_policy=policy["verification_time_policy"],
            revocation_policy=policy["revocation_policy"],
            allowed_suites=tuple(policy["accepted_suites"]),
        )

    def test_all_schemas_are_valid_draft_2020_12(self) -> None:
        for schema in self.schemas.values():
            Draft202012Validator.check_schema(schema)

    def test_mandatory_formats_do_not_depend_on_optional_packages(self) -> None:
        request = vector("dcmp-2/valid-decision-request.json")
        invalid_date = copy.deepcopy(request)
        invalid_date["issued_at"] = "2026-02-31T04:30:00Z"
        self.assertTrue(
            list(
                self.validator("https://externalcontrollayer.ai/ns/schema/dcmp/2").iter_errors(
                    invalid_date
                )
            )
        )

        invalid_uri = copy.deepcopy(request)
        invalid_uri["actor"]["id"] = "urn:example:invalid actor"
        self.assertTrue(
            list(
                self.validator("https://externalcontrollayer.ai/ns/schema/dcmp/2").iter_errors(
                    invalid_uri
                )
            )
        )
        for malformed_uri in (
            "urn:example:bad%GG",
            "urn:example:non-ascii-\u2603",
            "https://example.com/bad\\path",
        ):
            invalid_uri = copy.deepcopy(request)
            invalid_uri["actor"]["id"] = malformed_uri
            self.assertTrue(
                list(
                    self.validator("https://externalcontrollayer.ai/ns/schema/dcmp/2").iter_errors(
                        invalid_uri
                    )
                )
            )

    def test_semantic_validator_fails_closed_on_schema_invalid_shapes(
        self,
    ) -> None:
        malformed = {
            "protocol": "DCMP-2",
            "extensions": [{"id": [], "version": "not-an-integer"}],
            "workflow": [],
            "integrity_policy": {
                "required": True,
                "threshold": "one",
                "required_key_ids": {},
                "eligible_key_ids": [],
            },
            "issued_at": "not-a-time",
            "expires_at": {},
        }
        findings = self.semantic.validate(malformed)
        self.assertIn(
            "ecl.error.schema-invalid.v1",
            {item.rule_id for item in findings},
        )

    def test_foundation_vectors_pass_schema_and_semantics(self) -> None:
        cases = [
            ("https://externalcontrollayer.ai/ns/schema/dcmp/2", "dcmp-2/valid-decision-request.json"),
            (
                "https://externalcontrollayer.ai/ns/schema/dcmp/2",
                "dcmp-2/valid-decision-response-admit.json",
            ),
            (
                "https://externalcontrollayer.ai/ns/schema/ebmp/2",
                "ebmp-2/valid-execution-terminal.json",
            ),
        ]
        for schema_uri, path in cases:
            with self.subTest(path=path):
                instance = vector(path)
                self.assert_schema_valid(schema_uri, instance)
                self.assertEqual([], self.semantic.validate(instance))

    def test_deny_cannot_issue_authority(self) -> None:
        instance = vector("dcmp-2/valid-decision-response-admit.json")
        instance["outcome"] = "deny"
        errors = list(
            self.validator("https://externalcontrollayer.ai/ns/schema/dcmp/2").iter_errors(instance)
        )
        self.assertTrue(errors)
        findings = self.semantic.validate(instance)
        self.assertIn(
            "ecl.rule.non-admit-prohibits-authority.v1",
            {item.rule_id for item in findings},
        )

    def test_unknown_critical_extension_fails_semantically(self) -> None:
        instance = vector("dcmp-2/valid-decision-request.json")
        instance["extensions"][0]["id"] = "ecl.ext.unallocated-example.v1"
        self.assert_schema_valid("https://externalcontrollayer.ai/ns/schema/dcmp/2", instance)
        findings = self.semantic.validate(instance)
        self.assertIn(
            "ecl.rule.unknown-critical-extension-rejected.v1",
            {item.rule_id for item in findings},
        )

    def test_reversed_expiry_fails_semantically(self) -> None:
        instance = vector("dcmp-2/valid-decision-request.json")
        instance["expires_at"] = instance["issued_at"]
        self.assert_schema_valid("https://externalcontrollayer.ai/ns/schema/dcmp/2", instance)
        findings = self.semantic.validate(instance)
        self.assertIn(
            "ecl.rule.expiry-after-issue.v1",
            {item.rule_id for item in findings},
        )

    def test_terminal_event_rejects_running_state(self) -> None:
        instance = vector("ebmp-2/valid-execution-terminal.json")
        instance["event"]["state"] = "running"
        self.assert_schema_valid("https://externalcontrollayer.ai/ns/schema/ebmp/2", instance)
        findings = self.semantic.validate(instance)
        self.assertIn(
            "ecl.rule.terminal-execution-state-consistent.v1",
            {item.rule_id for item in findings},
        )

    def test_strict_json_rejects_duplicate_float_negative_zero_and_big_int(
        self,
    ) -> None:
        invalid = [
            '{"a":1,"a":2}',
            '{"a":1.25}',
            '{"a":-0}',
            '{"a":9007199254740992}',
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(CanonicalizationError):
                    loads_json_strict(payload)

    def test_strict_json_has_deterministic_resource_and_cycle_limits(
        self,
    ) -> None:
        with self.assertRaisesRegex(CanonicalizationError, "byte budget"):
            loads_json_strict('{"value":"too large"}', max_bytes=8)
        nested = "[" * 300 + "0" + "]" * 300
        with self.assertRaisesRegex(CanonicalizationError, "nesting budget"):
            loads_json_strict(nested)
        with self.assertRaisesRegex(CanonicalizationError, "invalid strict JSON"):
            loads_json_strict('{"unterminated":')
        cyclic: list = []
        cyclic.append(cyclic)
        with self.assertRaisesRegex(CanonicalizationError, "cyclic"):
            canonicalize(cyclic)

    def test_canonicalization_uses_utf16_property_order(self) -> None:
        value = {
            "\u20ac": "Euro",
            "\r": "CR",
            "\ufb33": "Hebrew",
            "1": "One",
            "\U0001f600": "Emoji",
            "\u0080": "Control",
            "\u00f6": "Latin",
        }
        expected = (
            '{"\\r":"CR","1":"One","\u0080":"Control","\u00f6":"Latin",'
            '"\u20ac":"Euro","\U0001f600":"Emoji","\ufb33":"Hebrew"}'
        ).encode("utf-8")
        self.assertEqual(expected, canonicalize(value))

    def test_object_id_is_stable_across_member_order(self) -> None:
        left = {"b": [2, 3], "a": 1}
        right = {"a": 1, "b": [2, 3]}
        self.assertEqual(object_id(left), object_id(right))

    def test_integrity_envelope_payload_and_domain_separation(self) -> None:
        payload_value = vector("dcmp-2/valid-decision-request.json")
        payload = canonicalize(payload_value)
        envelope = {
            "envelope_version": "ECL-IE-1",
            "payload_type": "application/vnd.ecl.dcmp+json",
            "payload": base64.b64encode(payload).decode("ascii"),
            "payload_digest": {
                "algorithm": "ecl.digest.sha-256.v1",
                "value": hashlib.sha256(payload).hexdigest(),
            },
            "signatures": [
                {
                    "key_id": "urn:example:key:payments-agent-1",
                    "suite_id": "ecl.sig.ed25519.v1",
                    "signature": base64.b64encode(b"placeholder").decode("ascii"),
                }
            ],
        }
        self.assert_schema_valid(
            "https://externalcontrollayer.ai/ns/schema/integrity-envelope/1", envelope
        )
        self.assertEqual(payload_value, decode_canonical_json_payload(envelope))
        self.assertNotEqual(
            signing_input("application/vnd.ecl.dcmp+json", payload),
            signing_input("application/vnd.ecl.ebmp+json", payload),
        )

    def test_integrity_envelope_rejects_payload_digest_mismatch(self) -> None:
        payload = canonicalize({"a": 1})
        envelope = {
            "payload": base64.b64encode(payload).decode("ascii"),
            "payload_digest": {
                "algorithm": "ecl.digest.sha-256.v1",
                "value": "0" * 64,
            },
        }
        with self.assertRaises(IntegrityError):
            decode_canonical_json_payload(envelope)

    def test_ed25519_envelope_verification_is_policy_bound(self) -> None:
        payload_value = vector("dcmp-2/valid-decision-request.json")
        payload = canonicalize(payload_value)
        payload_type = "application/vnd.ecl.dcmp+json"
        private_key = Ed25519PrivateKey.generate()
        signature = private_key.sign(signing_input(payload_type, payload))
        key_id = "urn:example:key:payments-agent-1"
        envelope = {
            "envelope_version": "ECL-IE-1",
            "payload_type": payload_type,
            "payload": base64.b64encode(payload).decode("ascii"),
            "payload_digest": {
                "algorithm": "ecl.digest.sha-256.v1",
                "value": hashlib.sha256(payload).hexdigest(),
            },
            "signatures": [
                {
                    "key_id": key_id,
                    "suite_id": "ecl.sig.ed25519.v1",
                    "signature": base64.b64encode(signature).decode("ascii"),
                }
            ],
        }
        keyring = {
            key_id: VerificationKey(
                key_id=key_id,
                suite_id="ecl.sig.ed25519.v1",
                public_key=private_key.public_key(),
            )
        }
        context = self.verification_context(payload_value)
        result = verify_envelope(envelope, keyring, context)
        self.assertEqual((key_id,), result.valid_key_ids)
        self.assertEqual(payload_value, result.payload)

        altered = copy.deepcopy(envelope)
        altered["payload_type"] = "application/vnd.ecl.ebmp+json"
        with self.assertRaises(IntegrityError):
            verify_envelope(altered, keyring, context)

        altered["signatures"][0]["signature"] = base64.b64encode(
            private_key.sign(
                signing_input(altered["payload_type"], payload)
            )
        ).decode("ascii")
        with self.assertRaisesRegex(
            IntegrityError,
            "payload_type does not match",
        ):
            verify_envelope(altered, keyring, context)


if __name__ == "__main__":
    unittest.main()
