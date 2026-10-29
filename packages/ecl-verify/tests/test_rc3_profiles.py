from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "ecl-verify" / "src"))

from ecl_verify.schema import ecl_format_checker  # noqa: E402


COMMON = ROOT / "schemas" / "ecl-common-v1.schema.json"
SCHEMA_PATHS = {
    "ecl_action_register_v1": ROOT
    / "schemas"
    / "ecl-action-register-v1.schema.json",
    "ecl_assessment_package_v1": ROOT
    / "schemas"
    / "ecl-assessment-package-v1.schema.json",
    "ecl_conformance_claim_v1": ROOT
    / "schemas"
    / "ecl-conformance-claim-v1.schema.json",
    "ecl_mapping_packet_v1": ROOT
    / "schemas"
    / "ecl-mapping-packet-v1.schema.json",
    "ecl_deployment_profile_v1": ROOT
    / "schemas"
    / "ecl-deployment-profile-v1.schema.json",
}


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class Rc3ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = {
            name: load(path) for name, path in SCHEMA_PATHS.items()
        }
        cls.registry = Registry()
        for schema in [load(COMMON), *cls.schemas.values()]:
            cls.registry = cls.registry.with_resource(
                schema["$id"], Resource.from_contents(schema)
            )

    def validator(self, schema_version: str) -> Draft202012Validator:
        return Draft202012Validator(
            self.schemas[schema_version],
            registry=self.registry,
            format_checker=ecl_format_checker(),
        )

    def errors(self, value: dict) -> list:
        return sorted(
            self.validator(value["schema_version"]).iter_errors(value),
            key=lambda error: (list(error.absolute_path), error.message),
        )

    def deployment(self, name: str) -> dict:
        return load(ROOT / "profiles" / "examples" / "deployment" / name)

    def claim_artifact(self, name: str) -> dict:
        return load(ROOT / "profiles" / "examples" / "claims" / name)

    def test_every_profile_and_claim_example_is_schema_valid(self) -> None:
        paths = sorted((ROOT / "profiles" / "examples").rglob("*.json"))
        self.assertGreaterEqual(len(paths), 9)
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT).as_posix()):
                self.assertEqual([], [error.message for error in self.errors(load(path))])

    def test_all_profile_contract_schemas_are_valid_draft_2020_12(self) -> None:
        for schema in self.schemas.values():
            Draft202012Validator.check_schema(schema)

    def test_local_gate_and_network_free_release_path_are_invariants(self) -> None:
        profile = self.deployment("centralized-hosted-local-gate.json")
        profile["delivery_surfaces"].remove("local_gate")
        self.assertTrue(self.errors(profile))

        profile = self.deployment("centralized-hosted-local-gate.json")
        profile["release_path"]["remote_dependency_in_hot_path"] = True
        self.assertTrue(self.errors(profile))

        profile = self.deployment("centralized-hosted-local-gate.json")
        profile["release_path"]["signed_local_or_cached_state"] = False
        self.assertTrue(self.errors(profile))

    def test_each_topology_requires_its_distinguishing_controls(self) -> None:
        cases = [
            ("centralized-hosted-local-gate.json", "centralized"),
            ("federated-local-gate.json", "federated"),
            ("sovereign-self-managed-local-gate.json", "sovereign"),
            ("offline-edge-local-gate.json", "offline"),
            ("air-gapped-local-gate.json", "air_gapped"),
        ]
        for name, key in cases:
            with self.subTest(name=name):
                profile = self.deployment(name)
                del profile["topology_controls"][key]
                self.assertTrue(self.errors(profile))

    def test_nondefault_timing_requires_rationale_assumptions_and_risk(
        self,
    ) -> None:
        profile = self.deployment("offline-edge-local-gate.json")
        profile["timing_case"]["uses_default_baseline"] = False
        self.assertTrue(self.errors(profile))
        profile["timing_case"].update(
            {
                "variance_rationale": "A sector rule requires faster expiration.",
                "control_assumptions": ["The trusted time source remains available."],
                "residual_risk": "Physical transfer can still delay evidence export.",
            }
        )
        self.assertEqual([], self.errors(profile))

    def test_fallback_precedence_and_restricted_actions_are_closed(self) -> None:
        profile = self.deployment("offline-edge-local-gate.json")
        profile["fallback"]["precedence"] = [
            "restricted",
            "emergency_halt",
            "degraded",
            "ordinary",
        ]
        self.assertTrue(self.errors(profile))

        profile = self.deployment("offline-edge-local-gate.json")
        profile["fallback"]["restricted"]["allowed_actions"].append(
            "new_customer_payment"
        )
        self.assertTrue(self.errors(profile))

    def test_claim_requires_every_responsibility_and_rejects_conditional_l4(
        self,
    ) -> None:
        claim = self.claim_artifact("public-assessment-only-claim.json")
        claim["responsibilities"].remove("fleet")
        self.assertTrue(self.errors(claim))

        claim = self.claim_artifact("public-assessment-only-claim.json")
        claim["level"] = 4
        claim["status"] = "conditional_conformance"
        claim["independence"]["class"] = "C"
        claim["conditions"] = [
            {
                "condition_id": "urn:example:condition:1",
                "finding_reference": {
                    "uri": "urn:example:finding:1",
                    "version": "1",
                },
                "remediation": "close the condition",
                "owner": "urn:example:owner:1",
                "deadline": "2026-08-27T12:00:00Z",
                "operating_limit": "no consequential release",
            }
        ]
        self.assertTrue(self.errors(claim))

    def test_direct_mapping_requires_ecl_surface_and_evidence(self) -> None:
        packet = self.claim_artifact("framework-mapping.json")
        direct = packet["obligations"][0]
        direct["ecl_surfaces"] = []
        direct["evidence"] = []
        self.assertTrue(self.errors(packet))

    def test_not_applicable_is_never_an_unsubstantiated_waiver(self) -> None:
        package = self.claim_artifact("assessment-package.json")
        item = package["checklist"][0]
        item["result"] = "not_applicable"
        item["evidence"] = []
        self.assertTrue(self.errors(package))
        item["applicability_false_evidence"] = [
            "urn:example:ecl:evidence:predicate-false"
        ]
        self.assertEqual([], self.errors(package))

    def test_l4_assessment_requires_class_c_and_nonconditional_result(self) -> None:
        package = self.claim_artifact("assessment-package.json")
        package["level"] = 4
        package["claim_decision"]["status"] = "conditional_conformance"
        self.assertTrue(self.errors(package))

        package = self.claim_artifact("assessment-package.json")
        package["level"] = 4
        package["independence"]["class"] = "C"
        self.assertEqual([], self.errors(package))

    def test_examples_are_nonclaims_with_explicit_limitations(self) -> None:
        claim = self.claim_artifact("public-assessment-only-claim.json")
        self.assertEqual("assessment_only", claim["status"])
        limitations = " ".join(claim["limitations"]).lower()
        self.assertIn("not a conformance", limitations)
        self.assertIn("ml-dsa-65", limitations)

    def test_offline_profile_and_deterministic_container_are_bound(self) -> None:
        media = {
            item["id"]: item for item in load(
                ROOT / "registries" / "media-types.json"
            )["entries"]
        }
        container = {
            item["id"]: item for item in load(
                ROOT / "registries" / "operational-values.json"
            )["entries"]
        }
        bundle = media["ecl.media.bundle-zip.v1"]
        profile_path = ROOT / bundle["attributes"]["deterministic_profile"]
        self.assertTrue(profile_path.is_file())
        self.assertEqual(
            "ecl.zip.store.v1",
            bundle["attributes"]["container_profile"],
        )
        self.assertFalse(
            container["ecl.zip.store.v1"]["attributes"]["compression"]
        )

        schema = load(
            ROOT
            / "schemas"
            / "ecl-offline-verification-package-v1.schema.json"
        )
        assembly = schema["properties"]["deterministic_assembly"]
        properties = assembly["properties"]
        self.assertEqual(
            "ecl.zip.store.v1",
            properties["container_profile"]["const"],
        )
        self.assertEqual("zip-stored", properties["storage_policy"]["const"])
