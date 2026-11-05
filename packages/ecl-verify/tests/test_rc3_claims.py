from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "ecl-verify" / "src"))

from ecl_verify.claims import (  # noqa: E402
    AIBOM_REQUIRED_FIELDS,
    SIX_RESPONSIBILITIES,
    ActionRegisterEntry,
    AssessmentOutcome,
    AssessmentPackage,
    AssessorIndependence,
    ChecklistItem,
    ClaimBoundary,
    ClaimError,
    ConversationalScopeInputs,
    EquivalenceDossier,
    MappingPacket,
    PositioningStatement,
    PublicClaim,
    ReferenceUse,
    RiskScore,
    SystemScopeInputs,
    SectorProfileInvocation,
    SupplierDeliverables,
    TraceBoundary,
    VersionTransition,
    classify_action,
    classify_system_scope,
    classify_conversational_scope,
    validate_aibom,
    validate_procurement_gate,
)


def action() -> ActionRegisterEntry:
    return ActionRegisterEntry(
        action_class_id="ecl.action.payment.v1",
        classification="consequential",
        rationale="mutates financial state",
        affected_resources=("urn:account:1",),
        identities=("urn:actor:1", "urn:subject:1"),
        data_classes=("financial",),
        enforcement_class="hard",
        human_approval_threshold=(
            {
                "parameter": "/amount",
                "unit": "ecl.unit.usd.v1",
                "value": "10000.00",
                "approvers": 2,
            },
        ),
        capability_paths=("tool:payments:submit",),
        witness_posture="fresh balance and account state",
        capability_freeze_scope="payment tool and authority manifest",
        budget_dimensions=("currency:USD",),
        irreversibility_class="ecl.irreversibility.compensatable.v1",
        commit_mode="ecl.commit.two-phase.v1",
        quorum_rule="ecl.quorum.heterogeneous-two.v1",
    )


class Rc3ClaimTests(unittest.TestCase):
    def test_scope_and_action_classification_are_conservative(self) -> None:
        self.assertEqual(
            "in_scope",
            classify_system_scope(SystemScopeInputs(True, True, True)),
        )
        self.assertEqual(
            "in_scope_pending_review",
            classify_system_scope(SystemScopeInputs(True, None, True)),
        )
        flags = {
            "external_state_mutation": False,
            "nonpublic_data_disclosure": False,
            "financial_legal_contractual_identity_infrastructure_network_physical_effect": True,
            "authority_or_reach_expansion": False,
            "material_external_cost_obligation_or_exposure": False,
        }
        self.assertEqual("consequential", classify_action(flags))
        self.assertEqual(
            "non_consequential",
            classify_action({key: False for key in flags}),
        )
        self.assertEqual(
            "out_of_scope_candidate",
            classify_conversational_scope(
                ConversationalScopeInputs(True, True, True, True, True)
            ),
        )
        self.assertEqual(
            "in_scope",
            classify_conversational_scope(
                ConversationalScopeInputs(True, False, True, True, True)
            ),
        )

    def test_trace_models_fanout_models_and_fleet_of_one(self) -> None:
        trace = TraceBoundary(
            root_trace_id="https://externalcontrollayer.ai/ns/trace/1",
            external_action_ids=("https://externalcontrollayer.ai/ns/action/1", "https://externalcontrollayer.ai/ns/action/2"),
            child_parent_links={"https://externalcontrollayer.ai/ns/action/2": "https://externalcontrollayer.ai/ns/action/1"},
            capable_model_ids=frozenset({"urn:model:a", "urn:model:b"}),
            declared_soi_model_ids=frozenset({"urn:model:a", "urn:model:b"}),
            fleet_responsibility_present=True,
        )
        trace.validate()
        with self.assertRaisesRegex(ClaimError, "capable model"):
            TraceBoundary(
                **{
                    **trace.__dict__,
                    "declared_soi_model_ids": frozenset({"urn:model:a"}),
                }
            ).validate()

    def test_claim_boundary_reconciles_runtime_capabilities_and_negative_annex(
        self,
    ) -> None:
        boundary = ClaimBoundary(
            soi_id="https://externalcontrollayer.ai/ns/soi/payments",
            claim_class="bounded-action-class-mediation",
            claimed_level=3,
            action_register=(action(),),
            included_effect_paths=frozenset({"tool:payments:submit"}),
            reachable_effect_paths=frozenset(
                {"tool:payments:submit", "admin:manual-refund"}
            ),
            negative_boundary_paths=frozenset({"admin:manual-refund"}),
            deployment_topology="local hard gate plus sovereign control plane",
            responsibilities=SIX_RESPONSIBILITIES,
            trust_boundaries=("runtime", "gate", "authority", "evidence-store"),
            independence_class="B",
        )
        boundary.validate()
        with self.assertRaisesRegex(ClaimError, "omitted"):
            ClaimBoundary(
                **{**boundary.__dict__, "negative_boundary_paths": frozenset()}
            ).validate()

    def test_high_water_risk_and_public_claim_boundaries(self) -> None:
        self.assertEqual((4, False), RiskScore(2, 3, 4).required_level())
        self.assertEqual((4, True), RiskScore(2, None, 3).required_level())
        claim = PublicClaim(
            soi_id="https://externalcontrollayer.ai/ns/soi/payments",
            level=2,
            status="assessment_only",
            boundary_class="bounded-action-class-mediation",
            independence_class="B",
            core_version="1.0",
            companion_versions=("DCMP-2:2.0", "EBMP-2:2.0"),
            profile_versions=("ecl.profile.local-gate.v1",),
            refreshed_at="2026-07-27T05:00:00Z",
            limitations=("development candidate; no certification claim",),
            framework_name="Example Framework",
            mapping_packet_id="https://externalcontrollayer.ai/ns/mapping/example/1",
            obligation_slice="runtime action admission only",
            residual_gap="organizational controls remain external",
            mapping_validation_state="internally_reviewed",
        )
        claim.validate()
        with self.assertRaisesRegex(ClaimError, "L4"):
            PublicClaim(
                **{
                    **claim.__dict__,
                    "level": 4,
                    "independence_class": "C",
                    "status": "conditional_conformance",
                }
            ).validate()
        PositioningStatement(
            runtime_control_scope_stated=True,
            level_and_boundary_stated=True,
            direct_control_distinguished_from_mapping=True,
        ).validate()
        with self.assertRaisesRegex(ClaimError, "prohibited overclaim"):
            PositioningStatement(
                runtime_control_scope_stated=True,
                level_and_boundary_stated=True,
                direct_control_distinguished_from_mapping=True,
                asserts_automatic_legal_compliance=True,
            ).validate()

    def test_reference_lock_equivalence_and_aibom_are_complete(self) -> None:
        with self.assertRaisesRegex(ClaimError, "version locked"):
            ReferenceUse("living-spec", normative=True).validate()
        ReferenceUse("living-spec", normative=True, version="2026-07").validate()
        SectorProfileInvocation(
            sector="industrial-control",
            applicable_standard="IEC 62443",
            co_normative=True,
            reference=ReferenceUse(
                "IEC 62443",
                normative=True,
                version="locked applicable edition",
            ),
        ).validate()
        EquivalenceDossier(
            replaced_requirement_id="FR-202",
            alternative="isolated hardware gate",
            preserved_property="tamper-resistant enforcement",
            residual_difference="different attestation root",
            expiry_conditions="hardware or trust-root change",
            deny_by_default_preserved=True,
            anti_bypass_preserved=True,
            independence_preserved=True,
            evidence_integrity_preserved=True,
            assessor_decision_id="https://externalcontrollayer.ai/ns/assessor-decision/1",
            independent_validation_id="https://externalcontrollayer.ai/ns/validation/1",
            level=3,
            replaces_hard_property=True,
        ).validate()
        validate_aibom({key: f"value:{key}" for key in AIBOM_REQUIRED_FIELDS})
        VersionTransition(
            breaking=True,
            deprecation_window_days=365,
            emergency_security_fix=False,
            emergency_justification=None,
        ).validate()
        with self.assertRaisesRegex(ClaimError, "deprecation window"):
            VersionTransition(
                breaking=True,
                deprecation_window_days=30,
                emergency_security_fix=False,
                emergency_justification=None,
            ).validate()

    def test_mapping_packet_separates_support_residuals_and_endorsement(self) -> None:
        packet = MappingPacket(
            packet_id="https://externalcontrollayer.ai/ns/mapping/example/1",
            version="1",
            framework="Example Framework",
            framework_edition="2026 immutable edition",
            obligation_classes={
                "clause:runtime-control": "direct_runtime_support",
                "clause:training-data": "out_of_scope",
            },
            ecl_surfaces={
                "clause:runtime-control": ("FR-101", "DCMP2-040"),
                "clause:training-data": (),
            },
            residual_obligations={
                "clause:runtime-control": "organizational monitoring remains",
                "clause:training-data": "entire obligation remains external",
            },
            assumptions=("claimed SoI matches the mapped runtime boundary",),
            validation_state="internally_reviewed",
            updated_at="2026-07-27T05:00:00Z",
        )
        packet.validate()
        with self.assertRaisesRegex(ClaimError, "endorsement"):
            MappingPacket(
                **{**packet.__dict__, "claims_owner_endorsement": True}
            ).validate()

    def test_assessment_package_enforces_independence_na_and_currentness(
        self,
    ) -> None:
        independence = AssessorIndependence(
            level=2,
            assessor_id="https://externalcontrollayer.ai/ns/assessor/1",
            primary_implementer=False,
            managed_operator_within_24_months=False,
            claim_approval_authority_within_24_months=False,
            compensation_contingent_on_claim=False,
            material_affiliate_or_reseller=False,
        )
        package = AssessmentPackage(
            level=2,
            evaluated_at="2026-07-27T05:00:00Z",
            runtime_evidence_observed_at="2026-01-01T00:00:00Z",
            static_artifact=False,
            artifact_hashes={"claim": "a" * 64, "checklist": "b" * 64},
            checklist=(
                ChecklistItem(
                    "check:enforcement",
                    "pass",
                    2,
                    ("https://externalcontrollayer.ai/ns/evidence/enforcement/1",),
                ),
                ChecklistItem(
                    "check:delegation",
                    "not_applicable",
                    2,
                    (),
                    ("https://externalcontrollayer.ai/ns/evidence/no-delegation-path/1",),
                ),
            ),
            soi_boundary_id="https://externalcontrollayer.ai/ns/soi/payments",
            boundary_class="bounded-action-class-mediation",
            negative_boundary_annex_id="https://externalcontrollayer.ai/ns/annex/negative/1",
            fr_coverage_matrix_id="https://externalcontrollayer.ai/ns/matrix/fr-checklist/1",
            structured_claim_decision_id="https://externalcontrollayer.ai/ns/decision/assessment/1",
            findings_id="https://externalcontrollayer.ai/ns/findings/1",
            residual_risk_id="https://externalcontrollayer.ai/ns/risk/1",
            independence_disclosure_id="https://externalcontrollayer.ai/ns/independence/1",
            assessor_independence=independence,
        )
        package.validate()
        with self.assertRaisesRegex(ClaimError, "Not Applicable"):
            AssessmentPackage(
                **{
                    **package.__dict__,
                    "checklist": (
                        ChecklistItem(
                            "check:delegation",
                            "not_applicable",
                            2,
                            (),
                        ),
                    ),
                }
            ).validate()
        AssessmentOutcome(
            checklist_results={"check:enforcement": "pass"},
            finding_severities={"finding:1": "minor"},
            claim_status="full_conformance",
            procurement_decision="award",
        ).validate()
        with self.assertRaisesRegex(ClaimError, "critical finding"):
            AssessmentOutcome(
                checklist_results={"check:enforcement": "fail"},
                finding_severities={"finding:1": "critical"},
                claim_status="full_conformance",
                procurement_decision="award",
            ).validate()
        with self.assertRaisesRegex(ClaimError, "conditional award"):
            validate_procurement_gate(
                level=4,
                regulator_requires_full_closure=True,
                procurement_decision="conditional_award",
            )

    def test_supplier_deliverables_expand_for_level_coupling_and_mapping(
        self,
    ) -> None:
        names = {
            "public_claim",
            "checklist",
            "requirement_evidence_matrix",
            "fr_checklist_matrix",
            "soi_diagram",
            "trust_boundary_diagram",
            "action_register",
            "negative_boundary_annex",
            "declared_timing_case",
            "privilege_matrix",
            "dcmp_request",
            "dcmp_response",
            "ebmp_bundle",
            "redacted_ebmp_bundle",
            "revocation_drill",
            "emergency_drill",
            "incident_response",
            "change_management",
            "independent_assessment",
            "assessor_competency_conflict",
            "structured_claim_decision",
            "findings",
            "residual_risk",
            "independence_disclosure",
            "state_witness_register",
            "capability_manifest",
            "consequence_budget_ledger",
            "irreversibility_commit_modes",
            "quorum_rule",
            "external_mapping_packet",
        }
        SupplierDeliverables(
            level=3,
            artifact_ids={name: f"https://externalcontrollayer.ai/ns/artifact/{name}" for name in names},
            consequence_coupling_invoked=True,
            external_mapping_invoked=True,
        ).validate()
        with self.assertRaisesRegex(ClaimError, "supplier deliverables"):
            SupplierDeliverables(
                level=3,
                artifact_ids={},
                consequence_coupling_invoked=True,
                external_mapping_invoked=True,
            ).validate()


if __name__ == "__main__":
    unittest.main()
