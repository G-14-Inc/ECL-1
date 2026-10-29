"""Scope, claim, mapping, equivalence, and assessment-package validation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Mapping

from .schema import parse_rfc3339_utc


class ClaimError(ValueError):
    """Raised when a conformance or mapping claim exceeds its evidence."""


SIX_RESPONSIBILITIES = frozenset(
    {
        "decision",
        "authority",
        "enforcement",
        "provenance",
        "verification",
        "fleet",
    }
)


def _time(value: str) -> datetime:
    """An ECL RFC 3339 UTC instant, by the shared parser (one to nine fractional digits)."""
    try:
        return parse_rfc3339_utc(value)
    except ValueError as exc:
        raise ClaimError(f"invalid UTC timestamp: {value!r}") from exc

@dataclass(frozen=True)
class SystemScopeInputs:
    can_initiate_without_per_action_human_authorization: bool | None
    has_consequential_action: bool | None
    open_or_partially_open_world: bool | None


def classify_system_scope(inputs: SystemScopeInputs) -> str:
    values = (
        inputs.can_initiate_without_per_action_human_authorization,
        inputs.has_consequential_action,
        inputs.open_or_partially_open_world,
    )
    if any(value is None for value in values):
        return "in_scope_pending_review"
    return "in_scope" if all(values) else "out_of_scope_candidate"


CONSEQUENTIAL_FLAGS = frozenset(
    {
        "external_state_mutation",
        "nonpublic_data_disclosure",
        "financial_legal_contractual_identity_infrastructure_network_physical_effect",
        "authority_or_reach_expansion",
        "material_external_cost_obligation_or_exposure",
    }
)


def classify_action(flags: Mapping[str, bool | None]) -> str:
    if set(flags) != CONSEQUENTIAL_FLAGS:
        raise ClaimError("action classification does not evaluate every rule")
    if any(value is None for value in flags.values()):
        return "consequential_pending_review"
    if any(flags.values()):
        return "consequential"
    return "non_consequential"


@dataclass(frozen=True)
class ConversationalScopeInputs:
    view_or_draft_only: bool | None
    nonpublic_data_stays_within_permitted_view: bool | None
    creates_no_consequential_effect: bool | None
    not_consumed_as_downstream_action_channel: bool | None
    invokes_or_materially_advances_no_consequential_action: bool | None


def classify_conversational_scope(inputs: ConversationalScopeInputs) -> str:
    values = (
        inputs.view_or_draft_only,
        inputs.nonpublic_data_stays_within_permitted_view,
        inputs.creates_no_consequential_effect,
        inputs.not_consumed_as_downstream_action_channel,
        inputs.invokes_or_materially_advances_no_consequential_action,
    )
    if any(value is None for value in values):
        return "in_scope_pending_review"
    return "out_of_scope_candidate" if all(values) else "in_scope"


@dataclass(frozen=True)
class TraceBoundary:
    root_trace_id: str
    external_action_ids: tuple[str, ...]
    child_parent_links: Mapping[str, str]
    capable_model_ids: frozenset[str]
    declared_soi_model_ids: frozenset[str]
    fleet_responsibility_present: bool

    def validate(self) -> None:
        if (
            not self.root_trace_id
            or not self.external_action_ids
            or len(self.external_action_ids) != len(set(self.external_action_ids))
        ):
            raise ClaimError("action trace identity is incomplete or ambiguous")
        children = set(self.child_parent_links)
        if children - set(self.external_action_ids):
            raise ClaimError("child linkage references an unknown action")
        if set(self.child_parent_links.values()) - set(self.external_action_ids):
            raise ClaimError("child linkage references an unknown parent")
        if self.capable_model_ids - self.declared_soi_model_ids:
            raise ClaimError("capable model is omitted from the System of Interest")
        if not self.fleet_responsibility_present:
            raise ClaimError("fleet-of-one responsibility is missing")


@dataclass(frozen=True)
class PositioningStatement:
    runtime_control_scope_stated: bool
    level_and_boundary_stated: bool
    direct_control_distinguished_from_mapping: bool
    asserts_liveness_guarantee: bool = False
    asserts_business_outcome_guarantee: bool = False
    asserts_universal_model_correctness: bool = False
    asserts_automatic_legal_compliance: bool = False
    asserts_framework_certification: bool = False
    asserts_external_owner_endorsement: bool = False

    def validate(self) -> None:
        if not all(
            (
                self.runtime_control_scope_stated,
                self.level_and_boundary_stated,
                self.direct_control_distinguished_from_mapping,
            )
        ):
            raise ClaimError("positioning statement omits its runtime claim boundary")
        prohibited = (
            self.asserts_liveness_guarantee,
            self.asserts_business_outcome_guarantee,
            self.asserts_universal_model_correctness,
            self.asserts_automatic_legal_compliance,
            self.asserts_framework_certification,
            self.asserts_external_owner_endorsement,
        )
        if any(prohibited):
            raise ClaimError("positioning statement makes a prohibited overclaim")


@dataclass(frozen=True)
class ActionRegisterEntry:
    action_class_id: str
    classification: str
    rationale: str
    affected_resources: tuple[str, ...]
    identities: tuple[str, ...]
    data_classes: tuple[str, ...]
    enforcement_class: str
    # ECL1N-0177: the register's human_approval_threshold list, each threshold naming a
    # parameter or a measure with its unit, value and approvers, or None when the class has none.
    human_approval_threshold: tuple[Mapping[str, object], ...] | None
    capability_paths: tuple[str, ...]
    witness_posture: str | None = None
    capability_freeze_scope: str | None = None
    budget_dimensions: tuple[str, ...] = ()
    irreversibility_class: str | None = None
    commit_mode: str | None = None
    quorum_rule: str | None = None

    def validate(self) -> None:
        if (
            not self.action_class_id
            or self.classification
            not in {
                "consequential",
                "non_consequential",
                "consequential_pending_review",
            }
            or not self.rationale
            or self.enforcement_class not in {"soft", "hard"}
        ):
            raise ClaimError("consequential action register entry is incomplete")
        if self.classification == "consequential" and not self.capability_paths:
            raise ClaimError("consequential action lacks reachable capability paths")


@dataclass(frozen=True)
class ClaimBoundary:
    soi_id: str
    claim_class: str
    claimed_level: int
    action_register: tuple[ActionRegisterEntry, ...]
    included_effect_paths: frozenset[str]
    reachable_effect_paths: frozenset[str]
    negative_boundary_paths: frozenset[str]
    deployment_topology: str
    responsibilities: frozenset[str]
    trust_boundaries: tuple[str, ...]
    independence_class: str

    def validate(self) -> None:
        if self.claim_class not in {
            "full-system-mediation",
            "bounded-action-class-mediation",
            "component-or-profile-implementation",
        }:
            raise ClaimError("unknown claim boundary class")
        if self.claimed_level not in {1, 2, 3, 4}:
            raise ClaimError("claimed level is invalid")
        if (
            not self.soi_id
            or not self.action_register
            or not self.deployment_topology
            or not self.trust_boundaries
        ):
            raise ClaimError("System of Interest boundary is incomplete")
        for entry in self.action_register:
            entry.validate()
        if self.responsibilities != SIX_RESPONSIBILITIES:
            raise ClaimError("claim does not preserve all six responsibilities")
        accounted = self.included_effect_paths | self.negative_boundary_paths
        omitted = self.reachable_effect_paths - accounted
        if omitted:
            raise ClaimError(f"reachable effect paths are omitted: {sorted(omitted)}")
        registered = {
            path for entry in self.action_register for path in entry.capability_paths
        }
        unregistered = self.reachable_effect_paths - registered
        if unregistered - self.negative_boundary_paths:
            raise ClaimError(
                "runtime capability inventory is not reconciled to the action register"
            )


@dataclass(frozen=True)
class RiskScore:
    autonomy_level: int | None
    data_level: int | None
    consequence_level: int | None

    def required_level(self) -> tuple[int, bool]:
        values = (self.autonomy_level, self.data_level, self.consequence_level)
        known = [value for value in values if value is not None]
        if any(value not in {1, 2, 3, 4} for value in known):
            raise ClaimError("risk dimension is outside L1-L4")
        if len(known) == 3:
            return max(known), False
        baseline = max(known, default=1)
        return min(4, baseline + 1), True


MINIMUM_INDEPENDENCE = {1: "A", 2: "B", 3: "B", 4: "C"}
INDEPENDENCE_RANK = {"A": 1, "B": 2, "C": 3}


@dataclass(frozen=True)
class PublicClaim:
    soi_id: str
    level: int
    status: str
    boundary_class: str
    independence_class: str
    core_version: str
    companion_versions: tuple[str, ...]
    profile_versions: tuple[str, ...]
    refreshed_at: str
    limitations: tuple[str, ...]
    class_a_disclosure: str | None = None
    framework_name: str | None = None
    mapping_packet_id: str | None = None
    obligation_slice: str | None = None
    residual_gap: str | None = None
    mapping_validation_state: str | None = None
    consecutive_conditional_periods: int = 0
    borrowed_endorsement: bool = False

    def validate(self) -> None:
        if (
            not self.soi_id
            or self.level not in {1, 2, 3, 4}
            or self.status
            not in {
                "full_conformance",
                "conditional_conformance",
                "assessment_only",
            }
            or self.boundary_class
            not in {
                "full-system-mediation",
                "bounded-action-class-mediation",
                "component-or-profile-implementation",
            }
            or self.independence_class not in INDEPENDENCE_RANK
            or not self.core_version
            or not self.companion_versions
        ):
            raise ClaimError("minimum public claim statement is incomplete")
        _time(self.refreshed_at)
        if INDEPENDENCE_RANK[self.independence_class] < INDEPENDENCE_RANK[
            MINIMUM_INDEPENDENCE[self.level]
        ]:
            raise ClaimError("claim independence class is below the level minimum")
        if self.independence_class == "A" and not self.class_a_disclosure:
            raise ClaimError("Class A claim lacks same-operator disclosure")
        if self.level == 4 and self.status == "conditional_conformance":
            raise ClaimError("L4 cannot claim conditional conformance")
        if (
            self.status == "conditional_conformance"
            and self.consecutive_conditional_periods > 2
        ):
            raise ClaimError("conditional conformance requires full reassessment")
        mapping_values = (
            self.framework_name,
            self.mapping_packet_id,
            self.obligation_slice,
            self.residual_gap,
            self.mapping_validation_state,
        )
        if any(mapping_values) and not all(mapping_values):
            raise ClaimError("external framework claim is incomplete")
        if self.borrowed_endorsement:
            raise ClaimError("claim asserts unproven external endorsement")


@dataclass(frozen=True)
class ReferenceUse:
    identifier: str
    normative: bool
    version: str | None = None
    date: str | None = None
    immutable_digest: str | None = None

    def validate(self) -> None:
        if not self.identifier:
            raise ClaimError("reference identifier is required")
        if self.normative and not (
            self.version or self.date or self.immutable_digest
        ):
            raise ClaimError("normative living reference is not version locked")


@dataclass(frozen=True)
class SectorProfileInvocation:
    sector: str
    applicable_standard: str
    co_normative: bool
    reference: ReferenceUse

    def validate(self) -> None:
        if self.sector in {"industrial-control", "automotive-safety"}:
            if not self.applicable_standard or not self.co_normative:
                raise ClaimError("applicable sector controls are not co-normative")
            self.reference.validate()


@dataclass(frozen=True)
class EquivalenceDossier:
    replaced_requirement_id: str
    alternative: str
    preserved_property: str
    residual_difference: str
    expiry_conditions: str
    deny_by_default_preserved: bool
    anti_bypass_preserved: bool
    independence_preserved: bool
    evidence_integrity_preserved: bool
    assessor_decision_id: str
    independent_validation_id: str | None
    level: int
    replaces_hard_property: bool

    def validate(self) -> None:
        required = (
            self.replaced_requirement_id,
            self.alternative,
            self.preserved_property,
            self.residual_difference,
            self.expiry_conditions,
            self.assessor_decision_id,
        )
        if any(not value for value in required):
            raise ClaimError("equivalence dossier is incomplete")
        if not all(
            (
                self.deny_by_default_preserved,
                self.anti_bypass_preserved,
                self.independence_preserved,
                self.evidence_integrity_preserved,
            )
        ):
            raise ClaimError("equivalence weakens a protected core property")
        if (
            self.level >= 3
            and self.replaces_hard_property
            and not self.independent_validation_id
        ):
            raise ClaimError("high-assurance equivalence lacks independent validation")


MAPPING_CLASSES = frozenset(
    {"direct_runtime_support", "supporting_evidence_only", "out_of_scope"}
)


@dataclass(frozen=True)
class MappingPacket:
    packet_id: str
    version: str
    framework: str
    framework_edition: str
    obligation_classes: Mapping[str, str]
    ecl_surfaces: Mapping[str, tuple[str, ...]]
    residual_obligations: Mapping[str, str]
    assumptions: tuple[str, ...]
    validation_state: str
    updated_at: str
    claims_owner_endorsement: bool = False

    def validate(self) -> None:
        if (
            not self.packet_id
            or not self.version
            or not self.framework
            or not self.framework_edition
            or not self.obligation_classes
            or set(self.obligation_classes.values()) - MAPPING_CLASSES
            or not self.assumptions
            or self.validation_state
            not in {"draft", "internally_reviewed", "externally_reviewed"}
        ):
            raise ClaimError("mapping packet is incomplete")
        _time(self.updated_at)
        for obligation in self.obligation_classes:
            if obligation not in self.ecl_surfaces:
                raise ClaimError("mapping obligation lacks cited ECL surface")
            if obligation not in self.residual_obligations:
                raise ClaimError("mapping obligation lacks residual disclosure")
        if self.claims_owner_endorsement:
            raise ClaimError("mapping borrows unproven framework-owner endorsement")


@dataclass(frozen=True)
class VersionTransition:
    breaking: bool
    deprecation_window_days: int
    emergency_security_fix: bool
    emergency_justification: str | None

    def validate(self) -> None:
        if not self.breaking:
            return
        if self.deprecation_window_days >= 365:
            return
        if not self.emergency_security_fix or not self.emergency_justification:
            raise ClaimError("breaking change lacks the minimum deprecation window")


@dataclass(frozen=True)
class AssessmentOutcome:
    checklist_results: Mapping[str, str]
    finding_severities: Mapping[str, str]
    claim_status: str
    procurement_decision: str

    def validate(self) -> None:
        if (
            not self.checklist_results
            or set(self.checklist_results.values())
            - {"pass", "fail", "not_applicable"}
            or set(self.finding_severities.values())
            - {"critical", "major", "minor"}
            or self.claim_status
            not in {"full_conformance", "conditional_conformance", "assessment_only"}
            or self.procurement_decision
            not in {"award", "conditional_award", "deny", "defer"}
        ):
            raise ClaimError("assessment hierarchy is incomplete or conflated")
        if "critical" in self.finding_severities.values() and self.claim_status != "assessment_only":
            raise ClaimError("critical finding cannot produce a conformance claim")


def validate_procurement_gate(
    *,
    level: int,
    regulator_requires_full_closure: bool,
    procurement_decision: str,
) -> None:
    if (
        level == 4
        and regulator_requires_full_closure
        and procurement_decision == "conditional_award"
    ):
        raise ClaimError("L4 regulated operation cannot use conditional award")


@dataclass(frozen=True)
class AssessorIndependence:
    level: int
    assessor_id: str
    primary_implementer: bool
    managed_operator_within_24_months: bool
    claim_approval_authority_within_24_months: bool
    compensation_contingent_on_claim: bool
    material_affiliate_or_reseller: bool
    published_sector_exception: str | None = None

    def validate(self) -> None:
        if not self.assessor_id:
            raise ClaimError("assessor identity is required")
        if self.primary_implementer:
            raise ClaimError(
                "primary implementer cannot satisfy assessor independence"
            )
        if self.level >= 2 and (
            self.managed_operator_within_24_months
            or self.claim_approval_authority_within_24_months
            or self.compensation_contingent_on_claim
        ):
            raise ClaimError("L2+ assessor independence is not satisfied")
        if (
            self.level >= 2
            and self.material_affiliate_or_reseller
            and not self.published_sector_exception
        ):
            raise ClaimError("material assessor relationship is disqualifying")


@dataclass(frozen=True)
class ChecklistItem:
    item_id: str
    result: str
    minimum_level: int
    evidence_links: tuple[str, ...]
    applicability_false_evidence: tuple[str, ...] = ()

    def validate(self, *, claimed_level: int) -> None:
        if self.result not in {"pass", "fail", "not_applicable"}:
            raise ClaimError("checklist result is invalid")
        if self.result in {"pass", "fail"} and not self.evidence_links:
            raise ClaimError("applicable checklist item lacks evidence links")
        if (
            self.result == "not_applicable"
            and claimed_level >= self.minimum_level
            and not self.applicability_false_evidence
        ):
            raise ClaimError("Not Applicable lacks predicate evidence")


@dataclass(frozen=True)
class AssessmentPackage:
    level: int
    evaluated_at: str
    runtime_evidence_observed_at: str
    static_artifact: bool
    artifact_hashes: Mapping[str, str]
    checklist: tuple[ChecklistItem, ...]
    soi_boundary_id: str
    boundary_class: str
    negative_boundary_annex_id: str
    fr_coverage_matrix_id: str
    structured_claim_decision_id: str | None
    findings_id: str | None
    residual_risk_id: str | None
    independence_disclosure_id: str | None
    assessor_independence: AssessorIndependence

    def validate(self) -> None:
        evaluated = _time(self.evaluated_at)
        observed = _time(self.runtime_evidence_observed_at)
        maximum_age = timedelta(days=365 if self.level <= 2 else 183)
        if not self.static_artifact and evaluated - observed > maximum_age:
            raise ClaimError("runtime evidence is stale for the claimed level")
        if (
            not self.artifact_hashes
            or any(len(value) != 64 for value in self.artifact_hashes.values())
            or not self.soi_boundary_id
            or not self.boundary_class
            or not self.negative_boundary_annex_id
            or not self.fr_coverage_matrix_id
        ):
            raise ClaimError("assessment package is incomplete")
        for item in self.checklist:
            item.validate(claimed_level=self.level)
        self.assessor_independence.validate()
        if self.level >= 2 and not all(
            (
                self.structured_claim_decision_id,
                self.findings_id,
                self.residual_risk_id,
                self.independence_disclosure_id,
            )
        ):
            raise ClaimError("L2+ structured assessor output is incomplete")


@dataclass(frozen=True)
class SupplierDeliverables:
    level: int
    artifact_ids: Mapping[str, str]
    consequence_coupling_invoked: bool
    external_mapping_invoked: bool

    def validate(self) -> None:
        required = {
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
        }
        if self.level >= 2:
            required |= {
                "independent_assessment",
                "assessor_competency_conflict",
                "structured_claim_decision",
                "findings",
                "residual_risk",
                "independence_disclosure",
            }
        if self.consequence_coupling_invoked:
            required |= {
                "state_witness_register",
                "capability_manifest",
                "consequence_budget_ledger",
                "irreversibility_commit_modes",
                "quorum_rule",
            }
        if self.external_mapping_invoked:
            required.add("external_mapping_packet")
        missing = sorted(required - set(self.artifact_ids))
        if missing or any(not self.artifact_ids.get(key) for key in required):
            raise ClaimError(f"supplier deliverables are incomplete: {missing}")


AIBOM_REQUIRED_FIELDS = frozenset(
    {
        "artifact_id",
        "supplier",
        "component_type",
        "version_or_digest",
        "capability_id",
        "capability_manifest_reference",
        "deployment_profile_reference",
        "trust_or_attestation_reference",
        "usage_or_license_restrictions",
    }
)


def validate_aibom(value: Mapping[str, str]) -> None:
    if set(value) != AIBOM_REQUIRED_FIELDS or any(
        not item for item in value.values()
    ):
        raise ClaimError("AIBOM does not satisfy AIBOM-MIN-1")
