"""Validate supplied scope, claim, mapping and assessment declarations.

These helpers check declared input domains and the relationships implemented
below. They do not replace document-schema validation or establish the truth,
authenticity or completeness of the caller's underlying evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .schema import rfc3339_utc_nanoseconds


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


def _time(value: str) -> int:
    """An exact ECL instant, retaining all one to nine fractional digits."""
    try:
        return rfc3339_utc_nanoseconds(value)
    except ValueError as exc:
        raise ClaimError(f"invalid UTC timestamp: {value!r}") from exc


def _validate_level(value: object) -> None:
    if type(value) is not int or value not in {1, 2, 3, 4}:
        raise ClaimError("conformance level must be an integer from L1 to L4")


def _validate_boolean(value: object, name: str, *, optional: bool = False) -> None:
    if type(value) is bool or (optional and value is None):
        return
    suffix = " or unspecified" if optional else ""
    raise ClaimError(f"{name} must be boolean{suffix}")


def _validate_nonnegative_integer(value: object, name: str) -> None:
    if type(value) is not int or value < 0:
        raise ClaimError(f"{name} must be a nonnegative integer")


def _validate_text(value: object, name: str) -> None:
    if type(value) is not str or not value.strip():
        raise ClaimError(f"{name} must be nonempty text")


def _validate_text_tuple(value: object, name: str) -> None:
    if type(value) is not tuple:
        raise ClaimError(f"{name} must be a tuple of nonempty strings")
    for item in value:
        _validate_text(item, name)


def _validate_optional_text(value: object, name: str) -> None:
    if value is not None:
        _validate_text(value, name)


def _validate_text_frozenset(value: object, name: str) -> None:
    if type(value) is not frozenset:
        raise ClaimError(f"{name} must be a frozenset of nonempty strings")
    for item in value:
        _validate_text(item, name)


def _validate_text_mapping(value: object, name: str) -> None:
    if not isinstance(value, Mapping):
        raise ClaimError(f"{name} must be a mapping")
    for key, item in value.items():
        _validate_text(key, f"{name} key")
        _validate_text(item, f"{name} value")


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
    for value in values:
        _validate_boolean(value, "system scope declaration", optional=True)
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


def classify_action(
    flags: Mapping[str, bool | None],
    *,
    fully_confined_to_isolated_context: bool | None = None,
) -> str:
    """Classify declared action facts, including ECL1N-0005's isolation condition.

    All consequence triggers being false is insufficient for a non-consequential
    classification unless the caller explicitly declares confinement. Unknown
    consequence flags retain the existing pending-review result.
    """
    if not isinstance(flags, Mapping) or set(flags) != CONSEQUENTIAL_FLAGS:
        raise ClaimError("action classification does not evaluate every rule")
    _validate_boolean(fully_confined_to_isolated_context, "isolated context declaration", optional=True)
    for value in flags.values():
        _validate_boolean(value, "action classification declaration", optional=True)
    if any(value is None for value in flags.values()):
        return "consequential_pending_review"
    if any(flags.values()):
        return "consequential"
    return "non_consequential" if fully_confined_to_isolated_context is True else "consequential_pending_review"


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
    for value in values:
        _validate_boolean(value, "conversational scope declaration", optional=True)
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
        _validate_boolean(self.fleet_responsibility_present, "fleet responsibility declaration")
        _validate_text(self.root_trace_id, "root trace identifier")
        _validate_text_tuple(self.external_action_ids, "external action identifiers")
        _validate_text_mapping(self.child_parent_links, "child-parent links")
        _validate_text_frozenset(self.capable_model_ids, "capable model identifiers")
        _validate_text_frozenset(self.declared_soi_model_ids, "declared SoI model identifiers")
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
        completed: set[str] = set()
        for child in children:
            path: set[str] = set()
            current = child
            while current in self.child_parent_links and current not in completed:
                if current in path:
                    raise ClaimError("child-parent linkage contains a cycle")
                path.add(current)
                current = self.child_parent_links[current]
            completed.update(path)
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
        for name in (
            "runtime_control_scope_stated",
            "level_and_boundary_stated",
            "direct_control_distinguished_from_mapping",
            "asserts_liveness_guarantee",
            "asserts_business_outcome_guarantee",
            "asserts_universal_model_correctness",
            "asserts_automatic_legal_compliance",
            "asserts_framework_certification",
            "asserts_external_owner_endorsement",
        ):
            _validate_boolean(getattr(self, name), name)
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
        for name in ("action_class_id", "classification", "rationale", "enforcement_class"):
            _validate_text(getattr(self, name), name)
        for name in ("affected_resources", "identities", "data_classes", "capability_paths", "budget_dimensions"):
            _validate_text_tuple(getattr(self, name), name)
        for name in ("witness_posture", "capability_freeze_scope", "irreversibility_class", "commit_mode", "quorum_rule"):
            _validate_optional_text(getattr(self, name), name)
        if self.human_approval_threshold is not None:
            if type(self.human_approval_threshold) is not tuple or any(
                not isinstance(threshold, Mapping) for threshold in self.human_approval_threshold
            ):
                raise ClaimError("human approval thresholds must be a tuple of mappings or unspecified")
            for threshold in self.human_approval_threshold:
                for key in threshold:
                    _validate_text(key, "human approval threshold field")
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
        if self.classification in {"consequential", "consequential_pending_review"} and not self.capability_paths:
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
        _validate_level(self.claimed_level)
        for name in ("soi_id", "claim_class", "deployment_topology"):
            _validate_text(getattr(self, name), name)
        for name in ("included_effect_paths", "reachable_effect_paths", "negative_boundary_paths", "responsibilities"):
            _validate_text_frozenset(getattr(self, name), name)
        _validate_text_tuple(self.trust_boundaries, "trust boundaries")
        if type(self.action_register) is not tuple or any(
            not isinstance(entry, ActionRegisterEntry) for entry in self.action_register
        ):
            raise ClaimError("action register must be a tuple of action register entries")
        if (type(self.independence_class) is not str
            or self.independence_class not in INDEPENDENCE_RANK
            or INDEPENDENCE_RANK[self.independence_class] < INDEPENDENCE_RANK[MINIMUM_INDEPENDENCE[self.claimed_level]]):
            raise ClaimError("boundary independence class is below the level minimum or unknown")
        if self.included_effect_paths & self.negative_boundary_paths:
            raise ClaimError("included and excluded effect paths overlap")
        if self.claim_class not in {
            "full-system-mediation",
            "bounded-action-class-mediation",
        }:
            raise ClaimError("unknown claim boundary class")
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
        if (
            self.claim_class == "full-system-mediation"
            and self.reachable_effect_paths - self.included_effect_paths
        ):
            raise ClaimError("full-system mediation excludes reachable effect paths")
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
        for value in known:
            _validate_level(value)
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
        _validate_level(self.level)
        _validate_boolean(self.borrowed_endorsement, "borrowed endorsement declaration")
        _validate_nonnegative_integer(self.consecutive_conditional_periods, "conditional period count")
        for name in ("soi_id", "status", "boundary_class", "independence_class", "core_version"):
            _validate_text(getattr(self, name), name)
        for name in ("companion_versions", "profile_versions", "limitations"):
            _validate_text_tuple(getattr(self, name), name)
        for name in ("class_a_disclosure", "framework_name", "mapping_packet_id", "obligation_slice", "residual_gap", "mapping_validation_state"):
            _validate_optional_text(getattr(self, name), name)
        if (
            not self.soi_id
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
        if self.level not in {2, 3} and self.status == "conditional_conformance":
            raise ClaimError("L1 and L4 cannot claim conditional conformance; it is limited to L2 and L3")
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
        if self.mapping_validation_state is not None and (
            type(self.mapping_validation_state) is not str
            or self.mapping_validation_state not in {"draft", "internally_reviewed", "independently_reviewed", "owner_validated"}
        ):
            raise ClaimError("mapping validation state is unknown")
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
        _validate_boolean(self.normative, "normative reference declaration")
        _validate_text(self.identifier, "reference identifier")
        for name in ("version", "date", "immutable_digest"):
            _validate_optional_text(getattr(self, name), name)
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
        _validate_boolean(self.co_normative, "co-normative declaration")
        _validate_text(self.sector, "sector declaration")
        if self.sector in {"industrial-control", "automotive-safety"}:
            _validate_text(self.applicable_standard, "applicable sector standard")
            if not isinstance(self.reference, ReferenceUse):
                raise ClaimError("invoked sector reference must be a ReferenceUse declaration")
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
        _validate_level(self.level)
        for name in (
            "deny_by_default_preserved",
            "anti_bypass_preserved",
            "independence_preserved",
            "evidence_integrity_preserved",
            "replaces_hard_property",
        ):
            _validate_boolean(getattr(self, name), name)
        for name in ("replaced_requirement_id", "alternative", "preserved_property",
                     "residual_difference", "expiry_conditions", "assessor_decision_id"):
            _validate_text(getattr(self, name), name)
        _validate_optional_text(self.independent_validation_id, "independent validation identifier")
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
        _validate_boolean(self.claims_owner_endorsement, "framework-owner endorsement declaration")
        for name in ("packet_id", "version", "framework", "framework_edition", "validation_state"):
            _validate_text(getattr(self, name), name)
        _validate_text_tuple(self.assumptions, "mapping assumptions")
        _validate_text_mapping(self.obligation_classes, "obligation classes")
        _validate_text_mapping(self.residual_obligations, "residual obligations")
        if not isinstance(self.ecl_surfaces, Mapping):
            raise ClaimError("ecl_surfaces must be a mapping")
        for obligation, surfaces in self.ecl_surfaces.items():
            _validate_text(obligation, "mapped obligation identifier")
            _validate_text_tuple(surfaces, "cited ECL surfaces")
        if (
            not self.packet_id
            or not self.version
            or not self.framework
            or not self.framework_edition
            or not self.obligation_classes
            or set(self.obligation_classes.values()) - MAPPING_CLASSES
            or not self.assumptions
            or self.validation_state
            not in {"draft", "internally_reviewed", "independently_reviewed", "owner_validated"}
        ):
            raise ClaimError("mapping packet is incomplete")
        _time(self.updated_at)
        for obligation in self.obligation_classes:
            if (obligation not in self.ecl_surfaces
                    or (self.obligation_classes[obligation] != "out_of_scope"
                        and not self.ecl_surfaces[obligation])):
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
        _validate_boolean(self.breaking, "breaking change declaration")
        _validate_boolean(self.emergency_security_fix, "emergency security fix declaration")
        _validate_nonnegative_integer(self.deprecation_window_days, "deprecation window days")
        _validate_optional_text(self.emergency_justification, "emergency justification")
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
    checklist_findings: Mapping[str, str] | None = None

    def validate(self) -> None:
        _validate_text_mapping(self.checklist_results, "checklist results")
        _validate_text_mapping(self.finding_severities, "finding severities")
        _validate_text(self.claim_status, "claim status")
        _validate_text(self.procurement_decision, "procurement decision")
        if self.checklist_findings is not None:
            _validate_text_mapping(self.checklist_findings, "checklist finding links")
        if (
            not self.checklist_results
            or set(self.checklist_results.values())
            - {"pass", "fail", "not_applicable"}
            or set(self.finding_severities.values())
            - {"critical", "major", "minor", "observation"}
            or self.claim_status
            not in {"full_conformance", "conditional_conformance", "assessment_only"}
            or self.procurement_decision
            not in {"award", "conditional_award", "deny", "defer", "not_evaluated"}
        ):
            raise ClaimError("assessment hierarchy is incomplete or conflated")
        if "critical" in self.finding_severities.values() and self.claim_status != "assessment_only":
            raise ClaimError("critical finding cannot produce a conformance claim")
        if "major" in self.finding_severities.values() and self.claim_status == "full_conformance":
            raise ClaimError("major finding blocks full conformance")
        if "fail" in self.checklist_results.values() and not self.finding_severities:
            raise ClaimError("failed checklist item lacks finding severity")
        failed = {item for item, result in self.checklist_results.items() if result == "fail"}
        links = self.checklist_findings
        if links is None:
            if failed:
                raise ClaimError("failed checklist items lack finding links")
        else:
            if not isinstance(links, Mapping) or set(links) != failed:
                raise ClaimError("finding links must name exactly the failed checklist items")
            if any(finding not in self.finding_severities for finding in links.values()):
                raise ClaimError("checklist finding link does not name a known finding")
            if any(self.finding_severities[finding] == "observation" for finding in links.values()):
                raise ClaimError("a failed checklist item needs critical, major or minor severity")


def validate_procurement_gate(
    *,
    level: int,
    regulator_requires_full_closure: bool,
    procurement_decision: str,
) -> None:
    """Check the no-departure procurement recommendation of ECL1N-0135.

    A rejection flags a departure for assessment against RFC 2119 Section 4.
    This helper does not assess the reasons for a departure, determine an ECL-1
    conformance status, or authorize operation before required closure.
    """
    _validate_level(level)
    _validate_boolean(regulator_requires_full_closure, "regulatory closure declaration")
    if type(procurement_decision) is not str or procurement_decision not in {
        "award", "conditional_award", "deny", "defer", "not_evaluated"
    }:
        raise ClaimError("procurement decision is invalid")
    if (
        level == 4
        and regulator_requires_full_closure
        and procurement_decision == "conditional_award"
    ):
        raise ClaimError("L4 conditional award departs from ECL1N-0135; assess the procurement justification")


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
    direct_implementation_within_24_months: bool | None = None

    def validate(self) -> None:
        _validate_level(self.level)
        _validate_text(self.assessor_id, "assessor identifier")
        _validate_optional_text(self.published_sector_exception, "published sector exception")
        declarations = (
            self.primary_implementer,
            self.managed_operator_within_24_months,
            self.claim_approval_authority_within_24_months,
            self.compensation_contingent_on_claim,
            self.material_affiliate_or_reseller,
        )
        if any(type(value) is not bool for value in declarations):
            raise ClaimError("assessor independence declarations must be boolean")
        direct = self.direct_implementation_within_24_months
        if direct is not None and type(direct) is not bool:
            raise ClaimError("direct implementation history must be boolean or unspecified")
        if self.level >= 2 and direct is not False:
            raise ClaimError("L2+ requires an explicit absence of direct implementation within 24 months")
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
        _validate_level(claimed_level)
        _validate_level(self.minimum_level)
        _validate_text(self.item_id, "checklist item identifier")
        _validate_text_tuple(self.evidence_links, "checklist evidence links")
        _validate_text_tuple(self.applicability_false_evidence, "applicability predicate evidence")
        if type(self.result) is not str or self.result not in {"pass", "fail", "not_applicable"}:
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
        _validate_level(self.level)
        _validate_boolean(self.static_artifact, "static artifact declaration")
        _validate_text_mapping(self.artifact_hashes, "artifact hashes")
        for name in ("soi_boundary_id", "boundary_class", "negative_boundary_annex_id", "fr_coverage_matrix_id"):
            _validate_text(getattr(self, name), name)
        for name in ("structured_claim_decision_id", "findings_id", "residual_risk_id", "independence_disclosure_id"):
            _validate_optional_text(getattr(self, name), name)
        if not isinstance(self.assessor_independence, AssessorIndependence):
            raise ClaimError("assessor independence must be an AssessorIndependence declaration")
        evaluated = _time(self.evaluated_at)
        observed = _time(self.runtime_evidence_observed_at)
        if observed > evaluated:
            raise ClaimError("runtime evidence is later than the assessment time")
        maximum_age = (365 if self.level <= 2 else 183) * 86400 * 1_000_000_000
        if not self.static_artifact and evaluated - observed > maximum_age:
            raise ClaimError("runtime evidence is stale for the claimed level")
        if (
            not self.artifact_hashes
            or any(type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
                   for value in self.artifact_hashes.values())
            or not self.soi_boundary_id
            or self.boundary_class not in {"full-system-mediation", "bounded-action-class-mediation"}
            or not self.negative_boundary_annex_id
            or not self.fr_coverage_matrix_id
        ):
            raise ClaimError("assessment package is incomplete")
        if type(self.checklist) is not tuple or not self.checklist or any(
            not isinstance(item, ChecklistItem) for item in self.checklist
        ):
            raise ClaimError("assessment checklist must be a nonempty tuple of checklist items")
        for item in self.checklist:
            item.validate(claimed_level=self.level)
        if len({item.item_id for item in self.checklist}) != len(self.checklist):
            raise ClaimError("assessment checklist repeats an item identifier")
        if self.assessor_independence.level != self.level:
            raise ClaimError("assessor independence level differs from assessment level")
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
        _validate_level(self.level)
        _validate_boolean(self.consequence_coupling_invoked, "consequence coupling declaration")
        _validate_boolean(self.external_mapping_invoked, "external mapping declaration")
        _validate_text_mapping(self.artifact_ids, "supplier artifact identifiers")
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
    _validate_text_mapping(value, "AIBOM metadata")
    if set(value) != AIBOM_REQUIRED_FIELDS or any(
        not item for item in value.values()
    ):
        raise ClaimError("AIBOM does not satisfy AIBOM-MIN-1")
