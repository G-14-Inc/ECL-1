"""Typed timing, safe-state and assessment declarations reject ambiguous inputs.

Robert F. Tilley Jr.; G-14, Inc.
"""
from dataclasses import replace
import pytest
from ecl_verify.timing import (TimeEvidence, LatencyMeasurementPlan, LatencyEvidence,
    DependencyDeclaration, LocalGateDependencyProfile, EmergencyChannelDrill,
    AvailabilityEvidence, TimingError, REQUIRED_STALENESS_DOMAINS)
from ecl_verify.safe_state import ActionSafeStatePolicy, SafeStateError, decide_safe_state
from ecl_verify.claims import (MappingPacket, ChecklistItem, AssessmentPackage,
    AssessorIndependence, ClaimError, validate_procurement_gate)

STAMP = "2026-11-10T00:00:00Z"
PLAN = LatencyMeasurementPlan("begin", "end", ("p50",), "hour", "none", "cpu", ("a",), ())
LATENCY = LatencyEvidence(PLAN, (0,), "complete", (), (), "a" * 64, "a" * 64)
DEPENDENCY = DependencyDeclaration("d", "cached", 0, False)
LOCAL = LocalGateDependencyProfile((DEPENDENCY,), dict.fromkeys(REQUIRED_STALENESS_DOMAINS, 0), False)
DRILL = EmergencyChannelDrill("channel", 60, STAMP, STAMP, None, True)
AVAILABILITY = AvailabilityEvidence(("measured",), ("designed",), ("untested",))

@pytest.mark.parametrize("evidence", [
    TimeEvidence("monotonic_duration", clock_id="c", ticks=True, unit="nanosecond"),
    TimeEvidence("policy_epoch", epoch_name="p", epoch_value=False),
    TimeEvidence("monotonic_duration", clock_id=True, ticks=0, unit="nanosecond"),
    TimeEvidence("trusted_external", wall_time=STAMP, trusted_source_id=True),
    replace(PLAN, start_boundary=True), replace(PLAN, action_classes="act"),
    replace(PLAN, hot_path_dependencies=("",)), replace(PLAN, percentiles="p50"),
    *[replace(LATENCY, raw_observations_ns=(v,)) for v in (True, 0.25, float("nan"), float("inf"), -1)],
    replace(LATENCY, raw_observations_ns=[]), replace(LATENCY, calculation_method=True),
    replace(LATENCY, exclusions="none"), replace(LATENCY, breach_observation_ids=("",)),
    replace(LATENCY, tested_configuration_digest="Z" * 64, product_claim_configuration_digest="Z" * 64),
    replace(LATENCY, tested_configuration_digest=tuple("a" * 64), product_claim_configuration_digest=tuple("a" * 64)),
    replace(DEPENDENCY, staleness_budget_seconds=True), replace(DEPENDENCY, staleness_budget_seconds=0.5),
    replace(DEPENDENCY, required_before_release="false"), replace(DEPENDENCY, dependency_id=" "),
    replace(LOCAL, undeclared_network_dependency=0), replace(LOCAL, dependencies="d"),
    replace(LOCAL, domain_budgets_seconds=dict.fromkeys(REQUIRED_STALENESS_DOMAINS, False)),
    replace(LOCAL, domain_budgets_seconds=dict.fromkeys(REQUIRED_STALENESS_DOMAINS, 0.5)),
    replace(DRILL, interval_seconds=True), replace(DRILL, interval_seconds=0.5),
    replace(DRILL, independence_verified="false"), replace(DRILL, channel_id=True),
    replace(AVAILABILITY, measured_behavior="abc"), replace(AVAILABILITY, measured_behavior=("",)),
    replace(AVAILABILITY, designed_behavior=(True,)),
])
def test_malformed_timing_declarations_are_not_accepted(evidence):
    with pytest.raises(TimingError):
        evidence.validate()


def test_valid_zero_and_optional_timing_controls():
    for evidence in (PLAN, LATENCY, DEPENDENCY, LOCAL, DRILL, AVAILABILITY,
        TimeEvidence("monotonic_duration", clock_id="c", ticks=0, unit="nanosecond"),
        TimeEvidence("policy_epoch", epoch_name="p", epoch_value=0),
        AvailabilityEvidence((), (), ("untested",))):
        evidence.validate()

POLICY = ActionSafeStatePolicy("act", "restricted", "fail_closed", "fail_closed", "fail_closed", ("diagnose",))
@pytest.mark.parametrize("changes", [
    {"action_class": ""}, {"action_class": True}, {"restricted_operations": "diagnose"},
    {"restricted_operations": ("",)}, {"restricted_operations": (True,)},
    {"restricted_operations": ("diagnose", "diagnose")},
])
def test_restricted_policy_does_not_split_or_coerce_identifiers(changes):
    with pytest.raises(SafeStateError):
        decide_safe_state(["deadline_exceeded"], replace(POLICY, **changes), evaluated_at=STAMP)


def test_empty_restricted_set_and_valid_operations_remain_permitted():
    assert decide_safe_state(["deadline_exceeded"], replace(POLICY, restricted_operations=()), evaluated_at=STAMP).permitted_operations == ()
    assert decide_safe_state(["deadline_exceeded"], POLICY, evaluated_at=STAMP).permitted_operations == ("diagnose",)

MAPPING = MappingPacket("id", "1", "framework", "2026", {"o": "out_of_scope"}, {"o": ()}, {"o": "external duty"}, ("assumption",), "draft", STAMP)
ITEM = ChecklistItem("i", "pass", 1, ("evidence",))
INDEPENDENCE = AssessorIndependence(1, "assessor", False, False, False, False, False)
PACKAGE = AssessmentPackage(1, STAMP, STAMP, False, {"a": "a" * 64}, (ITEM,), "soi", "full-system-mediation", "negative", "fr", None, None, None, None, INDEPENDENCE)

@pytest.mark.parametrize("packet", [
    replace(MAPPING, residual_obligations={"o": ""}),
    replace(MAPPING, residual_obligations={"o": True}),
    replace(MAPPING, obligation_classes={"": "out_of_scope"}, ecl_surfaces={"": ()}, residual_obligations={"": "duty"}),
    replace(MAPPING, obligation_classes={"o": "supporting_evidence_only"}, ecl_surfaces={"o": ("",)}),
    replace(MAPPING, obligation_classes={"o": "supporting_evidence_only"}, ecl_surfaces={"o": "surface"}),
])
def test_mapping_disclosures_are_named_nonempty_declarations(packet):
    with pytest.raises(ClaimError): packet.validate()

@pytest.mark.parametrize("item", [replace(ITEM, item_id=""), replace(ITEM, item_id=True),
    replace(ITEM, evidence_links="evidence"), replace(ITEM, evidence_links=("",)),
    replace(ITEM, result="not_applicable", applicability_false_evidence="predicate")])
def test_checklist_identity_and_evidence_domains(item):
    with pytest.raises(ClaimError): item.validate(claimed_level=1)

@pytest.mark.parametrize("items", [(), (ITEM, ITEM), "item"])
def test_assessment_checklist_has_unique_named_items(items):
    with pytest.raises(ClaimError): replace(PACKAGE, checklist=items).validate()

@pytest.mark.parametrize("decision", ["conditional-award", "", True, None])
def test_procurement_decision_domain_precedes_recommendation(decision):
    with pytest.raises(ClaimError):
        validate_procurement_gate(level=4, regulator_requires_full_closure=True, procurement_decision=decision)


def test_valid_mapping_checklist_and_procurement_controls():
    MAPPING.validate(); ITEM.validate(claimed_level=1); PACKAGE.validate()
    for decision in ("award", "deny", "defer", "not_evaluated"):
        validate_procurement_gate(level=4, regulator_requires_full_closure=True, procurement_decision=decision)
    validate_procurement_gate(level=4, regulator_requires_full_closure=False, procurement_decision="conditional_award")
    validate_procurement_gate(level=3, regulator_requires_full_closure=True, procurement_decision="conditional_award")
    with pytest.raises(ClaimError, match="departs"):
        validate_procurement_gate(level=4, regulator_requires_full_closure=True, procurement_decision="conditional_award")
