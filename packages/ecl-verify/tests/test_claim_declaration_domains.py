"""Declaration domains and parent consistency at the Python claim helper boundary."""
from dataclasses import fields, replace

import pytest

from ecl_verify.claims import (
    AssessmentPackage, AssessorIndependence, ChecklistItem, ClaimError,
    CONSEQUENTIAL_FLAGS, ConversationalScopeInputs, EquivalenceDossier,
    MappingPacket, PositioningStatement, PublicClaim, ReferenceUse,
    SectorProfileInvocation, SupplierDeliverables, SystemScopeInputs,
    TraceBoundary, VersionTransition, classify_action,
    classify_conversational_scope, classify_system_scope, validate_procurement_gate,
)


BAD_BOOLEANS = [0, 1, 1.0, "false", "", [], {}, None]


def _claim():
    return PublicClaim("urn:example:soi", 2, "full_conformance",
                       "bounded-action-class-mediation", "B", "1", ("DCMP-2:2",), (),
                       "2026-11-10T00:00:00Z", ())


def _trace():
    return TraceBoundary("urn:example:trace", ("a", "b", "c", "d"),
                         {"b": "a", "c": "a"}, frozenset({"model"}),
                         frozenset({"model"}), True)


def _equivalence():
    return EquivalenceDossier("FR-001", "Alternative", "Property", "Difference",
                              "Expiry", True, True, True, True, "urn:decision", None,
                              2, False)


def _mapping():
    return MappingPacket("urn:mapping", "1", "Framework", "2026",
                         {"one": "direct_runtime_support"}, {"one": ("FR-001",)},
                         {"one": "Residual"}, ("Boundary",), "internally_reviewed",
                         "2026-11-10T00:00:00Z")


def _package():
    independence = AssessorIndependence(2, "urn:assessor", False, False, False,
                                       False, False, direct_implementation_within_24_months=False)
    return AssessmentPackage(2, "2026-11-10T00:00:00Z", "2026-11-10T00:00:00Z",
                             False, {"artifact": "0" * 64},
                             (ChecklistItem("EA-01", "pass", 1, ("urn:evidence",)),),
                             "urn:boundary", "bounded-action-class-mediation", "urn:negative",
                             "urn:matrix", "urn:decision", "urn:findings", "urn:risk",
                             "urn:independence", independence)


def _supplier():
    names = ("public_claim checklist requirement_evidence_matrix fr_checklist_matrix "
             "soi_diagram trust_boundary_diagram action_register negative_boundary_annex "
             "declared_timing_case privilege_matrix dcmp_request dcmp_response ebmp_bundle "
             "redacted_ebmp_bundle revocation_drill emergency_drill incident_response "
             "change_management").split()
    return SupplierDeliverables(1, {name: "urn:" + name for name in names}, False, False)


DECLARATIONS = [
    (lambda: PositioningStatement(True, True, True), field.name)
    for field in fields(PositioningStatement)
] + [
    (_equivalence, name) for name in (
        "deny_by_default_preserved", "anti_bypass_preserved", "independence_preserved",
        "evidence_integrity_preserved", "replaces_hard_property")
] + [
    (_claim, "borrowed_endorsement"),
    (lambda: ReferenceUse("urn:reference", True, version="1"), "normative"),
    (lambda: SectorProfileInvocation("industrial-control", "IEC 62443", True,
                                    ReferenceUse("urn:reference", True, version="1")), "co_normative"),
    (_mapping, "claims_owner_endorsement"),
    (lambda: VersionTransition(False, 365, False, None), "breaking"),
    (lambda: VersionTransition(False, 365, False, None), "emergency_security_fix"),
    (_package, "static_artifact"),
    (_supplier, "consequence_coupling_invoked"),
    (_supplier, "external_mapping_invoked"),
    (_trace, "fleet_responsibility_present"),
]


@pytest.mark.parametrize("factory,member", DECLARATIONS,
                         ids=[member for _, member in DECLARATIONS])
@pytest.mark.parametrize("value", BAD_BOOLEANS)
def test_all_required_boolean_declarations_refuse_other_types(factory, member, value):
    with pytest.raises(ClaimError, match="boolean"):
        replace(factory(), **{member: value}).validate()


@pytest.mark.parametrize("factory,member", DECLARATIONS,
                         ids=[member for _, member in DECLARATIONS])
def test_existing_valid_boolean_declarations_remain_valid(factory, member):
    factory().validate()


@pytest.mark.parametrize("value", BAD_BOOLEANS)
def test_procurement_declaration_is_boolean(value):
    with pytest.raises(ClaimError, match="boolean"):
        validate_procurement_gate(level=2, regulator_requires_full_closure=value,
                                  procurement_decision="award")


@pytest.mark.parametrize("value", BAD_BOOLEANS[:-1])
@pytest.mark.parametrize("position", range(3))
def test_system_scope_invalid_type_never_becomes_an_exclusion(value, position):
    flags = [True, True, True]
    flags[position] = value
    with pytest.raises(ClaimError, match="boolean"):
        classify_system_scope(SystemScopeInputs(*flags))


@pytest.mark.parametrize("value", BAD_BOOLEANS[:-1])
@pytest.mark.parametrize("position", range(5))
def test_conversational_scope_invalid_type_never_becomes_an_exclusion(value, position):
    flags = [True] * 5
    flags[position] = value
    with pytest.raises(ClaimError, match="boolean"):
        classify_conversational_scope(ConversationalScopeInputs(*flags))


@pytest.mark.parametrize("value", BAD_BOOLEANS[:-1])
@pytest.mark.parametrize("member", sorted(CONSEQUENTIAL_FLAGS))
def test_action_classification_requires_boolean_or_unknown_flags(value, member):
    flags = {key: False for key in CONSEQUENTIAL_FLAGS}
    flags[member] = value
    with pytest.raises(ClaimError, match="boolean"):
        classify_action(flags)


@pytest.mark.parametrize("value,expected", [(True, "in_scope"), (False, "out_of_scope_candidate"),
                                           (None, "in_scope_pending_review")])
@pytest.mark.parametrize("position", range(3))
def test_system_scope_valid_declarations(value, expected, position):
    flags = [True] * 3
    flags[position] = value
    assert classify_system_scope(SystemScopeInputs(*flags)) == expected


@pytest.mark.parametrize("value,expected", [(True, "out_of_scope_candidate"), (False, "in_scope"),
                                           (None, "in_scope_pending_review")])
@pytest.mark.parametrize("position", range(5))
def test_conversational_scope_valid_declarations(value, expected, position):
    flags = [True] * 5
    flags[position] = value
    assert classify_conversational_scope(ConversationalScopeInputs(*flags)) == expected


@pytest.mark.parametrize("value,expected", [(True, "consequential"), (False, "non_consequential"),
                                           (None, "consequential_pending_review")])
@pytest.mark.parametrize("member", sorted(CONSEQUENTIAL_FLAGS))
def test_action_classification_valid_declarations(value, expected, member):
    flags = {key: False for key in CONSEQUENTIAL_FLAGS}
    flags[member] = value
    assert classify_action(flags, fully_confined_to_isolated_context=True) == expected


@pytest.mark.parametrize("isolation", [False, True, None])
@pytest.mark.parametrize("effect", [False, True, None])
def test_action_isolation_is_required_for_nonconsequential_exemption(isolation, effect):
    flags = {key: False for key in CONSEQUENTIAL_FLAGS}
    flags["external_state_mutation"] = effect
    expected = ("consequential" if effect is True else "non_consequential"
                if effect is False and isolation is True else "consequential_pending_review")
    assert classify_action(flags, fully_confined_to_isolated_context=isolation) == expected


@pytest.mark.parametrize("effect,expected", [(False, "consequential_pending_review"),
                                           (True, "consequential"),
                                           (None, "consequential_pending_review")])
def test_action_isolation_omission_preserves_conservative_results(effect, expected):
    flags = {key: False for key in CONSEQUENTIAL_FLAGS}
    flags["external_state_mutation"] = effect
    assert classify_action(flags) == expected


@pytest.mark.parametrize("isolation", BAD_BOOLEANS[:-1])
@pytest.mark.parametrize("effect", [False, True, None])
def test_action_isolation_declaration_requires_boolean_or_unknown(isolation, effect):
    flags = {key: False for key in CONSEQUENTIAL_FLAGS}
    flags["external_state_mutation"] = effect
    with pytest.raises(ClaimError, match="boolean"):
        classify_action(flags, fully_confined_to_isolated_context=isolation)


def test_action_isolation_does_not_erase_an_unknown_consequence():
    flags = {key: False for key in CONSEQUENTIAL_FLAGS}
    flags["external_state_mutation"] = True
    flags["nonpublic_data_disclosure"] = None
    assert classify_action(flags, fully_confined_to_isolated_context=True) == "consequential_pending_review"


def test_pending_value_does_not_mask_a_malformed_declaration():
    with pytest.raises(ClaimError, match="boolean"):
        classify_system_scope(SystemScopeInputs(None, "false", True))


@pytest.mark.parametrize("links", [{"a": "a"}, {"a": "b", "b": "a"},
                                    {"a": "b", "b": "c", "c": "a"},
                                    {"a": "b", "c": "d", "d": "c"}])
def test_trace_refuses_self_and_longer_parent_cycles(links):
    with pytest.raises(ClaimError, match="cycle"):
        replace(_trace(), child_parent_links=links).validate()


@pytest.mark.parametrize("links", [{}, {"b": "a"}, {"b": "a", "c": "a"},
                                    {"b": "a", "d": "c"},
                                    {"b": "a", "c": "b", "d": "c"}])
def test_trace_preserves_forests_shared_parents_and_chains(links):
    replace(_trace(), child_parent_links=links).validate()


def test_trace_long_chain_does_not_depend_on_python_recursion_depth():
    actions = tuple(f"action:{i}" for i in range(5000))
    links = {actions[i]: actions[i - 1] for i in range(1, len(actions))}
    replace(_trace(), external_action_ids=actions, child_parent_links=links).validate()


@pytest.mark.parametrize("value", [-1, True, False, 1.5, "1", None, [], {}])
def test_conditional_period_count_is_nonnegative_integer(value):
    with pytest.raises(ClaimError, match="nonnegative integer"):
        replace(_claim(), status="conditional_conformance", consecutive_conditional_periods=value).validate()


@pytest.mark.parametrize("value", [-1, True, False, 365.5, "365", None, [], {}])
def test_deprecation_days_are_nonnegative_integer_even_for_nonbreaking_change(value):
    with pytest.raises(ClaimError, match="nonnegative integer"):
        VersionTransition(False, value, False, None).validate()


@pytest.mark.parametrize("count", [0, 1, 2])
def test_valid_conditional_period_counts(count):
    replace(_claim(), status="conditional_conformance", consecutive_conditional_periods=count).validate()


def test_existing_conditional_period_ceiling_remains():
    with pytest.raises(ClaimError, match="reassessment"):
        replace(_claim(), status="conditional_conformance", consecutive_conditional_periods=3).validate()
    replace(_claim(), consecutive_conditional_periods=3).validate()


def test_existing_deprecation_policy_and_emergency_exception_remain():
    VersionTransition(False, 0, False, None).validate()
    VersionTransition(True, 365, False, None).validate()
    VersionTransition(True, 0, True, "Declared emergency").validate()
    with pytest.raises(ClaimError, match="deprecation window"):
        VersionTransition(True, 364, False, None).validate()
