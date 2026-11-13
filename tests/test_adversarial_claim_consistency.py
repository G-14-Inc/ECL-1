"""Reject contradictory declarations without treating helpers as deployment assessments."""
from dataclasses import replace

import pytest

from ecl_verify.claims import (
    ActionRegisterEntry,
    AssessmentOutcome,
    AssessmentPackage,
    AssessorIndependence,
    ClaimBoundary,
    ClaimError,
    ChecklistItem,
    EquivalenceDossier,
    PublicClaim,
    RiskScore,
    SIX_RESPONSIBILITIES,
    SupplierDeliverables,
    validate_procurement_gate,
)


def boundary():
    action = ActionRegisterEntry(
        "urn:test:financial-action", "consequential", "Financial effect",
        ("urn:test:account",), ("urn:test:actor",), ("financial",), "hard", None,
        ("tool:payment", "tool:wire"),
    )
    return ClaimBoundary(
        "urn:test:soi", "full-system-mediation", 2, (action,),
        frozenset({"tool:payment", "tool:wire"}),
        frozenset({"tool:payment", "tool:wire"}), frozenset(),
        "separate-host gate", SIX_RESPONSIBILITIES, ("actor", "control"), "B",
    )


def package():
    independence = AssessorIndependence(
        2, "urn:test:assessor", False, False, False, False, False,
        direct_implementation_within_24_months=False,
    )
    return AssessmentPackage(
        2, "2026-11-10T00:00:00Z", "2026-11-01T00:00:00Z", False,
        {"evidence": "a" * 64},
        (ChecklistItem("EA-01", "pass", 1, ("urn:test:evidence",)),),
        "urn:test:soi", "bounded-action-class-mediation", "urn:test:annex",
        "urn:test:matrix", "urn:test:decision", "urn:test:findings",
        "urn:test:residual", "urn:test:independence", independence,
    )


def test_full_system_exclusion_requires_a_bounded_claim():
    complete = boundary()
    complete.validate()
    excluded = replace(
        complete, included_effect_paths=frozenset({"tool:payment"}),
        negative_boundary_paths=frozenset({"tool:wire"}),
    )
    with pytest.raises(ClaimError, match="full-system"):
        excluded.validate()
    replace(excluded, claim_class="bounded-action-class-mediation").validate()


@pytest.mark.parametrize("severity", ["major", "critical"])
def test_explicit_material_finding_cannot_yield_full_conformance(severity):
    outcome = AssessmentOutcome(
        {"EA-01": "fail"}, {"finding:1": severity}, "full_conformance", "award",
        checklist_findings={"EA-01": "finding:1"},
    )
    with pytest.raises(ClaimError, match="finding"):
        outcome.validate()
    replace(outcome, claim_status="assessment_only", procurement_decision="defer").validate()


def test_major_finding_may_remain_conditional_but_critical_may_not():
    # This helper checks declaration consistency; the full claim's level,
    # remediation deadline and independent evidence remain separate inputs.
    conditional = AssessmentOutcome(
        {"EA-01": "fail"}, {"finding:1": "major"},
        "conditional_conformance", "not_evaluated",
        checklist_findings={"EA-01": "finding:1"},
    )
    conditional.validate()
    with pytest.raises(ClaimError, match="critical"):
        replace(conditional, finding_severities={"finding:1": "critical"}).validate()


def test_accepted_minor_caveat_is_not_promoted_to_a_material_failure():
    AssessmentOutcome(
        {"EA-01": "fail"}, {"finding:1": "minor"},
        "full_conformance", "not_evaluated",
        checklist_findings={"EA-01": "finding:1"},
    ).validate()


def test_failed_checklist_cannot_omit_all_finding_severities():
    with pytest.raises(ClaimError, match="severity"):
        AssessmentOutcome(
            {"EA-01": "fail"}, {}, "assessment_only", "not_evaluated",
        ).validate()


@pytest.mark.parametrize("conflict", [
    "managed_operator_within_24_months",
    "claim_approval_authority_within_24_months",
    "compensation_contingent_on_claim",
    "material_affiliate_or_reseller",
])
def test_l2_package_cannot_downgrade_its_assessor_to_bypass_a_conflict(conflict):
    assessed = package()
    assessed.validate()
    declared = replace(assessed.assessor_independence, **{conflict: True})
    with pytest.raises(ClaimError):
        replace(assessed, assessor_independence=declared).validate()
    with pytest.raises(ClaimError, match="level"):
        replace(assessed, assessor_independence=replace(declared, level=1)).validate()


@pytest.mark.parametrize("level", [0, 5, True, False, 2.0, "2", None])
@pytest.mark.parametrize("surface", ["boundary", "package", "assessor", "public-claim", "risk"])
def test_level_inputs_do_not_select_or_skip_rules_by_coercion(surface, level):
    if surface == "risk" and level is None:
        # Missing risk information has a conservative, explicitly provisional
        # result; it is the only level-input exception.
        assert RiskScore(None, 2, 2).required_level() == (3, True)
        return
    with pytest.raises(ClaimError, match="level"):
        if surface == "boundary":
            replace(boundary(), claimed_level=level).validate()
        elif surface == "package":
            replace(package(), level=level).validate()
        elif surface == "assessor":
            replace(package().assessor_independence, level=level).validate()
        elif surface == "public-claim":
            PublicClaim(
                "urn:test:soi", level, "assessment_only", "bounded-action-class-mediation",
                "C", "1.0", ("DCMP-2:2.0",), (), "2026-11-10T00:00:00Z", (),
            ).validate()
        else:
            RiskScore(level, 2, 2).required_level()


@pytest.mark.parametrize("level", [0, 5, True, 2.0])
def test_secondary_level_inputs_cannot_evade_declared_minimums(level):
    with pytest.raises(ClaimError, match="level"):
        ChecklistItem("EA-01", "not_applicable", 1, ()).validate(claimed_level=level)
    with pytest.raises(ClaimError, match="level"):
        ChecklistItem("EA-01", "not_applicable", level, ()).validate(claimed_level=2)
    with pytest.raises(ClaimError, match="level"):
        SupplierDeliverables(level, {}, False, False).validate()
    with pytest.raises(ClaimError, match="level"):
        validate_procurement_gate(
            level=level, regulator_requires_full_closure=True, procurement_decision="conditional_award",
        )
    with pytest.raises(ClaimError, match="level"):
        EquivalenceDossier(
            "FR-202", "equivalent control", "hard enforcement", "different root",
            "root change", True, True, True, True, "urn:test:assessor-decision",
            "urn:test:independent-validation", level, True,
        ).validate()


@pytest.mark.parametrize("static", [False, True])
def test_assessment_cannot_use_future_observation_even_one_nanosecond_later(static):
    assessed = replace(
        package(), static_artifact=static, evaluated_at="2026-11-10T00:00:00.123456789Z",
        runtime_evidence_observed_at="2026-11-10T00:00:00.123456789Z",
    )
    assessed.validate()
    with pytest.raises(ClaimError, match="later than"):
        replace(assessed, runtime_evidence_observed_at="2026-11-10T00:00:00.123456790Z").validate()


@pytest.mark.parametrize("level,oldest", [
    (1, "2025-11-10"), (2, "2025-11-10"),
    (3, "2026-05-11"), (4, "2026-05-11"),
])
def test_evidence_age_accepts_the_boundary_and_refuses_one_nanosecond_older(level, oldest):
    assessed = replace(
        package(), level=level,
        assessor_independence=replace(package().assessor_independence, level=level),
        evaluated_at="2026-11-10T00:00:00.123456789Z",
        runtime_evidence_observed_at=oldest + "T00:00:00.123456789Z",
    )
    assessed.validate()
    with pytest.raises(ClaimError, match="stale"):
        replace(assessed, runtime_evidence_observed_at=oldest + "T00:00:00.123456788Z").validate()
