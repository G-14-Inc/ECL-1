"""Exercise explicit assessment links and direct-implementation declarations."""
from dataclasses import replace

import pytest

from ecl_verify.claims import AssessmentOutcome, AssessorIndependence, ClaimError


def linked_outcome():
    return AssessmentOutcome(
        {"EA-01": "fail", "EA-02": "fail", "EA-03": "pass", "EA-04": "not_applicable"},
        {"finding:1": "minor", "finding:2": "minor", "finding:general": "minor"},
        "full_conformance", "not_evaluated",
        checklist_findings={"EA-01": "finding:1", "EA-02": "finding:2"},
    )


def independent(level=2, **kwargs):
    return AssessorIndependence(
        level, "urn:test:assessor", False, False, False, False, False, **kwargs,
    )


def test_every_failed_item_is_linked_and_general_findings_keep_their_own_ids():
    linked_outcome().validate()
    # One finding may describe a shared weakness affecting multiple items.
    replace(linked_outcome(), checklist_findings={"EA-01": "finding:1", "EA-02": "finding:1"}).validate()


@pytest.mark.parametrize("links", [
    None, {}, {"EA-01": "finding:1"},
    {"EA-01": "finding:1", "EA-02": "finding:missing"},
    {"EA-01": "finding:1", "EA-02": "finding:2", "EA-03": "finding:general"},
    {"EA-01": "finding:1", "EA-02": "finding:2", "EA-04": "finding:general"},
    {"EA-01": "finding:1", "EA-02": "finding:2", "EA-absent": "finding:general"},
    {"EA-01": "finding:1", "EA-02": ["finding:2"]},
    {"EA-01": "finding:1", "EA-02": ""}, [], "EA-01",
])
def test_missing_unknown_extraneous_or_malformed_links_are_refused(links):
    with pytest.raises(ClaimError, match="finding"):
        replace(linked_outcome(), checklist_findings=links).validate()


@pytest.mark.parametrize("links", [None, {}])
def test_all_pass_callers_need_no_links_and_can_record_a_general_minor_finding(links):
    AssessmentOutcome(
        {"EA-01": "pass"}, {"finding:general": "minor"},
        "full_conformance", "not_evaluated", checklist_findings=links,
    ).validate()


@pytest.mark.parametrize("severity", ["critical", "major"])
def test_linkage_does_not_hide_a_material_general_finding(severity):
    outcome = linked_outcome()
    severities = {**outcome.finding_severities, "finding:general": severity}
    with pytest.raises(ClaimError, match="finding"):
        replace(outcome, finding_severities=severities).validate()


@pytest.mark.parametrize("level", [2, 3, 4])
def test_l2_plus_requires_explicit_false_direct_implementation_history(level):
    independent(level, direct_implementation_within_24_months=False).validate()
    with pytest.raises(ClaimError, match="direct implementation"):
        independent(level).validate()
    with pytest.raises(ClaimError, match="direct implementation"):
        independent(level, direct_implementation_within_24_months=True).validate()


@pytest.mark.parametrize("direct", [None, False, True])
def test_l1_retains_its_non_primary_implementer_baseline(direct):
    assessor = independent(1, direct_implementation_within_24_months=direct)
    assessor.validate()
    with pytest.raises(ClaimError, match="primary implementer"):
        replace(assessor, primary_implementer=True).validate()


@pytest.mark.parametrize("level", [1, 2])
@pytest.mark.parametrize("field", [
    "primary_implementer", "managed_operator_within_24_months",
    "claim_approval_authority_within_24_months", "compensation_contingent_on_claim",
    "material_affiliate_or_reseller", "direct_implementation_within_24_months",
])
@pytest.mark.parametrize("invalid", [0, 1, 0.0, "false", "", [], {}])
def test_independence_flags_do_not_coerce_truthy_or_falsey_values(level, field, invalid):
    assessor = independent(level, direct_implementation_within_24_months=False)
    with pytest.raises(ClaimError, match="boolean"):
        replace(assessor, **{field: invalid}).validate()


@pytest.mark.parametrize("field", [
    "primary_implementer", "managed_operator_within_24_months",
    "claim_approval_authority_within_24_months", "compensation_contingent_on_claim",
    "material_affiliate_or_reseller",
])
def test_existing_required_flags_cannot_be_unspecified(field):
    with pytest.raises(ClaimError, match="boolean"):
        replace(independent(1), **{field: None}).validate()


def test_sector_affiliate_exception_cannot_waive_direct_implementation_history():
    assessor = replace(
        independent(direct_implementation_within_24_months=False),
        material_affiliate_or_reseller=True,
        published_sector_exception="urn:test:published-sector-exception",
    )
    assessor.validate()
    with pytest.raises(ClaimError, match="direct implementation"):
        replace(assessor, direct_implementation_within_24_months=True).validate()
