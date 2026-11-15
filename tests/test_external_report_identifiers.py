"""Declared provenance and finding-identity checks on bound synthetic reports.

These controls exercise report integrity; they do not claim vector execution or
authenticate the implementation identity declared by a report.

Robert F. Tilley Jr.; G-14, Inc.
"""

import copy

import pytest

from test_external_report_v3 import bound, row_for
from scripts.external_report_v3 import OBSERVATIONS


@pytest.fixture(params=(2, 3), ids=("legacy-v2", "current-v3"))
def report_version(bound, request):
    report, bind, check = bound
    version = request.param
    if version == 2:
        report.update(
            schema_version="ecl_cross_implementation_report_v2",
            profile_version="2",
            claim_boundary="cross-implementation-replay-only-not-independent-assessment",
        )
        for row in report["vector_results"]:
            for name in OBSERVATIONS.values():
                row.pop(name, None)

    def bind_version():
        bind(version)

    def check_version():
        return check(allow_legacy_v2=version == 2)

    bind_version()
    return report, bind_version, check_version


def failing_row(report):
    return next(row for row in report["vector_results"] if row["expected"] == "fail")


def test_registered_secondary_depth_may_differ(report_version):
    report, bind, check = report_version
    row = failing_row(report)
    row["observed_secondary_ids"] = ["ecl.rule.decision-basis-one-way.v1"]
    assert row["observed_primary_id"] not in row["observed_secondary_ids"]
    bind()
    assert check()["replay_decision"] == "pass"


@pytest.mark.parametrize("identifier", [
    "ecl.error.unallocated-report-probe.v1", "   ", "unregistered\nidentifier",
])
def test_unregistered_secondary_cannot_claim_met(report_version, identifier):
    report, bind, check = report_version
    failing_row(report)["observed_secondary_ids"] = [identifier]
    bind()
    with pytest.raises(ValueError, match="requires registered finding identifiers"):
        check()


@pytest.mark.parametrize("member", ["observed_primary_id", "observed_secondary_ids"])
def test_unregistered_finding_is_retained_in_truthful_failed_report(report_version, member):
    report, bind, check = report_version
    row = failing_row(report)
    row[member] = ["unallocated-actual-secondary"] if member.endswith("ids") else "unallocated-actual-primary"
    row["status"] = "not-met"
    report["decision"] = "fail"
    bind()
    result = check()
    assert result["decision"] == "verified-report-integrity"
    assert result["replay_decision"] == "fail"
    assert result["not_met_vectors"] == [row["id"]]


def test_failed_unknown_finding_still_needs_matching_raw_evidence(report_version):
    report, bind, check = report_version
    row = failing_row(report)
    row["observed_secondary_ids"] = ["unallocated-actual-secondary"]
    row["status"] = "not-met"
    report["decision"] = "fail"
    bind()
    row["observed_secondary_ids"] = ["a-different-actual-secondary"]
    with pytest.raises(ValueError, match="raw evidence differs"):
        check()


@pytest.mark.parametrize("field", [
    "name", "version", "source_repository", "source_revision", "language",
    "runtime", "maintainer", "relationship_disclosure",
])
@pytest.mark.parametrize("value", [" \t ", "unassigned", " UNASSIGNED "])
def test_provenance_requires_filled_declarations(report_version, field, value):
    report, bind, check = report_version
    report["implementation"][field] = value
    bind()
    with pytest.raises(ValueError, match="provenance is blank or unassigned"):
        check()


def test_freeform_and_unicode_provenance_is_preserved(report_version):
    report, bind, check = report_version
    report["implementation"].update(
        name=" Δοκιμή verifier ", source_repository=" local source export ",
        source_revision="release-tag:review/1", maintainer="Fixture maintainer 雪",
    )
    report["limitations"] = []
    before = copy.deepcopy(report["implementation"])
    bind()
    assert check()["replay_decision"] == "pass"
    assert report["implementation"] == before


def test_blank_limitation_is_not_a_filled_disclosure(report_version):
    report, bind, check = report_version
    report["limitations"] = [" \t "]
    bind()
    with pytest.raises(ValueError, match="limitation must contain non-whitespace"):
        check()


@pytest.mark.parametrize("action_id", ["urn:example:other-action", "custom-action-token"])
def test_other_actions_remain_outside_the_named_effect_comparison(bound, action_id):
    report, bind, check = bound
    row = row_for(report, "observed_effects")
    row["observed_effects"].append({"action_id": action_id, "level": "none"})
    bind()
    assert check()["replay_decision"] == "pass"
