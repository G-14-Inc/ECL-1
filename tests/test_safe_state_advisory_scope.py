"""A scoped advisory exception does not erase a stronger concurrent declaration."""
from dataclasses import replace

import pytest

from ecl_verify.safe_state import ActionSafeStatePolicy, FailOpenAuthorization, decide_safe_state


AT = "2026-09-30T09:00:00Z"
DEPENDENCY = "urn:example:dependency:advisory"
AUTHORIZATION = FailOpenAuthorization(
    "urn:example:owner", "bounded advisory outage", "2026-09-30T09:01:00Z",
    "ecl.evidence.standard.v1", (DEPENDENCY,),
)
POLICY = ActionSafeStatePolicy(
    "ecl.action.ai-proposed-operation.v1", "fail_open", "fail_open", "fail_open",
    "fail_open", (), fail_open_authorization=AUTHORIZATION,
)


@pytest.mark.parametrize("failure", ["deadline_exceeded", "evidence_buffer_exhausted", "dependency_stale"])
def test_multiple_failures_attributed_to_covered_advisory_dependency(failure):
    result = decide_safe_state(
        [failure, "dependency_unavailable"], POLICY, evaluated_at=AT,
        failed_advisory_dependencies=(DEPENDENCY,), required_proof_available=True,
    )
    assert result.disposition == "fail_open"


@pytest.mark.parametrize("proof", [False, None])
def test_mixed_failure_cannot_open_without_required_proof(proof):
    result = decide_safe_state(
        ["evidence_buffer_exhausted", "dependency_unavailable"], POLICY, evaluated_at=AT,
        failed_advisory_dependencies=(DEPENDENCY,), required_proof_available=proof,
    )
    assert result.disposition == "fail_closed"


@pytest.mark.parametrize("disposition", ["restricted", "fail_closed", "quarantine"])
def test_unrelated_buffer_failure_keeps_its_stronger_policy(disposition):
    result = decide_safe_state(
        ["evidence_buffer_exhausted", "dependency_unavailable"],
        replace(POLICY, buffer_exhaustion_disposition=disposition), evaluated_at=AT,
        failed_advisory_dependencies=(DEPENDENCY,), required_proof_available=True,
    )
    assert result.disposition == disposition


def test_missing_pre_release_evidence_cannot_be_covered_by_advisory_outage():
    result = decide_safe_state(
        ["missing_pre_release_evidence", "evidence_buffer_exhausted", "dependency_unavailable"],
        POLICY, evaluated_at=AT, failed_advisory_dependencies=(DEPENDENCY,),
        required_proof_available=True,
    )
    assert result.disposition == "fail_closed"
