"""Exercise effect guards and verify newly bound public example evidence."""

import copy
import unittest
from typing import Any

from ecl_verify.bundle_verification import verify_bundle
from ecl_verify.trust import TrustPolicy
from examples.bounded_workflow.workflow import (
    FIXTURES,
    Permit,
    Workflow,
    digest,
    evidence,
    exercise,
)


class WorkflowTests(unittest.TestCase):
    def test_failure_cases_have_no_effect(self) -> None:
        assert all(exercise().values())

    def test_action_mutation_cannot_reuse_authority(self) -> None:
        action: dict[str, Any] = {"record_id": "r-1", "patch": {"status": "closed"}}
        flow = Workflow()
        _, permit = flow.decide(action)
        action["patch"]["status"] = "archived"
        assert not flow.release(action, permit)
        assert flow.records == {"r-1": {"status": "open"}}

    def test_forged_permit_and_old_approval_cannot_release(self) -> None:
        action: dict[str, Any] = {"record_id": "r-1", "patch": {"status": "archived"}}
        flow = Workflow()
        assert not flow.release(action, Permit(1, digest(action)["value"], 5))
        old = digest(action)["value"]
        changed = copy.deepcopy(action)
        changed["record_id"] = "r-2"
        assert flow.decide(changed, approved_digest=old) == ("deny", None)

    def test_new_wire_bindings_verify(self) -> None:
        policy = TrustPolicy.load((FIXTURES / "trust-policy.json").read_bytes())
        for admitted in (True, False):
            with self.subTest(admitted=admitted):
                action: dict[str, Any] = {"record_id": "r-1", "patch": {"status": "closed"}}
                report = verify_bundle(
                    evidence(action, admitted=admitted, name="test"),
                    policy,
                    now="2026-10-01T00:00:00Z",
                )
                assert report.verdict == "verified", report.findings


if __name__ == "__main__":
    unittest.main()
