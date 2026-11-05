"""RC-4 safe-state profile checks, separate from the imported RC-3 validator."""

from __future__ import annotations

from typing import Any

from .semantic import Finding

PROOF_RULE = "ecl.rule.required-proof-dependency-fails-closed.v1"
STRICT_RULE = "ecl.rule.strict-profile-forbids-fail-open.v1"
# SF1-004: a document claims STRICT-FAILURE-1 by listing it in `claimed_profiles`. Its name or
# profile_id decides nothing.
STRICT_PROFILE = "STRICT-FAILURE-1"
CLOSED_DISPOSITIONS = frozenset({"fail_closed", "quarantine", "emergency_halt"})
ACTION_DISPOSITIONS = (
    "timeout_disposition",
    "dependency_disposition",
    "stale_dependency_disposition",
    "buffer_exhaustion_disposition",
)


def validate_safe_state_profile(value: dict[str, Any]) -> list[Finding]:
    """Check declared dispositions; schema validation and truthful classification are separate."""
    findings: list[Finding] = []
    claimed = value.get("claimed_profiles")
    strict = isinstance(claimed, list) and STRICT_PROFILE in claimed
    dependencies = value.get("dependencies")
    if isinstance(dependencies, list):
        for index, dependency in enumerate(dependencies):
            if not isinstance(dependency, dict):
                continue
            disposition = dependency.get("loss_disposition")
            path = f"/dependencies/{index}/loss_disposition"
            if dependency.get("supplies_required_proof") is True and (
                not isinstance(disposition, str) or disposition not in CLOSED_DISPOSITIONS
            ):
                findings.append(
                    Finding(PROOF_RULE, path, "required-proof loss must block the effect")
                )
            if strict and disposition == "fail_open":
                findings.append(Finding(STRICT_RULE, path, "strict failure forbids fail_open"))
    classes = value.get("action_classes")
    if strict and isinstance(classes, list):
        for index, action in enumerate(classes):
            if not isinstance(action, dict):
                continue
            findings.extend(
                Finding(
                    STRICT_RULE,
                    f"/action_classes/{index}/{member}",
                    "strict failure forbids fail_open",
                )
                for member in ACTION_DISPOSITIONS
                if action.get(member) == "fail_open"
            )
    buffer = value.get("evidence_buffer")
    if strict and isinstance(buffer, dict) and buffer.get("overflow") == "fail_open":
        findings.append(
            Finding(STRICT_RULE, "/evidence_buffer/overflow", "strict failure forbids fail_open")
        )
    return findings
