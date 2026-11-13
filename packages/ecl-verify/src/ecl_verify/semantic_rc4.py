"""RC-4 safe-state profile checks, separate from the imported RC-3 validator."""

from __future__ import annotations

from typing import Any

from .semantic import Finding

PROOF_RULE = "ecl.rule.required-proof-dependency-fails-closed.v1"
CLASSIFICATION_RULE = "ecl.rule.dependency-classification-consistent.v1"
STRICT_RULE = "ecl.rule.strict-profile-forbids-fail-open.v1"
ACTION_CLASS_RULE = "ecl.rule.action-class-policy-unambiguous.v1"
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
    declared: dict[str, dict[str, Any] | None] = {}
    if isinstance(dependencies, list):
        for index, dependency in enumerate(dependencies):
            if not isinstance(dependency, dict):
                continue
            identifier = dependency.get("id")
            if isinstance(identifier, str):
                if identifier in declared:
                    findings.append(Finding(CLASSIFICATION_RULE, f"/dependencies/{index}/id", "a dependency identifier is declared more than once"))
                    declared[identifier] = None
                else:
                    declared[identifier] = dependency
            disposition = dependency.get("loss_disposition")
            path = f"/dependencies/{index}/loss_disposition"
            if dependency.get("class") == "advisory" and dependency.get("supplies_required_proof") is True:
                findings.append(Finding(
                    CLASSIFICATION_RULE, f"/dependencies/{index}/class",
                    "an advisory dependency cannot supply required proof",
                ))
            if dependency.get("supplies_required_proof") is True and (
                not isinstance(disposition, str) or disposition not in CLOSED_DISPOSITIONS
            ):
                findings.append(
                    Finding(PROOF_RULE, path, "required-proof loss must block the effect")
                )
            if strict and disposition == "fail_open":
                findings.append(Finding(STRICT_RULE, path, "strict failure forbids fail_open"))
    classes = value.get("action_classes")
    if isinstance(classes, list):
        declared_classes: set[str] = set()
        for index, action in enumerate(classes):
            if not isinstance(action, dict):
                continue
            identifier = action.get("action_class")
            if isinstance(identifier, str):
                if identifier in declared_classes:
                    findings.append(Finding(ACTION_CLASS_RULE, f"/action_classes/{index}/action_class", "an action class is declared more than once"))
                declared_classes.add(identifier)
            authorization = action.get("fail_open_authorization")
            if isinstance(authorization, dict):
                covered = authorization.get("covered_advisory_dependencies")
                base = f"/action_classes/{index}/fail_open_authorization/covered_advisory_dependencies"
                if not isinstance(covered, list) or not covered:
                    findings.append(Finding(CLASSIFICATION_RULE, base, "fail-open authorization names its covered advisory dependencies"))
                else:
                    seen: set[str] = set()
                    for position, identifier in enumerate(covered):
                        dependency = declared.get(identifier) if isinstance(identifier, str) else None
                        if not isinstance(identifier, str) or not identifier.strip() or identifier in seen or dependency is None or dependency.get("class") != "advisory" or dependency.get("supplies_required_proof") is not False:
                            findings.append(Finding(CLASSIFICATION_RULE, f"{base}/{position}", "fail-open coverage must name each declared advisory dependency once and none may supply required proof"))
                        if isinstance(identifier, str):
                            seen.add(identifier)
            if not strict:
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
