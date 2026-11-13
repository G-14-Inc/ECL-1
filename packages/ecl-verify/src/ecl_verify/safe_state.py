"""Offline verification checks and read-only metadata for safe_state."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from .schema import rfc3339_utc_nanoseconds


class SafeStateError(ValueError):
    """Raised when a safe-state policy is invalid or cannot preserve evidence."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code

DISPOSITION_PRECEDENCE = {
    "fail_open": 0,
    "degraded": 10,
    "restricted": 20,
    "fail_closed": 30,
    "quarantine": 40,
    "emergency_halt": 50,
}

UNCONDITIONAL_FAIL_CLOSED = frozenset(
    {
        "missing_policy",
        "missing_identity",
        "missing_authority",
        "missing_pre_release_evidence",
        "invalid_integrity",
        "unknown_critical_extension",
        "critical_verification_failure",
        "replay_detected",
    }
)

def _time(value: str) -> int:
    """An ECL RFC 3339 UTC instant as exact nanoseconds since the Unix epoch."""
    try:
        return rfc3339_utc_nanoseconds(value)
    except ValueError as exc:
        raise SafeStateError(f"invalid UTC timestamp: {value!r}", "ecl.error.semantic-invalid.v1") from exc

@dataclass(frozen=True)
class FailOpenAuthorization:
    owner: str
    rationale: str
    expires_at: str
    evidence_profile: str
    covered_advisory_dependencies: tuple[str, ...] = ()

@dataclass(frozen=True)
class ActionSafeStatePolicy:
    action_class: str
    timeout_disposition: str
    dependency_disposition: str
    stale_dependency_disposition: str
    buffer_exhaustion_disposition: str
    restricted_operations: tuple[str, ...]
    irreversible_risk_requires_fail_closed: bool = False
    law_or_contract_requires_fail_closed: bool = False
    fail_open_authorization: FailOpenAuthorization | None = None

@dataclass(frozen=True)
class SafeStateDecision:
    disposition: str
    triggering_failures: tuple[str, ...]
    permitted_operations: tuple[str, ...]
    evidence_obligations: tuple[str, ...]

def _dependency_names(values: tuple[str, ...], name: str) -> None:
    if type(values) is not tuple or any(type(item) is not str or not item.strip() for item in values):
        raise SafeStateError(f"{name} must be a tuple of nonempty dependency identifiers", "ecl.error.semantic-invalid.v1")
    if len(set(values)) != len(values):
        raise SafeStateError(f"{name} repeats a dependency identifier", "ecl.error.semantic-invalid.v1")


def _validate_disposition(value: str) -> None:
    if type(value) is not str or value not in DISPOSITION_PRECEDENCE:
        raise SafeStateError(
            f"unknown safe-state disposition: {value!r}",
            "ecl.error.semantic-invalid.v1",
        )

def _fail_open_is_authorized(
    policy: ActionSafeStatePolicy,
    *,
    evaluated_at: str,
    failed_advisory_dependencies: tuple[str, ...],
    required_proof_available: bool | None,
) -> bool:
    authorization = policy.fail_open_authorization
    if authorization is None or required_proof_available is not True:
        return False
    if not failed_advisory_dependencies or not set(failed_advisory_dependencies) <= set(authorization.covered_advisory_dependencies):
        return False
    if (
        not authorization.owner
        or not authorization.rationale
        or not authorization.evidence_profile
    ):
        return False
    if policy.irreversible_risk_requires_fail_closed:
        return False
    if policy.law_or_contract_requires_fail_closed:
        return False
    return _time(evaluated_at) < _time(authorization.expires_at)

def decide_safe_state(
    failures: Iterable[str],
    policy: ActionSafeStatePolicy,
    *,
    evaluated_at: str,
    failed_advisory_dependencies: tuple[str, ...] = (),
    required_proof_available: bool | None = None,
) -> SafeStateDecision:
    """Select the strongest authorized disposition for one or more observed failures.

    This helper evaluates a failure transition, not healthy operation. The caller
    must supply at least one failure and retain any higher-precedence current state.
    Fail-open additionally needs the identities of the failed advisory dependencies,
    covered by the policy, and an explicit declaration that all required proof remains
    present, valid and unexpired. Unknown proof availability fails closed. The caller
    establishes these facts from its deployment; this helper does not inspect it.

    Each failure whose policy selects fail_open must be attributable to the declared
    covered advisory dependencies; the tuple must account for every failed dependency
    at this transition. A concurrent advisory outage does not cover an unrelated local
    timeout or evidence-buffer failure. The caller selects a stronger policy disposition
    for that failure, or reports any resulting loss of required proof under TS1-032.
    """
    _time(evaluated_at)
    if type(policy.action_class) is not str or not policy.action_class.strip():
        raise SafeStateError("action_class must be nonempty text", "ecl.error.semantic-invalid.v1")
    if type(policy.restricted_operations) is not tuple or any(
        type(item) is not str or not item.strip() for item in policy.restricted_operations
    ):
        raise SafeStateError("restricted_operations must be a tuple of nonempty operation identifiers", "ecl.error.semantic-invalid.v1")
    if len(set(policy.restricted_operations)) != len(policy.restricted_operations):
        raise SafeStateError("restricted_operations repeats an operation identifier", "ecl.error.semantic-invalid.v1")
    for name in ("irreversible_risk_requires_fail_closed", "law_or_contract_requires_fail_closed"):
        if type(getattr(policy, name)) is not bool:
            raise SafeStateError(f"{name} must be a boolean", "ecl.error.semantic-invalid.v1")
    if required_proof_available is not None and type(required_proof_available) is not bool:
        raise SafeStateError("required_proof_available must be a boolean or None", "ecl.error.semantic-invalid.v1")
    for name in ("timeout_disposition", "dependency_disposition", "stale_dependency_disposition", "buffer_exhaustion_disposition"):
        _validate_disposition(getattr(policy, name))
    _dependency_names(failed_advisory_dependencies, "failed_advisory_dependencies")
    authorization = policy.fail_open_authorization
    if authorization is not None:
        for name in ("owner", "rationale", "evidence_profile"):
            item = getattr(authorization, name)
            if type(item) is not str or not item.strip():
                raise SafeStateError(f"fail-open {name} must be nonempty text", "ecl.error.semantic-invalid.v1")
        _time(authorization.expires_at)
        _dependency_names(authorization.covered_advisory_dependencies, "covered_advisory_dependencies")
    values = tuple(sorted(set(failures)))
    if not values:
        raise ValueError("a safe-state failure decision requires at least one failure")
    candidates: list[str] = ["fail_closed"] if required_proof_available is False else []
    for value in values:
        if value in UNCONDITIONAL_FAIL_CLOSED:
            candidates.append("fail_closed")
        elif value == "emergency_halt":
            candidates.append("emergency_halt")
        elif value in {"quarantine", "conflicting_authority"}:
            candidates.append("quarantine")
        elif value == "deadline_exceeded":
            candidates.append(policy.timeout_disposition)
        elif value == "dependency_unavailable":
            candidates.append(policy.dependency_disposition)
        elif value == "dependency_stale":
            candidates.append(policy.stale_dependency_disposition)
        elif value == "evidence_buffer_exhausted":
            candidates.append(policy.buffer_exhaustion_disposition)
        else:
            raise SafeStateError(
                f"unknown failure class: {value!r}",
                "ecl.error.semantic-invalid.v1",
            )
    for candidate in candidates:
        _validate_disposition(candidate)
    # Resolve each failure before precedence: an unauthorized fail-open condition
    # remains fail-closed when another, lower-precedence failure is added.
    if "fail_open" in candidates and not _fail_open_is_authorized(
        policy, evaluated_at=evaluated_at,
        failed_advisory_dependencies=failed_advisory_dependencies,
        required_proof_available=required_proof_available,
    ):
        candidates = ["fail_closed" if item == "fail_open" else item for item in candidates]
    disposition = max(candidates, key=lambda item: DISPOSITION_PRECEDENCE[item])
    permitted = (
        policy.restricted_operations
        if disposition in {"restricted", "degraded"}
        else ()
    )
    return SafeStateDecision(
        disposition=disposition,
        triggering_failures=values,
        permitted_operations=tuple(sorted(set(permitted))),
        evidence_obligations=(
            "failure-class observations",
            "selected disposition and precedence",
            "policy identity and epoch",
            "entry time and recovery decision",
        ),
    )

@dataclass(frozen=True)
class RecoveryEvidence:
    policy_epochs_reconciled: bool
    revocations_reconciled: bool
    consumed_authorities_reconciled: bool
    buffered_evidence_reconciled: bool
    clock_discontinuities_reconciled: bool
    unresolved_effect_ids: tuple[str, ...] = ()

def recovery_is_complete(evidence: RecoveryEvidence) -> bool:
    """Check typed reconciliation declarations and the declared unresolved-effect set."""
    for name in (
        "policy_epochs_reconciled", "revocations_reconciled", "consumed_authorities_reconciled",
        "buffered_evidence_reconciled", "clock_discontinuities_reconciled",
    ):
        if type(getattr(evidence, name)) is not bool:
            raise SafeStateError("recovery reconciliation declarations must be boolean", "ecl.error.semantic-invalid.v1")
    if type(evidence.unresolved_effect_ids) is not tuple or any(
        type(value) is not str or not value.strip() for value in evidence.unresolved_effect_ids
    ):
        raise SafeStateError("unresolved effect identities must be a tuple of nonempty strings", "ecl.error.semantic-invalid.v1")
    return (
        evidence.policy_epochs_reconciled
        and evidence.revocations_reconciled
        and evidence.consumed_authorities_reconciled
        and evidence.buffered_evidence_reconciled
        and evidence.clock_discontinuities_reconciled
        and not evidence.unresolved_effect_ids
    )
