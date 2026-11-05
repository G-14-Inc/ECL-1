"""Offline verification checks and read-only metadata for safe_state."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from .schema import parse_rfc3339_utc


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
        "invalid_integrity",
        "unknown_critical_extension",
        "critical_verification_failure",
        "replay_detected",
    }
)

def _time(value: str) -> datetime:
    """An ECL RFC 3339 UTC instant, by the shared parser (one to nine fractional digits)."""
    try:
        return parse_rfc3339_utc(value)
    except ValueError as exc:
        raise SafeStateError(f"invalid UTC timestamp: {value!r}", "ecl.error.semantic-invalid.v1") from exc

@dataclass(frozen=True)
class FailOpenAuthorization:
    owner: str
    rationale: str
    expires_at: str
    evidence_profile: str

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

def _validate_disposition(value: str) -> None:
    if value not in DISPOSITION_PRECEDENCE:
        raise SafeStateError(
            f"unknown safe-state disposition: {value!r}",
            "ecl.error.semantic-invalid.v1",
        )

def _fail_open_is_authorized(
    policy: ActionSafeStatePolicy,
    *,
    evaluated_at: str,
) -> bool:
    authorization = policy.fail_open_authorization
    if authorization is None:
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
) -> SafeStateDecision:
    values = tuple(sorted(set(failures)))
    candidates: list[str] = []
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
    disposition = (
        max(candidates, key=lambda item: DISPOSITION_PRECEDENCE[item])
        if candidates
        else "degraded"
    )
    if disposition == "fail_open" and not _fail_open_is_authorized(
        policy,
        evaluated_at=evaluated_at,
    ):
        disposition = "fail_closed"
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
    return (
        evidence.policy_epochs_reconciled
        and evidence.revocations_reconciled
        and evidence.consumed_authorities_reconciled
        and evidence.buffered_evidence_reconciled
        and evidence.clock_discontinuities_reconciled
        and not evidence.unresolved_effect_ids
    )
