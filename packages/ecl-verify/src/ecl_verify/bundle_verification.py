"""Offline verification of signed ECL evidence bundles (EBMP-2 section 11).

Historical validity is evaluated under the trust-policy version named by each signed object, at
the object's own time or, when the envelope carries trusted-time countersignatures, at the
earliest time a separate time authority attests (IE1-032 to IE1-035); ``current`` is a separate
status under the caller's latest policy (TRUST-POLICY-1). A bundle that
is otherwise verified but has a signer that is not acceptable now gets the distinct verdict
``current-trust-failed`` (EBMP2-060) unless the caller accepts that explicitly. An observation
only corroborates an effect when it names the same URI and digest, is later than the terminal
event, and is signed by a separately purposed principal using disjoint authenticated key material
(EBMP2-061). The verifier applies the reference verification profile,
``ecl.verification-profile.reference.v1``: a response clock-skew allowance of zero unless the
caller passes another (DCMP2-047) and the fail-closed-deny state-outcome table (EBMP2-051).
A caller that requires trusted time applies ``ecl.verification-profile.reference-trusted-time.v1``,
which also refuses an envelope without a trusted-time countersignature (IE1-035).

The decision basis (ECL1N-0181, DCMP2-053): every signed decision response is checked under the
one-way rule as an object. Every decision response carries ``ecl.ext.decision-basis.v1``;
a response without that record is refused (``ecl.rule.decision-basis-required.v1``).
A caller that supplies the Consequential Action Register also
refuses a decision basis that names another register version, whose inputs are not the inputs
that the register declares for the request's action class, or whose times show that an input
recorded as available was late (``ecl.rule.decision-basis-matches-register.v1``). Every caller
refuses a decision basis that records as ``verifiable`` an input whose source is the request's
actor (``ecl.rule.decision-basis-one-way.v1``). A register that
fails its schema or ``ecl.rule.register-declarations-consistent.v1``, one that declares an action
class or an input of a class twice among them, is refused as a usage error (DCMP2-053).

All malformed bundle inputs produce an ``invalid`` report. Only an invalid ``now`` argument is a
usage error and raises ``ValueError``. Fixed verifier summaries avoid input values; bounded
schema diagnostics can quote invalid values.

A report's findings are in the order of EBMP2-068: by the stage of verification that found them,
and within a stage by the order the stage gives, never by the position of an object in the
bundle. ``primary_finding`` names the primary finding of a report.

Pre-release obligations (DCMP2-017, EBMP2-070): an ``execution_released`` event whose signed
response carries an obligation to be met before release, or a witness result required before
release, records in ``ecl.ext.obligation-discharge.v1`` a discharge of each one; the obligations
come from the response as the bundle holds it, never from the producer's own list
(``ecl.rule.prerelease-obligations-discharged.v1``). A proof that is an ECL object is carried in
the bundle as its own object, which the entry names by reference and digest, and is checked
there: a valid envelope under the trust policy, signed by the issuer the obligation names (for an
approval obligation, by keys that hold the approval purpose) and never by the requesting actor, of
a type the obligation admits, bound to this exchange by the request's digest, and fresh at the
release; each failure is ``ecl.error.obligation-unproven.v1``.
An entry's ``fresh_until`` must lie after the release plus its declared release guard.

The release (EBMP2-050, EBMP2-071): an ``execution_released`` event records ``release_guard_ms``,
the enforcement point's declared bound on the delay from its ``observed_at`` to the release, and
``observed_at`` plus that guard must be earlier than the authorization's ``valid_until``. A
terminal event that records, in ``ecl.ext.mcp-binding.v1``, that the release completed after
``valid_until`` (``released_after_valid_until``) makes the bundle invalid with
``ecl.error.expired.v1`` (EBMP2-072); a ``forward_completed_at`` at or after ``valid_until`` is
the server's late answer, not a finding, and sets the report's ``completion_after_window``.
The use counts of consumed authority stay within the authorization's use policy (EBMP2-073), a
release of single-use authority has its consumption recorded (EBMP2-074), and an event that
carries the MCP binding names the call that its request bound (EBMP2-075).

Every report carries its scope (EBMP2-076): ``established``, the checks that the verifier made and
that held, and ``not_established``, the checks that apply but did not hold or were not made and
the statements that no verification establishes, with a ``reasons`` map for the items that a
stated reason keeps out of ``established``: ``release-within-authority`` is ``no-release-recorded``
when the bundle records no release, and ``prerelease-obligations-proofs-verified`` is
``proof-not-ecl-object`` when a discharge entry's proof is not an object of the bundle, or
``issuer-not-named`` when every proof is carried and the decision names no issuer for an
obligation (a witness result without ``source``). ``report_scope`` computes the scope from the
report.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from functools import cache, partial
from types import MappingProxyType
from typing import Any, Protocol

from . import binding, integrity
from . import bundle as causal
from . import decision_basis_checks as basis
from .canonical import CanonicalizationError, loads_json_strict, object_digest
from .resources import object_findings, registry_document, schema_is_valid, validator_for
from .schema import rfc3339_utc_nanoseconds
from .signature_metadata import TIME_ATTESTATION_TYPE
from .trust import (
    PURPOSE_APPROVAL,
    PURPOSE_DECISION_REQUEST,
    PURPOSE_DECISION_RESPONSE,
    PURPOSE_EVIDENCE_EVENT,
    PURPOSE_OBSERVATION,
    PURPOSE_TRUSTED_TIME,
    TrustedKey,
    TrustPolicy,
)

BUNDLE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/evidence-bundle/1"
MAX_ENVELOPES = 256
MAX_OBSERVATIONS = 256
MAX_TOTAL_PAYLOAD_NODES = 100_000
MAX_REGISTER_BYTES = 1024 * 1024

REFERENCE_PROFILE = "ecl.verification-profile.reference.v1"
TRUSTED_TIME_PROFILE = "ecl.verification-profile.reference-trusted-time.v1"
TIME_ATTESTATION_SCHEMA = "https://externalcontrollayer.ai/ns/schema/time-attestation/1"
CURRENT_TRUST_FAILED = "current-trust-failed"
TRUSTED_TIME_REQUIRED = "ecl.error.trusted-time-required.v1"
TRUSTED_TIME_INVALID = "ecl.error.trusted-time-invalid.v1"
SCHEMA_INVALID = "ecl.error.schema-invalid.v1"
SEMANTIC_INVALID = "ecl.error.semantic-invalid.v1"
INTEGRITY_INVALID = "ecl.error.integrity-invalid.v1"
POLICY_INVALID = "ecl.error.signature-policy-invalid.v1"
DECISION_BINDING_INVALID = "ecl.error.decision-binding-invalid.v1"
DIGEST_MISMATCH = "ecl.error.digest-mismatch.v1"
REVOKED = "ecl.error.revoked.v1"
EXPIRED = "ecl.error.expired.v1"
RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1"
THRESHOLD_NOT_MET = "ecl.error.threshold-not-met.v1"
CAUSAL_CLOSURE_INCOMPLETE = "ecl.error.causal-closure-incomplete.v1"
# EBMP2-057 (F08): an object time, or an attested time, later than the evaluation time.
CLOCK_REGRESSED = "ecl.error.clock-regressed.v1"
OUTCOME_REASON = "ecl.ext.outcome-reason.v1"
# EBMP2-070: the record of the obligations that Enforcement proved before the release, the rule
# that checks it, and the names that a witness result required before release takes in it.
OBLIGATION_DISCHARGE = "ecl.ext.obligation-discharge.v1"
DISCHARGE_RULE = "ecl.rule.prerelease-obligations-discharged.v1"
COUPLING = "ecl.ext.consequence-coupling.v1"
WITNESS_OBLIGATION_TYPE = "ecl.obligation.verify-witness.v1"
APPROVAL_OBLIGATION_TYPE = "ecl.obligation.approval-record.v1"
POST_RELEASE = frozenset({"during_execution", "after_execution"})
# EBMP2-070: the finding of a carried proof that fails one of its checks, or of a stale proof.
OBLIGATION_UNPROVEN = "ecl.error.obligation-unproven.v1"
# EBMP2-076: the items of the scope that a stated reason keeps out of `established`, and the
# reasons.
SCOPE_RELEASE = "release-within-authority"
SCOPE_PROOFS = "prerelease-obligations-proofs-verified"
REASON_NO_RELEASE = "no-release-recorded"
REASON_PROOF_NOT_ECL_OBJECT = "proof-not-ecl-object"
REASON_ISSUER_NOT_NAMED = "issuer-not-named"
# EBMP2-072 and EBMP2-075: the MCP binding of a request and of the events of its action.
MCP_BINDING = "ecl.ext.mcp-binding.v1"
MCP_RESPONSE_STATES = frozenset({"succeeded", "failed"})

# EBMP2-076: the scope of a verdict. The checks a verifier makes, in the order of the table of
# EBMP2-076, then the statements that no verification establishes. Two checks and one statement
# apply only to some bundles (CONDITIONAL_SCOPE); the others apply to every report.
SCOPE_CHECKS = (
    "envelope-signatures",
    "current-trust",
    "trusted-time",
    "object-rules",
    "decision-basis-recorded",
    "decision-basis-register",
    "bindings",
    "release-within-authority",
    "causal-completeness",
    "prerelease-obligations-discharge-recorded",
    "prerelease-obligations-proofs-verified",
)
SCOPE_NEVER = (
    "prerelease-obligations-met",
    "post-release-obligations-met",
    "recorded-times-true",
    "effects-occurred",
    "deployment-assessed",
    "statements-true",
)
SCOPE_DISCHARGE = (
    "prerelease-obligations-discharge-recorded",
    "prerelease-obligations-proofs-verified",
    "prerelease-obligations-met",
)
SCOPE_POST_RELEASE = "post-release-obligations-met"
# The item that applies only when the caller supplies a Consequential Action Register.
SCOPE_REGISTER = "decision-basis-register"
CONDITIONAL_SCOPE = frozenset({*SCOPE_DISCHARGE, SCOPE_POST_RELEASE})
# The sentence for people that each item of the scope stands for (the table of EBMP2-076).
SCOPE_TEXT: Mapping[str, str] = MappingProxyType(
    {
        "envelope-signatures": "each envelope's and observation's payload digest and signatures "
        "verify under the trust-policy version its object names, at the object's own time or its "
        "trusted time, and the current trust policy revokes none of its trust dependencies at or "
        "before its time",
        "current-trust": "each trust dependency, each signing key of each envelope and "
        "observation and of each time attestation, is acceptable under the current trust policy "
        "at the evaluation time",
        "trusted-time": "a separate time authority attests a time for each signature of each "
        "envelope and observation, binding that signature, each signature was valid at that "
        "time, and each time authority's key was valid then and is not revoked by the current "
        "trust policy at or before it",
        "object-rules": "each signed object satisfies its schema and semantic rules, the one-way "
        "rule for a recorded decision basis among them",
        "decision-basis-recorded": "each decision response records its decision basis",
        "decision-basis-register": "each decision basis agrees with the Consequential Action "
        "Register supplied",
        "bindings": "each response binds its request, each event binds its request, response "
        "and authority, with the digests and use counts they name, each continuation binds the "
        "request, challenge and approval it continues, and each terminal event carries the "
        "outcome reason its state and response require",
        "release-within-authority": "each recorded release time lies within the authorization's "
        "validity window",
        "causal-completeness": "over every object of the bundle, observations included, every "
        "causal predecessor is in the bundle with the digest that names it and in the workflow, "
        "trace and attempt that the rules allow, the graph is acyclic, identifiers are unique, "
        "and every request has a terminal event",
        "prerelease-obligations-discharge-recorded": "each release records a discharge of every "
        "obligation its decision left to Enforcement before the release, checked no later than "
        "the release was observed",
        "prerelease-obligations-proofs-verified": "each pre-release discharge carries its proof, "
        "and each proof is a valid ECL object under the trust policy, signed by the issuer the "
        "obligation names, of a type the obligation admits, bound to this exchange and fresh at "
        "the release",
        "prerelease-obligations-met": "that each pre-release obligation was met: the verifier "
        "checks a proof's signatures, issuer, type, binding and freshness, not what the proof "
        "shows",
        "post-release-obligations-met": "that the obligations to be met during or after execution "
        "were met, which the verifier does not check",
        "recorded-times-true": "that each recorded time is the true time of its event: each "
        "producer states its own times",
        "effects-occurred": "that the effects happened: a terminal event is its producer's "
        "statement, and corroboration is another signed statement, an observation bound to that "
        "terminal event and its attempt",
        "deployment-assessed": "that the deployment that produced the evidence has been assessed "
        "or meets ECL-1",
        "statements-true": "that the statements in the bundle are true, among them the "
        "enforcement point's statements of what it checked and released",
    }
)

# EBMP2-068: the stages of verification, in order, and within each stage the order of its
# findings. _RULES stands for the registered rules, which rank by their registry precedence.
STAGE_PAYLOADS = 2
STAGE_OBJECTS = 3
STAGE_SIGNERS = 4
STAGE_PAIRING = 5
STAGE_REQUESTS = 6
STAGE_EVENTS = 7
STAGE_CAUSAL = 8
STAGE_REASONS = 9
_RULES = "registered rules"
SIGNER_ORDER = (
    CLOCK_REGRESSED,
    POLICY_INVALID,
    TRUSTED_TIME_INVALID,
    TRUSTED_TIME_REQUIRED,
    REVOKED,
    EXPIRED,
    RESOURCE_LIMIT,
    INTEGRITY_INVALID,
    THRESHOLD_NOT_MET,
)
_STAGE_ORDERS: Mapping[int, tuple[str, ...]] = MappingProxyType(
    {
        STAGE_PAYLOADS: (RESOURCE_LIMIT, INTEGRITY_INVALID),
        STAGE_OBJECTS: (SCHEMA_INVALID, _RULES, SEMANTIC_INVALID),
        STAGE_SIGNERS: SIGNER_ORDER,
        STAGE_PAIRING: (SCHEMA_INVALID, DECISION_BINDING_INVALID),
        STAGE_REQUESTS: (
            binding.REQUEST_BINDING_INVALID,
            DIGEST_MISMATCH,
            binding.AUDIENCE_MISMATCH,
            binding.SCOPE_MISMATCH,
        ),
        STAGE_EVENTS: (DECISION_BINDING_INVALID, DIGEST_MISMATCH, EXPIRED),
        STAGE_CAUSAL: (RESOURCE_LIMIT, _RULES, DECISION_BINDING_INVALID, OBLIGATION_UNPROVEN),
        STAGE_REASONS: (SEMANTIC_INVALID,),
    }
)


@cache
def _rule_precedence() -> Mapping[str, int]:
    entries = registry_document("semantic-rules")["entries"]
    return MappingProxyType(
        {
            item["id"]: item["attributes"]["precedence"]
            for item in entries
            if item.get("status") == "active"
        }
    )


@cache
def _rule_stage() -> Mapping[str, int]:
    """The stage of EBMP2-068 that each bundle rule names in its registry `stage` attribute."""
    entries = registry_document("semantic-rules")["entries"]
    return MappingProxyType(
        {
            item["id"]: item["attributes"]["stage"]
            for item in entries
            if item.get("status") == "active" and type(item["attributes"].get("stage")) is int
        }
    )


class _Sink(Protocol):
    def append(self, finding: str) -> None: ...

    def extend(self, items: Iterable[str]) -> None: ...


class _StageSink:
    """Where one stage's findings go."""

    def __init__(self, findings: _Findings, stage: int) -> None:
        self._findings = findings
        self._stage = stage

    def append(self, finding: str) -> None:
        self._findings.add(self._stage, finding)

    def extend(self, items: Iterable[str]) -> None:
        for finding in items:
            self._findings.add(self._stage, finding)


class _Findings:
    """The findings of one verification, each with the stage that found it (EBMP2-068)."""

    def __init__(self) -> None:
        self._items: list[tuple[int, str]] = []

    def add(self, stage: int, finding: str) -> None:
        self._items.append((stage, finding))

    def at(self, stage: int) -> _StageSink:
        return _StageSink(self, stage)

    def __bool__(self) -> bool:
        return bool(self._items)

    def codes(self, stage: int) -> set[str]:
        """The codes of the findings that one stage found."""
        return {finding.split(":", 1)[0] for found, finding in self._items if found == stage}

    def ordered(self) -> tuple[str, ...]:
        """The findings in the order of EBMP2-068; findings that rank alike keep their order. A
        bundle rule ranks in the stage that its registry entry names (`stage`), by precedence."""
        precedence = _rule_precedence()
        stages = _rule_stage()

        def rank(item: tuple[int, tuple[int, str]]) -> tuple[int, int, int, int]:
            position, (found_at, finding) = item
            code = finding.split(":", 1)[0]
            stage = stages.get(code, found_at)
            order = _STAGE_ORDERS.get(stage, ())
            if code in order:
                return (stage, order.index(code), 0, position)
            if code in precedence and _RULES in order:
                return (stage, order.index(_RULES), precedence[code], position)
            return (stage, len(order), 0, position)

        return tuple(finding for _, (_, finding) in sorted(enumerate(self._items), key=rank))


_NOW = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:[0-2][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{3}|\.[0-9]{6})?Z"
)
_NON_RELEASE = frozenset({"denied", "held", "challenged", "expired_before_release"})


@dataclass(frozen=True)
class EnvelopeCheck:
    index: int
    object_id: str | None
    kind: str
    signer_key_ids: tuple[str, ...]
    historical: str
    current: str
    historical_policy_version: str | None = None
    trusted_time: str | None = None


@dataclass(frozen=True)
class TrustDependency:
    """TP1-006: one trust dependency of a bundle, a signing key of an object (`signer`) or of a
    time attestation that a trusted-time countersignature of the object carries
    (`time-authority`, with the countersignature's `counter_id`). `at` is the time of its
    historical check (IE1-034), `historical` its status under the policy version that its object
    or attestation names with the current policy's revocations applied, `revoked_effective_at`
    the effective time of the current policy's revocation of its key identifier, and `current`
    its status under the current policy at the evaluation time."""

    index: int
    role: str
    counter_id: str | None
    key_id: str
    suite: str
    at: str | None
    historical_policy_version: str | None
    historical: str
    current_policy_version: str
    revoked_effective_at: str | None
    current: str


@dataclass(frozen=True)
class BindingCheck:
    name: str
    passed: bool
    code: str | None


@dataclass(frozen=True)
class EffectEvidence:
    action_id: str
    state: str
    level: str
    authority: str
    reason: str | None


@dataclass(frozen=True)
class ReportScope:
    """EBMP2-076: what a verdict establishes and what it does not, each in the order of the table
    of EBMP2-076, and the stated reason for each item that a reason keeps out of `established`:
    `release-within-authority` is `no-release-recorded` when the bundle records no release, and
    `prerelease-obligations-proofs-verified` is `proof-not-ecl-object` when an entry's proof is
    not an object of the bundle, or `issuer-not-named` when every proof is carried and the
    decision names no issuer for an obligation."""

    established: tuple[str, ...] = ()
    not_established: tuple[str, ...] = ()
    reasons: dict[str, str] = field(default_factory=dict)
    # EBMP2-076: for each item in `established`, the checks of registries/scope-checks.json that
    # ran for it and held, in registry order, and the indexes of the objects they covered.
    checks: dict[str, dict[str, list[Any]]] = field(default_factory=dict)


@dataclass(frozen=True)
class BundleReport:
    verdict: str
    envelope_checks: tuple[EnvelopeCheck, ...]
    binding_checks: tuple[BindingCheck, ...]
    causal_status: str
    effects: tuple[EffectEvidence, ...]
    findings: tuple[str, ...]
    verification_profile: str = REFERENCE_PROFILE
    accepted_current_trust_failure: bool = False
    # The register version the decision bases were checked against, if any (DCMP2-053, IE1-023).
    register: dict[str, Any] | None = None
    # EBMP2-076: the scope of the verdict; `report_scope` computes it from the rest of the report.
    scope: ReportScope = field(default_factory=ReportScope)
    # EBMP2-072: whether a terminal event records, in the MCP binding, a server answer that arrived
    # at or after the authorization's `valid_until`. The release itself was inside the window, or
    # the bundle is invalid: this member is information, not a finding.
    completion_after_window: bool = False
    # TP1-006: every trust dependency of the bundle, in the order of the objects' indexes, each
    # object's signers before the signers of its time attestations.
    trust_dependencies: tuple[TrustDependency, ...] = ()
    # EBMP2-057: the evaluation time the verification used, as the caller gave it.
    evaluation_time: str | None = None
    # EBMP-2 section 4: the identifiers of the causal predecessors that the bundle does not hold,
    # in ascending code-point order, each once.
    unresolved_predecessor_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Entry:
    index: int
    observation: bool
    envelope: dict[str, Any]
    payload: dict[str, Any]
    check: EnvelopeCheck
    signing_keys: frozenset[tuple[str, bytes]]


def _issue(code: str, message: str) -> str:
    return f"{code}: {message}"


def _invalid(*findings: str) -> BundleReport:
    return BundleReport("invalid", (), (), "not-analyzed", (), tuple(findings))


def _instant_ns(value: str) -> int:
    return rfc3339_utc_nanoseconds(value)


def _valid_now(now: object) -> str:
    if type(now) is not str or _NOW.fullmatch(now) is None:
        raise ValueError("now must be RFC 3339 UTC with 0, 3 or 6 fractional digits")
    try:
        _instant_ns(now)
    except ValueError as error:
        raise ValueError("now is not a calendar-valid UTC instant") from error
    return now


def _nodes(value: object, budget: int) -> int:
    """Count all containers and scalars, stopping as soon as the remaining budget is exceeded."""
    count = 0
    stack = [value]
    while stack:
        item = stack.pop()
        count += 1
        if count > budget:
            return count
        if type(item) is dict:
            stack.extend(item.values())
        elif type(item) is list:
            stack.extend(item)
    return count


def _text(value: Mapping[str, Any], *path: str) -> str | None:
    found: Any = value
    for part in path:
        if type(found) is not dict:
            return None
        found = found.get(part)
    return found if type(found) is str else None


def _mapping(value: Mapping[str, Any], *path: str) -> dict[str, Any] | None:
    found: Any = value
    for part in path:
        if type(found) is not dict:
            return None
        found = found.get(part)
    return found if type(found) is dict else None


def _identifier(payload: dict[str, Any]) -> str | None:
    return _text(payload, "message_id") or _text(payload, "object_id")


def _kind(payload: dict[str, Any]) -> str:
    return _text(payload, "message_type") or _text(payload, "event_type") or "unknown"


def _purpose(payload: dict[str, Any], observation: bool) -> str | None:
    if _text(payload, "protocol") == "DCMP-2":
        kind = _text(payload, "message_type")
        if kind == "decision_request":
            return PURPOSE_DECISION_REQUEST
        if kind == "decision_response":
            return PURPOSE_DECISION_RESPONSE
    if _text(payload, "protocol") == "EBMP-2":
        return PURPOSE_OBSERVATION if observation else PURPOSE_EVIDENCE_EVENT
    return None


def _object_time(payload: dict[str, Any]) -> str | None:
    if _text(payload, "protocol") == "DCMP-2":
        return _text(payload, "issued_at")
    if _text(payload, "protocol") == "EBMP-2":
        return _text(payload, "observed_at")
    return None


def _time_policy(payload: dict[str, Any]) -> str | None:
    return _text(payload, "integrity_policy", "verification_time_policy")


def _principal(payload: dict[str, Any]) -> str | None:
    owner = "issuer" if _text(payload, "protocol") == "DCMP-2" else "producer"
    return _text(payload, owner, "id")


def _trusted_key(policy: TrustPolicy, key_id: str) -> TrustedKey | None:
    try:
        return policy.key(key_id)
    except KeyError:
        return None


def _current_revocation(
    current: TrustPolicy, key_id: str, public_key: bytes | None = None
) -> str | None:
    """The earliest `effective_at` among the current policy's revocations that reach a
    dependency (TP1-006): a revocation of its key identifier, whatever key material the current
    policy holds under it, or of a key that the current policy lists with the dependency's
    public key under another identifier."""
    times = [
        item.effective_at
        for item in current.revocations
        if item.key_id == key_id
        or (
            public_key is not None
            and (listed := _trusted_key(current, item.key_id)) is not None
            and listed.public_key == public_key
        )
    ]
    return min(times, key=_instant_ns) if times else None


def _key_time_status(
    key: TrustedKey, policy: TrustPolicy, at: str, current: TrustPolicy | None = None
) -> str:
    """A key's status at `at` under `policy`: revoked, then outside its validity interval. With
    `current`, a revocation in the caller's current policy effective at or before `at` also
    revokes it (TP1-006, ECL1N-0159)."""
    instant = _instant_ns(at)
    if any(
        revocation.key_id == key.key_id and instant >= _instant_ns(revocation.effective_at)
        for revocation in policy.revocations
    ):
        return REVOKED
    if current is not None:
        revoked = _current_revocation(current, key.key_id, key.public_key)
        if revoked is not None and instant >= _instant_ns(revoked):
            return REVOKED
    if instant < _instant_ns(key.valid_from):
        return EXPIRED
    if key.valid_until is not None and instant >= _instant_ns(key.valid_until):
        return EXPIRED
    return "valid"


def _history_problem(policy: TrustPolicy, history: Sequence[TrustPolicy]) -> str | None:
    seen = {policy.digest}
    for older in history:
        if (
            not isinstance(older, TrustPolicy)
            or older.policy_id != policy.policy_id
            or older.epoch >= policy.epoch
            or older.digest in seen
        ):
            return _issue(
                POLICY_INVALID, "history must hold distinct earlier versions of this policy"
            )
        seen.add(older.digest)
    return None


def _registered_errors() -> frozenset[str]:
    entries = registry_document("error-codes")["entries"]
    return frozenset(
        item["id"]
        for item in entries
        if item.get("status") == "active" and item["id"].startswith("ecl.error.")
    )


def _signature_ids(envelope: dict[str, Any]) -> tuple[str, ...]:
    signatures = envelope.get("signatures")
    if type(signatures) is not list:
        return ()
    return tuple(
        signature["key_id"]
        for signature in signatures
        if type(signature) is dict and type(signature.get("key_id")) is str
    )


def _member_text(value: Mapping[str, Any], member: str) -> str:
    """A member's text, or the empty string when it is not text."""
    found = value.get(member)
    return found if type(found) is str else ""


def _signature_entries(envelope: dict[str, Any]) -> list[tuple[str, str]]:
    """The (key_id, suite_id) of each signature entry, in envelope order, text or not."""
    signatures = envelope.get("signatures")
    if type(signatures) is not list:
        return []
    return [
        (
            _member_text(item, "key_id"),
            _member_text(item, "suite_id"),
        )
        for item in signatures
        if type(item) is dict
    ]


def _key_acceptable(
    key: TrustedKey | None,
    signature: Mapping[str, Any],
    purpose: str,
    owner: str | None,
    original: TrustPolicy | None,
) -> bool:
    """TP1-004, TP1-005 and IE1-040 step 6 (a): the key is the policy's, for the entry's suite,
    with the object's purpose and principal, and, for current status, the same public key as the
    historical check used."""
    if key is None:
        return False
    if original is not None:
        old = _trusted_key(original, key.key_id)
        if old is None or old.public_key != key.public_key:
            return False
    return (
        key.suite_id == signature.get("suite_id")
        and purpose in key.purposes
        and key.principal == owner
    )


def _signer_status(
    envelope: dict[str, Any],
    payload: dict[str, Any],
    policy: TrustPolicy,
    purpose: str,
    at: str,
    *,
    original: TrustPolicy | None = None,
    times: Mapping[str, str] | None = None,
    current: TrustPolicy | None = None,
) -> str:
    """Check every signer, counted or not (TP1-004, TP1-005), in the order of IE1-040, step 6:
    every key acceptable for the object's suite, purpose and principal, and for current status
    the same public key as at signing; then no key revoked at its time; then every key within its
    validity interval at its time. A key's time is `times[key_id]` when given (IE1-034), else
    `at`; with `current`, the current policy's revocations apply too (TP1-006)."""
    signatures = envelope["signatures"]
    owner = _principal(payload)
    keys: list[TrustedKey] = []
    for signature in signatures:
        key = _trusted_key(policy, signature["key_id"])
        if key is None or not _key_acceptable(key, signature, purpose, owner, original):
            return POLICY_INVALID
        keys.append(key)
    statuses = {
        _key_time_status(key, policy, (times or {}).get(key.key_id, at), current) for key in keys
    }
    for status in (REVOKED, EXPIRED):
        if status in statuses:
            return status
    return "valid"


def _verify_signature(
    envelope: dict[str, Any],
    policy: TrustPolicy,
    payload: dict[str, Any],
    at: str,
    *,
    signed_policy: TrustPolicy | None = None,
    times: Mapping[str, str] | None = None,
    current: TrustPolicy | None = None,
) -> tuple[str, frozenset[str]]:
    time_policy = _time_policy(payload)
    expected_time_policy = (
        "ecl.time.issued-at.v1"
        if _text(payload, "protocol") == "DCMP-2"
        else "ecl.time.observed-at.v1"
    )
    if time_policy != expected_time_policy:
        return POLICY_INVALID, frozenset()
    try:
        context = policy.verification_context(evaluated_at=at, time_policy=time_policy)
        if signed_policy is not None:
            context = replace(
                context,
                trust_policy_id=signed_policy.policy_id,
                trust_policy_version=signed_policy.version,
                trust_policy_digest=signed_policy.digest,
                trust_policy_epoch=signed_policy.epoch,
            )
        if current is not None:
            # TP1-006: the current policy's revocations reach the historical check.
            context = replace(context, revocations=(*context.revocations, *current.revocations))
        result = integrity.verify_envelope(
            envelope, policy.keyring(), context, key_times=None if times is None else dict(times)
        )
    except integrity.IntegrityError as error:
        # The error code of INTEGRITY-ENVELOPE-1, IE1-040.
        return error.code, frozenset()
    except (ValueError, TypeError):
        return INTEGRITY_INVALID, frozenset()
    return "valid", frozenset(result.valid_key_ids)


def _signature_valid(
    key: TrustedKey, entry: Mapping[str, Any], envelope: Mapping[str, Any], policy: TrustPolicy
) -> bool:
    """Whether one signature entry verifies with the key's public key (IE1-040 step 6 (d), (e))."""
    material = policy.keyring().get(key.key_id)
    return material is not None and integrity.signature_verifies(
        dict(envelope), dict(entry), material
    )


@dataclass(frozen=True)
class _Attestation:
    """One valid trusted-time countersignature: its id, attested time, the indexes of the
    envelope's signature entries it covers, and the trust dependencies of its signers."""

    counter_id: str
    attested: str
    covered: tuple[int, ...]
    dependencies: tuple[TrustDependency, ...]


def _signature_digest_or_none(entry: object) -> dict[str, str] | None:
    try:
        return integrity.signature_digest(entry)  # type: ignore[arg-type]
    except integrity.IntegrityError:
        return None


def _covered_indexes(
    statement: Mapping[str, Any], envelope: Mapping[str, Any]
) -> tuple[int, ...] | None:
    """IE1-033, IE1-034: the indexes of the envelope's signature entries that `covered.signatures`
    names, each with its key_id, suite and signature digest, in envelope order and each once; None
    when an entry names no such signature or the order or uniqueness fails."""
    covered = _mapping(dict(statement), "covered")
    listed = covered.get("signatures") if covered is not None else None
    signatures = envelope.get("signatures")
    if type(listed) is not list or not listed or type(signatures) is not list:
        return None
    digests = [_signature_digest_or_none(item) for item in signatures]
    indexes: list[int] = []
    for named in listed:
        found = next(
            (
                position
                for position, item in enumerate(signatures)
                if type(item) is dict
                and type(named) is dict
                and named.get("key_id") == item.get("key_id")
                and named.get("suite") == item.get("suite_id")
                and digests[position] is not None
                and named.get("signature_digest") == digests[position]
            ),
            None,
        )
        if found is None or (indexes and found <= indexes[-1]):
            return None
        indexes.append(found)
    return tuple(indexes)


def _statement(entry: object) -> dict[str, Any] | None:
    """The decoded time-attestation statement of a countersignature entry, when it has one."""
    if type(entry) is not dict:
        return None
    attestation = entry.get("attestation")
    if type(attestation) is not dict or attestation.get("payload_type") != TIME_ATTESTATION_TYPE:
        return None
    try:
        statement = integrity.decode_canonical_json_payload(attestation)
    except (integrity.IntegrityError, ValueError, TypeError):
        return None
    return statement if type(statement) is dict else None


def _authority_current(
    attestation: dict[str, Any],
    issuer: str | None,
    version: TrustPolicy | None,
    current: TrustPolicy,
    now: str,
) -> list[tuple[str, str, str]]:
    """The (key_id, suite, current status) of each signer of a time attestation under the current
    policy at `now` (TP1-006): the same public key as the historical check used, the trusted-time
    purpose and the issuer's principal, then not revoked and within its validity interval."""
    result: list[tuple[str, str, str]] = []
    signatures = attestation.get("signatures")
    for signature in signatures if type(signatures) is list else []:
        if type(signature) is not dict:
            continue
        key_id = _member_text(signature, "key_id")
        suite = _member_text(signature, "suite_id")
        key = _trusted_key(current, key_id)
        if (
            key is None
            or version is None
            or not _key_acceptable(key, signature, PURPOSE_TRUSTED_TIME, issuer, version)
        ):
            status = POLICY_INVALID
        else:
            status = _key_time_status(key, current, now)
        result.append((key_id, suite, status))
    return result


def _attested_time(
    entry: dict[str, Any],
    envelope: dict[str, Any],
    payload: dict[str, Any],
    versions: Sequence[TrustPolicy],
    current: TrustPolicy,
) -> tuple[str, tuple[int, ...]] | None:
    """The time one trusted-time countersignature attests and the indexes of the signature
    entries it covers, or None when it is not valid (IE1-033, IE1-034, TP1-006)."""
    attestation = entry.get("attestation")
    statement = _statement(entry)
    if type(attestation) is not dict or statement is None:
        return None
    if not schema_is_valid(TIME_ATTESTATION_SCHEMA, statement):
        return None
    covered = {
        "media_type": envelope.get("payload_type"),
        "digest": envelope.get("payload_digest"),
        "signatures": statement.get("covered", {}).get("signatures"),
    }
    issuer = _text(statement, "issuer", "id")
    attested = _text(statement, "issued_at")
    own = _object_time(payload)
    indexes = _covered_indexes(statement, envelope)
    if (
        statement.get("attestation_id") != entry.get("counter_id")
        or statement.get("claim") != entry.get("claim")
        or statement.get("covered") != covered
        or indexes is None
        or issuer is None
        or issuer == _principal(payload)
        or attested is None
        or own is None
        or _instant_ns(own) > _instant_ns(attested)
        or _text(statement, "integrity_policy", "verification_time_policy")
        != "ecl.time.issued-at.v1"
    ):
        return None
    reference = _mapping(statement, "integrity_policy", "trust_policy")
    version = next((item for item in versions if item.reference() == reference), None)
    if version is None:
        return None
    for signature in attestation["signatures"]:
        key = _trusted_key(version, signature["key_id"])
        if (
            key is None
            or key.suite_id != signature["suite_id"]
            or PURPOSE_TRUSTED_TIME not in key.purposes
            or key.principal != issuer
            # TP1-006: the named version's and the current policy's revocations at the attested
            # time.
            or _key_time_status(key, version, attested, current) != "valid"
        ):
            return None
    try:
        context = version.verification_context(
            evaluated_at=attested, time_policy="ecl.time.issued-at.v1"
        )
        context = replace(context, revocations=(*context.revocations, *current.revocations))
        integrity.verify_envelope(attestation, version.keyring(), context)
    except (integrity.IntegrityError, ValueError, TypeError):
        return None
    return attested, indexes


def _countersignatures(
    envelope: dict[str, Any],
    payload: dict[str, Any],
    index: int,
    versions: Sequence[TrustPolicy],
    current: TrustPolicy,
    now: str,
) -> tuple[list[_Attestation] | None, list[TrustDependency]]:
    """Each trusted-time countersignature of the envelope, valid, and the trust dependencies of
    the time authorities' signers; None for the first list when one of them is not valid."""
    entries = envelope.get("countersignatures")
    if entries is None:
        return [], []
    valid: list[_Attestation] = []
    dependencies: list[TrustDependency] = []
    failed = False
    for entry in entries if type(entries) is list else []:
        statement = _statement(entry)
        attestation = entry.get("attestation") if type(entry) is dict else None
        counter_id = entry.get("counter_id") if type(entry) is dict else None
        counter = counter_id if type(counter_id) is str else None
        result = (
            _attested_time(entry, envelope, payload, versions, current)
            if type(entry) is dict and entry.get("claim") == integrity.TRUSTED_TIME_CLAIM
            else None
        )
        issuer = _text(statement, "issuer", "id") if statement is not None else None
        reference = (
            _mapping(statement, "integrity_policy", "trust_policy")
            if statement is not None
            else None
        )
        version = next((item for item in versions if item.reference() == reference), None)
        attested = _text(statement, "issued_at") if statement is not None else None
        signers = (
            _authority_current(attestation, issuer, version, current, now)
            if type(attestation) is dict
            else []
        )
        deps = tuple(
            TrustDependency(
                index,
                "time-authority",
                counter,
                key_id,
                suite,
                attested if result is not None else None,
                None if version is None else version.version,
                _authority_historical(attestation, key_id, version)
                if result is not None
                else TRUSTED_TIME_INVALID,
                current.version,
                _current_revocation(
                    current,
                    key_id,
                    None if version is None else _material(version, key_id),
                ),
                status,
            )
            for key_id, suite, status in signers
        )
        dependencies.extend(deps)
        if result is None:
            failed = True
            continue
        valid.append(_Attestation(counter or "", result[0], result[1], deps))
    return (None if failed else valid), dependencies


def _material(policy: TrustPolicy, key_id: str) -> bytes | None:
    key = _trusted_key(policy, key_id)
    return None if key is None else key.public_key


def _authority_historical(attestation: Any, key_id: str, version: TrustPolicy | None) -> str:
    """The historical status of one signer of a valid attestation: its signature verifies with
    the key of the version the attestation names, or the dependency is not valid with
    `ecl.error.integrity-invalid.v1` (decision "A signature that does not verify"; the
    attestation's validity, from the signatures that count, is unchanged)."""
    signatures = attestation.get("signatures") if type(attestation) is dict else None
    listed = signatures if type(signatures) is list else []
    entry = next(
        (item for item in listed if type(item) is dict and item.get("key_id") == key_id),
        None,
    )
    material = None if version is None else version.keyring().get(key_id)
    if entry is None or material is None:
        return INTEGRITY_INVALID
    return (
        "valid" if integrity.signature_verifies(attestation, entry, material) else INTEGRITY_INVALID
    )


def _later_than_now(payload: dict[str, Any], envelope: dict[str, Any], now: str) -> bool:
    """F08, EBMP2-057: the object's own time, or the attested time of one of its trusted-time
    countersignatures, is later than the evaluation time."""
    limit = _instant_ns(now)
    times = [_object_time(payload)]
    entries = envelope.get("countersignatures")
    for entry in entries if type(entries) is list else []:
        statement = _statement(entry)
        times.append(_text(statement, "issued_at") if statement is not None else None)
    return any(
        (instant := _instant_or_none(value)) is not None and instant > limit for value in times
    )


def _evaluate_envelope(
    envelope: dict[str, Any],
    payload: dict[str, Any],
    index: int,
    observation: bool,
    current_policy: TrustPolicy,
    versions: Sequence[TrustPolicy],
    now: str,
    findings: _Sink,
    require_trusted_time: bool = False,
) -> tuple[EnvelopeCheck, frozenset[tuple[str, bytes]], tuple[TrustDependency, ...], bool]:
    """One envelope's statuses, its signing key material, its trust dependencies (TP1-006) and
    whether a valid trusted-time countersignature covers every one of its signatures."""
    identifier = _identifier(payload)
    kind = _kind(payload)
    signers = _signature_ids(envelope)
    entries = _signature_entries(envelope)

    def plain(status: str, version: TrustPolicy | None = None) -> tuple[TrustDependency, ...]:
        return tuple(
            TrustDependency(
                index,
                "signer",
                None,
                key_id,
                suite,
                None,
                None if version is None else version.version,
                status,
                current_policy.version,
                _current_revocation(
                    current_policy,
                    key_id,
                    None if version is None else _material(version, key_id),
                ),
                status,
            )
            for key_id, suite in entries
        )

    invalid = object_findings(payload)
    if invalid:
        findings.extend(
            _issue(item.rule_id, f"object {index}: {item.path}: {item.message}") for item in invalid
        )
        # EBMP2-068, stage 3: an object that fails its schema is schema-invalid; one that satisfies
        # it but fails a semantic rule is semantic-invalid, which ranks after the rules, so that the
        # object's own primary finding (DCMP2-043) leads.
        status = (
            SCHEMA_INVALID
            if any(item.rule_id == SCHEMA_INVALID for item in invalid)
            else SEMANTIC_INVALID
        )
        check = EnvelopeCheck(index, identifier, kind, signers, status, status)
        return check, frozenset(), plain(status), False
    purpose = _purpose(payload, observation)
    at = _object_time(payload)
    reference = _mapping(payload, "integrity_policy", "trust_policy")
    version = next((item for item in versions if item.reference() == reference), None)
    if purpose is None or at is None or version is None:
        check = EnvelopeCheck(index, identifier, kind, signers, POLICY_INVALID, POLICY_INVALID)
        return check, frozenset(), plain(POLICY_INVALID, version), False
    signed_ids: frozenset[str] = frozenset()
    attestations, authority_dependencies = _countersignatures(
        envelope, payload, index, versions, current_policy, now
    )
    # IE1-034: a covered signature is evaluated at the earliest attested time among the valid
    # countersignatures that cover it, every other one at the object's own time.
    times: dict[str, str] = {}
    covered_all = False
    trusted: str | None = None
    if attestations:
        for item in attestations:
            for position in item.covered:
                key_id = entries[position][0]
                if key_id not in times or _instant_ns(item.attested) < _instant_ns(times[key_id]):
                    times[key_id] = item.attested
        trusted = min((item.attested for item in attestations), key=_instant_ns)
        covered_all = all(
            any(position in item.covered for item in attestations)
            for position in range(len(entries))
        )
    try:
        if _later_than_now(payload, envelope, now):
            history_status = CLOCK_REGRESSED
        elif attestations is None:
            history_status = TRUSTED_TIME_INVALID
        elif require_trusted_time and not covered_all:
            history_status = TRUSTED_TIME_REQUIRED
        else:
            history_status = _signer_status(
                envelope, payload, version, purpose, at, times=times, current=current_policy
            )
            if history_status == "valid":
                history_status, signed_ids = _verify_signature(
                    envelope, version, payload, at, times=times, current=current_policy
                )
        current_status = _signer_status(
            envelope, payload, current_policy, purpose, now, original=version
        )
        if current_status == "valid":
            current_status, _ = _verify_signature(
                envelope, current_policy, payload, now, signed_policy=version
            )
        dependencies = _signer_dependencies(
            envelope,
            payload,
            index,
            purpose,
            version,
            current_policy,
            now,
            times,
            at,
            history_status,
        )
    except ValueError:
        history_status = SCHEMA_INVALID
        current_status = SCHEMA_INVALID
        dependencies = plain(SCHEMA_INVALID, version)
        covered_all = False
    signing_keys = frozenset(
        (key.suite_id, key.public_key)
        for key_id in signed_ids
        if (key := _trusted_key(version, key_id)) is not None
    )
    check = EnvelopeCheck(
        index,
        identifier,
        kind,
        signers,
        history_status,
        current_status,
        version.version,
        trusted if attestations else None,
    )
    return check, signing_keys, (*dependencies, *authority_dependencies), covered_all


# The statuses of an envelope that are not any one signer's: each of its signers takes it.
_ENVELOPE_WIDE = frozenset({CLOCK_REGRESSED, TRUSTED_TIME_INVALID, TRUSTED_TIME_REQUIRED})


def _signer_dependencies(
    envelope: dict[str, Any],
    payload: dict[str, Any],
    index: int,
    purpose: str,
    version: TrustPolicy,
    current: TrustPolicy,
    now: str,
    times: Mapping[str, str],
    at: str,
    envelope_status: str,
) -> tuple[TrustDependency, ...]:
    """TP1-006: each signer of the envelope as a trust dependency, with the time of its
    historical check, its historical status under the named version and the current policy's
    revocations, and its current status under the current policy at `now`."""
    owner = _principal(payload)
    result: list[TrustDependency] = []
    signatures = envelope.get("signatures")
    for signature in signatures if type(signatures) is list else []:
        if type(signature) is not dict:
            continue
        key_id = _member_text(signature, "key_id")
        suite = _member_text(signature, "suite_id")
        own = times.get(key_id, at)
        key = _trusted_key(version, key_id)
        if envelope_status in _ENVELOPE_WIDE:
            historical = envelope_status
        elif key is None or not _key_acceptable(key, signature, purpose, owner, None):
            historical = POLICY_INVALID
        else:
            historical = _key_time_status(key, version, own, current)
            if historical == "valid" and not _signature_valid(key, signature, envelope, version):
                historical = INTEGRITY_INVALID
        present = _trusted_key(current, key_id)
        if present is None or not _key_acceptable(present, signature, purpose, owner, version):
            now_status = POLICY_INVALID
        else:
            now_status = _key_time_status(present, current, now)
        result.append(
            TrustDependency(
                index,
                "signer",
                None,
                key_id,
                suite,
                # A dependency not evaluated, because the envelope's status was decided for the
                # whole envelope, has no time of its own (A's report structure).
                None if envelope_status in _ENVELOPE_WIDE else own,
                version.version,
                historical,
                current.version,
                _current_revocation(current, key_id, _material(version, key_id)),
                now_status,
            )
        )
    return tuple(result)


def _attempt_key(payload: dict[str, Any], *, event: bool = False) -> tuple[str, str, int] | None:
    action_id = _text(payload, "event" if event else "action", "action_id")
    workflow_id = _text(payload, "workflow", "workflow_id")
    workflow = _mapping(payload, "workflow")
    attempt = workflow.get("attempt") if workflow is not None else None
    if action_id is None or workflow_id is None or type(attempt) is not int:
        return None
    return (action_id, workflow_id, attempt)


def _run_binding(
    name: str,
    check: Callable[[], None],
    checks: list[BindingCheck],
    findings: _Sink,
) -> bool:
    try:
        check()
    except binding.BindingError as error:
        checks.append(BindingCheck(name, False, error.code))
        findings.append(_issue(error.code, f"{name} does not bind"))
        return False
    checks.append(BindingCheck(name, True, None))
    return True


def _reference_digest_matches(reference: dict[str, Any], value: dict[str, Any]) -> bool:
    return reference.get("digest") == {
        "algorithm": "ecl.digest.sha-256.v1",
        "value": object_digest(value),
    }


def _check_authority_digest(event: _Entry, response: _Entry, findings: _Sink) -> None:
    reference = _mapping(event.payload, "event", "authority")
    if reference is None:
        return
    authorization = _mapping(response.payload, "authorization")
    if authorization is None or not _reference_digest_matches(reference, authorization):
        findings.append(_issue(DIGEST_MISMATCH, "event authority digest does not match the grant"))


def _check_event_message_references(
    entries: Sequence[_Entry],
    pairs: _Pairs,
    checks: list[BindingCheck],
    findings: _Sink,
) -> None:
    responses = {
        identifier: entry
        for entry in pairs.responses.values()
        if (identifier := _identifier(entry.payload)) is not None
    }
    for entry in entries:
        if entry.observation or _text(entry.payload, "protocol") != "EBMP-2":
            continue
        for member, targets in (("request", pairs.requests), ("decision", responses)):
            reference = _mapping(entry.payload, "event", member)
            if reference is None:
                continue
            uri = reference.get("uri")
            target = targets.get(uri) if type(uri) is str else None
            name = f"{member}-reference:{entry.index}"
            if target is None:
                checks.append(BindingCheck(name, False, DECISION_BINDING_INVALID))
                findings.append(_issue(DECISION_BINDING_INVALID, f"event {member} has no message"))
                continue
            event_workflow = _mapping(entry.payload, "workflow") or {}
            target_workflow = _mapping(target.payload, "workflow") or {}
            if any(
                event_workflow.get(member) != target_workflow.get(member)
                for member in ("workflow_id", "root_trace_id", "attempt")
            ):
                checks.append(BindingCheck(name, False, DECISION_BINDING_INVALID))
                findings.append(
                    _issue(DECISION_BINDING_INVALID, f"event {member} belongs to another workflow")
                )
                continue
            if "digest" in reference and not _reference_digest_matches(reference, target.payload):
                checks.append(BindingCheck(name, False, DIGEST_MISMATCH))
                findings.append(_issue(DIGEST_MISMATCH, f"event {member} digest does not match"))
                continue
            checks.append(BindingCheck(name, True, None))
            if member == "decision" and entry.check.kind == "decision_recorded":
                event = _mapping(entry.payload, "event") or {}
                if event.get("outcome") != target.payload.get("outcome") or event.get(
                    "policy"
                ) != target.payload.get("policy"):
                    checks.append(
                        BindingCheck(
                            f"decision-content:{entry.index}", False, DECISION_BINDING_INVALID
                        )
                    )
                    findings.append(
                        _issue(DECISION_BINDING_INVALID, "decision event contradicts its response")
                    )
                else:
                    checks.append(BindingCheck(f"decision-content:{entry.index}", True, None))


def _check_attempt_identity(main: Sequence[_Entry], findings: _Sink) -> None:
    """EBMP2-066: the execution events of one action attempt (`event.action_id`,
    `workflow.workflow_id`, `workflow.attempt`) carry one `event.attempt_id`, and one attempt
    identifier names one such attempt. One finding reports the first conflict."""
    by_key: dict[tuple[str, str, int], str] = {}
    by_attempt: dict[str, tuple[str, str, int]] = {}
    for entry in main:
        payload = entry.payload
        if _text(payload, "protocol") != "EBMP-2" or _text(payload, "event", "kind") != "execution":
            continue
        key = _attempt_key(payload, event=True)
        attempt_id = _text(payload, "event", "attempt_id")
        if key is None or attempt_id is None:
            continue
        if by_key.setdefault(key, attempt_id) != attempt_id or (
            by_attempt.setdefault(attempt_id, key) != key
        ):
            findings.append(
                _issue(
                    DECISION_BINDING_INVALID,
                    "execution events of one attempt carry different attempt identifiers",
                )
            )
            return


def _instant_or_none(value: object) -> int | None:
    """An ECL instant in nanoseconds, or None for a value that is not one, so that a check that
    needs a time leaves a malformed value to the schema rules."""
    try:
        return _instant_ns(value)  # type: ignore[arg-type]
    except ValueError:
        return None


def _extension_values(value: Mapping[str, Any], identifier: str) -> list[dict[str, Any]]:
    """The value of each occurrence of one extension whose value is an object, in order."""
    extensions = value.get("extensions")
    if type(extensions) is not list:
        return []
    return [
        extension["value"]
        for extension in extensions
        if type(extension) is dict
        and extension.get("id") == identifier
        and type(extension.get("value")) is dict
    ]


def _use_limit(response: Mapping[str, Any]) -> int | None:
    """EBMP2-073: the uses that an authorization allows: 1 when it is `single_use`, otherwise its
    `max_uses` when it has one, and no limit otherwise."""
    authorization = _mapping(response, "authorization")
    if authorization is None:
        return None
    if authorization.get("use_policy") == "single_use":
        return 1
    uses = authorization.get("max_uses")
    return uses if type(uses) is int else None


def _check_use_counts(consumed: Sequence[tuple[_Entry, _Entry]], findings: _Sink) -> None:
    """EBMP2-073: for each authorization, the `authority_consumed` events in state `consumed` that
    bind its response give use counts from 1 to the uses it allows, no two alike, and are no more
    than it allows. Findings of stage 7 of EBMP2-068."""
    by_authorization: dict[str, list[tuple[_Entry, _Entry]]] = {}
    for event, response in consumed:
        identifier = _text(event.payload, "event", "authorization_id")
        if identifier is not None:
            by_authorization.setdefault(identifier, []).append((event, response))
    for events in by_authorization.values():
        limit = _use_limit(events[0][1].payload)
        counts: list[int] = []
        for event, _ in events:
            count = (_mapping(event.payload, "event") or {}).get("use_count")
            if type(count) is not int:
                continue
            if count < 1 or (limit is not None and count > limit):
                findings.append(
                    _issue(
                        DECISION_BINDING_INVALID,
                        f"envelope {event.index}: the use count is outside the authorization's "
                        "use policy",
                    )
                )
            counts.append(count)
        if len(set(counts)) != len(counts):
            findings.append(
                _issue(
                    DECISION_BINDING_INVALID, "two consumptions of one authorization record one use"
                )
            )
        if limit is not None and len(events) > limit:
            findings.append(
                _issue(
                    DECISION_BINDING_INVALID,
                    "an authorization is consumed more often than its use policy allows",
                )
            )


def _released_after_valid_until(terminal: Mapping[str, Any]) -> bool:
    """EBMP2-072: whether a terminal event records, in the MCP binding, that the gateway observed
    after its write that the authorization's `valid_until` had passed."""
    return any(
        value.get("released_after_valid_until") is True
        for value in _extension_values(terminal, MCP_BINDING)
    )


def _completed_after_window(terminal: Mapping[str, Any], response: Mapping[str, Any]) -> bool:
    """EBMP2-072: whether a terminal event records, in the MCP binding, a `forward_completed_at`
    at or after the authorization's `valid_until`: the server's answer came late, which is not a
    finding about the release."""
    end = _instant_or_none(_text(response, "authorization", "valid_until"))
    if end is None:
        return False
    for value in _extension_values(terminal, MCP_BINDING):
        completed = _instant_or_none(value.get("forward_completed_at"))
        if completed is not None and completed >= end:
            return True
    return False


def _release_guard_ns(event: Mapping[str, Any]) -> int | None:
    """EBMP2-071: the release guard an `execution_released` event declares, in nanoseconds, or
    None when the event does not carry it as an integer (its schema then refuses it)."""
    value = (_mapping(event, "event") or {}).get("release_guard_ms")
    return value * 1_000_000 if type(value) is int else None


def _mcp_binding_problem(event: Mapping[str, Any], request: Mapping[str, Any]) -> str | None:
    """EBMP2-075: when the request carries the MCP binding, each occurrence of it in an execution
    event carries every member of the request's value with the same value, and a `succeeded` or
    `failed` terminal event binds the server's response by its digest."""
    decided = _extension_values(request, MCP_BINDING)
    if not decided:
        return None
    call = decided[0]
    recorded = _extension_values(event, MCP_BINDING)
    for value in recorded:
        if any(member not in value or value[member] != call[member] for member in call):
            return "the event's MCP binding names another call than its request"
    if (
        _text(event, "event_type") == "execution_terminal"
        and _text(event, "event", "state") in MCP_RESPONSE_STATES
        and not any("response_digest" in value for value in recorded)
    ):
        return "the terminal event binds no server response"
    return None


@dataclass
class _Pairs:
    requests: dict[str, _Entry]
    responses: dict[str, _Entry]
    event_request: dict[int, _Entry]
    event_response: dict[int, _Entry | None]
    consumed: set[tuple[str, str, int]]
    released: set[tuple[str, str, int]]
    terminal: set[tuple[str, str, int]]
    # The envelope indexes of the execution_released events that bind their request and response.
    bound_releases: set[int]
    # Whether any envelope holds an execution_released event (EBMP2-076: `no-release-recorded`).
    release_recorded: bool
    # EBMP2-072: whether a bound terminal records a server answer at or after `valid_until`.
    completion_after_window: bool


def _pair_main(
    entries: Sequence[_Entry], checks: list[BindingCheck], found: _Findings, skew: int = 0
) -> _Pairs:
    """Pair by request identity and action/attempt, never by an event's claimed decision URI.
    Pairing, request-response binding and event binding are stages 5 to 7 of EBMP2-068."""
    pairing = found.at(STAGE_PAIRING)
    requests_binding = found.at(STAGE_REQUESTS)
    events = found.at(STAGE_EVENTS)
    main = [entry for entry in entries if not entry.observation]
    requests: dict[str, _Entry] = {}
    by_action: dict[tuple[str, str, int], _Entry] = {}
    responses: dict[str, _Entry] = {}
    event_request: dict[int, _Entry] = {}
    event_response: dict[int, _Entry | None] = {}
    consumed: set[tuple[str, str, int]] = set()
    released: set[tuple[str, str, int]] = set()
    terminal: set[tuple[str, str, int]] = set()
    bound_releases: set[int] = set()
    release_recorded = False
    completion_after_window = False
    # EBMP2-073: each authority_consumed event in state consumed that binds its response.
    uses: list[tuple[_Entry, _Entry]] = []

    for entry in main:
        if entry.check.kind != "decision_request":
            continue
        identifier = _identifier(entry.payload)
        key = _attempt_key(entry.payload)
        if identifier is None or key is None:
            pairing.append(_issue(SCHEMA_INVALID, "a request lacks an identity or action"))
            continue
        if identifier in requests or key in by_action:
            pairing.append(
                _issue(DECISION_BINDING_INVALID, "requests repeat an identity or action")
            )
            continue
        requests[identifier] = entry
        by_action[key] = entry

    for entry in main:
        if entry.check.kind != "decision_response":
            continue
        request_id = _text(entry.payload, "request_id")
        request = requests.get(request_id or "")
        if request_id is None or request is None:
            pairing.append(_issue(DECISION_BINDING_INVALID, "a response has no request"))
            continue
        if request_id in responses:
            pairing.append(_issue(DECISION_BINDING_INVALID, "a request has multiple responses"))
            continue
        responses[request_id] = entry
        _run_binding(
            f"response:{entry.index}",
            partial(
                binding.check_response_binding,
                request.payload,
                entry.payload,
                response_clock_skew_seconds=skew,
            ),
            checks,
            requests_binding,
        )

    _check_attempt_identity(main, pairing)

    for entry in main:
        payload = entry.payload
        if _text(payload, "protocol") != "EBMP-2":
            continue
        kind = entry.check.kind
        if kind in {"authority_issued", "authority_consumed"}:
            auth_id = _text(payload, "event", "authorization_id")
            matches = [
                response
                for response in responses.values()
                if _text(response.payload, "authorization", "authorization_id") == auth_id
            ]
            if len(matches) != 1:
                pairing.append(
                    _issue(DECISION_BINDING_INVALID, "an authority event has no unique response")
                )
                continue
            response = matches[0]
            request_id = _text(response.payload, "request_id")
            request = requests.get(request_id or "")
            if request is None:
                pairing.append(
                    _issue(DECISION_BINDING_INVALID, "an authority event has no request")
                )
                continue
            event_request[entry.index] = request
            event_response[entry.index] = response
            passed = _run_binding(
                f"authority:{entry.index}",
                partial(
                    binding.check_authority_event_binding, entry.payload, response=response.payload
                ),
                checks,
                events,
            )
            _check_authority_digest(entry, response, events)
            key = _attempt_key(request.payload)
            if (
                passed
                and key is not None
                and entry.check.historical == "valid"
                and _text(payload, "event", "state") == "consumed"
            ):
                consumed.add(key)
            if (
                passed
                and kind == "authority_consumed"
                and _text(payload, "event", "state") == "consumed"
            ):
                uses.append((entry, response))
            continue
        if kind not in {"execution_released", "execution_terminal"}:
            continue
        release_recorded = release_recorded or kind == "execution_released"
        key = _attempt_key(payload, event=True)
        request = by_action.get(key) if key is not None else None
        if request is None:
            pairing.append(_issue(DECISION_BINDING_INVALID, "an execution event has no request"))
            continue
        request_id = _identifier(request.payload)
        paired_response = responses.get(request_id or "")
        event_request[entry.index] = request
        event_response[entry.index] = paired_response
        passed = _run_binding(
            f"execution:{entry.index}",
            partial(
                binding.check_event_binding,
                entry.payload,
                request=request.payload,
                response=None if paired_response is None else paired_response.payload,
            ),
            checks,
            events,
        )
        if paired_response is not None:
            _check_authority_digest(entry, paired_response, events)
        if passed:
            # EBMP2-075: an event that carries the MCP binding names the call its request bound.
            problem = _mcp_binding_problem(payload, request.payload)
            if problem is not None:
                events.append(
                    _issue(DECISION_BINDING_INVALID, f"envelope {entry.index}: {problem}")
                )
        if key is not None and kind == "execution_terminal":
            terminal.add(key)
            if passed and paired_response is not None:
                # EBMP2-072: a terminal event that records that the release completed after the
                # authorization's valid_until; a late answer from the server is information.
                if _released_after_valid_until(payload):
                    events.append(
                        _issue(
                            EXPIRED,
                            f"envelope {entry.index}: the terminal event records that the "
                            "release completed after the authorization's valid_until",
                        )
                    )
                if _completed_after_window(payload, paired_response.payload):
                    completion_after_window = True
        if key is not None and passed and kind == "execution_released":
            released.add(key)
            bound_releases.add(entry.index)
            authorization = (
                _mapping(paired_response.payload, "authorization") if paired_response else None
            )
            start = _text(authorization, "valid_from") if authorization is not None else None
            end = _text(authorization, "valid_until") if authorization is not None else None
            observed = _text(payload, "observed_at")
            guard = _release_guard_ns(payload)
            # EBMP2-050 and EBMP2-071: the release is observed no earlier than valid_from, and the
            # observation plus the declared release guard is earlier than valid_until.
            if (
                start is None
                or end is None
                or observed is None
                or guard is None
                or not _instant_ns(start) <= _instant_ns(observed)
                or not _instant_ns(observed) + guard < _instant_ns(end)
            ):
                events.append(
                    _issue(
                        EXPIRED,
                        "the release, with its declared release guard, lies outside the "
                        "authorization's validity window",
                    )
                )

    _check_use_counts(uses, events)

    for entry in main:
        if entry.check.kind != "execution_terminal":
            continue
        key = _attempt_key(entry.payload, event=True)
        state = _text(entry.payload, "event", "state")
        if key is None or state not in _NON_RELEASE:
            continue
        event = _mapping(entry.payload, "event") or {}
        if key in consumed or key in released or "authority" in event or event.get("side_effects"):
            events.append(
                _issue(
                    DECISION_BINDING_INVALID,
                    "a non-release terminal contradicts authority use or release",
                )
            )

    return _Pairs(
        requests,
        responses,
        event_request,
        event_response,
        consumed,
        released,
        terminal,
        bound_releases,
        release_recorded,
        completion_after_window,
    )


# DCMP2-056: the members of a continuation that equal those of the request it continues.
_CONTINUED_MEMBERS = ("action", "actor", "subject", "authority_request")


def _attempt_names_unresolved(
    key: tuple[str, str, int], entries: Sequence[_Entry], pairs: _Pairs, unresolved: set[str]
) -> bool:
    """Whether an attempt's own objects (its request, the response paired with it, and the
    authority and execution events of the attempt) name a causal predecessor that the bundle
    does not hold (EBMP2-059)."""
    if not unresolved:
        return False
    request = next(
        (entry for entry in pairs.requests.values() if _attempt_key(entry.payload) == key),
        None,
    )
    own: list[_Entry] = []
    if request is not None:
        own.append(request)
        identifier = _identifier(request.payload)
        response = pairs.responses.get(identifier or "")
        if response is not None:
            own.append(response)
        own.extend(entry for entry in entries if pairs.event_request.get(entry.index) is request)
    own.extend(
        entry
        for entry in entries
        if not entry.observation
        and _text(entry.payload, "event", "kind") == "execution"
        and _attempt_key(entry.payload, event=True) == key
    )
    for entry in own:
        workflow = _mapping(entry.payload, "workflow") or {}
        listed = workflow.get("causal_predecessors")
        for item in listed if type(listed) is list else []:
            if type(item) is dict and item.get("id") in unresolved:
                return True
    return False


def _check_continuations(
    entries: Sequence[_Entry], findings: _Sink, versions: Sequence[TrustPolicy]
) -> tuple[bool, set[int]]:
    """EBMP2-078: each decision request that carries `continues` names, among the bundle's
    objects, the request it continues, that request's `challenge` response and the `approve`
    intervention event on that request; it keeps the continued request's workflow and root trace
    with a greater attempt and the same action, actor, subject and requested authority; it lists
    the response and the approval among its causal predecessors by identifier and digest; when
    the continuation's response is an `admit`, every key that signed the approval holds
    `ecl.purpose.approval.v1` in the version the approval names and none is bound to the
    request's actor, and the approval's `expires_at`, when present, is later than that
    response's `evaluated_at`; and no two requests continue one response. Each failure is a
    finding of stage 5 with `ecl.error.decision-binding-invalid.v1`.

    Every check whose objects the bundle holds is made: a named object that the bundle does not
    hold exempts no other check (EBMP2-059). Returns whether a named object is not in the bundle,
    which leaves the causal closure incomplete and keeps `bindings`, whose object set names it,
    out of `established` (EBMP2-076), and the indexes of the named objects that the bundle holds
    (part of the `request-response-pairs` object set)."""
    by_id: dict[str, _Entry] = {}
    for entry in entries:
        identifier = _identifier(entry.payload)
        if identifier is not None and identifier not in by_id:
            by_id[identifier] = entry
    missing = False
    named_indexes: set[int] = set()
    continued: set[str] = set()
    for entry in entries:
        if entry.observation or entry.check.kind != "decision_request":
            continue
        link = _mapping(entry.payload, "continues")
        if link is None:
            continue

        def fail(message: str, index: int = entry.index) -> None:
            findings.append(
                _issue(DECISION_BINDING_INVALID, f"envelope {index}: the continuation {message}")
            )

        request_id = _text(link, "request_id")
        response_id = _text(link, "response_id")
        approval_id = _text(link, "approval_id")
        prior = by_id.get(request_id) if request_id is not None else None
        response = by_id.get(response_id) if response_id is not None else None
        approval = by_id.get(approval_id) if approval_id is not None else None
        if prior is None or response is None or approval is None:
            missing = True
        named_indexes.update(item.index for item in (prior, response, approval) if item)
        if response_id is not None:
            if response_id in continued:
                fail("continues a response that another request continues")
            continued.add(response_id)
        if prior is not None:
            if prior.observation or prior.check.kind != "decision_request":
                fail("names as its continued request an object that is not a decision request")
            else:
                workflow = _mapping(entry.payload, "workflow") or {}
                before = _mapping(prior.payload, "workflow") or {}
                attempt, prior_attempt = workflow.get("attempt"), before.get("attempt")
                if workflow.get("workflow_id") != before.get("workflow_id") or workflow.get(
                    "root_trace_id"
                ) != before.get("root_trace_id"):
                    fail("is not in the continued request's workflow and root trace")
                if (
                    type(attempt) is not int
                    or type(prior_attempt) is not int
                    or attempt <= prior_attempt
                ):
                    fail("does not have a greater attempt than the continued request")
                for member in _CONTINUED_MEMBERS:
                    if entry.payload.get(member) != prior.payload.get(member):
                        fail(f"changes the continued request's {member}")
        if response is not None and (
            response.observation
            or response.check.kind != "decision_response"
            or _text(response.payload, "request_id") != request_id
            or _text(response.payload, "outcome") != "challenge"
        ):
            fail(
                "names as its challenge an object that is not the challenge response to the "
                "continued request"
            )
        if approval is not None:
            event = _mapping(approval.payload, "event") or {}
            if (
                _text(approval.payload, "protocol") != "EBMP-2"
                or event.get("kind") != "intervention"
                or event.get("operation") != "approve"
                or request_id is None
                or event.get("target_id") != request_id
            ):
                fail(
                    "names as its approval an object that is not an approval of the continued request"
                )
            own = _text(entry.payload, "message_id")
            answer = next(
                (
                    other
                    for other in entries
                    if not other.observation
                    and other.check.kind == "decision_response"
                    and own is not None
                    and _text(other.payload, "request_id") == own
                ),
                None,
            )
            # The approval's keys and expiry bear on the continuation only when its response
            # admits it: a deny or a new challenge is the right answer to an approval that has
            # expired or is not acceptable (DCMP2-057).
            if answer is not None and _text(answer.payload, "outcome") == "admit":
                # As EBMP2-070 condition 5 asks of an approval record: the approval service's
                # keys, none of them bound to the request's actor.
                keys = _signer_keys(approval, versions)
                if not keys or any(PURPOSE_APPROVAL not in key.purposes for key in keys):
                    fail("names an approval signed by a key without the approval purpose")
                actor = _text(entry.payload, "actor", "id")
                if any(key.principal == actor for key in keys):
                    fail("names an approval signed by a key of the request's actor")
                # The approval is still in force when the continuation's response is evaluated.
                expires = _instant_or_none(event.get("expires_at"))
                evaluated = _instant_or_none(answer.payload.get("evaluated_at"))
                if (
                    "expires_at" in event
                    and expires is not None
                    and evaluated is not None
                    and not expires > evaluated
                ):
                    fail("rests on an approval that expired before its response was evaluated")
        # DCMP2-056: the response and the approval are causal predecessors, by identifier and
        # digest.
        workflow = _mapping(entry.payload, "workflow") or {}
        listed = workflow.get("causal_predecessors")
        references = [item for item in listed if type(item) is dict] if type(listed) is list else []
        for name, identifier, held in (
            ("challenge response", response_id, response),
            ("approval", approval_id, approval),
        ):
            reference = next(
                (
                    item
                    for item in references
                    if identifier is not None and item.get("id") == identifier
                ),
                None,
            )
            if reference is None or (
                held is not None and not _reference_digest_matches(reference, held.payload)
            ):
                fail(f"does not list its {name} among its causal predecessors with its digest")
    return missing, named_indexes


def _obligation_keys(
    response: Mapping[str, Any],
) -> tuple[list[tuple[str, str]], set[tuple[str, str]], bool, dict[tuple[str, str], Any]]:
    """EBMP2-070 on one decision response: the obligations it leaves to Enforcement before the
    release, by (`obligation_id`, `type`), in order and each once: each obligation whose
    `satisfaction` is `before_release`, and a witness result whose `outcome` is
    `required_before_release`, named by the `uri` of its reference and the type
    `ecl.obligation.verify-witness.v1`; every obligation it carries, the witness result included;
    whether it carries an obligation to be met during or after execution (EBMP2-076); and the
    value of each obligation it carries, the witness's URI for the witness result."""
    required: list[tuple[str, str]] = []
    carried: set[tuple[str, str]] = set()
    values: dict[tuple[str, str], Any] = {}
    post_release = False
    obligations = response.get("obligations")
    for item in obligations if type(obligations) is list else []:
        if type(item) is not dict:
            continue
        identifier, kind = item.get("id"), item.get("type")
        if type(identifier) is not str or type(kind) is not str:
            continue
        key = (identifier, kind)
        carried.add(key)
        values.setdefault(key, item.get("value"))
        satisfaction = item.get("satisfaction")
        if satisfaction == "before_release":
            if key not in required:
                required.append(key)
        elif type(satisfaction) is str and satisfaction in POST_RELEASE:
            post_release = True
    for value in _extension_values(response, COUPLING):
        witness = value.get("witness_result")
        reference = witness.get("reference") if type(witness) is dict else None
        uri = reference.get("uri") if type(reference) is dict else None
        if (
            type(witness) is dict
            and witness.get("outcome") == "required_before_release"
            and type(uri) is str
        ):
            key = (uri, WITNESS_OBLIGATION_TYPE)
            carried.add(key)
            values.setdefault(key, uri)
            if key not in required:
                required.append(key)
    return required, carried, post_release, values


def _witness_source(response: Mapping[str, Any], witness: str) -> str | None:
    """The `source` that the response's witness result names for `witness`, if it names one: the
    issuer that a verify-witness obligation names (EBMP2-070, condition b)."""
    for value in _extension_values(response, COUPLING):
        result = value.get("witness_result")
        if type(result) is not dict:
            continue
        reference = result.get("reference")
        uri = reference.get("uri") if type(reference) is dict else None
        source = result.get("source")
        if uri == witness and type(source) is str:
            return source
    return None


def _discharges(event: Mapping[str, Any]) -> tuple[bool, list[tuple[int, int, dict[str, Any]]]]:
    """Whether an event carries `ecl.ext.obligation-discharge.v1`, and each entry of it that is an
    object, with the index of its extension and its position in `obligations`."""
    extensions = event.get("extensions")
    present = False
    found: list[tuple[int, int, dict[str, Any]]] = []
    for index, extension in enumerate(extensions if type(extensions) is list else []):
        if type(extension) is not dict or extension.get("id") != OBLIGATION_DISCHARGE:
            continue
        present = True
        value = extension.get("value")
        listed = value.get("obligations") if type(value) is dict else None
        for position, item in enumerate(listed if type(listed) is list else []):
            if type(item) is dict:
                found.append((index, position, item))
    return present, found


@dataclass(frozen=True)
class _Release:
    """What the conditions of EBMP2-070 compare an entry with: the bound release, its request and
    response, the release's observation and declared guard, the response's issue time, the
    response clock-skew allowance and the request's actor."""

    request: dict[str, Any]
    response: dict[str, Any]
    observed: int | None
    guard: int | None
    issued: int | None
    skew_seconds: int
    actor: str | None

    @property
    def deadline(self) -> int | None:
        """The release plus its declared release guard, before which every proof must be fresh."""
        if self.observed is None or self.guard is None:
            return None
        return self.observed + self.guard


def _discharge_problems(item: Mapping[str, Any], release: _Release) -> list[tuple[str, str, str]]:
    """Conditions 2 to 4 of EBMP2-070 and the freshness of a recorded `fresh_until` on one entry
    that names an obligation of the response, each checked on members present with the types the
    value schema gives them: (code, path below the entry, message) for each that fails."""
    problems: list[tuple[str, str, str]] = []
    result = item.get("result")
    if type(result) is str and result != "satisfied":
        problems.append((DISCHARGE_RULE, "/result", "records an obligation that was not met"))
    checked = _instant_or_none(item.get("checked_at"))
    if checked is not None and release.observed is not None and checked > release.observed:
        problems.append(
            (DISCHARGE_RULE, "/checked_at", "was checked after the release was observed")
        )
    if (
        checked is not None
        and release.issued is not None
        and checked < release.issued - max(release.skew_seconds, 0) * 1_000_000_000
    ):
        problems.append(
            (DISCHARGE_RULE, "/checked_at", "was checked before the decision was issued")
        )
    proof = item.get("proof")
    if type(proof) is dict:
        obtained = _instant_or_none(proof.get("obtained_at"))
        if obtained is not None and checked is not None and obtained > checked:
            problems.append(
                (DISCHARGE_RULE, "/proof/obtained_at", "has a proof obtained after it was checked")
            )
    # EBMP2-070, freshness: the release plus its declared guard comes before `fresh_until`.
    fresh = _instant_or_none(item.get("fresh_until"))
    deadline = release.deadline
    if fresh is not None and deadline is not None and not deadline < fresh:
        problems.append(
            (
                OBLIGATION_UNPROVEN,
                "/fresh_until",
                "is not later than the release plus its declared release guard",
            )
        )
    return problems


def _signer_keys(entry: _Entry, versions: Sequence[TrustPolicy]) -> tuple[TrustedKey, ...]:
    """The keys of the trust-policy version an object names that signed its envelope, with the
    principals and purposes the policy binds them to (EBMP2-070, condition b)."""
    reference = _mapping(entry.payload, "integrity_policy", "trust_policy")
    version = next((item for item in versions if item.reference() == reference), None)
    if version is None:
        return ()
    return tuple(
        key
        for key_id in _signature_ids(entry.envelope)
        if (key := _trusted_key(version, key_id)) is not None
    )


def _signer_principals(entry: _Entry, versions: Sequence[TrustPolicy]) -> set[str]:
    """The principals that the trust-policy version an object names binds to the keys that
    signed its envelope (EBMP2-070, condition b)."""
    return {key.principal for key in _signer_keys(entry, versions)}


def _issuer_named(key: tuple[str, str], value: Any, response: Mapping[str, Any]) -> bool:
    """Whether the decision names an issuer for the obligation (EBMP2-070, condition b): a
    verify-witness obligation names the `source` of its witness result, when the response gives
    one; an approval obligation's issuer is the approval service, which the trust policy marks
    with the approval purpose; an obligation of any other type names none. When none is named,
    the issuer test is not made and the scope item is not established (EBMP2-076,
    `issuer-not-named`)."""
    _, kind = key
    if kind == APPROVAL_OBLIGATION_TYPE:
        return True
    if kind == WITNESS_OBLIGATION_TYPE:
        return type(value) is str and _witness_source(response, value) is not None
    return False


def _names_the_request(proof: Mapping[str, Any], request: Mapping[str, Any]) -> bool:
    """EBMP2-070, condition d: a causal predecessor of the proof names the decision request by
    its `message_id` and its digest."""
    workflow = _mapping(proof, "workflow")
    predecessors = workflow.get("causal_predecessors") if workflow is not None else None
    identifier = _text(request, "message_id")
    return any(
        type(predecessor) is dict
        and predecessor.get("id") == identifier
        and _reference_digest_matches(predecessor, dict(request))
        for predecessor in (predecessors if type(predecessors) is list else [])
    )


def _proof_problems(
    item: Mapping[str, Any],
    key: tuple[str, str],
    value: Any,
    proof: _Entry,
    release: _Release,
    versions: Sequence[TrustPolicy],
) -> list[tuple[str, str, str]]:
    """Conditions a to e of EBMP2-070 on a carried proof: the object of the bundle that the entry
    names by reference, whose digest the entry records. (code, path, message) for each failure:
    (a) the object is a valid envelope under the trust policy; (b) the trust policy binds its
    signing keys to the issuer the obligation names, when it names one, and never to the
    requesting actor; (c) the object is of a type the obligation admits: for a verify-witness
    obligation a `verification` event of the witness that passed, for an approval-record
    obligation a `human_intervention` event that approves by the approver the obligation names,
    and never a decision message; (d) the object names this exchange: a causal predecessor names
    the decision request with its digest, and an approval's `target_id` is the request; (e) the
    object is fresh at the release plus its declared guard, by the bound the object declares, and
    the recorded `fresh_until` is not later than that bound. For an approval obligation the issuer
    test of (b) is that every signing key holds the approval purpose."""
    path = "/proof/reference"
    if proof.check.historical != "valid":
        return [
            (
                OBLIGATION_UNPROVEN,
                path,
                "names a proof whose envelope is not valid under the trust policy",
            )
        ]
    problems: list[tuple[str, str, str]] = []
    payload = proof.payload
    _, kind = key
    witness = value if kind == WITNESS_OBLIGATION_TYPE and type(value) is str else None
    # (b) The signers, as the trust policy binds the keys.
    keys = _signer_keys(proof, versions)
    principals = {key.principal for key in keys}
    issuer = _witness_source(release.response, witness) if witness is not None else None
    if issuer is not None and principals != {issuer}:
        problems.append(
            (
                OBLIGATION_UNPROVEN,
                path,
                "names a proof not signed by the issuer the obligation names",
            )
        )
    if release.actor is not None and release.actor in principals:
        problems.append(
            (OBLIGATION_UNPROVEN, path, "names a proof that the requesting actor signed")
        )
    if (
        kind == APPROVAL_OBLIGATION_TYPE
        and _text(payload, "event_type") == "human_intervention"
        and (not keys or any(PURPOSE_APPROVAL not in key.purposes for key in keys))
    ):
        # The approval service's keys hold the approval purpose (MG1-013): any other trusted
        # producer of evidence events, the enforcement point itself among them, could otherwise
        # sign an approval of its own request.
        problems.append(
            (
                OBLIGATION_UNPROVEN,
                path,
                "names an approval record signed by a key without the approval purpose",
            )
        )
    # (c) The type the obligation admits.
    if _text(payload, "protocol") != "EBMP-2":
        problems.append((OBLIGATION_UNPROVEN, path, "names a decision message as a proof"))
        return problems
    event_type = _text(payload, "event_type")
    event = _mapping(payload, "event") or {}
    if kind == WITNESS_OBLIGATION_TYPE:
        if event_type != "verification":
            problems.append(
                (OBLIGATION_UNPROVEN, path, "names a proof of a type the obligation does not admit")
            )
        else:
            if _text(event, "subject", "uri") != witness:
                problems.append(
                    (OBLIGATION_UNPROVEN, path, "names a witness result of another witness")
                )
            if event.get("decision") != "pass":
                problems.append(
                    (OBLIGATION_UNPROVEN, path, "names a witness result that did not pass")
                )
    elif kind == APPROVAL_OBLIGATION_TYPE:
        if event_type != "human_intervention":
            problems.append(
                (OBLIGATION_UNPROVEN, path, "names a proof of a type the obligation does not admit")
            )
        else:
            approver = value.get("approver") if type(value) is dict else None
            if event.get("operation") != "approve":
                problems.append(
                    (OBLIGATION_UNPROVEN, path, "names an intervention that does not approve")
                )
            if type(approver) is not str or _text(event, "actor", "id") != approver:
                problems.append(
                    (
                        OBLIGATION_UNPROVEN,
                        path,
                        "names an approval by an approver other than the one the obligation names",
                    )
                )
    # (d) The binding to this exchange.
    if event_type == "human_intervention" and event.get("target_id") != _text(
        release.request, "message_id"
    ):
        problems.append((OBLIGATION_UNPROVEN, path, "names an approval of another request"))
    if not _names_the_request(payload, release.request):
        problems.append(
            (
                OBLIGATION_UNPROVEN,
                path,
                "names a proof whose causal predecessors do not name this request with its digest",
            )
        )
    # (e) Freshness by the bound the proof declares: an intervention expires at `expires_at`.
    bound = (
        _instant_or_none(event.get("expires_at")) if event_type == "human_intervention" else None
    )
    deadline = release.deadline
    if bound is not None and deadline is not None:
        if not deadline < bound:
            problems.append(
                (
                    OBLIGATION_UNPROVEN,
                    path,
                    "names a proof that expired before the release plus its declared release guard",
                )
            )
        fresh = _instant_or_none(item.get("fresh_until"))
        if fresh is not None and fresh > bound:
            problems.append(
                (OBLIGATION_UNPROVEN, "/fresh_until", "is later than the bound the proof declares")
            )
    return problems


def _check_obligation_discharge(
    entries: Sequence[_Entry],
    pairs: _Pairs,
    findings: _Sink,
    *,
    versions: Sequence[TrustPolicy],
    skew_seconds: int = 0,
) -> tuple[bool, bool, bool, bool, set[int]]:
    """EBMP2-070 on each `execution_released` event that binds its request and response: the
    obligations its response leaves to Enforcement before the release each have a consistent
    discharge, no entry names an obligation the response does not carry or names one twice, and
    each proof that the bundle carries passes conditions a to e. The obligations come from the
    signed response that the bundle holds. Findings belong to stage 8 of EBMP2-068, the stage of
    `ecl.rule.prerelease-obligations-discharged.v1`.

    Returns whether the rule applied to a release whose response leaves an obligation to
    Enforcement, whether a response that a release records carries an obligation to be met
    during or after execution, whether an entry's proof is not an object of the bundle, and whether
    the decision names no issuer for an obligation whose proof is carried: the conditional items
    and the reason of the report's scope (EBMP2-076); and the `discharge-entries` object set: the
    indexes of the releases that carry discharge entries and of the carried proofs they name."""
    objects = {
        identifier: entry
        for entry in entries
        if (identifier := _identifier(entry.payload)) is not None
    }
    applied = False
    post_release = False
    uncarried = False
    unnamed = False
    proofs: set[int] = set()
    for entry in entries:
        if entry.observation or entry.index not in pairs.bound_releases:
            continue
        response = pairs.event_response.get(entry.index)
        request = pairs.event_request.get(entry.index)
        if response is None or request is None:
            continue
        required, carried, post, values = _obligation_keys(response.payload)
        post_release = post_release or post
        applied = applied or bool(required)
        present, discharged = _discharges(entry.payload)
        if discharged:
            # `discharge-entries`: each release that carries entries, with the proofs they name.
            proofs.add(entry.index)
        if required and not present:
            findings.append(
                _issue(
                    DISCHARGE_RULE,
                    f"object {entry.index}: the release rests on obligations left to Enforcement "
                    "and records no discharge",
                )
            )
            continue
        release = _Release(
            request.payload,
            response.payload,
            _instant_or_none(entry.payload.get("observed_at")),
            _release_guard_ns(entry.payload),
            _instant_or_none(response.payload.get("issued_at")),
            skew_seconds,
            _text(request.payload, "actor", "id"),
        )
        named: set[tuple[str, str]] = set()
        for index, position, item in discharged:
            path = f"object {entry.index}: /extensions/{index}/value/obligations/{position}"
            identifier, kind = item.get("obligation_id"), item.get("type")
            if type(identifier) is not str or type(kind) is not str:
                continue
            key = (identifier, kind)
            if key not in carried:
                findings.append(
                    _issue(
                        DISCHARGE_RULE, f"{path}: names an obligation the response does not carry"
                    )
                )
                continue
            if key in named:
                findings.append(
                    _issue(DISCHARGE_RULE, f"{path}: names an obligation that another entry names")
                )
                continue
            named.add(key)
            problems = _discharge_problems(item, release)
            proof = item.get("proof")
            reference = proof.get("reference") if type(proof) is dict else None
            carried_proof = objects.get(reference) if type(reference) is str else None
            digest = proof.get("digest") if type(proof) is dict else None
            if carried_proof is not None:
                proofs.add(carried_proof.index)
            if carried_proof is None:
                # The proof is not an object of the bundle: not an ECL object that the verifier
                # can check (EBMP2-076, `proof-not-ecl-object`).
                uncarried = True
            elif type(digest) is dict and digest != {
                "algorithm": "ecl.digest.sha-256.v1",
                "value": object_digest(carried_proof.payload),
            }:
                problems.append(
                    (
                        DISCHARGE_RULE,
                        "/proof/digest",
                        "names an object of the bundle by another digest",
                    )
                )
            else:
                if not _issuer_named(key, values.get(key), release.response):
                    # The decision names no issuer, so the issuer test of condition b is not made
                    # and the proofs are not reported verified (EBMP2-076, `issuer-not-named`).
                    unnamed = True
                problems.extend(
                    _proof_problems(item, key, values.get(key), carried_proof, release, versions)
                )
            findings.extend(
                _issue(code, f"{path}{suffix}: {message}") for code, suffix, message in problems
            )
        findings.extend(
            _issue(
                DISCHARGE_RULE,
                f"object {entry.index}: an obligation left to Enforcement has no discharge",
            )
            for key in required
            if key not in named
        )
    return applied, post_release, uncarried, unnamed, proofs


def _reason(entry: _Entry, response: _Entry | None, findings: _Sink) -> str | None:
    state = _text(entry.payload, "event", "state")
    extensions = entry.payload.get("extensions")
    matching = (
        [
            extension
            for extension in extensions
            if type(extension) is dict and extension.get("id") == OUTCOME_REASON
        ]
        if type(extensions) is list
        else []
    )
    if len(matching) > 1:
        findings.append(_issue(SEMANTIC_INVALID, "a terminal has multiple outcome reasons"))
    if matching:
        value = matching[0].get("value")
        code = value.get("code") if type(value) is dict else None
        if (
            type(value) is not dict
            or set(value) != {"code"}
            or type(code) is not str
            or code not in _registered_errors()
        ):
            findings.append(_issue(SEMANTIC_INVALID, "a terminal has an invalid outcome reason"))
            return None
        if state == "succeeded":
            findings.append(_issue(SEMANTIC_INVALID, "a succeeded terminal has an outcome reason"))
        return code
    outcome = _text(response.payload, "outcome") if response else None
    if state == "expired_before_release" or (state == "denied" and outcome in {None, "admit"}):
        findings.append(
            _issue(SEMANTIC_INVALID, "a terminal is missing its required outcome reason")
        )
    if state in _NON_RELEASE and response is not None:
        reasons = response.payload.get("reasons")
        if type(reasons) is list and reasons and type(reasons[0]) is dict:
            code = reasons[0].get("code")
            return code if type(code) is str else None
    return None


def _names_the_terminal(observation: Mapping[str, Any], terminal: Mapping[str, Any]) -> bool:
    """EBMP2-061: the observation names the terminal event among its causal predecessors by
    `object_id` and digest."""
    workflow = _mapping(dict(observation), "workflow") or {}
    predecessors = workflow.get("causal_predecessors")
    identifier = terminal.get("object_id")
    if type(predecessors) is not list or type(identifier) is not str:
        return False
    return any(
        type(item) is dict
        and item.get("id") == identifier
        and _reference_digest_matches(item, dict(terminal))
        for item in predecessors
    )


def _corroborated(terminal: _Entry, observations: Sequence[_Entry]) -> bool:
    """EBMP2-061: every side effect of the terminal has an observation bound to this terminal
    and attempt; the caller checks that the bundle's causal closure is complete."""
    event = _mapping(terminal.payload, "event") or {}
    effects = event.get("side_effects")
    if type(effects) is not list or not effects or not terminal.signing_keys:
        return False
    terminal_at = _text(terminal.payload, "observed_at")
    producer = _principal(terminal.payload)
    workflow = _text(terminal.payload, "workflow", "workflow_id")
    context = _mapping(terminal.payload, "workflow") or {}
    if terminal_at is None or producer is None or workflow is None:
        return False
    for effect in effects:
        if type(effect) is not dict or type(effect.get("digest")) is not dict:
            return False
        matched = False
        for observation in observations:
            payload = observation.payload
            subject = _mapping(payload, "event", "subject")
            observed_at = _text(payload, "observed_at")
            if (
                observation.check.historical == "valid"
                and bool(observation.signing_keys)
                and terminal.signing_keys.isdisjoint(observation.signing_keys)
                and observation.check.kind == "verification"
                and _text(payload, "event", "decision") == "pass"
                and subject is not None
                and subject.get("uri") == effect.get("uri")
                and subject.get("digest") == effect.get("digest")
                and _principal(payload) != producer
                and _text(payload, "workflow", "workflow_id") == workflow
                and (_mapping(payload, "workflow") or {}).get("root_trace_id")
                == context.get("root_trace_id")
                and type((_mapping(payload, "workflow") or {}).get("attempt")) is int
                and (_mapping(payload, "workflow") or {}).get("attempt") == context.get("attempt")
                and _names_the_terminal(payload, terminal.payload)
                and observed_at is not None
                and _instant_ns(observed_at) >= _instant_ns(terminal_at)
            ):
                matched = True
                break
        if not matched:
            return False
    return True


def _effects(
    entries: Sequence[_Entry], pairs: _Pairs, findings: _Sink, *, closure_complete: bool
) -> tuple[EffectEvidence, ...]:
    """EBMP2-061: each terminal's evidence level; `corroborated` only when the bundle's causal
    closure is complete."""
    observations = [entry for entry in entries if entry.observation]
    result: list[EffectEvidence] = []
    for entry in entries:
        if entry.observation or entry.check.kind != "execution_terminal":
            continue
        payload = entry.payload
        action_id = _text(payload, "event", "action_id") or ""
        state = _text(payload, "event", "state") or "unknown"
        key = _attempt_key(payload, event=True)
        response = pairs.event_response.get(entry.index)
        authority = (
            "consumed"
            if key in pairs.consumed
            else "issued-unused"
            if response is not None and _text(response.payload, "outcome") == "admit"
            else "none"
        )
        level = "none" if entry.check.historical != "valid" else "issuer-asserted"
        if (
            level == "issuer-asserted"
            and state == "succeeded"
            and closure_complete
            and _corroborated(entry, observations)
        ):
            level = "corroborated"
        reason = _reason(entry, response, findings)
        result.append(EffectEvidence(action_id, state, level, authority, reason))
    return tuple(result)


def _check_decision_bases(
    entries: Sequence[_Entry],
    findings: _Sink,
    *,
    register: Mapping[str, Any] | None,
    skew_seconds: int = 0,
) -> None:
    """DCMP2-053 in the evidence: each decision response carries its decision basis; no input
    whose source is the request's actor is recorded as `verifiable`, and the request was not
    received before it was issued, less the response clock-skew allowance
    (DCMP2-047); and a basis agrees with the register when the caller supplies one. These are
    findings of stage 3 of EBMP2-068, ranked by their precedence."""
    requests = {
        identifier: entry.payload
        for entry in entries
        if not entry.observation
        and _text(entry.payload, "protocol") == "DCMP-2"
        and _text(entry.payload, "message_type") == "decision_request"
        and (identifier := _text(entry.payload, "message_id")) is not None
    }
    for entry in entries:
        payload = entry.payload
        if (
            entry.observation
            or _text(payload, "protocol") != "DCMP-2"
            or _text(payload, "message_type") != "decision_response"
        ):
            continue
        found = basis.values(payload)
        if not found:
            findings.append(
                _issue(
                    basis.REQUIRED_RULE,
                    f"object {entry.index}: /extensions: the decision response records no "
                    "decision basis",
                )
            )
            continue
        request_id = _text(payload, "request_id")
        request = requests.get(request_id) if request_id is not None else None
        if len(found) != 1 or request is None:
            continue
        index, value = found[0]
        if not isinstance(value, dict):
            continue
        findings.extend(
            _issue(
                basis.ONE_WAY_RULE,
                f"object {entry.index}: /extensions/{index}/value{path}: {message}",
            )
            for path, message in basis.request_problems(value, request, skew_seconds=skew_seconds)
        )
        if register is None:
            continue
        action = request.get("action")
        action_class = action.get("action_class") if isinstance(action, dict) else None
        findings.extend(
            _issue(
                basis.REGISTER_RULE,
                f"object {entry.index}: /extensions/{index}/value{path}: {message}",
            )
            for path, message in basis.register_problems(
                value, register, action_class, evaluated_at=payload.get("evaluated_at")
            )
        )


def _verify(
    source: object,
    policy: TrustPolicy,
    *,
    now: str,
    history: Sequence[TrustPolicy],
    response_clock_skew_seconds: int,
    accept_current_trust_failure: bool,
    require_trusted_time: bool = False,
    register: Mapping[str, Any] | None = None,
) -> BundleReport:
    if not isinstance(policy, TrustPolicy):
        return _invalid(_issue(POLICY_INVALID, "the current trust policy is not loaded"))
    problem = _history_problem(policy, history)
    if problem is not None:
        return _invalid(problem)
    if type(source) is not dict:
        return _invalid(_issue(SCHEMA_INVALID, "the evidence bundle is not a JSON object"))
    envelopes = source.get("envelopes")
    observations = source.get("observations", [])
    if type(envelopes) is not list or type(observations) is not list:
        return _invalid(_issue(SCHEMA_INVALID, "envelopes and observations must be arrays"))
    if len(envelopes) > MAX_ENVELOPES:
        return _invalid(_issue(RESOURCE_LIMIT, f"envelopes exceed the {MAX_ENVELOPES} entry limit"))
    if len(observations) > MAX_OBSERVATIONS:
        return _invalid(
            _issue(RESOURCE_LIMIT, f"observations exceed the {MAX_OBSERVATIONS} entry limit")
        )
    if not schema_is_valid(BUNDLE_SCHEMA, source):
        return _invalid(_issue(SCHEMA_INVALID, "the evidence bundle does not satisfy its schema"))

    findings = _Findings()
    checks: list[EnvelopeCheck] = []
    bindings: list[BindingCheck] = []
    decoded: list[tuple[int, bool, dict[str, Any], dict[str, Any]]] = []
    node_count = 0
    budget_exceeded = _issue(
        RESOURCE_LIMIT, f"decoded payloads exceed the {MAX_TOTAL_PAYLOAD_NODES} node budget"
    )
    for index, (is_observation, envelope) in enumerate(
        [(False, value) for value in envelopes] + [(True, value) for value in observations]
    ):
        # EBMP2-062: each payload is parsed with the nodes that remain of the bundle's budget as its
        # value limit, so that no payload is built beyond the budget (IE1-029; EBMP2-068, stage 2).
        try:
            payload = integrity.decode_canonical_json_payload(
                envelope, max_nodes=max(MAX_TOTAL_PAYLOAD_NODES - node_count, 1)
            )
            if type(payload) is not dict:
                raise ValueError("signed payload is not an object")
        except integrity.PayloadNodeBudgetError:
            findings.add(STAGE_PAYLOADS, budget_exceeded)
            return BundleReport(
                "invalid", tuple(checks), (), "not-analyzed", (), findings.ordered()
            )
        except (integrity.IntegrityError, ValueError, TypeError) as error:
            # A declared limit that the strict parse of the payload reaches is a resource limit;
            # any other failure leaves it outside canonical strict JSON (IE1-040, step 3).
            code = (
                RESOURCE_LIMIT
                if isinstance(error, integrity.IntegrityError) and error.code == RESOURCE_LIMIT
                else INTEGRITY_INVALID
            )
            checks.append(
                EnvelopeCheck(index, None, "unknown", _signature_ids(envelope), code, code)
            )
            findings.add(STAGE_PAYLOADS, _issue(code, f"envelope {index} has an invalid payload"))
            continue
        node_count += _nodes(payload, MAX_TOTAL_PAYLOAD_NODES - node_count)
        if node_count > MAX_TOTAL_PAYLOAD_NODES:
            findings.add(STAGE_PAYLOADS, budget_exceeded)
            return BundleReport(
                "invalid", tuple(checks), (), "not-analyzed", (), findings.ordered()
            )
        decoded.append((index, is_observation, envelope, payload))

    versions = (policy, *history)
    entries: list[_Entry] = []
    seen_ids: set[str] = set()
    dependencies: list[TrustDependency] = []
    covered: dict[int, bool] = {}
    for index, is_observation, envelope, payload in decoded:
        check, signing_keys, depends, covered_all = _evaluate_envelope(
            envelope,
            payload,
            index,
            is_observation,
            policy,
            versions,
            now,
            findings.at(STAGE_OBJECTS),
            require_trusted_time,
        )
        checks.append(check)
        dependencies.extend(depends)
        covered[index] = covered_all
        entries.append(_Entry(index, is_observation, envelope, payload, check, signing_keys))
        if check.historical in (SCHEMA_INVALID, SEMANTIC_INVALID):
            # The object's own schema or semantic rules refuse it, and their findings are listed;
            # its signatures were not evaluated, so this is a finding of stage 3, not one about
            # the signers.
            message = f"envelope {index} holds an object that fails its schema or semantic rules"
            findings.add(STAGE_OBJECTS, _issue(check.historical, message))
        elif check.historical != "valid":
            # Any other status is the signers', a finding of stage 4.
            message = f"envelope {index} is not historically valid"
            findings.add(STAGE_SIGNERS, _issue(check.historical, message))
        identifier = check.object_id
        if identifier is not None:
            if identifier in seen_ids:
                findings.add(
                    STAGE_OBJECTS,
                    _issue(
                        "ecl.rule.bundle-object-identifiers-unique.v1",
                        "message or object identifier is duplicated",
                    ),
                )
            seen_ids.add(identifier)
        if is_observation and (
            _text(payload, "protocol") != "EBMP-2" or check.kind != "verification"
        ):
            findings.add(
                STAGE_OBJECTS,
                _issue(SEMANTIC_INVALID, "an observation is not a verification event"),
            )

    _check_decision_bases(
        entries,
        findings.at(STAGE_OBJECTS),
        register=register,
        skew_seconds=response_clock_skew_seconds,
    )
    pairs = _pair_main(entries, bindings, findings, response_clock_skew_seconds)
    continuation_missing, continued = _check_continuations(
        entries, findings.at(STAGE_PAIRING), versions
    )
    _check_event_message_references(entries, pairs, bindings, findings.at(STAGE_EVENTS))
    discharge_applied, post_release, uncarried, unnamed, proofs = _check_obligation_discharge(
        entries,
        pairs,
        findings.at(STAGE_CAUSAL),
        versions=versions,
        skew_seconds=response_clock_skew_seconds,
    )
    # EBMP2-059: one causal graph over every object of the bundle, DCMP-2 messages (by
    # `message_id`) and observations included, with no external predecessor, and EBMP2-077.
    analysis = causal.analyze_bundle(
        [entry.payload for entry in entries],
        identifier_members=("object_id", "message_id"),
        check_context=True,
    )
    findings.at(STAGE_CAUSAL).extend(
        _issue(item.rule_id, f"causal graph: {item.path}: {item.message}")
        for item in analysis.findings
    )
    # EBMP2-055 and EBMP2-074 run for every attempt whose own objects the bundle holds, whatever
    # the closure; they stay silent only for an attempt whose own objects name an unresolved
    # predecessor, which could be the consumption or the release they look for.
    unresolved = set(analysis.unresolved_predecessor_ids)
    for entry in entries:
        if entry.observation or entry.check.kind != "execution_terminal":
            continue
        if _text(entry.payload, "event", "state") != "succeeded":
            continue
        key = _attempt_key(entry.payload, event=True)
        if key is not None and _attempt_names_unresolved(key, entries, pairs, unresolved):
            continue
        if key is None or key not in pairs.consumed or key not in pairs.released:
            findings.add(
                STAGE_CAUSAL,
                _issue(
                    DECISION_BINDING_INVALID,
                    "a succeeded attempt lacks consumed authority or release evidence",
                ),
            )
    # EBMP2-074: a release of single-use authority has its consumption recorded, whatever the
    # terminal state of its attempt.
    for entry in entries:
        if entry.observation or entry.index not in pairs.bound_releases:
            continue
        key = _attempt_key(entry.payload, event=True)
        response = pairs.event_response.get(entry.index)
        if (
            key is not None
            and not _attempt_names_unresolved(key, entries, pairs, unresolved)
            and key not in pairs.consumed
            and response is not None
            and _text(response.payload, "authorization", "use_policy") == "single_use"
        ):
            findings.add(
                STAGE_CAUSAL,
                _issue(
                    DECISION_BINDING_INVALID,
                    f"envelope {entry.index}: a release of single-use authority has no "
                    "recorded consumption",
                ),
            )
    missing_terminal = any(
        key not in pairs.terminal
        for request in pairs.requests.values()
        if (key := _attempt_key(request.payload)) is not None
    )
    causal_status = (
        "incomplete"
        if (missing_terminal or continuation_missing) and analysis.status == "complete"
        else analysis.status
    )
    effects = _effects(
        entries, pairs, findings.at(STAGE_REASONS), closure_complete=causal_status == "complete"
    )
    verdict = (
        "invalid"
        if findings or causal_status == "indeterminate"
        else ("incomplete" if causal_status != "complete" else "verified")
    )
    accepted = False
    # EBMP2-060: every trust dependency, a time authority's key included, is acceptable now.
    if verdict == "verified" and (
        any(check.current != "valid" for check in checks)
        or any(item.current != "valid" for item in dependencies)
    ):
        if accept_current_trust_failure:
            accepted = True
        else:
            verdict = CURRENT_TRUST_FAILED
    # The conditional items of the scope that apply to this bundle, and the stated reasons that
    # keep an item out of `established`; `report_scope` places them.
    conditional = (SCOPE_DISCHARGE if discharge_applied else ()) + (
        (SCOPE_POST_RELEASE,) if post_release else ()
    )
    reasons: dict[str, str] = {}
    if not pairs.release_recorded:
        reasons[SCOPE_RELEASE] = REASON_NO_RELEASE
    if discharge_applied and uncarried:
        reasons[SCOPE_PROOFS] = REASON_PROOF_NOT_ECL_OBJECT
    elif discharge_applied and unnamed:
        # Both reasons true, the report gives `proof-not-ecl-object`: a proof that is not carried
        # was not checked at all.
        reasons[SCOPE_PROOFS] = REASON_ISSUER_NOT_NAMED
    ran = _checks_that_held(
        checks=checks,
        entries=entries,
        dependencies=dependencies,
        covered=covered,
        findings=findings,
        analysis=analysis,
        missing_terminal=missing_terminal,
        continuation_missing=continuation_missing,
        continued=continued,
        proofs=proofs,
        pairs=pairs,
        register=register is not None,
    )
    return BundleReport(
        verdict,
        tuple(sorted(checks, key=lambda item: item.index)),
        tuple(bindings),
        causal_status,
        effects,
        findings.ordered(),
        REFERENCE_PROFILE,
        accepted,
        scope=ReportScope((), conditional, reasons, ran),
        completion_after_window=pairs.completion_after_window,
        trust_dependencies=tuple(sorted(dependencies, key=lambda item: item.index)),
        # Non-empty only for an incomplete verdict (EBMP2-076).
        unresolved_predecessor_ids=(
            tuple(sorted(set(analysis.unresolved_predecessor_ids)))
            if verdict == "incomplete"
            else ()
        ),
    )


# EBMP2-076 and registries/scope-checks.json: the checks of the claim-to-check map, in registry
# order, and for each item of the scope the object set and the checks that must run over it and
# hold before the item is established.
SCOPE_CHECK_IDS = (
    "envelope-integrity",
    "time-not-after-evaluation",
    "historical-signers",
    "current-compromise-knowledge",
    "trusted-time-countersignatures",
    "trusted-time-coverage",
    "current-status",
    "object-schema",
    "object-semantics",
    "observation-kind",
    "identifiers-unique",
    "decision-basis-present",
    "decision-basis-one-way",
    "decision-basis-register",
    "pairing",
    "continuation-history",
    "response-binding",
    "event-binding",
    "release-window",
    "predecessors-resolved",
    "predecessor-digests",
    "graph-acyclic",
    "causal-context",
    "sequence-monotonic",
    "state-transitions",
    "terminal-per-request",
    "attempt-authority-consumed",
    "obligation-discharge",
    "obligation-proofs",
    "outcome-reasons",
    "corroborating-observation",
)
SCOPE_OBJECT_SETS: Mapping[str, str] = MappingProxyType(
    {
        "envelope-signatures": "trust-dependencies",
        "current-trust": "trust-dependencies",
        "trusted-time": "object-signatures",
        "object-rules": "bundle-objects",
        "decision-basis-recorded": "decision-responses",
        "decision-basis-register": "decision-responses",
        "bindings": "request-response-pairs",
        "release-within-authority": "released-attempts",
        "causal-completeness": "bundle-objects",
        "prerelease-obligations-discharge-recorded": "released-attempts",
        "prerelease-obligations-proofs-verified": "discharge-entries",
    }
)
SCOPE_REQUIRED_CHECKS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "envelope-signatures": (
            "envelope-integrity",
            "time-not-after-evaluation",
            "historical-signers",
            "current-compromise-knowledge",
            "trusted-time-countersignatures",
        ),
        "current-trust": ("current-status",),
        "trusted-time": (
            "historical-signers",
            "current-compromise-knowledge",
            "trusted-time-countersignatures",
            "trusted-time-coverage",
        ),
        "object-rules": (
            "object-schema",
            "object-semantics",
            "observation-kind",
            "identifiers-unique",
            "decision-basis-one-way",
        ),
        "decision-basis-recorded": ("decision-basis-present",),
        "decision-basis-register": ("decision-basis-register",),
        "bindings": (
            "pairing",
            "continuation-history",
            "response-binding",
            "event-binding",
            "outcome-reasons",
        ),
        "release-within-authority": ("release-window",),
        "causal-completeness": (
            "identifiers-unique",
            "predecessors-resolved",
            "predecessor-digests",
            "graph-acyclic",
            "causal-context",
            "sequence-monotonic",
            "state-transitions",
            "terminal-per-request",
            "attempt-authority-consumed",
        ),
        "prerelease-obligations-discharge-recorded": ("obligation-discharge",),
        "prerelease-obligations-proofs-verified": ("obligation-proofs",),
    }
)
# The object sets that a report's envelope checks determine, which `report_scope` requires an
# item's objects to cover: every object, and the decision responses.
_WHOLE_BUNDLE_SETS = frozenset({"bundle-objects", "trust-dependencies", "object-signatures"})


def _checks_that_held(
    *,
    checks: Sequence[EnvelopeCheck],
    entries: Sequence[_Entry],
    dependencies: Sequence[TrustDependency],
    covered: Mapping[int, bool],
    findings: _Findings,
    analysis: causal.BundleAnalysis,
    missing_terminal: bool,
    continuation_missing: bool,
    continued: set[int],
    proofs: set[int],
    pairs: _Pairs,
    register: bool,
) -> dict[str, dict[str, list[Any]]]:
    """EBMP2-076: for each item of the scope, the checks of SCOPE_REQUIRED_CHECKS that ran over
    the item's object set and held, and the indexes of the objects they covered. An item whose
    checks did not all hold has no entry; `report_scope` lists an item in `established` only when
    its entry names every required check and covers the item's object set."""
    every = sorted(check.index for check in checks)
    codes = {stage: findings.codes(stage) for stage in range(STAGE_PAYLOADS, STAGE_REASONS + 1)}
    historical = {check.historical for check in checks}
    rules = {item.rule_id for item in analysis.findings}
    signers_valid = all(
        item.historical == "valid" for item in dependencies if item.role == "signer"
    )
    every_dependency_valid = all(item.historical == "valid" for item in dependencies)
    holds: dict[str, bool] = {
        "envelope-integrity": not codes[STAGE_PAYLOADS]
        and not historical & {INTEGRITY_INVALID, RESOURCE_LIMIT, POLICY_INVALID},
        "time-not-after-evaluation": CLOCK_REGRESSED not in historical,
        # `envelope-signatures` rests on the signers of envelopes and observations; the time
        # authorities' signers count for `trusted-time` below (decision "A signature that does
        # not verify").
        "historical-signers": historical == {"valid"} and signers_valid,
        "current-compromise-knowledge": REVOKED not in historical and signers_valid,
        "trusted-time-countersignatures": TRUSTED_TIME_INVALID not in historical,
        "trusted-time-coverage": bool(every) and all(covered.get(index) for index in every),
        "current-status": all(check.current == "valid" for check in checks)
        and all(item.current == "valid" for item in dependencies),
        "object-schema": SCHEMA_INVALID not in codes[STAGE_OBJECTS],
        "object-semantics": not (
            codes[STAGE_OBJECTS]
            - {
                SCHEMA_INVALID,
                basis.REQUIRED_RULE,
                basis.REGISTER_RULE,
                "ecl.rule.bundle-object-identifiers-unique.v1",
            }
        ),
        "observation-kind": SEMANTIC_INVALID not in codes[STAGE_OBJECTS],
        "identifiers-unique": "ecl.rule.bundle-object-identifiers-unique.v1"
        not in codes[STAGE_OBJECTS] | rules,
        "decision-basis-present": basis.REQUIRED_RULE not in codes[STAGE_OBJECTS],
        "decision-basis-one-way": basis.ONE_WAY_RULE not in codes[STAGE_OBJECTS],
        "decision-basis-register": register and basis.REGISTER_RULE not in codes[STAGE_OBJECTS],
        "pairing": not codes[STAGE_PAIRING],
        # An object that a continuation names and the bundle does not hold keeps the check from
        # holding over the item's whole object set (EBMP2-076).
        "continuation-history": not codes[STAGE_PAIRING] and not continuation_missing,
        "response-binding": not codes[STAGE_REQUESTS],
        "event-binding": not codes[STAGE_EVENTS],
        "release-window": EXPIRED not in codes[STAGE_EVENTS],
        "predecessors-resolved": not analysis.unresolved_predecessor_ids
        and not continuation_missing,
        "predecessor-digests": "ecl.rule.bundle-predecessor-digest-valid.v1" not in rules,
        "graph-acyclic": "ecl.rule.bundle-causal-graph-acyclic.v1" not in rules,
        "causal-context": causal.CONTEXT_RULE not in rules,
        "sequence-monotonic": "ecl.rule.bundle-causal-sequence-monotonic.v1" not in rules,
        "state-transitions": "ecl.rule.execution-state-transition-valid.v1" not in rules
        and not analysis.open_action_ids,
        "terminal-per-request": not missing_terminal,
        "attempt-authority-consumed": DECISION_BINDING_INVALID not in codes[STAGE_CAUSAL],
        "obligation-discharge": DISCHARGE_RULE not in codes[STAGE_CAUSAL],
        "obligation-proofs": DISCHARGE_RULE not in codes[STAGE_CAUSAL]
        and OBLIGATION_UNPROVEN not in codes[STAGE_CAUSAL],
        "outcome-reasons": not codes[STAGE_REASONS],
    }
    if codes[STAGE_CAUSAL] & {RESOURCE_LIMIT}:
        # A declared limit stopped the analysis: no causal check ran over the whole graph.
        for check in SCOPE_REQUIRED_CHECKS["causal-completeness"]:
            holds[check] = False
    responses = sorted(entry.index for entry in entries if entry.check.kind == "decision_response")
    paired = sorted(
        {
            *(entry.index for entry in pairs.requests.values()),
            *(entry.index for entry in pairs.responses.values()),
            *pairs.event_request,
            *continued,
        }
    )
    released_keys = {
        key
        for entry in entries
        if entry.index in pairs.bound_releases
        and (key := _attempt_key(entry.payload, event=True)) is not None
    }
    released = sorted(
        {
            *pairs.bound_releases,
            # The terminal events of each released attempt (`released-attempts`).
            *(
                entry.index
                for entry in entries
                if not entry.observation
                and entry.check.kind == "execution_terminal"
                and _attempt_key(entry.payload, event=True) in released_keys
            ),
            *(pairs.event_request[index].index for index in pairs.bound_releases),
            *(
                response.index
                for index in pairs.bound_releases
                if (response := pairs.event_response.get(index)) is not None
            ),
        }
    )
    objects = {
        "trust-dependencies": sorted({item.index for item in dependencies}),
        "object-signatures": every,
        "bundle-objects": every,
        "decision-responses": responses,
        "request-response-pairs": paired,
        "released-attempts": released,
        "discharge-entries": sorted(proofs),
    }
    result: dict[str, dict[str, list[Any]]] = {}
    for item, required in SCOPE_REQUIRED_CHECKS.items():
        # `trusted-time` also rests on every signer of the attestations it relies on.
        if item == "trusted-time" and not every_dependency_valid:
            continue
        if all(holds.get(check, False) for check in required):
            result[item] = {
                "checks": [check for check in SCOPE_CHECK_IDS if check in required],
                "objects": list(objects[SCOPE_OBJECT_SETS[item]]),
            }
    return result


def _expected_objects(item: str, report: BundleReport) -> set[int] | None:
    """The indexes that an item's objects must cover, for the object sets that the report's
    envelope checks determine; None for another set, whose objects the verification recorded."""
    indexes = {check.index for check in report.envelope_checks}
    kind = SCOPE_OBJECT_SETS.get(item)
    if kind in _WHOLE_BUNDLE_SETS:
        return indexes
    if kind == "decision-responses":
        return {
            check.index for check in report.envelope_checks if check.kind == "decision_response"
        }
    return None


def _ran_in_full(item: str, report: BundleReport) -> bool:
    """Whether the report records, for `item`, every check that the claim-to-check map requires,
    held over the item's whole object set (EBMP2-076)."""
    entry = report.scope.checks.get(item)
    if type(entry) is not dict:
        return False
    required = [check for check in SCOPE_CHECK_IDS if check in SCOPE_REQUIRED_CHECKS[item]]
    if list(entry.get("checks", ())) != required:
        return False
    expected = _expected_objects(item, report)
    if expected is not None and not expected <= set(entry.get("objects", ())):
        return False
    if SCOPE_OBJECT_SETS[item] == "trust-dependencies":
        signed = {dependency.index for dependency in report.trust_dependencies}
        if not {check.index for check in report.envelope_checks} <= signed:
            return False
    return item != "current-trust" or all(
        dependency.current == "valid" for dependency in report.trust_dependencies
    )


def report_scope(report: BundleReport) -> ReportScope:
    """EBMP2-076: the scope of a report's verdict, from the report alone.

    `established` holds the checks that the verifier made and that held: none for an `invalid`
    report or one without an evaluated envelope; otherwise the signatures, object rules and
    bindings, the recorded release time when the bundle records a release, current trust when the
    verdict is `verified` or `incomplete` and every trust dependency is valid now, trusted time
    when a valid countersignature covers every signature, the decision basis, the register when
    the caller supplied one (the item applies only then), and each only when every check that
    the claim-to-check map requires held over its whole object set (`scope.checks`);
    causal completeness unless the verdict is `incomplete`, the recorded discharge of pre-release
    obligations when that rule applied, and the proofs of those obligations when every one is an
    object of the bundle that passed its checks. `not_established` holds the other items that
    apply and the statements that no verification establishes, and `reasons` the stated reason of
    each item that a reason keeps out of `established` (`no-release-recorded`,
    `proof-not-ecl-object`, `issuer-not-named`). The lists are in the order of the table of
    EBMP2-076. The conditional
    items that apply, and the reasons, are those already in the report's scope, so the function
    gives the same scope again for a report whose verdict another check has changed, as for an
    offline package (IE1-022)."""
    applies = set(report.scope.established) | set(report.scope.not_established)
    reasons = dict(report.scope.reasons)
    discharge = SCOPE_DISCHARGE[0] in applies
    post_release = SCOPE_POST_RELEASE in applies
    checks = report.envelope_checks
    established: set[str] = set()
    if checks and report.verdict in ("verified", CURRENT_TRUST_FAILED, "incomplete"):
        established.update(("envelope-signatures", "object-rules", "bindings"))
        if SCOPE_RELEASE not in reasons:
            established.add(SCOPE_RELEASE)
        if report.verdict in ("verified", "incomplete") and all(
            check.current == "valid" for check in checks
        ):
            established.add("current-trust")
        established.add("trusted-time")
        established.add("decision-basis-recorded")
        if report.register is not None:
            established.add("decision-basis-register")
        if report.verdict != "incomplete":
            established.add("causal-completeness")
        if discharge:
            established.add(SCOPE_DISCHARGE[0])
            if SCOPE_PROOFS not in reasons:
                established.add(SCOPE_PROOFS)
        # The claim-to-check map: an item is established only when every check that it requires
        # ran over its whole object set and held.
        established = {item for item in established if _ran_in_full(item, report)}
    items = [
        item
        for item in (*SCOPE_CHECKS, *SCOPE_NEVER)
        if (item not in CONDITIONAL_SCOPE and item != SCOPE_REGISTER)
        or (item in SCOPE_DISCHARGE and discharge)
        or (item == SCOPE_POST_RELEASE and post_release)
        # `decision-basis-register` applies only when the caller supplies a register
        # (registries/scope-checks.json).
        or (item == SCOPE_REGISTER and report.register is not None)
    ]
    return ReportScope(
        tuple(item for item in items if item in established),
        tuple(item for item in items if item not in established),
        {item: reasons[item] for item in items if item in reasons and item not in established},
        {
            item: {
                "checks": list(report.scope.checks[item]["checks"]),
                "objects": sorted(report.scope.checks[item]["objects"]),
            }
            for item in items
            if item in established
        },
    )


# `registries/scope-checks.json`, `evidence_levels`: the items that a report must establish for an
# effect to be `corroborated` (EBMP2-061).
CORROBORATION_ITEMS = ("envelope-signatures", "causal-completeness")


def with_scope(report: BundleReport) -> BundleReport:
    """The report with the scope of its verdict (EBMP2-076), and its evidence levels decided
    after the scope: `corroborated` only when the scope establishes CORROBORATION_ITEMS, else
    `issuer-asserted` (an `invalid` report establishes nothing, so it never reports
    `corroborated`)."""
    scope = report_scope(report)
    effects = report.effects
    if not all(item in scope.established for item in CORROBORATION_ITEMS):
        effects = tuple(
            replace(effect, level="issuer-asserted") if effect.level == "corroborated" else effect
            for effect in effects
        )
    return replace(report, scope=scope, effects=effects)


def _signer_rank(code: str) -> tuple[int, str]:
    return (SIGNER_ORDER.index(code) if code in SIGNER_ORDER else len(SIGNER_ORDER), code)


def reported_identifiers(report: BundleReport) -> list[str]:
    """The identifiers of a report in the order of EBMP2-068, each once, the primary first: the
    codes of the findings of an invalid or incomplete bundle, the causal-closure code for an
    incomplete bundle without findings, and for a bundle whose trust has failed now the current
    statuses that are not valid, in the order of stage 4 (EBMP2-060)."""
    if report.verdict == CURRENT_TRUST_FAILED:
        statuses = {check.current for check in report.envelope_checks if check.current != "valid"}
        statuses |= {item.current for item in report.trust_dependencies if item.current != "valid"}
        return sorted(statuses or {*()}, key=_signer_rank)
    codes = list(dict.fromkeys(item.split(":", 1)[0] for item in report.findings))
    if report.verdict == "incomplete" and not codes:
        return [CAUSAL_CLOSURE_INCOMPLETE]
    return codes


def primary_finding(report: BundleReport) -> str | None:
    """The primary finding (EBMP2-060, EBMP2-068, IE1-022), or None when verified."""
    # An expired offline package has its own finding before any bundle current statuses.
    if report.verdict == CURRENT_TRUST_FAILED and report.findings:
        return report.findings[0].split(":", 1)[0]
    identifiers = reported_identifiers(report)
    return identifiers[0] if identifiers else None


def report_to_json(report: BundleReport) -> dict[str, Any]:
    """The JSON-compatible report, including its primary finding as the CLI reports it."""
    value: dict[str, Any] = json.loads(json.dumps(asdict(report), ensure_ascii=False))
    value["primary"] = primary_finding(report)
    return value


def verify_bundle(
    bundle: Mapping[str, Any],
    policy: TrustPolicy,
    *,
    now: str,
    history: Sequence[TrustPolicy] = (),
    response_clock_skew_seconds: int = 0,
    accept_current_trust_failure: bool = False,
    require_trusted_time: bool = False,
    register: Mapping[str, Any] | None = None,
) -> BundleReport:
    """Verify signatures, bindings, causality and effects under the reference verification profile.

    ``policy`` is current; ``history`` contains exact earlier versions of the same policy. The
    signed object's version decides historical validity. A signer that is not acceptable under the
    current policy at ``now`` turns an otherwise verified bundle into ``current-trust-failed``,
    unless ``accept_current_trust_failure`` is set, which the report then records. With
    ``require_trusted_time`` every envelope needs a valid trusted-time countersignature and the
    report names ``ecl.verification-profile.reference-trusted-time.v1``. A decision response
    without ``ecl.ext.decision-basis.v1`` makes the bundle invalid (DCMP2-053). ``register`` is a
    Consequential Action Register document that has passed its schema (``load_register``); each
    decision basis is then checked against it. Invalid bundle data is reported, never raised.
    ``now``, ``response_clock_skew_seconds``, ``require_trusted_time`` and ``register`` are caller
    arguments: a malformed value raises ``ValueError``. The report's
    ``scope`` says what its verdict establishes and what it does not (EBMP2-076).
    """
    checked_now = _valid_now(now)
    if type(response_clock_skew_seconds) is not int or response_clock_skew_seconds < 0:
        raise ValueError("the response clock-skew allowance is a non-negative integer of seconds")
    if type(require_trusted_time) is not bool:
        raise ValueError("require_trusted_time is a bool")
    if register is not None and register_schema_problems(register):
        raise ValueError("the register does not satisfy its schema")
    if register is not None and basis.register_document_problems(register):
        raise ValueError(f"the register breaks {basis.REGISTER_DOCUMENT_RULE}")
    try:
        report = _verify(
            bundle,
            policy,
            now=checked_now,
            history=history,
            response_clock_skew_seconds=response_clock_skew_seconds,
            accept_current_trust_failure=accept_current_trust_failure,
            require_trusted_time=require_trusted_time,
            register=register,
        )
    except Exception as error:
        report = _invalid(
            _issue(
                SEMANTIC_INVALID,
                f"bundle verification could not be completed: {type(error).__name__}",
            )
        )
    profile = TRUSTED_TIME_PROFILE if require_trusted_time else REFERENCE_PROFILE
    return with_scope(
        replace(
            report,
            verification_profile=profile,
            register=None if register is None else basis.register_reference(register),
            # Every report states the evaluation time it used, an invalid one included.
            evaluation_time=checked_now,
        )
    )


def register_schema_problems(register: object) -> list[str]:
    """The schema errors of a Consequential Action Register document, none when it is valid."""
    if type(register) is not dict:
        return ["the register is not a JSON object"]
    return [
        error.message[:200] for error in validator_for(basis.REGISTER_SCHEMA).iter_errors(register)
    ]


class RegisterError(ValueError):
    """A register that cannot be used; `code` is the registered code of the refusal, when there
    is one (`ecl.error.resource-limit-exceeded.v1` for a declared limit, TP1-007)."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


def load_register(data: bytes) -> dict[str, Any]:
    """A Consequential Action Register document from its bytes: strict JSON that satisfies the
    register schema and `ecl.rule.register-declarations-consistent.v1`, so that no action class
    and no input of a class is declared twice (DCMP2-053, ECL1N-0178). Raises RegisterError, a
    ValueError, otherwise, which a verifier command reports as a usage error; a register beyond a
    declared limit is refused with `ecl.error.resource-limit-exceeded.v1`."""
    if type(data) is bytes and len(data) > MAX_REGISTER_BYTES:
        raise RegisterError(
            f"the register exceeds the {MAX_REGISTER_BYTES} byte limit", RESOURCE_LIMIT
        )
    try:
        value = loads_json_strict(data, max_bytes=MAX_REGISTER_BYTES)
    except CanonicalizationError as error:
        if error.finding_id == RESOURCE_LIMIT:
            raise RegisterError("the register exceeds a declared limit", RESOURCE_LIMIT) from error
        raise RegisterError("the register is not strict JSON", error.finding_id) from error
    problems = register_schema_problems(value)
    if problems or not isinstance(value, dict):
        raise RegisterError(
            "the register does not satisfy its schema: " + "; ".join(problems[:1]), SCHEMA_INVALID
        )
    inconsistent = basis.register_document_problems(value)
    if inconsistent:
        path, message = inconsistent[0]
        raise RegisterError(
            f"the register breaks {basis.REGISTER_DOCUMENT_RULE}: {path}: {message}",
            basis.REGISTER_DOCUMENT_RULE,
        )
    return value
