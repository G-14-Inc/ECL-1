"""Offline verification checks and read-only metadata for integrity."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from .canonical import (
    MAX_JSON_NODES,
    NODE_BUDGET_MESSAGE,
    CanonicalizationError,
    canonicalize,
    loads_json_strict,
    same_json,
)
from .schema import parse_rfc3339_utc


class IntegrityError(ValueError):
    """Raised for a malformed or unverifiable integrity envelope."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "ecl.error.integrity-invalid.v1",
        policy_invalid: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.policy_invalid = policy_invalid

INTEGRITY_INVALID = "ecl.error.integrity-invalid.v1"

SIGNATURE_POLICY_INVALID = "ecl.error.signature-policy-invalid.v1"

REVOKED = "ecl.error.revoked.v1"

EXPIRED = "ecl.error.expired.v1"

THRESHOLD_NOT_MET = "ecl.error.threshold-not-met.v1"

RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1"

_UNACCEPTABLE = "unacceptable"

_KEY_REVOKED = "revoked"

_KEY_EXPIRED = "expired"

_UNVERIFIED = "unverified"

_REASON_CODES = (
    (_UNACCEPTABLE, SIGNATURE_POLICY_INVALID),
    (_KEY_REVOKED, REVOKED),
    (_KEY_EXPIRED, EXPIRED),
    (_UNVERIFIED, SIGNATURE_POLICY_INVALID),
)

class PayloadNodeBudgetError(IntegrityError):
    """A payload refused at the value limit that its caller passed as `max_nodes`: a resource
    limit, which a bundle verifier that passes the nodes remaining of its budget reads as the
    bundle's payload node limit (EBMP2-062)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code=RESOURCE_LIMIT)

def _policy_error(message: str, code: str = SIGNATURE_POLICY_INVALID) -> IntegrityError:
    return IntegrityError(message, code=code, policy_invalid=True)

def _limit_error(message: str) -> IntegrityError:
    return IntegrityError(message, code=RESOURCE_LIMIT)

_PROTOCOL_MEDIA_TYPES = {
    "DCMP-2": "application/vnd.ecl.dcmp+json",
    "EBMP-2": "application/vnd.ecl.ebmp+json",
}

MAX_INTEGRITY_PAYLOAD_BYTES = 64 * 1024 * 1024

MAX_SIGNATURE_BYTES = 16 * 1024

MAX_SIGNATURE_COUNT = 32

MAX_POLICY_LIST_ENTRIES = 64

MAX_ENCODED_PAYLOAD_CHARACTERS = ((MAX_INTEGRITY_PAYLOAD_BYTES + 2) // 3) * 4

MAX_ENCODED_SIGNATURE_CHARACTERS = ((MAX_SIGNATURE_BYTES + 2) // 3) * 4

@dataclass(frozen=True)
class VerificationKey:
    """A key `verify_envelope` may count. `purposes` are the payload types it may sign. When
    `role_purposes` is not empty, it holds the key's TRUST-POLICY-1 purposes, and a DCMP-2 message
    counts only under a key that holds the purpose IE1-039 gives its message type (TP1-010)."""

    key_id: str
    suite_id: str
    public_key: Any
    trust_policy_ids: tuple[str, ...] = ()
    purposes: tuple[str, ...] = ()
    valid_from: str | None = None
    valid_until: str | None = None
    role_purposes: tuple[str, ...] = ()

_ROLE_PURPOSES = {
    "decision_request": "ecl.purpose.decision-request.v1",
    "challenge_response": "ecl.purpose.decision-request.v1",
    "decision_response": "ecl.purpose.decision-response.v1",
    "challenge": "ecl.purpose.decision-response.v1",
    "control": "ecl.purpose.control.v1",
}

def _role_purpose(payload: Any) -> str | None:
    """The purpose that the signer of a DCMP-2 message must hold (IE1-039), or None."""
    if not isinstance(payload, dict) or payload.get("protocol") != "DCMP-2":
        return None
    message_type = payload.get("message_type")
    return _ROLE_PURPOSES.get(message_type) if isinstance(message_type, str) else None

@dataclass(frozen=True)
class KeyRevocation:
    key_id: str
    effective_at: str
    reason: str

@dataclass(frozen=True)
class VerificationContext:
    trust_policy_id: str
    trust_policy_version: str
    trust_policy_digest: str
    trust_policy_epoch: int
    evaluated_at: str
    verification_time_policy: str
    revocation_policy: str
    allowed_suites: tuple[str, ...]
    prohibited_suites: tuple[str, ...] = ()
    revocations: tuple[KeyRevocation, ...] = ()

@dataclass(frozen=True)
class VerificationResult:
    payload: Any
    valid_key_ids: tuple[str, ...]
    valid_signature_count: int
    evaluated_at: str
    trust_policy_id: str
    trust_policy_version: str
    trust_policy_epoch: int
    verification_time_policy: str
    revocation_policy: str

@dataclass(frozen=True)
class SignatureTransitionPolicy:
    mode: str
    classical_suites: frozenset[str]
    post_quantum_suites: frozenset[str]
    threshold: int
    required_classical: int
    required_post_quantum: int

    def validate(self, valid_suite_ids: Iterable[str]) -> bool:
        if self.mode not in {"both", "either", "quorum"}:
            raise _policy_error("unknown signature transition mode")
        if (
            not self.classical_suites
            or not self.post_quantum_suites
            or self.classical_suites & self.post_quantum_suites
        ):
            raise _policy_error("signature suite classes are invalid")
        observed = set(valid_suite_ids)
        classical = len(observed & self.classical_suites)
        post_quantum = len(observed & self.post_quantum_suites)
        total = classical + post_quantum
        if self.mode == "both":
            return classical >= 1 and post_quantum >= 1
        if self.mode == "either":
            return total >= 1
        if self.threshold < 1:
            raise _policy_error("transition quorum threshold must be positive")
        return (
            total >= self.threshold
            and classical >= self.required_classical
            and post_quantum >= self.required_post_quantum
        )

@dataclass(frozen=True)
class MlDsaProviderDeclaration:
    suite_id: str
    profile_enabled: bool
    trust_policy_enabled: bool
    fips_204_revision: str
    active_errata_digest: str
    conformance_evidence_digest: str

    def validate(self) -> None:
        if self.suite_id != "ecl.sig.ml-dsa-65.v1":
            raise _policy_error("ML-DSA provider declares the wrong suite")
        if not self.profile_enabled or not self.trust_policy_enabled:
            raise _policy_error(
                "ML-DSA must be explicitly enabled by profile and trust policy"
            )
        if (
            not self.fips_204_revision
            or len(self.active_errata_digest) != 64
            or len(self.conformance_evidence_digest) != 64
        ):
            raise _policy_error(
                "ML-DSA provider lacks FIPS 204 and conformance evidence binding"
            )

@dataclass(frozen=True)
class MlDsa65ProviderEvidence:
    provider_package: str
    provider_version: str
    backend_version: str
    fips_204_reference: str
    active_errata_reference: str
    active_errata_digest: str
    acvp_prompt_reference: str
    acvp_prompt_digest: str
    acvp_expected_results_reference: str
    acvp_expected_results_digest: str
    acvp_group_id: int
    acvp_test_case_id: int
    public_key_bytes: int
    signature_bytes: int
    external_mu_bytes: int

    def validate(self) -> None:
        if (
            self.provider_package != "cryptography"
            or not self.provider_version
            or not self.backend_version
            or self.fips_204_reference != "https://doi.org/10.6028/NIST.FIPS.204"
            or not self.active_errata_reference.startswith("https://csrc.nist.gov/")
            or len(self.active_errata_digest) != 64
            or not self.acvp_prompt_reference.startswith(
                "https://github.com/usnistgov/ACVP-Server/"
            )
            or len(self.acvp_prompt_digest) != 64
            or not self.acvp_expected_results_reference.startswith(
                "https://github.com/usnistgov/ACVP-Server/"
            )
            or len(self.acvp_expected_results_digest) != 64
            or self.acvp_group_id < 1
            or self.acvp_test_case_id < 1
            or self.public_key_bytes != 1952
            or self.signature_bytes != 3309
            or self.external_mu_bytes != 64
        ):
            raise _policy_error("ML-DSA provider evidence is incomplete")

def mldsa65_provider_identity() -> tuple[str, str]:
    """Return the exact Python package and cryptographic backend identity."""

    try:
        provider_version = version("cryptography")
        from cryptography.hazmat.backends.openssl.backend import backend
        from cryptography.hazmat.primitives.asymmetric.mldsa import (
            MLDSA65PublicKey,
        )
    except (ImportError, PackageNotFoundError) as exc:
        raise IntegrityError(
            "ML-DSA-65 provider is unavailable; cryptography 50.0.2 or later "
            "with an ML-DSA-capable backend is required"
        ) from exc
    if MLDSA65PublicKey is None:  # pragma: no cover - defensive import contract
        raise IntegrityError("ML-DSA-65 public-key provider is unavailable")
    return provider_version, backend.openssl_version_text()

def load_mldsa65_public_key(raw_public_key: bytes) -> Any:
    """Load a FIPS 204 ML-DSA-65 raw public key through the pinned provider."""

    if len(raw_public_key) != 1952:
        raise IntegrityError("ML-DSA-65 public key must be 1952 bytes")
    mldsa65_provider_identity()
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey

    try:
        return MLDSA65PublicKey.from_public_bytes(raw_public_key)
    except ValueError as exc:
        raise IntegrityError("ML-DSA-65 public key encoding is invalid") from exc

def verify_mldsa65_external_mu(
    *,
    public_key: Any,
    signature: bytes,
    mu: bytes,
) -> None:
    """Verify the FIPS 204 external-mu interface used by NIST ACVP vectors."""

    mldsa65_provider_identity()
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey

    if not isinstance(public_key, MLDSA65PublicKey):
        raise IntegrityError(
            "ML-DSA-65 suite requires an ML-DSA-65 public key"
        )
    if len(signature) != 3309:
        raise IntegrityError("ML-DSA-65 signature must be 3309 bytes")
    if len(mu) != 64:
        raise IntegrityError("ML-DSA external mu must be 64 bytes")
    public_key.verify_mu(signature, mu)

TRUSTED_TIME_CLAIM = "ecl.claim.trusted-time.v1"

TIME_ATTESTATION_VERSION = "ecl_time_attestation_v1"

_ENVELOPE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/integrity-envelope/1"

_SIGNED_MEMBERS = ("envelope_version", "payload_type", "payload", "payload_digest", "signatures")

def signature_digest(entry: dict[str, Any]) -> dict[str, str]:
    """The `ecl.digest.sha-256.v1` digest of the signature bytes that a signature entry's
    `signature` encodes (IE1-033). Raises IntegrityError when the entry has no canonical
    base64 signature."""
    if not isinstance(entry, dict):
        raise IntegrityError("integrity signature entry must be an object")
    return {
        "algorithm": "ecl.digest.sha-256.v1",
        "value": hashlib.sha256(_decode_signature(entry.get("signature", ""))).hexdigest(),
    }

def covered_signatures(envelope: dict[str, Any]) -> list[dict[str, Any]]:
    """The `covered.signatures` of a time attestation over every signature of `envelope`, in
    the envelope's order: each entry's `key_id`, its `suite_id` as `suite`, and the digest of
    its signature bytes (IE1-033)."""
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise IntegrityError("integrity signature set is missing")
    return [
        {
            "key_id": entry.get("key_id"),
            "suite": entry.get("suite_id"),
            "signature_digest": signature_digest(entry),
        }
        for entry in signatures
    ]

def signature_verifies(
    envelope: dict[str, Any], entry: dict[str, Any], key: VerificationKey
) -> bool:
    """Whether one signature entry of `envelope` verifies with `key`'s public key over the
    envelope's signing input (IE1-040 step 6 (d) and (e)); False for any failure."""
    from cryptography.exceptions import InvalidSignature

    try:
        message = signing_input(envelope["payload_type"], decode_payload(envelope))
        _verify_signature(
            suite_id=key.suite_id,
            public_key=key.public_key,
            signature=_decode_signature(entry["signature"]),
            message=message,
        )
    except (InvalidSignature, IntegrityError, KeyError, TypeError, ValueError):
        return False
    return True

@dataclass(frozen=True)
class AlgorithmRegistryChange:
    suite_id: str
    status: str
    registry_version: int
    security_rationale: str
    effective_at: str
    affected_profiles: tuple[str, ...]
    appeal_uri: str
    offline_snapshot_digest: str
    replacement_suite_id: str | None = None
    transition_until: str | None = None

    def validate(self) -> None:
        if self.status not in {"deprecated", "prohibited"}:
            raise IntegrityError("algorithm change must deprecate or prohibit")
        if (
            self.registry_version < 1
            or not self.security_rationale
            or not self.affected_profiles
            or not self.appeal_uri
            or len(self.offline_snapshot_digest) != 64
        ):
            raise IntegrityError("algorithm registry change is incomplete")
        effective = _time(self.effective_at)
        if self.status == "deprecated":
            if not self.replacement_suite_id or not self.transition_until:
                raise IntegrityError(
                    "deprecation requires replacement and transition window"
                )
            if _time(self.transition_until) <= effective:
                raise IntegrityError("algorithm transition window is empty")

def _length(value: bytes) -> bytes:
    return str(len(value)).encode("ascii")

def signing_input(payload_type: str, payload: bytes) -> bytes:
    """Return the DSSE v1 pre-authentication encoding for an ECL payload."""

    if not isinstance(payload_type, str) or not isinstance(payload, bytes):
        raise IntegrityError("signing input requires a string type and byte payload")
    try:
        type_bytes = payload_type.encode("ascii")
    except UnicodeEncodeError as exc:
        raise IntegrityError("payload_type must be ASCII") from exc
    return (
        b"DSSEv1 "
        + _length(type_bytes)
        + b" "
        + type_bytes
        + b" "
        + _length(payload)
        + b" "
        + payload
    )

def decode_payload(envelope: dict[str, Any]) -> bytes:
    if not isinstance(envelope, dict):
        raise IntegrityError("integrity envelope must be an object")
    try:
        encoded = envelope["payload"]
        if not isinstance(encoded, str) or not encoded.isascii():
            raise ValueError("payload must be an ASCII base64 string")
    except (KeyError, TypeError, ValueError) as exc:
        raise IntegrityError("payload is not valid canonical base64") from exc
    if len(encoded) > MAX_ENCODED_PAYLOAD_CHARACTERS:
        raise _limit_error("payload exceeds the integrity byte budget")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError) as exc:
        raise IntegrityError("payload is not valid canonical base64") from exc
    if base64.b64encode(payload).decode("ascii") != encoded:
        raise IntegrityError("payload is not canonical base64")
    digest = hashlib.sha256(payload).hexdigest()
    declared = envelope.get("payload_digest") or {}
    if not isinstance(declared, dict):
        raise IntegrityError("payload digest must be an object")
    if declared.get("algorithm") != "ecl.digest.sha-256.v1":
        raise IntegrityError("unsupported or missing payload digest suite")
    if declared.get("value") != digest:
        raise IntegrityError("payload digest mismatch")
    return payload

def decode_canonical_json_payload(
    envelope: dict[str, Any], *, max_nodes: int = MAX_JSON_NODES
) -> Any:
    """The payload of `envelope` as strict, canonical ECL JSON (IE1-040, step 3), parsed with the
    value limit `max_nodes` (IE1-037, check 3), so that no value is built beyond it (IE1-029). A
    refusal at that limit is a `PayloadNodeBudgetError`."""
    payload = decode_payload(envelope)
    try:
        value = loads_json_strict(payload, max_nodes=max_nodes)
        if canonicalize(value) != payload:
            raise IntegrityError("payload is not canonical ECL JSON")
    except CanonicalizationError as exc:
        # A declared limit of the strict parser is a resource limit; any other refusal leaves
        # the payload outside canonical strict JSON (IE1-040, step 3).
        if exc.finding_id == RESOURCE_LIMIT and str(exc) == NODE_BUDGET_MESSAGE:
            raise PayloadNodeBudgetError(str(exc)) from exc
        code = RESOURCE_LIMIT if exc.finding_id == RESOURCE_LIMIT else INTEGRITY_INVALID
        raise IntegrityError(str(exc), code=code) from exc
    return value

def _decode_signature(value: str) -> bytes:
    if not isinstance(value, str) or not value.isascii():
        raise IntegrityError("signature is not valid canonical base64")
    if len(value) > MAX_ENCODED_SIGNATURE_CHARACTERS:
        raise _limit_error("signature exceeds the integrity byte budget")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise IntegrityError("signature is not valid canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise IntegrityError("signature is not canonical base64")
    return decoded

def _time(value: str) -> datetime:
    try:
        parsed = parse_rfc3339_utc(value)
    except ValueError as exc:
        raise IntegrityError(f"invalid UTC timestamp: {value!r}") from exc
    return parsed.astimezone(timezone.utc)

def _validate_context(
    policy: dict[str, Any],
    context: VerificationContext,
) -> datetime:
    trust = policy.get("trust_policy")
    if not isinstance(trust, dict):
        raise _policy_error("signed payload lacks a trust policy reference")
    declared_digest = trust.get("digest")
    if not isinstance(declared_digest, dict):
        raise _policy_error("trust policy digest suite is unsupported")
    expected = (
        context.trust_policy_id,
        context.trust_policy_version,
        context.trust_policy_digest,
        context.trust_policy_epoch,
    )
    observed = (
        trust.get("id"),
        trust.get("version"),
        declared_digest.get("value"),
        trust.get("epoch"),
    )
    if declared_digest.get("algorithm") != "ecl.digest.sha-256.v1":
        raise _policy_error("trust policy digest suite is unsupported")
    # Each member as the same JSON value, so an epoch of `true` is not epoch 1.
    if not all(same_json(left, right) for left, right in zip(observed, expected, strict=True)):
        raise _policy_error(
            "verification context does not match signed trust policy"
        )
    if policy.get("verification_time_policy") != context.verification_time_policy:
        raise _policy_error(
            "verification context does not match signed verification-time policy"
        )
    if policy.get("revocation_policy") != context.revocation_policy:
        raise _policy_error(
            "verification context does not match signed revocation policy"
        )
    evaluated_at = _time(context.evaluated_at)
    return evaluated_at

def _key_ineligibility(
    key: VerificationKey,
    *,
    payload_type: str,
    context: VerificationContext,
    evaluated_at: datetime,
    role: str | None = None,
) -> str | None:
    """Why a key cannot count for this payload at `evaluated_at` (IE1-040, step 6 (a) to (c)):
    not acceptable for the trust policy, payload type or role, revoked, or outside its validity
    interval, in that order; None when it can count."""
    if key.trust_policy_ids and context.trust_policy_id not in key.trust_policy_ids:
        return _UNACCEPTABLE
    if key.purposes and payload_type not in key.purposes:
        return _UNACCEPTABLE
    if role is not None and key.role_purposes and role not in key.role_purposes:
        return _UNACCEPTABLE
    for revocation in context.revocations:
        if (
            revocation.key_id == key.key_id
            and evaluated_at >= _time(revocation.effective_at)
        ):
            return _KEY_REVOKED
    if key.valid_from is not None and evaluated_at < _time(key.valid_from):
        return _KEY_EXPIRED
    if key.valid_until is not None and evaluated_at >= _time(key.valid_until):
        return _KEY_EXPIRED
    return None

def _verify_signature(
    *,
    suite_id: str,
    public_key: Any,
    signature: bytes,
    message: bytes,
) -> None:
    if suite_id == "ecl.sig.ed25519.v1":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        if not isinstance(public_key, Ed25519PublicKey):
            raise IntegrityError("Ed25519 suite requires an Ed25519 public key")
        public_key.verify(signature, message)
        return
    if suite_id == "ecl.sig.ecdsa-p256-sha256.v1":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
            encode_dss_signature,
        )

        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise IntegrityError("P-256 suite requires a P-256 public key")
        try:
            r, s = decode_dss_signature(signature)
        except ValueError as exc:
            raise IntegrityError("ECDSA signature is not minimally encoded DER") from exc
        if encode_dss_signature(r, s) != signature:
            raise IntegrityError("ECDSA signature is not minimally encoded DER")
        order = int(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            16,
        )
        if s > order // 2:
            raise IntegrityError("ECDSA signature is not low-S")
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return
    if suite_id == "ecl.sig.ml-dsa-65.v1":
        mldsa65_provider_identity()
        from cryptography.hazmat.primitives.asymmetric.mldsa import (
            MLDSA65PublicKey,
        )

        if not isinstance(public_key, MLDSA65PublicKey):
            raise IntegrityError(
                "ML-DSA-65 suite requires an ML-DSA-65 public key"
            )
        if len(signature) != 3309:
            raise IntegrityError("ML-DSA-65 signature must be 3309 bytes")
        public_key.verify(signature, message, b"")
        return
    raise IntegrityError(f"unsupported signature suite: {suite_id}")

def verify_envelope(
    envelope: dict[str, Any],
    keyring: dict[str, VerificationKey],
    context: VerificationContext,
    *,
    key_times: dict[str, str] | None = None,
) -> VerificationResult:
    """Verify signatures against the integrity policy bound inside the payload, in the order of
    INTEGRITY-ENVELOPE-1, IE1-040; the IntegrityError's code is the code of the step that fails.
    Step 1, the envelope schema, is the caller's (the conformance runner and the bundle verifier
    check it first). `key_times` gives a signing key its own evaluation time, which takes the
    place of the context's for that key's revocation and validity (IE1-034: a signature that a
    trusted-time countersignature covers is evaluated at its attested time, each other one at
    the object's own time); the threshold counts each signature as evaluated at its own time."""

    from cryptography.exceptions import InvalidSignature

    if not isinstance(envelope, dict):
        raise IntegrityError("integrity envelope must be an object")
    if not isinstance(keyring, dict):
        raise IntegrityError("verification keyring must be an object")
    # Step 2: the declared limits that the envelope as received shows.
    encoded = envelope.get("payload")
    if isinstance(encoded, str) and len(encoded) > MAX_ENCODED_PAYLOAD_CHARACTERS:
        raise _limit_error("payload exceeds the integrity byte budget")
    signatures = envelope.get("signatures")
    if isinstance(signatures, list):
        if len(signatures) > MAX_SIGNATURE_COUNT:
            raise _limit_error("integrity signature set exceeds the verifier budget")
        for item in signatures:
            value = item.get("signature") if isinstance(item, dict) else None
            if isinstance(value, str) and len(value) > MAX_ENCODED_SIGNATURE_CHARACTERS:
                raise _limit_error("signature exceeds the integrity byte budget")
    # Step 3: the payload's encoding, digest, canonical form and media type.
    payload_bytes = decode_payload(envelope)
    payload = decode_canonical_json_payload(envelope)
    payload_type = envelope.get("payload_type")
    if not isinstance(payload_type, str):
        raise IntegrityError("integrity envelope lacks a valid payload_type")
    if len(payload_type) > 255 or not payload_type.isascii():
        raise IntegrityError("integrity envelope payload_type is invalid")
    raw_protocol = payload.get("protocol") if isinstance(payload, dict) else None
    protocol = raw_protocol if isinstance(raw_protocol, str) else None
    expected_payload_type = (
        _PROTOCOL_MEDIA_TYPES.get(protocol)
        if protocol is not None
        else None
    )
    if expected_payload_type is not None and payload_type != expected_payload_type:
        raise IntegrityError(
            "integrity envelope payload_type does not match the signed "
            f"{protocol} payload"
        )
    claimed_protocol = next(
        (
            identifier
            for identifier, media_type in _PROTOCOL_MEDIA_TYPES.items()
            if media_type == payload_type
        ),
        None,
    )
    if claimed_protocol is not None and protocol != claimed_protocol:
        raise IntegrityError(
            "integrity envelope payload does not match the claimed "
            f"{claimed_protocol} media type"
        )
    policy = payload.get("integrity_policy") if isinstance(payload, dict) else None
    if not isinstance(policy, dict):
        raise IntegrityError("signed payload lacks integrity_policy")
    # Step 4: the payload-bound policy, its lists' declared limit first.
    for name in ("accepted_suites", "eligible_key_ids", "required_key_ids"):
        raw = policy.get(name)
        if isinstance(raw, list) and len(raw) > MAX_POLICY_LIST_ENTRIES:
            raise _limit_error(f"{name} exceeds the policy resource budget")
    # The policy requires integrity when `required` is the JSON value true; the number 1 is not.
    if policy.get("required") is not True:
        raise _policy_error(
            "an integrity envelope cannot elevate a payload that declares integrity optional"
        )
    threshold = policy.get("threshold")
    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold < 1
    ):
        raise _policy_error("integrity threshold must be at least one")

    def policy_string_set(name: str) -> set[str]:
        raw = policy.get(name)
        if not isinstance(raw, list) or any(
            not isinstance(item, str) or not item for item in raw
        ):
            raise _policy_error(f"{name} must be an array of identifiers")
        if len(raw) != len(set(raw)):
            raise _policy_error(f"{name} contains duplicate identifiers")
        return set(raw)

    accepted_suites = policy_string_set("accepted_suites")
    eligible_keys = policy_string_set("eligible_key_ids")
    required_keys = policy_string_set("required_key_ids")
    if not accepted_suites:
        raise _policy_error("accepted_suites cannot be empty")
    if required_keys and threshold < len(required_keys):
        raise _policy_error("threshold cannot be lower than required key count")
    evaluated_at = _validate_context(policy, context)
    context_allowed_suites = set(context.allowed_suites)
    context_prohibited_suites = set(context.prohibited_suites)
    role = _role_purpose(payload)

    # Step 5: every signature entry names a key and a suite, each pair once.
    if not isinstance(signatures, list) or not signatures:
        raise IntegrityError("integrity signature set is missing")
    entries: list[tuple[str, str, dict[str, Any]]] = []
    observed: set[tuple[str, str]] = set()
    for item in signatures:
        if not isinstance(item, dict):
            raise IntegrityError("integrity signature entry must be an object")
        key_id = str(item.get("key_id") or "")
        suite_id = str(item.get("suite_id") or "")
        if not key_id or not suite_id:
            raise IntegrityError("integrity signature identity is incomplete")
        if (key_id, suite_id) in observed:
            raise IntegrityError("duplicate signature identity")
        observed.add((key_id, suite_id))
        entries.append((key_id, suite_id, item))

    # Step 6: each signature in turn.
    message = signing_input(payload_type, payload_bytes)
    valid: set[str] = set()
    reasons: set[str] = set()
    for key_id, suite_id, item in entries:
        # (a) an acceptable key for this suite, payload and policy.
        key = keyring.get(key_id)
        if (
            suite_id not in accepted_suites
            or suite_id not in context_allowed_suites
            or suite_id in context_prohibited_suites
            or (eligible_keys and key_id not in eligible_keys)
            or key is None
            or key.suite_id != suite_id
            or key.key_id != key_id
        ):
            reasons.add(_UNACCEPTABLE)
            continue
        # (a) to (c): the key's trust policy, payload type, role, revocation and validity.
        reason = _key_ineligibility(
            key,
            payload_type=payload_type,
            context=context,
            evaluated_at=(
                _time(key_times[key_id])
                if key_times is not None and key_id in key_times
                else evaluated_at
            ),
            role=role,
        )
        if reason is not None:
            reasons.add(reason)
            continue
        # (d) and (e): the signature's encoding, then the signature itself.
        try:
            _verify_signature(
                suite_id=suite_id,
                public_key=key.public_key,
                signature=_decode_signature(item["signature"]),
                message=message,
            )
        except KeyError as exc:
            raise IntegrityError("integrity signature bytes are missing") from exc
        except InvalidSignature:
            reasons.add(_UNVERIFIED)
            continue
        valid.add(key_id)

    # Step 7: every required key and at least the threshold of keys counted.
    if not required_keys.issubset(valid) or len(valid) < threshold:
        code = next(
            (code for reason, code in _REASON_CODES if reason in reasons), THRESHOLD_NOT_MET
        )
        missing = sorted(required_keys - valid)
        if missing:
            raise _policy_error(f"required signatures are missing or invalid: {missing}", code)
        raise _policy_error(
            f"signature threshold not met: valid={len(valid)} required={threshold}", code
        )
    return VerificationResult(
        payload=payload,
        valid_key_ids=tuple(sorted(valid)),
        valid_signature_count=len(valid),
        evaluated_at=context.evaluated_at,
        trust_policy_id=context.trust_policy_id,
        trust_policy_version=context.trust_policy_version,
        trust_policy_epoch=context.trust_policy_epoch,
        verification_time_policy=context.verification_time_policy,
        revocation_policy=context.revocation_policy,
    )
