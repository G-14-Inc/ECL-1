"""A trust policy: which keys a verifier trusts, for which purposes, on whose behalf, and when.

The caller of a verifier supplies it; an evidence bundle never does (IE1-022). `TrustPolicy.load`
reads the document of `https://externalcontrollayer.ai/ns/schema/trust-policy/1` from bytes and refuses anything else with a
`TrustPolicyError`, whose `code` is a registered error. `ecl.error.schema-invalid.v1` means the
bytes are not UTF-8 strict JSON of the schema's shape (TP1-002).
`ecl.error.resource-limit-exceeded.v1` means the bytes exceed MAX_TRUST_POLICY_BYTES or the strict
parser's nesting or value limits (TP1-007, IE1-037).
`ecl.error.semantic-invalid.v1` means the document is well formed but cannot hold: a key id or a
public key twice, a suite that is not an active signature suite this version carries, a public key
that does not decode for its suite (for Ed25519: not the canonical encoding of a curve point, or a
point of small order), `valid_until` not after `valid_from`, a purpose or revocation policy the
vocabulary does not allocate, a key that carries the purposes of more than one role (TP1-009), a
revocation of a key the policy does not hold, a key revoked twice.

The digest is `canonical.object_digest` of the parsed document. It ignores whitespace and member
order and nothing else, so it covers the revocations: a revocation makes a new policy version.
`reference()` is what an object embeds as `integrity_policy.trust_policy`; `keyring()` and
`verification_context()` are what `integrity.verify_envelope` reads. This trust-document profile
permits whole seconds or three or six fractional digits. Signed object times retain their own
profile; the verifier's shared UTC parser handles one to nine fractional digits consistently
on the supported interpreters.
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from functools import cache, lru_cache
from types import MappingProxyType
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema.protocols import Validator

from .canonical import CanonicalizationError, loads_json_strict, object_digest
from .integrity import KeyRevocation, VerificationContext, VerificationKey
from .resources import ELLIPSIS, MAX_TEXT, registry_document, validator_for
from .schema import parse_rfc3339_utc
from .signature_metadata import ED25519_SUITE, P256_SUITE, payload_type_for

SCHEMA_INVALID = "ecl.error.schema-invalid.v1"
SEMANTIC_INVALID = "ecl.error.semantic-invalid.v1"
RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1"
TRUST_POLICY_SCHEMA = "https://externalcontrollayer.ai/ns/schema/trust-policy/1"
DIGEST_SUITE = "ecl.digest.sha-256.v1"
# The pilot contract's limit for a trust-policy file, section 8 (parser limits, IE1-028).
MAX_TRUST_POLICY_BYTES = 256 * 1024

PURPOSE_DECISION_REQUEST = "ecl.purpose.decision-request.v1"
PURPOSE_DECISION_RESPONSE = "ecl.purpose.decision-response.v1"
PURPOSE_EVIDENCE_EVENT = "ecl.purpose.evidence-event.v1"
PURPOSE_OBSERVATION = "ecl.purpose.observation.v1"
PURPOSE_TRUSTED_TIME = "ecl.purpose.trusted-time.v1"
PURPOSE_CONTROL = "ecl.purpose.control.v1"
# EBMP2-070: the approval purpose qualifies a key that holds the evidence-event purpose
# as an approval service's, so that a verifier admits a human intervention event as the proof of
# an approval obligation only when every key that signed it holds this purpose (MG1-013). A
# qualifying purpose lets a key sign no payload by itself.
PURPOSE_APPROVAL = "ecl.purpose.approval.v1"
QUALIFYING_PURPOSES = (PURPOSE_APPROVAL,)
_DCMP_2 = payload_type_for({"protocol": "DCMP-2"})
_EBMP_2 = payload_type_for({"protocol": "EBMP-2"})
_TIME_ATTESTATION = payload_type_for({"schema_version": "ecl_time_attestation_v1"})
# The payload types `integrity.VerificationKey.purposes` reads: a request, a response and a
# control message are DCMP-2 objects, an evidence event and an observation are EBMP-2 objects,
# and a trusted-time key signs time attestations (IE1-033, IE1-039).
PURPOSE_PAYLOAD_TYPES = MappingProxyType(
    {
        PURPOSE_DECISION_REQUEST: _DCMP_2,
        PURPOSE_DECISION_RESPONSE: _DCMP_2,
        PURPOSE_CONTROL: _DCMP_2,
        PURPOSE_EVIDENCE_EVENT: _EBMP_2,
        PURPOSE_OBSERVATION: _EBMP_2,
        PURPOSE_TRUSTED_TIME: _TIME_ATTESTATION,
    }
)

# TP1-009: the purposes that each belong to one component role: the requester of a decision, the
# decision point, the control plane, an observer and a time authority (ECL1N-0157). A key carries
# at most one of them. The evidence-event purpose is no role of its own: a requester, a decision
# point or another component records its evidence with it, so it may accompany one of these.
ROLE_PURPOSES = (
    PURPOSE_DECISION_REQUEST,
    PURPOSE_DECISION_RESPONSE,
    PURPOSE_CONTROL,
    PURPOSE_OBSERVATION,
    PURPOSE_TRUSTED_TIME,
)


def role_conflict(purposes: Sequence[str]) -> tuple[str, ...]:
    """The role purposes among `purposes` when there is more than one of them (TP1-009), in the
    order of ROLE_PURPOSES; empty when the purposes belong to one role at most."""
    roles = tuple(purpose for purpose in ROLE_PURPOSES if purpose in purposes)
    return roles if len(roles) > 1 else ()


_COMMON_SCHEMA = "https://externalcontrollayer.ai/ns/schema/common/1"
# The public-key sizes of the suites this version of the document carries.
_KEY_BYTES = {ED25519_SUITE: 32, P256_SUITE: 65}

# Edwards25519, RFC 8032 section 5.1: -x^2 + y^2 = 1 + d * x^2 * y^2 over the integers modulo p.
_FIELD = 2**255 - 19
_EDWARDS_D = -121665 * pow(121666, -1, _FIELD) % _FIELD
_SQRT_MINUS_ONE = pow(2, (_FIELD - 1) // 4, _FIELD)
_Point = tuple[int, int]


class TrustPolicyError(ValueError):
    """A trust policy that cannot be used, or a request that it cannot answer.

    `code` is `ecl.error.schema-invalid.v1` for bytes that are not the document, and
    `ecl.error.semantic-invalid.v1` for a document, or an argument, that cannot hold.
    """

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code

    def __reduce__(self) -> tuple[Any, ...]:
        # The default would call TrustPolicyError(message) and lose the required code.
        return (_restore_error, (str(self), self.code))


def _restore_error(message: str, code: str) -> TrustPolicyError:
    return TrustPolicyError(message, code=code)


def _schema_error(message: str) -> TrustPolicyError:
    return TrustPolicyError(_cut(message), code=SCHEMA_INVALID)


def _semantic_error(message: str) -> TrustPolicyError:
    return TrustPolicyError(_cut(message), code=SEMANTIC_INVALID)


def _cut(text: str) -> str:
    """`text`, at most MAX_TEXT characters: a message must not be as large as the value it names."""
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - len(ELLIPSIS)] + ELLIPSIS


@dataclass(frozen=True)
class TrustedKey:
    """One key of a trust policy. `public_key` is raw: 32 bytes, or the 65-byte SEC1 point."""

    key_id: str
    suite_id: str
    public_key: bytes
    principal: str
    purposes: tuple[str, ...]
    valid_from: str
    valid_until: str | None


@dataclass(frozen=True)
class TrustPolicy:
    """A loaded trust policy. Make one with `load`; it cannot be changed."""

    policy_id: str
    version: str
    epoch: int
    revocation_policy: str
    keys: tuple[TrustedKey, ...]
    revocations: tuple[KeyRevocation, ...]
    digest: str

    @classmethod
    def load(cls, data: bytes) -> TrustPolicy:
        """The policy in `data`: UTF-8 strict JSON, then the schema, then the semantic checks.

        Strict JSON refuses duplicate members and numbers outside the restricted profile. Raises
        TrustPolicyError, with the code that says which layer failed, and never returns a partly
        checked policy.
        """
        document = _parse(data)
        violation = _first_violation(document)
        if violation is not None:
            raise _schema_error(
                f"the trust policy does not satisfy {TRUST_POLICY_SCHEMA}: {violation}"
            )
        _require_revocation_policy(document["revocation_policy"])
        keys = _keys(document["keys"])
        revocations = _revocations(document["revocations"], {key.key_id for key in keys})
        return cls(
            policy_id=document["policy_id"],
            version=document["version"],
            epoch=document["epoch"],
            revocation_policy=document["revocation_policy"],
            keys=keys,
            revocations=revocations,
            digest=object_digest(document),
        )

    def reference(self) -> dict[str, Any]:
        """The policy as an object embeds it: `{"id", "version", "digest", "epoch"}`."""
        return {
            "id": self.policy_id,
            "version": self.version,
            "digest": {"algorithm": DIGEST_SUITE, "value": self.digest},
            "epoch": self.epoch,
        }

    def integrity_policy(
        self, key_ids: Sequence[str], *, time_policy: str, threshold: int = 1
    ) -> dict[str, Any]:
        """The `integrity_policy` of an object that `threshold` of the keys `key_ids` must sign.

        The keys named are the eligible ones, in the order given; the accepted suites are their
        suites. The keys are required exactly when the threshold is all of them, so that a
        smaller threshold leaves the choice of signers open. `time_policy` is the object's own:
        `ecl.time.issued-at.v1` for DCMP-2 and `ecl.time.observed-at.v1` for EBMP-2. The result
        satisfies the common `integrityPolicy`. Raises TrustPolicyError for a key the policy does
        not hold or that is named twice, more than 64 eligible keys (the reference verifier budget),
        a threshold outside 1 to len(key_ids), a time policy the
        vocabulary does not allocate, and a result the schema would refuse (more than 32 required
        keys).
        """
        ids = _key_ids(key_ids)
        if isinstance(threshold, bool) or not isinstance(threshold, int):
            raise _semantic_error("threshold must be an integer")
        if not 1 <= threshold <= len(ids):
            raise _semantic_error(
                f"threshold {threshold} is outside 1 to {len(ids)}, the keys named"
            )
        chosen = [self._held(key_id) for key_id in ids]
        _require_time_policy(time_policy)
        policy = {
            "required": True,
            "accepted_suites": sorted({key.suite_id for key in chosen}),
            "eligible_key_ids": ids,
            "required_key_ids": list(ids) if threshold == len(ids) else [],
            "threshold": threshold,
            "trust_policy": self.reference(),
            "verification_time_policy": time_policy,
            "revocation_policy": self.revocation_policy,
        }
        error = next(iter(_integrity_policy_validator().iter_errors(policy)), None)
        if error is not None:
            raise _schema_error(
                f"the integrity policy would not satisfy integrityPolicy: {_describe(error)}"
            )
        return policy

    def keyring(self) -> dict[str, VerificationKey]:
        """The `integrity.verify_envelope` keyring: one verification key for each key of the policy.

        A key's purposes become the payload types it may sign (a decision request or response: the
        DCMP-2 media type; an evidence event or an observation: the EBMP-2 one) and, as
        `role_purposes`, the roles it holds; its `trust_policy_ids` become `(policy_id,)`, and its
        validity window is passed on. So `verify_envelope` keeps DCMP-2 and EBMP-2 keys apart and,
        within the DCMP-2 media type, counts a decision request only under a key that holds the
        decision-request purpose and a decision response only under one that holds the
        decision-response purpose (TP1-010). Separating an evidence event from an observation,
        both EBMP-2, is the bundle verifier's, which knows where each object sits. The approval
        purpose, which qualifies an approval service's key (EBMP2-070), gives no payload type.

        A policy from `load` cannot fail here. One built by hand raises TrustPolicyError for a key
        with no purpose (which `verify_envelope` would read as any payload type), a purpose with no
        payload type, or a public key that its suite does not accept.
        """
        return {key.key_id: _verification_key(key, self.policy_id) for key in self.keys}

    def verification_context(self, *, evaluated_at: str, time_policy: str) -> VerificationContext:
        """The context for `verify_envelope` at `evaluated_at`, under the object's own time policy.

        `time_policy` must be the one the object embeds (`ecl.time.issued-at.v1` for DCMP-2,
        `ecl.time.observed-at.v1` for EBMP-2), or the verifier refuses the envelope. The context
        carries this policy's reference, the suites of its keys, and its revocations, which the
        verifier applies at `evaluated_at`: a key is revoked at or after its `effective_at`.
        """
        _require_time_policy(time_policy)
        return VerificationContext(
            trust_policy_id=self.policy_id,
            trust_policy_version=self.version,
            trust_policy_digest=self.digest,
            trust_policy_epoch=self.epoch,
            evaluated_at=evaluated_at,
            verification_time_policy=time_policy,
            revocation_policy=self.revocation_policy,
            allowed_suites=tuple(sorted({key.suite_id for key in self.keys})),
            prohibited_suites=(),
            revocations=self.revocations,
        )

    def key(self, key_id: str) -> TrustedKey:
        """The key with this id. Raises KeyError for one the policy does not hold."""
        for key in self.keys:
            if key.key_id == key_id:
                return key
        raise KeyError(f"{key_id} is not a key of this trust policy")

    def _held(self, key_id: str) -> TrustedKey:
        try:
            return self.key(key_id)
        except KeyError:
            raise _semantic_error(f"{key_id} is not a key of this trust policy") from None


# --- Reading the document ------------------------------------------------------------------------


@cache
def _schema_validator() -> Validator:
    # validator_for builds a registry on every call. This validator is only ever read from.
    return validator_for(TRUST_POLICY_SCHEMA)


@cache
def _integrity_policy_validator() -> Validator:
    return validator_for(_COMMON_SCHEMA).evolve(
        schema={"$ref": f"{_COMMON_SCHEMA}#/$defs/integrityPolicy"}
    )


def _parse(data: bytes) -> Any:
    """The strict JSON of a trust-policy document: a declared limit is
    `ecl.error.resource-limit-exceeded.v1` (TP1-007), and any other strict refusal is
    `ecl.error.schema-invalid.v1` (TP1-002)."""
    if not isinstance(data, bytes):
        raise _schema_error("a trust policy is loaded from bytes")
    if len(data) > MAX_TRUST_POLICY_BYTES:
        raise TrustPolicyError(
            f"a trust policy is at most {MAX_TRUST_POLICY_BYTES} bytes", code=RESOURCE_LIMIT
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _schema_error("a trust policy is UTF-8 JSON, without a byte order mark") from None
    try:
        return loads_json_strict(text, max_bytes=MAX_TRUST_POLICY_BYTES)
    except CanonicalizationError as error:
        if error.finding_id == RESOURCE_LIMIT:
            raise TrustPolicyError(_cut(str(error)), code=RESOURCE_LIMIT) from error
        raise _schema_error(str(error)) from error


def _describe(error: Any) -> str:
    member = "/" + "/".join(str(part) for part in error.absolute_path)
    return f"{member}: {error.validator}: {error.message}"


def _first_violation(document: Any) -> str | None:
    """The first constraint of the schema that `document` fails, or None."""
    error = next(iter(_schema_validator().iter_errors(document)), None)
    return None if error is None else _describe(error)


def _active_ids(registry: str, attribute: str, value: str) -> frozenset[str]:
    """The active entries of a registry whose attribute has this value."""
    entries = registry_document(registry)["entries"]
    return frozenset(
        entry["id"]
        for entry in entries
        if entry["status"] == "active" and entry.get("attributes", {}).get(attribute) == value
    )


def _require_revocation_policy(revocation_policy: str) -> None:
    if revocation_policy not in _active_ids("vocabulary", "category", "revocation_policy"):
        raise _semantic_error(
            f"{revocation_policy} is not an active revocation policy of the vocabulary registry"
        )


def _require_time_policy(time_policy: str) -> None:
    if not isinstance(time_policy, str) or time_policy not in _active_ids(
        "vocabulary", "category", "verification_time_policy"
    ):
        raise _semantic_error(
            f"{time_policy!r} is not a verification-time policy of the vocabulary registry"
        )


def _keys(items: list[dict[str, Any]]) -> tuple[TrustedKey, ...]:
    suites = _active_ids("algorithm-suites", "kind", "signature")
    purposes = _active_ids("vocabulary", "category", "key_purpose")
    ids: set[str] = set()
    holders: dict[bytes, str] = {}
    keys = []
    for item in items:
        key = _key(item, suites, purposes)
        if key.key_id in ids:
            raise _semantic_error(f"key_id {key.key_id} appears twice in the trust policy")
        ids.add(key.key_id)
        if key.public_key in holders:
            raise _semantic_error(
                f"keys {holders[key.public_key]} and {key.key_id} have the same public key"
            )
        holders[key.public_key] = key.key_id
        keys.append(key)
    return tuple(keys)


def _key(item: dict[str, Any], suites: frozenset[str], purposes: frozenset[str]) -> TrustedKey:
    key_id, suite_id = item["key_id"], item["suite_id"]
    if suite_id not in suites:
        raise _semantic_error(
            f"key {key_id}: {suite_id} is not an active signature suite of the algorithm-suites registry"
        )
    raw = _decode_canonical_base64(item["public_key"])
    if raw is None:
        raise _semantic_error(f"key {key_id}: public_key is not canonical standard base64")
    try:
        _public_key(suite_id, raw)
    except ValueError as error:
        raise _semantic_error(f"key {key_id}: {error}") from None
    for purpose in item["purposes"]:
        if purpose not in purposes:
            raise _semantic_error(
                f"key {key_id}: {purpose} is not an active key purpose of the vocabulary registry"
            )
        if purpose not in PURPOSE_PAYLOAD_TYPES and purpose not in QUALIFYING_PURPOSES:
            raise _semantic_error(f"key {key_id}: {purpose} has no payload type in this library")
    if not any(purpose in PURPOSE_PAYLOAD_TYPES for purpose in item["purposes"]):
        raise _semantic_error(
            f"key {key_id}: carries no purpose that signs a payload type, only a qualifying one"
        )
    roles = role_conflict(item["purposes"])
    if roles:
        raise _semantic_error(
            f"key {key_id}: one key carries the purposes of more than one role: "
            + ", ".join(roles)
            + " (TP1-009)"
        )
    valid_from, valid_until = item["valid_from"], item.get("valid_until")
    if valid_until is not None and _instant(valid_until) <= _instant(valid_from):
        raise _semantic_error(f"key {key_id}: valid_until must be later than valid_from")
    return TrustedKey(
        key_id=key_id,
        suite_id=suite_id,
        public_key=raw,
        principal=item["principal"],
        purposes=tuple(item["purposes"]),
        valid_from=valid_from,
        valid_until=valid_until,
    )


def _revocations(items: list[dict[str, Any]], held: set[str]) -> tuple[KeyRevocation, ...]:
    revoked: set[str] = set()
    for item in items:
        key_id = item["key_id"]
        if key_id not in held:
            raise _semantic_error(f"revocation names {key_id}, which is not a key of this policy")
        if key_id in revoked:
            raise _semantic_error(f"revocation of {key_id} appears twice in the trust policy")
        revoked.add(key_id)
    return tuple(
        KeyRevocation(item["key_id"], item["effective_at"], item["reason"]) for item in items
    )


def _decode_canonical_base64(text: str) -> bytes | None:
    """The bytes of standard base64 with padding and no other form, or None."""
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        return None
    return raw if base64.b64encode(raw).decode("ascii") == text else None


def _instant(text: str) -> datetime:
    # The schema has fixed the form: whole seconds or three or six digits, then Z.
    return parse_rfc3339_utc(text)


def _decode_ed25519(raw: bytes) -> _Point:
    """The point that `raw` encodes, as RFC 8032 section 5.1.3 decodes it.

    Raises ValueError, saying why, when it encodes none: y is not below p (the encoding is not
    canonical), no x fits y, or x is 0 with the sign bit set.
    """
    value = int.from_bytes(raw, "little")
    sign, y = value >> 255, value & (2**255 - 1)
    if y >= _FIELD:
        raise ValueError("the public key is not a canonical Ed25519 encoding: y is not below p")
    # x^2 = (y^2 - 1) / (d * y^2 + 1). The denominator is never 0, because d is not a square.
    x2 = (y * y - 1) * pow(_EDWARDS_D * y * y + 1, -1, _FIELD) % _FIELD
    x = pow(x2, (_FIELD + 3) // 8, _FIELD)
    if (x * x - x2) % _FIELD:
        x = x * _SQRT_MINUS_ONE % _FIELD
    if (x * x - x2) % _FIELD:
        raise ValueError("the public key is not a point on Ed25519")
    if x == 0 and sign:
        raise ValueError("the public key is not a point on Ed25519: x is 0 and the sign bit is 1")
    return (_FIELD - x if x & 1 != sign else x), y


def _edwards_add(a: _Point, b: _Point) -> _Point:
    """a + b on Ed25519 in affine coordinates. The formula is complete for points on the curve."""
    (x1, y1), (x2, y2) = a, b
    product = _EDWARDS_D * x1 * x2 % _FIELD * y1 % _FIELD * y2 % _FIELD
    x3 = (x1 * y2 + x2 * y1) * pow(1 + product, -1, _FIELD) % _FIELD
    y3 = (y1 * y2 + x1 * x2) * pow(1 - product, -1, _FIELD) % _FIELD
    return x3, y3


def _has_small_order(point: _Point) -> bool:
    """True if 8 times `point` is the identity, that is, if its order divides the cofactor 8."""
    for _ in range(3):
        point = _edwards_add(point, point)
    return point == (0, 1)


@lru_cache(maxsize=1024)
def _require_ed25519_point(raw: bytes) -> None:
    """Raise ValueError unless `raw` encodes a point of Ed25519 whose order is large.

    A key that passes is remembered: `keyring` asks about every key each time it is called, and the
    answer depends on the 32 bytes alone.
    """
    if _has_small_order(_decode_ed25519(raw)):
        raise ValueError(
            "the public key is a point of small order on Ed25519: a signature made without a "
            "private key verifies under it"
        )


def _public_key(suite_id: str, raw: bytes) -> Ed25519PublicKey | ec.EllipticCurvePublicKey:
    """The key that `raw` encodes under `suite_id`. Raises ValueError, saying why, if none.

    An Ed25519 key of small order is refused: a signature made without any private key verifies
    under it, for every message. (P-256 has cofactor 1, so a point on that curve has large order.)
    """
    size = _KEY_BYTES.get(suite_id)
    if size is None:
        raise ValueError(
            f"{suite_id} is not supported by trust policy v1 (Ed25519 and ECDSA P-256)"
        )
    if len(raw) != size:
        raise ValueError(f"a public key for {suite_id} is {size} bytes, not {len(raw)}")
    if suite_id == ED25519_SUITE:
        _require_ed25519_point(raw)
        return Ed25519PublicKey.from_public_bytes(raw)
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError:
        raise ValueError("the public key is not a point on P-256") from None


# --- Using a loaded policy -----------------------------------------------------------------------


def _key_ids(key_ids: Sequence[str]) -> list[str]:
    if isinstance(key_ids, str) or not isinstance(key_ids, Sequence):
        raise _semantic_error("key_ids must be a sequence of key identifiers")
    ids = list(key_ids)
    if not ids:
        raise _semantic_error("an integrity policy needs at least one key")
    if len(ids) > 64:
        raise _semantic_error("an integrity policy selects at most 64 eligible keys")
    if not all(isinstance(key_id, str) for key_id in ids):
        raise _semantic_error("key identifiers must be strings")
    if len(set(ids)) != len(ids):
        raise _semantic_error("a key identifier is named more than once")
    return ids


def _verification_key(key: TrustedKey, policy_id: str) -> VerificationKey:
    if not key.purposes:
        raise _semantic_error(
            f"key {key.key_id} has no purpose, and a verification key without one signs any payload type"
        )
    payload_types = set()
    for purpose in key.purposes:
        if purpose in QUALIFYING_PURPOSES:
            # A qualifying purpose (the approval purpose) lets the key sign no payload by itself.
            continue
        if purpose not in PURPOSE_PAYLOAD_TYPES:
            raise _semantic_error(
                f"key {key.key_id}: {purpose} has no payload type in this library"
            )
        payload_types.add(PURPOSE_PAYLOAD_TYPES[purpose])
    if not payload_types:
        raise _semantic_error(
            f"key {key.key_id}: carries no purpose that signs a payload type, only a qualifying one"
        )
    try:
        public_key = _public_key(key.suite_id, key.public_key)
    except ValueError as error:
        raise _semantic_error(f"key {key.key_id}: {error}") from None
    return VerificationKey(
        key_id=key.key_id,
        suite_id=key.suite_id,
        public_key=public_key,
        trust_policy_ids=(policy_id,),
        purposes=tuple(sorted(payload_types)),
        valid_from=key.valid_from,
        valid_until=key.valid_until,
        role_purposes=tuple(sorted(key.purposes)),
    )
