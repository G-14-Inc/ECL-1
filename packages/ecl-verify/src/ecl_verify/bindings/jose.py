"""Offline verification checks and read-only metadata for bindings.jose."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)

from ecl_verify.canonical import CanonicalizationError, loads_json_strict

ES256 = "ES256"

EDDSA = "EdDSA"

ALGORITHMS = frozenset({ES256, EDDSA})

ACCESS_TYPE = "at+jwt"

DPOP_TYPE = "dpop+jwt"

KEY_HEADERS = frozenset({"jwk", "jku", "x5u", "x5c"})

MAX_TOKEN_BYTES = 16 * 1024

_P256_COORDINATE = 32

_ED25519_KEY = 32

_ES256_SIGNATURE = 64

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class JoseError(ValueError):
    """A token, proof or key is malformed or does not verify. `reason` names the check."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def b64url(data: bytes) -> str:
    """Base64url without padding (RFC 7515 section 2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """The bytes of unpadded base64url text, refusing any other alphabet or a non-canonical tail."""
    if not _BASE64URL.match(text) or len(text) % 4 == 1:
        raise JoseError("malformed", "the text is not unpadded base64url")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as error:
        raise JoseError("malformed", "the text is not unpadded base64url") from error
    if b64url(data) != text:
        raise JoseError("malformed", "the base64url text is not in canonical form")
    return data


def compact_json(value: Mapping[str, Any]) -> bytes:
    """The JSON text this module signs: sorted member names, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def thumbprint(jwk: Mapping[str, Any]) -> str:
    """The RFC 7638 SHA-256 thumbprint of a public P-256 or Ed25519 JWK, in base64url."""
    kty = jwk.get("kty")
    names = ("crv", "kty", "x", "y") if kty == "EC" else ("crv", "kty", "x")
    if kty not in ("EC", "OKP") or not all(type(jwk.get(name)) is str for name in names):
        raise JoseError("key", "a thumbprint needs an EC or OKP public key with its members")
    required = {name: jwk[name] for name in names}
    return b64url(hashlib.sha256(compact_json(required)).digest())


def _coordinate(jwk: Mapping[str, Any], name: str, size: int) -> bytes:
    value = jwk.get(name)
    data = b64url_decode(value) if type(value) is str else b""
    if len(data) != size:
        raise JoseError("key", f"the JWK member {name} is not {size} bytes of base64url")
    return data


def _public_key(jwk: Mapping[str, Any]) -> ec.EllipticCurvePublicKey | Ed25519PublicKey:
    if "d" in jwk:
        raise JoseError("key", "a verification key must not carry private key material")
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        point = b"\x04" + _coordinate(jwk, "x", _P256_COORDINATE)
        point += _coordinate(jwk, "y", _P256_COORDINATE)
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        except ValueError as error:
            raise JoseError("key", "the JWK is not a point on P-256") from error
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        return Ed25519PublicKey.from_public_bytes(_coordinate(jwk, "x", _ED25519_KEY))
    raise JoseError("key", "the JWK is neither a P-256 nor an Ed25519 public key")


def _verify_signature(
    algorithm: str, jwk: Mapping[str, Any], signing_input: bytes, signature: bytes
) -> None:
    key = _public_key(jwk)
    try:
        if algorithm == ES256 and isinstance(key, ec.EllipticCurvePublicKey):
            if len(signature) != _ES256_SIGNATURE:
                raise JoseError("signature", "an ES256 signature is not 64 bytes")
            r = int.from_bytes(signature[:_P256_COORDINATE], "big")
            s = int.from_bytes(signature[_P256_COORDINATE:], "big")
            key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
            return
        if algorithm == EDDSA and isinstance(key, Ed25519PublicKey):
            key.verify(signature, signing_input)
            return
    except InvalidSignature as error:
        raise JoseError("signature", "the signature does not verify") from error
    raise JoseError("algorithm", "the algorithm does not match the key type")


def _object(segment: str) -> dict[str, Any]:
    """The JSON object of one segment, read under the strict JSON profile (IE1-002, OA1-007)."""
    try:
        value = loads_json_strict(b64url_decode(segment))
    except CanonicalizationError as error:
        reason = (
            "a JWS segment repeats a member name"
            if "duplicate" in str(error)
            else "a JWS segment is not strict JSON"
        )
        raise JoseError("malformed", reason) from error
    if type(value) is not dict:
        raise JoseError("malformed", "a JWS segment is not a JSON object")
    return value


def decode(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """The header, the claims, the signing input and the signature of a compact JWS, unverified."""
    if type(token) is not str or len(token) > MAX_TOKEN_BYTES:
        raise JoseError("malformed", "the token is not a compact JWS within the size limit")
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError("malformed", "a compact JWS has three segments")
    header, claims = _object(parts[0]), _object(parts[1])
    signature = b64url_decode(parts[2])
    return header, claims, (parts[0] + "." + parts[1]).encode("ascii"), signature


def _checked_header(header: Mapping[str, Any], expected_type: str) -> str:
    algorithm = header.get("alg")
    if type(algorithm) is not str or algorithm not in ALGORITHMS:
        raise JoseError("algorithm", "the algorithm is not in the declared asymmetric set")
    if header.get("typ") != expected_type:
        raise JoseError("type", f"the header's typ is not {expected_type}")
    if "crit" in header:
        raise JoseError("crit", "the header has a crit member this verifier does not understand")
    return str(algorithm)


def verify(
    token: str, keys: Mapping[str, Mapping[str, Any]], *, expected_type: str = ACCESS_TYPE
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The header and claims of a token signed by one of `keys` (by `kid`), after every check."""
    header, claims, signing_input, signature = decode(token)
    algorithm = _checked_header(header, expected_type)
    if KEY_HEADERS & set(header):
        raise JoseError("key-header", "the header carries or points to a key")
    key = keys.get(str(header.get("kid"))) if type(header.get("kid")) is str else None
    if key is None:
        raise JoseError("kid", "the header names no configured key")
    _verify_signature(algorithm, key, signing_input, signature)
    return header, claims


def verify_dpop(proof: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    """The header, claims and key thumbprint of a DPoP proof checked with the key it carries."""
    header, claims, signing_input, signature = decode(proof)
    algorithm = _checked_header(header, DPOP_TYPE)
    jwk = header.get("jwk")
    if type(jwk) is not dict or {"jku", "x5u", "x5c"} & set(header):
        raise JoseError("key-header", "a DPoP proof carries exactly its public key in jwk")
    _verify_signature(algorithm, jwk, signing_input, signature)
    return header, claims, thumbprint(jwk)


def token_hash(token: str) -> str:
    """The `ath` of RFC 9449: base64url SHA-256 of the token's ASCII bytes."""
    return b64url(hashlib.sha256(token.encode("ascii")).digest())


def certificate_thumbprint(der: bytes) -> str:
    """The `x5t#S256` of RFC 8705: base64url SHA-256 of the DER certificate."""
    return b64url(hashlib.sha256(der).digest())
