"""Offline verification checks and read-only metadata for bindings.oauth."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ecl_verify.canonical import same_json
from ecl_verify.semantic import Finding

from . import jose
from .common import (
    array,
    binds,
    digest_of,
    findings,
    instant,
    integer,
    member,
    obj,
    same_digest,
    text,
)

PRESENTATION_VERSION = "ecl_oauth_presentation_v1"

PRESENTATION_SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/oauth-presentation/1"

DETAILS_TYPE = "https://externalcontrollayer.ai/ns/authorization-details/action/1"

DEFAULT_MAX_LIFETIME = 300

DEFAULT_PROOF_WINDOW = 60

MAX_JTI_CHARACTERS = 256

TOKEN_STRING_CLAIMS = ("client_id", "iss", "jti")

DEFAULT_CLOCK_SKEW = 0

_NANOSECONDS = 1_000_000_000

AUDIENCE_MISMATCH = "ecl.error.audience-mismatch.v1"

SCOPE_MISMATCH = "ecl.error.scope-mismatch.v1"

EXPIRED = "ecl.error.expired.v1"

REPLAY = "ecl.error.replay.v1"

INTEGRITY_INVALID = "ecl.error.integrity-invalid.v1"

NO_AUTHORITY = "ecl.error.no-authority.v1"

ISSUE_RULE = "ecl.rule.oauth-token-expresses-admit.v1"

SIGNATURE_RULE = "ecl.rule.oauth-token-signature-checked.v1"

PRESENTATION_RULE = "ecl.rule.oauth-presentation-checked.v1"

REFUSAL_RULE = "ecl.rule.oauth-refusal-named.v1"

RULES = (ISSUE_RULE, SIGNATURE_RULE, PRESENTATION_RULE, REFUSAL_RULE)


def _expected_authorization_details(
    request: Mapping[str, Any], response: Mapping[str, Any], *, with_decision: bool = True
) -> dict[str, Any]:
    """The ECL `authorization_details` entry for an admit, as the profile's entry table gives."""
    authorization = response["authorization"]
    action = request["action"]
    entry: dict[str, Any] = {
        "type": DETAILS_TYPE,
        "locations": [authorization["audience"]],
        "actions": [action["operation"]],
        "identifier": action["target"]["uri"],
        "authorization_id": authorization["authorization_id"],
        "request_id": request["message_id"],
        "action_id": action["action_id"],
        "action_class": action["action_class"],
        "scope_digest": dict(authorization["scope_digest"]),
        "parameters_digest": dict(action["parameters_digest"]),
        "use_policy": authorization["use_policy"],
        "valid_from": authorization["valid_from"],
        "valid_until": authorization["valid_until"],
    }
    if "max_uses" in authorization:
        entry["max_uses"] = authorization["max_uses"]
    if with_decision:
        entry["decision"] = {"uri": response["message_id"], "digest": digest_of(dict(response))}
    return entry


def subject_and_actor(request: Mapping[str, Any]) -> tuple[str, str | None]:
    """`sub`, and `act.sub` when the subject differs from the actor (OA1-006)."""
    actor = str(member(request, "actor", "id"))
    subject = text(request, "subject", "id")
    if subject is None or subject == actor:
        return actor, None
    return subject, actor


def token_reference_digest(token: str) -> dict[str, str]:
    """The digest an admit's `authorization.token_reference` carries for its token (OA1-008)."""
    return {
        "algorithm": "ecl.digest.sha-256.v1",
        "value": hashlib.sha256(token.encode("ascii")).hexdigest(),
    }


def _entries(claims: Mapping[str, Any]) -> list[Any]:
    return [
        item
        for item in array(claims, "authorization_details")
        if text(item, "type") == DETAILS_TYPE
    ]


def issue_problems(
    request: Mapping[str, Any], response: Mapping[str, Any], token: str, *, max_lifetime: int
) -> list[tuple[str, str]]:
    """(path, message) for each way a token fails to express its admit (issuer side)."""
    if response.get("outcome") != "admit" or not binds(request, response):
        return [("/token", "the token was issued for something other than a verified admit")]
    if response.get("obligations") != []:
        return [("/response/obligations", "OAuth profile 1.0 cannot carry obligations")]
    try:
        _, claims, _, _ = jose.decode(token)
    except jose.JoseError:
        return [("/token", "the token is not a compact JWS")]
    problems: list[tuple[str, str]] = []
    entries = _entries(claims)
    expected = _expected_authorization_details(request, response, with_decision=False)
    if len(entries) != 1:
        problems.append(("/token/authorization_details", "not exactly one ECL entry"))
    else:
        entry = dict(entries[0])
        # The entry may name the decision; a `decision` of null is present and names none, so it
        # is not taken for an entry without one.
        named = "decision" in entry
        decision = entry.pop("decision", None)
        # OA1-001: the entry's members are the admit's as the same JSON values, so `true` is not a
        # `max_uses` of 1.
        if not same_json(entry, expected):
            problems.append(("/token/authorization_details", "the entry is not the admit's"))
        if named and decision != {
            "uri": response.get("message_id"),
            "digest": digest_of(dict(response)),
        }:
            problems.append(("/token/authorization_details", "the entry names another decision"))
    if claims.get("aud") != member(response, "authorization", "audience"):
        problems.append(("/token/aud", "not the authorization's audience as a single value"))
    start = instant(member(response, "authorization", "valid_from"))
    end = instant(member(response, "authorization", "valid_until"))
    issued, begins, expires = (
        claims.get("iat"),
        claims.get("nbf", claims.get("iat")),
        claims.get("exp"),
    )
    if (
        type(issued) is not int
        or type(begins) is not int
        or type(expires) is not int
        or start is None
        or end is None
        or begins * _NANOSECONDS < start
        or expires * _NANOSECONDS > end
        or not 0 < expires - issued <= max_lifetime
    ):
        problems.append(("/token/exp", "the token's validity is not inside the window and bound"))
    subject, actor = subject_and_actor(request)
    if claims.get("sub") != subject or (
        actor is not None and member(claims, "act", "sub") != actor
    ):
        problems.append(("/token/act", "the subject and actor are not the request's"))
    confirmation = claims.get("cnf")
    # OA1-004: one key, named by a string; a `jkt` or `x5t#S256` of null names no key.
    if (
        type(confirmation) is not dict
        or set(confirmation) not in ({"jkt"}, {"x5t#S256"})
        or any(type(value) is not str for value in confirmation.values())
    ):
        problems.append(("/token/cnf", "the token is not sender-constrained by one key"))
    reference = member(response, "authorization", "token_reference", "digest")
    if reference is not None and not same_digest(reference, token_reference_digest(token)):
        problems.append(("/token", "the admit's token_reference names another token"))
    # OA1-001: the token is a JWT access token of RFC 9068, whose Section 2.2 requires `iss`,
    # `client_id` and `jti`, each a string (RFC 7519, Sections 4.1.1 and 4.1.7; RFC 8693,
    # Section 4.3) (H10).
    problems.extend(
        (f"/token/{name}", f"the token carries no {name} string, which RFC 9068 requires")
        for name in TOKEN_STRING_CLAIMS
        if type(claims.get(name)) is not str
    )
    return problems


def signature_problems(
    token: str, keys: Mapping[str, Mapping[str, Any]], issuer: object
) -> list[tuple[str, str]]:
    """(path, message) when a resource server should refuse the token's JWS (OA1-007)."""
    try:
        _, claims = jose.verify(token, keys)
    except jose.JoseError as error:
        return [("/token", f"the token fails the {error.reason} check")]
    if claims.get("iss") != issuer:
        return [("/token/iss", "the token's issuer is not the configured one")]
    return []


def _htu(uri: str) -> str | None:
    """The request URI without its query and fragment (RFC 9449, Section 4.3), or None when the
    URI cannot be split."""
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def presentation_problems(record: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """(path, message, error code) for each reason a resource server must refuse the presentation
    (OA1-002 to OA1-005), in the order a resource server checks them."""
    token = text(record, "token") or ""
    try:
        _, claims, _, _ = jose.decode(token)
    except jose.JoseError:
        return [("/token", "the token is not a compact JWS", INTEGRITY_INVALID)]
    presentation = obj(record, "presentation") or {}
    problems: list[tuple[str, str, str]] = []
    if claims.get("aud") != record.get("resource_server"):
        problems.append(("/token/aud", "the token is for another audience", AUDIENCE_MISMATCH))
    presented = instant(presentation.get("presented_at"))
    entries = _entries(claims)
    entry = entries[0] if len(entries) == 1 else {}
    if not _within_validity(record, claims, entries, presented):
        problems.append(("/presentation/presented_at", "outside the token's validity", EXPIRED))
    problems += _possession(record, claims, token, presentation, presented)
    if (
        presentation.get("target") != entry.get("identifier")
        or presentation.get("operation") not in array(entry, "actions")
        or not same_digest(presentation.get("parameters_digest"), entry.get("parameters_digest"))
    ):
        problems.append(
            ("/presentation", "another target, operation or parameter digest", SCOPE_MISMATCH)
        )
    limit = 1 if entry.get("use_policy") == "single_use" else integer(entry, "max_uses")
    used = integer(presentation, "use_count")
    if used is None or (limit is not None and used > limit):
        problems.append(("/presentation/use_count", "beyond the entry's use policy", REPLAY))
    return problems


def _within_validity(
    record: Mapping[str, Any], claims: Mapping[str, Any], entries: list[Any], presented: int | None
) -> bool:
    """OA1-003: the time of presentation lies within the token's validity, widened by the declared
    clock-skew allowance, and, when the token carries one ECL entry, within that entry's window,
    to which no allowance applies."""
    skew = integer(record, "clock_skew_seconds") or DEFAULT_CLOCK_SKEW
    begins, expires = claims.get("nbf", claims.get("iat")), claims.get("exp")
    if presented is None or type(begins) is not int or type(expires) is not int:
        return False
    if not (begins - skew) * _NANOSECONDS <= presented < (expires + skew) * _NANOSECONDS:
        return False
    if len(entries) != 1:
        return True
    start = instant(member(entries[0], "valid_from"))
    end = instant(member(entries[0], "valid_until"))
    return start is not None and end is not None and start <= presented < end


def refusal_problems(record: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """(path, message, code) of each check of the presentation table that the presentation fails,
    in the table's order (OA1-011): the token's JWS checks (OA1-007), then the resource server's
    checks of audience, validity, proof of possession, scope and uses."""
    token = text(record, "token") or ""
    signature = signature_problems(token, _issuer_keys(record), record.get("issuer"))
    if signature:
        return [(path, message, INTEGRITY_INVALID) for path, message in signature]
    return presentation_problems(record)


def _refusal(record: Mapping[str, Any]) -> list[tuple[str, str]]:
    """A refusal names the code of the first check of the presentation table that fails; a refusal
    of a presentation that fails no check may name any registered error."""
    problems = refusal_problems(record)
    if not problems:
        return []
    expected = problems[0][2]
    named = member(record, "result", "error")
    if named != expected:
        return [("/result/error", f"the first check that fails gives {expected}")]
    return []


def _issuer_keys(record: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(item.get("kid")): item
        for item in array(record, "issuer_keys", "keys")
        if type(item) is dict and type(item.get("kid")) is str
    }


def _possession(
    record: Mapping[str, Any],
    claims: Mapping[str, Any],
    token: str,
    presentation: Mapping[str, Any],
    presented: int | None,
) -> list[tuple[str, str, str]]:
    confirmation = obj(claims, "cnf") or {}
    if "x5t#S256" in confirmation:
        # The bound thumbprint is a string: a null one is not matched by a presentation that
        # carries no client certificate.
        bound = confirmation["x5t#S256"]
        if type(bound) is not str or presentation.get("client_certificate_sha256") != bound:
            return [
                ("/presentation", "the client certificate is not the bound one", INTEGRITY_INVALID)
            ]
        return []
    proof = presentation.get("dpop_proof")
    if "jkt" not in confirmation or type(proof) is not str:
        return [("/presentation/dpop_proof", "no proof of possession", INTEGRITY_INVALID)]
    try:
        _, proof_claims, key = jose.verify_dpop(proof)
    except jose.JoseError as error:
        return [
            (
                "/presentation/dpop_proof",
                f"the proof fails the {error.reason} check",
                INTEGRITY_INVALID,
            )
        ]
    problems: list[tuple[str, str, str]] = []
    window = integer(record, "dpop_proof_window_seconds") or DEFAULT_PROOF_WINDOW
    issued = proof_claims.get("iat")
    method, uri = presentation.get("method"), presentation.get("uri")
    target_uri = _htu(uri) if type(uri) is str else None
    if (
        key != confirmation["jkt"]
        or proof_claims.get("htm") != method
        or target_uri is None
        or proof_claims.get("htu") != target_uri
        or proof_claims.get("ath") != jose.token_hash(token)
        or type(issued) is not int
        or presented is None
        or abs(presented - issued * _NANOSECONDS) > window * _NANOSECONDS
    ):
        problems.append(
            ("/presentation/dpop_proof", "the proof does not bind this request", INTEGRITY_INVALID)
        )
    # OA1-004: the proof's `jti` is a string of 1 to 256 characters that the resource server has
    # not accepted; a proof without one, with one of another type or with one that no
    # presentation record can hold among the `jti` values seen cannot be checked for
    # replay.
    jti = proof_claims.get("jti")
    if type(jti) is not str or not 1 <= len(jti) <= MAX_JTI_CHARACTERS:
        problems.append(
            (
                "/presentation/dpop_proof",
                "the proof carries no jti string of 1 to 256 characters",
                INTEGRITY_INVALID,
            )
        )
    elif jti in array(presentation, "seen_dpop_jti"):
        problems.append(("/presentation/dpop_proof", "the proof's jti was seen before", REPLAY))
    return problems


def check(record: Mapping[str, Any]) -> list[Finding]:
    """The findings of an `ecl_oauth_presentation_v1` record that its schema has accepted."""
    request, response, token = (
        obj(record, "request"),
        obj(record, "response"),
        text(record, "token"),
    )
    if request is None or response is None or token is None:
        return []
    max_lifetime = integer(record, "max_token_lifetime_seconds") or DEFAULT_MAX_LIFETIME
    result = findings(
        ISSUE_RULE, issue_problems(request, response, token, max_lifetime=max_lifetime)
    )
    accepted = member(record, "result", "accepted")
    if accepted is False:
        return result + findings(REFUSAL_RULE, _refusal(record))
    if accepted is not True:
        return result
    keys = _issuer_keys(record)
    result += findings(SIGNATURE_RULE, signature_problems(token, keys, record.get("issuer")))
    result += findings(
        PRESENTATION_RULE, [(path, message) for path, message, _ in presentation_problems(record)]
    )
    return result
