"""Offline verification checks and read-only metadata for bindings.common."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ecl_verify.binding import BindingError, check_response_binding
from ecl_verify.canonical import CanonicalizationError, object_digest, same_json
from ecl_verify.decision_basis_checks import input_key, request_problems, response_one_way_problems
from ecl_verify.schema import rfc3339_utc_nanoseconds
from ecl_verify.semantic import Finding

from . import jcs

SCHEMA_INVALID = "ecl.error.schema-invalid.v1"

DIGEST_SUITE = "ecl.digest.sha-256.v1"

ENCODED = "rfc8785"

MODIFICATION_OF = "ecl.relation.modification-of.v1"

RESPONDS_TO = "ecl.relation.responds-to.v1"

RECEIPT_PREFIX = "https://externalcontrollayer.ai/ns/receipt/sha256/"

OUTCOMES = ("admit", "deny", "hold", "challenge")

NO_EFFECT_SAFE_STATES = frozenset(
    {
        "ecl.state.fail-closed.v1",
        "ecl.state.quarantine.v1",
        "ecl.state.emergency-halt.v1",
        "ecl.state.restricted.v1",
    }
)

INPUT_CLASSES = ("verifiable", "actor_supplied", "judgment")

DECISION_BASIS = "ecl.ext.decision-basis.v1"

ONE_WAY_RULE = "ecl.rule.decision-basis-one-way.v1"


def member(value: object, *path: str) -> object:
    """The member at `path` of nested JSON objects, or None when a step is not there."""
    found = value
    for step in path:
        if type(found) is not dict or step not in found:
            return None
        found = found[step]
    return found


def text(value: object, *path: str) -> str | None:
    found = member(value, *path)
    return found if type(found) is str else None


def integer(value: object, *path: str) -> int | None:
    found = member(value, *path)
    return found if type(found) is int else None


def obj(value: object, *path: str) -> dict[str, Any] | None:
    found = member(value, *path)
    return found if type(found) is dict else None


def array(value: object, *path: str) -> list[Any]:
    found = member(value, *path)
    return found if type(found) is list else []


def instant(value: object) -> int | None:
    """An ECL instant in nanoseconds since the epoch, or None when it is not one."""
    try:
        return rfc3339_utc_nanoseconds(value)
    except ValueError:
        return None


def digest_of(value: object) -> dict[str, str] | None:
    """The `ecl.digest.sha-256.v1` digest of the restricted canonical JSON of `value` (IE1-001),
    or None when `value` is outside that profile."""
    try:
        return {"algorithm": DIGEST_SUITE, "value": object_digest(value)}
    except (CanonicalizationError, TypeError, ValueError, RecursionError):
        return None


class ContentError(ValueError):
    """A record member in the encoded form of MG1-012 that does not decode as that form requires."""


def is_encoded(value: object) -> bool:
    """`value` has the shape of the encoded form: an object whose only member is `rfc8785`."""
    return type(value) is dict and set(value) == {ENCODED}


def decode_content(value: object) -> Any:
    """The content that a record member holds: the member itself, or what its encoded form
    decodes to. An encoded member decodes only when its text is canonical base64, its bytes are
    the RFC 8785 canonical form of a JSON object, and that object lies outside the restricted
    profile, since content within the profile is held as itself; otherwise ContentError."""
    if not is_encoded(value):
        return value
    text_value = value[ENCODED]  # type: ignore[index]
    if type(text_value) is not str:
        raise ContentError("the encoded content is not a string")
    try:
        data = base64.b64decode(text_value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ContentError("the encoded content is not base64") from error
    if base64.b64encode(data).decode("ascii") != text_value:
        raise ContentError("the encoded content is not canonical base64")
    try:
        content = jcs.loads(data)
        canonical = jcs.canonicalize(content)
    except jcs.JcsError as error:
        raise ContentError("the encoded bytes are not I-JSON with an RFC 8785 form") from error
    if canonical != data:
        raise ContentError("the encoded bytes are not the RFC 8785 canonical form of the content")
    if type(content) is not dict:
        raise ContentError("the encoded content is not a JSON object")
    if digest_of(content) is not None:
        raise ContentError("content within the restricted profile is held as itself")
    return content


def decoded_record(
    record: Mapping[str, Any], paths: Iterable[tuple[str, ...]]
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """A copy of `record` with the member at each of `paths` replaced by the content it holds,
    and (path, message) for each member whose encoded form does not decode (MG1-012)."""
    result = dict(record)
    problems: list[tuple[str, str]] = []
    for path in paths:
        parent: Any = result
        for step in path[:-1]:
            found = parent.get(step) if type(parent) is dict else None
            if type(found) is not dict:
                parent = None
                break
            copied = dict(found)
            parent[step] = copied
            parent = copied
        if type(parent) is not dict or path[-1] not in parent:
            continue
        try:
            parent[path[-1]] = decode_content(parent[path[-1]])
        except ContentError as error:
            problems.append(("/" + "/".join(path), str(error)))
    return result, problems


def same_digest(left: object, right: object) -> bool:
    """Two digest objects name the same algorithm and value, and both are digest objects."""
    return (
        type(left) is dict
        and type(right) is dict
        and text(left, "algorithm") is not None
        and text(left, "value") is not None
        and text(left, "algorithm") == text(right, "algorithm")
        and text(left, "value") == text(right, "value")
    )


def binds(request: object, response: object) -> bool:
    """`response` is bound to `request` under DCMP2-044 to DCMP2-050 (binding.py)."""
    if type(request) is not dict or type(response) is not dict:
        return False
    try:
        check_response_binding(request, response)
    except BindingError:
        return False
    return True


def extension_values(value: object, identifier: str) -> list[dict[str, Any]]:
    """The values of the extensions with this identifier that `value` carries."""
    return [
        item["value"]
        for item in array(value, "extensions")
        if type(item) is dict and item.get("id") == identifier and type(item.get("value")) is dict
    ]


def extension_entries(value: object, identifier: str) -> list[dict[str, Any]]:
    """The whole extension entries with this identifier, with their `critical` flags."""
    return [
        item
        for item in array(value, "extensions")
        if type(item) is dict and item.get("id") == identifier
    ]


@dataclass(frozen=True)
class Exchange:
    """A decision request of a record and the response to it, if the record has one."""

    request: dict[str, Any]
    response: dict[str, Any] | None

    @property
    def request_id(self) -> str | None:
        return text(self.request, "message_id")

    @property
    def outcome(self) -> str | None:
        return text(self.response, "outcome")

    def admits(self) -> bool:
        return self.outcome == "admit" and binds(self.request, self.response)


def exchanges(record: Mapping[str, Any], *pairs: tuple[str, str]) -> list[Exchange]:
    """The (request, response) pairs that the record holds under the given member names."""
    found: list[Exchange] = []
    for request_name, response_name in pairs:
        request = obj(record, request_name)
        if request is not None:
            found.append(Exchange(request, obj(record, response_name)))
    return found


def release_problems(release: object, candidates: Iterable[Exchange]) -> list[tuple[str, str]]:
    """(path, message) for each reason a recorded release is not one an admit authorized.

    A release names the request it went ahead under, the parameters digest it released and its
    time. The request must be one the record holds; its response must admit and be bound to it;
    the digest must be the request's; and the time must lie in the authorization's window,
    from `valid_from` until before `valid_until`.
    """
    if release is None:
        return []
    if type(release) is not dict:
        return [("/release", "the release record is not an object")]
    named = text(release, "request_id")
    exchange = next((item for item in candidates if item.request_id == named), None)
    if exchange is None:
        return [("/release/request_id", "the release names no decision request of the record")]
    if exchange.response is None or exchange.outcome != "admit":
        return [("/release/request_id", "the action was released without an admit")]
    if not binds(exchange.request, exchange.response):
        return [("/release/request_id", "the admit is not bound to the exact request")]
    problems: list[tuple[str, str]] = []
    if not same_digest(
        member(release, "parameters_digest"),
        member(exchange.request, "action", "parameters_digest"),
    ):
        problems.append(
            ("/release/parameters_digest", "the released parameters are not the admitted ones")
        )
    released = instant(member(release, "released_at"))
    start = instant(member(exchange.response, "authorization", "valid_from"))
    end = instant(member(exchange.response, "authorization", "valid_until"))
    if released is None or start is None or end is None or not start <= released < end:
        problems.append(
            ("/release/released_at", "the release lies outside the authorization's window")
        )
    return problems


UNCHANGED_BY_MODIFICATION = (
    "issuer",
    "actor",
    "subject",
    "delegation_chain",
    "authority_request",
    "constraints",
    "integrity_policy",
)

CHANGED_IN_MODIFIED_ACTION = frozenset({"action_id", "parameters", "parameters_digest"})


def modification_problems(
    original: Mapping[str, Any], modified: object, parameters: object
) -> list[tuple[str, str]]:
    """(member, message) for each way `modified` is not the new request for a modification.

    The new request (AB1-004, AC1-005) has its own message_id; it carries `parameters` as
    `action.parameters`, as the same JSON values (`same_json`, so a boolean never stands for a
    number), with their digest; it names the original request as a causal
    predecessor by id and digest with the relation `ecl.relation.modification-of.v1`; and it
    describes the original's action: it keeps the original's `issuer`, `actor`, `subject`,
    `delegation_chain`, `authority_request`, `constraints` and `integrity_policy`, and every
    member of its `action` other than `action_id`, `parameters` and `parameters_digest`, so the
    admit that releases the modified action is an admit for the same operation, target, action
    class and risk class, for the same actor and subject.
    """
    if type(modified) is not dict:
        return [("modification_request", "the modification has no new decision request")]
    problems: list[tuple[str, str]] = []
    if text(modified, "message_id") in (None, text(original, "message_id")):
        problems.append(("modification_request/message_id", "the new request reuses the id"))
    actual = member(modified, "action", "parameters")
    if type(parameters) is not dict or not same_json(actual, parameters):
        problems.append(
            ("modification_request/action/parameters", "the parameters are not the modified ones")
        )
    expected_digest = digest_of(actual)
    if expected_digest is None or not same_digest(
        member(modified, "action", "parameters_digest"), expected_digest
    ):
        problems.append(
            (
                "modification_request/action/parameters_digest",
                "the digest is not that of the parameters",
            )
        )
    original_digest = digest_of(dict(original))
    linked = any(
        type(item) is dict
        and item.get("id") == text(original, "message_id")
        and item.get("relation") == MODIFICATION_OF
        and same_digest(item.get("digest"), original_digest)
        for item in array(modified, "workflow", "causal_predecessors")
    )
    if not linked:
        problems.append(
            (
                "modification_request/workflow/causal_predecessors",
                "the new request does not name the original as modification-of",
            )
        )
    problems.extend(
        (f"modification_request/{name}", f"the new request changes the original's {name}")
        for name in UNCHANGED_BY_MODIFICATION
        if not same_json(member(original, name), member(modified, name))
    )
    before, after = obj(original, "action") or {}, obj(modified, "action") or {}
    problems.extend(
        (f"modification_request/action/{name}", f"the new request changes the action's {name}")
        for name in sorted(set(before) | set(after))
        if name not in CHANGED_IN_MODIFIED_ACTION
        and not same_json(before.get(name), after.get(name))
    )
    return problems


def new_request_problems(record: Mapping[str, Any]) -> list[tuple[str, str]]:
    """(path, message) for each member of a new request that a record holds although its decision
    is not a modification (AB1-004, AC1-005): only a MODIFY or a `modify` has a new request, so the
    record of any other decision, or of a decision failure, holds no `modification_request` and no
    `modification_response`, and its action is released, if at all, only under the record's
    `request` (`release_problems` then finds no other request to release under)."""
    return [
        ("/" + name, "only a modification has a new decision request")
        for name in ("modification_request", "modification_response")
        if name in record
    ]


def modification_response_problems(record: Mapping[str, Any]) -> list[tuple[str, str]]:
    """(path, message) for a modification response that a record of a modification holds without
    the new request it answers (AB1-004, AC1-005). A record of a modification that holds neither a
    new request nor a release shows a deny of the original with no new request, which releases
    nothing: the modification could not be applied, for example because it changes the target
    as the deployment derives it, which the record does not show, or its action did not go
    ahead."""
    if "modification_response" in record:
        return [("/modification_response", "a modification response answers no new request")]
    return []


def deferral_problems(response: object, deadline: int | None) -> list[tuple[str, str]]:
    """(path, message) for a hold or challenge whose expiry could release the action.

    The response carries `expires_at`, no later than the deadline of the deferral or approval
    (nanoseconds since the epoch) when there is one, and a `safe_state` that permits no new
    effect (DCMP2-018, DCMP2-041).
    """
    problems: list[tuple[str, str]] = []
    expires = instant(member(response, "expires_at"))
    if expires is None or (deadline is not None and expires > deadline):
        problems.append(("/response/expires_at", "the response outlasts the deadline it maps"))
    if text(response, "safe_state") not in NO_EFFECT_SAFE_STATES:
        problems.append(("/response/safe_state", "the safe state on expiry permits a new effect"))
    return problems


def input_problems(
    inputs: list[Any], outcome: str | None, *, judgment_required: Iterable[int] = ()
) -> list[tuple[str, str]]:
    """(path, message) for each way the inputs break the one-way rule of the core standard.

    The inputs are entries of the decision basis (`ecl.ext.decision-basis.v1`), each with the
    member its profile adds. Inputs at the positions in `judgment_required` must be `judgment`.
    Only an available `verifiable` input supports an outcome, whatever the outcome (ECL1N-0181),
    and an `admit` rests on at least one (DCMP2-053).
    """
    problems = [
        (f"/inputs/{index}/class", "this input must be judgment")
        for index in judgment_required
        if text(inputs[index], "class") != "judgment"
    ]
    supporting = [
        (index, item) for index, item in enumerate(inputs) if text(item, "effect") == "supports"
    ]
    problems.extend(
        (f"/inputs/{index}/effect", "only a verifiable input can be the basis of admit")
        for index, item in supporting
        if text(item, "class") != "verifiable" or text(item, "status") != "available"
    )
    if outcome == "admit" and not any(
        text(item, "class") == "verifiable" for _, item in supporting
    ):
        problems.append(("/inputs", "the admit rests on no verifiable input"))
    return problems


def basis_problems(record: Mapping[str, Any], marker: str) -> list[tuple[str, str]]:
    """(path, message) for each way the record's `inputs` disagree with the decision basis that
    its `response` records in `ecl.ext.decision-basis.v1` (AB1-013, AC1-012).

    Each input of the record, without the member `marker` that its profile adds, equals the entry
    of the basis whose `input` is the same, and each entry appears in the record exactly once. A
    response that does not carry the extension records no inputs. One that carries it more than
    once, or whose value has no `inputs` array, agrees with no record. A record without a response
    has nothing to agree with.
    """
    response = obj(record, "response")
    if response is None:
        return []
    extensions = array(response, "extensions")
    positions = [
        index
        for index, item in enumerate(extensions)
        if type(item) is dict and item.get("id") == DECISION_BASIS
    ]
    if len(positions) > 1:
        return [("/response/extensions", "the response records its decision basis more than once")]
    entries: list[Any] = []
    prefix = "/response/extensions"
    if positions:
        prefix = f"/response/extensions/{positions[0]}/value/inputs"
        listed = member(extensions[positions[0]], "value", "inputs")
        if type(listed) is not list:
            return [(prefix, "the decision basis has no inputs array")]
        entries = listed
    problems: list[tuple[str, str]] = []
    named: dict[str, list[int]] = {}
    for position, entry in enumerate(entries):
        name = text(entry, "input")
        if name is None:
            problems.append((f"{prefix}/{position}", "the decision-basis entry names no input"))
        else:
            named.setdefault(name, []).append(position)
    listed_names: set[str] = set()
    for index, item in enumerate(array(record, "inputs")):
        path = f"/inputs/{index}"
        name = text(item, "input")
        if name is not None and name in listed_names:
            problems.append((path + "/input", "the record lists this input more than once"))
            continue
        if name is not None:
            listed_names.add(name)
        matches = named.get(name, []) if name is not None else []
        if len(matches) != 1:
            problems.append(
                (
                    path + "/input",
                    "the response's decision basis does not record this input"
                    if not matches
                    else "the response's decision basis records this input more than once",
                )
            )
            continue
        entry = entries[matches[0]]
        own = (
            {key: value for key, value in item.items() if key != marker}
            if type(item) is dict
            else {}
        )
        recorded = entry if type(entry) is dict else {}
        problems.extend(
            (f"{path}/{key}", f"the {key} is not the one the response records")
            for key in sorted(set(own) | set(recorded))
            if (key in own) != (key in recorded) or not same_json(own.get(key), recorded.get(key))
        )
    for name, matched in named.items():
        if name not in listed_names:
            problems.extend(
                (f"{prefix}/{position}/input", "the record does not list this input")
                for position in matched
            )
    return problems


def one_way_response_problems(
    record: Mapping[str, Any], *exchanges: tuple[tuple[str, ...], tuple[str, ...]]
) -> list[tuple[str, str]]:
    """(path, message) for each way a decision response of the record breaks DCMP2-053
    (AB1-013, AC1-012, MG1-007).

    Each exchange names the path of a decision request in the record and the path of the decision
    response that answers it. Each response carries exactly one value of
    `ecl.ext.decision-basis.v1`, since a response without one shows no basis that a checker of
    the record could see. Each response is checked as a decision response is checked on its own,
    with its outcome and `evaluated_at`: the reference's own check of the one-way rule,
    `ecl_verify.decision_basis_checks.response_one_way_problems`, runs on each value it carries. With
    the request that the record holds, `ecl_verify.decision_basis_checks.request_problems` refuses an
    input recorded as `verifiable` whose `source` is the request's `actor`, and a request recorded
    as received before it was issued, as an evidence verifier does with the request of a signed
    bundle under the reference verification profile. A record therefore never holds a response
    that the same checks refuse in a signed bundle. A response that the record does not hold has
    nothing to check.
    """
    problems: list[tuple[str, str]] = []
    for request_path, response_path in exchanges:
        response = obj(record, *response_path)
        if response is None or text(response, "message_type") != "decision_response":
            continue
        request = obj(record, *request_path)
        prefix = "/" + "/".join(response_path) + "/extensions"
        carried = [
            (index, item)
            for index, item in enumerate(array(response, "extensions"))
            if type(item) is dict and item.get("id") == DECISION_BASIS
        ]
        if len(carried) != 1:
            problems.append(
                (
                    prefix,
                    "the decision response does not carry exactly one decision basis",
                )
            )
        for index, item in carried:
            if type(item.get("value")) is not dict:
                continue
            problems.extend(
                (f"{prefix}/{index}/value{where}", message)
                for where, message in response_one_way_problems(response, item["value"])
            )
            if request is not None:
                problems.extend(
                    (f"{prefix}/{index}/value{where}", message)
                    for where, message in request_problems(item["value"], request)
                )
    return problems


def basis_class_problems(
    record: Mapping[str, Any], response_path: tuple[str, ...], required: Mapping[str, str]
) -> list[tuple[str, str]]:
    """(path, message) for each entry of a decision basis that the response at `response_path`
    records whose input a profile gives a class (`required`, keyed by
    `ecl_verify.decision_basis_checks.input_key`) and that records another class (AB1-006,
    AC1-004). The class that a profile gives an input holds in every decision basis that the
    record holds, the modification response's included, whose `admit` releases the modified
    action (AB1-004, AC1-005). An input listed under another name is not found by name."""
    response = obj(record, *response_path)
    problems: list[tuple[str, str]] = []
    if response is None or not required:
        return problems
    prefix = "/" + "/".join(response_path) + "/extensions"
    for index, item in enumerate(array(response, "extensions")):
        if type(item) is not dict or item.get("id") != DECISION_BASIS:
            continue
        for position, entry in enumerate(array(item.get("value"), "inputs")):
            name = text(entry, "input")
            expected = required.get(input_key(name)) if name is not None else None
            if expected is not None and text(entry, "class") != expected:
                problems.append(
                    (
                        f"{prefix}/{index}/value/inputs/{position}/class",
                        f"this input must be {expected}, as the record's inputs class it",
                    )
                )
    return problems


def modification_basis_problems(record: Mapping[str, Any]) -> list[tuple[str, str]]:
    """(path, message) for each way the decision basis of the record's `modification_response`
    disagrees with the record (AB1-013, AC1-012): it carries the `register` reference of the
    basis of the `response`, member for member, and it records the record's `inputs`, each once,
    compared as input names are (`ecl_verify.decision_basis_checks.input_key`), each with the
    `class`, `required`, `source` and `derived_from` that the record's input gives it, sources
    and the names in `derived_from` compared as input names are and an absent `derived_from`
    naming no input.

    The new request is the original action with other parameters (AB1-004, AC1-005), so its
    action class is the original's and the register version declares the same inputs for both
    decisions; the new request is decided under the register version of the first decision. The
    status, effect, reference and times of each entry describe the new decision and may differ.
    A record whose `response` or `modification_response` does not carry exactly one decision
    basis is left to `one_way_response_problems`, which reports it."""

    def single(path: str) -> tuple[int, dict[str, Any]] | None:
        found = [
            (index, item.get("value"))
            for index, item in enumerate(array(obj(record, path), "extensions"))
            if type(item) is dict and item.get("id") == DECISION_BASIS
        ]
        if len(found) != 1:
            return None
        index, value = found[0]
        return (index, value) if type(value) is dict else None

    first, second = single("response"), single("modification_response")
    if first is None or second is None:
        return []
    index, value = second
    prefix = f"/modification_response/extensions/{index}/value"
    problems: list[tuple[str, str]] = []
    if not same_json(value.get("register"), first[1].get("register")):
        problems.append(
            (prefix + "/register", "the modification response carries another register reference")
        )
    declared = {
        input_key(name): item
        for item in array(record, "inputs")
        if (name := text(item, "input")) is not None
    }
    listed: set[str] = set()
    for position, entry in enumerate(array(value, "inputs")):
        name = text(entry, "input")
        if name is None:
            continue
        key = input_key(name)
        listed.add(key)
        item = declared.get(key)
        path = f"{prefix}/inputs/{position}"
        if item is None:
            problems.append((path + "/input", "the record lists no such input"))
            continue
        problems.extend(
            (f"{path}/{field}", f"the {field} is not the one the record's inputs give")
            for field in ("class", "required")
            if not same_json(entry.get(field), item.get(field))
        )
        source, given = text(entry, "source"), text(item, "source")
        if source is None or given is None or input_key(source) != input_key(given):
            problems.append(
                (path + "/source", "the source is not the one the record's inputs give")
            )
        derived = {input_key(n) for n in array(entry, "derived_from") if type(n) is str}
        if derived != {input_key(n) for n in array(item, "derived_from") if type(n) is str}:
            problems.append(
                (path + "/derived_from", "derived_from is not the one the record's inputs give")
            )
    problems.extend(
        (
            prefix + "/inputs",
            f"the modification response does not record the input {text(item, 'input')}",
        )
        for key, item in declared.items()
        if key not in listed
    )
    return problems


def message_findings(record: Mapping[str, Any], *paths: tuple[str, ...]) -> list[Finding]:
    """The semantic rules of DCMP-2 that each DCMP-2 message that the record holds at one of
    `paths` fails (AB1-013, AC1-012, MG1-007): a message that a consumer would reject on its own,
    such as a request that declares a negative budget debit (DCMP2-055) or an extension value
    that its value schema refuses (XR1-023), is not part of a valid exchange. Each rule that a
    message fails is reported once, at the message's place in the record, with the first of its
    findings as the message; validated on its own, the message gives every finding with its
    path. The one-way rule of a decision basis is left to `one_way_response_problems`, which
    applies it with the record's requests. The record's schema has already checked each
    message's shape."""
    from ecl_verify.resources import object_findings

    result: list[Finding] = []
    for path in paths:
        message = obj(record, *path)
        if message is None or text(message, "protocol") != "DCMP-2":
            continue
        first: dict[str, str] = {}
        for item in object_findings(message):
            if item.rule_id != ONE_WAY_RULE:
                first.setdefault(item.rule_id, item.message)
        result.extend(Finding(rule, "/" + "/".join(path), first[rule]) for rule in sorted(first))
    return result


def findings(rule_id: str, problems: Iterable[tuple[str, str]]) -> list[Finding]:
    return [Finding(rule_id, path, message) for path, message in problems]
