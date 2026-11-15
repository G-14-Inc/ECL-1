"""Offline verification checks and read-only metadata for bindings.acs."""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from ecl_verify.canonical import CanonicalizationError, loads_json_strict
from ecl_verify.decision_basis_checks import input_key, least_trusted
from ecl_verify.semantic import Finding

from . import jcs
from .common import (
    ONE_WAY_RULE,
    OUTCOMES,
    array,
    basis_class_problems,
    basis_problems,
    deferral_problems,
    digest_of,
    exchanges,
    extension_entries,
    extension_values,
    findings,
    input_problems,
    instant,
    integer,
    member,
    message_findings,
    modification_basis_problems,
    modification_problems,
    modification_response_problems,
    new_request_problems,
    obj,
    one_way_response_problems,
    release_problems,
    response_binding_findings,
    same_digest,
    text,
)

ACS_VERSION = "0.1.0"

EXCHANGE_VERSION = "ecl_acs_exchange_v1"

EXCHANGE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/acs-exchange/1"

DECISION_EXTENSION = "ecl.ext.acs-decision.v1"

DECISION_SCHEMA = "https://externalcontrollayer.ai/ns/schema/extension/acs-decision/1"

DISPOSITIONS = ("allow", "deny", "modify", "ask", "defer")

EVALUATORS = ("deterministic", "agent", "composite")

JUDGMENT_EVALUATORS = frozenset({"agent", "composite"})

DETERMINISTIC_EVALUATOR = "deterministic"

CHANNELS = ("direct", "signed", "hook")

AUTHENTICATED_CHANNELS = frozenset({"direct", "signed"})

PERMITTED_OUTCOMES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "allow": frozenset(OUTCOMES),
        "deny": frozenset({"deny"}),
        "modify": frozenset({"deny"}),
        "ask": frozenset({"challenge", "hold", "deny"}),
        "defer": frozenset({"hold", "deny"}),
    }
)

REDACTED = "[REDACTED]"

_NANOSECONDS = 1_000_000_000

_MILLISECOND = 1_000_000

FAILURE_RULE = "ecl.rule.acs-decision-failure-closed.v1"

EXPIRY_RULE = "ecl.rule.acs-expiry-no-release.v1"

MODIFICATION_RULE = "ecl.rule.acs-modification-new-request.v1"

JUDGMENT_RULE = "ecl.rule.acs-judgment-guardian.v1"

OUTCOME_RULE = "ecl.rule.acs-outcome-no-weaker.v1"

RELEASE_RULE = "ecl.rule.acs-release-requires-admit.v1"

RECORD_RULE = "ecl.rule.acs-decision-recorded.v1"

BASIS_RULE = "ecl.rule.acs-inputs-match-basis.v1"

RULES = (
    FAILURE_RULE,
    EXPIRY_RULE,
    MODIFICATION_RULE,
    JUDGMENT_RULE,
    OUTCOME_RULE,
    RELEASE_RULE,
    RECORD_RULE,
    BASIS_RULE,
)


def _pointer(path: str) -> list[str] | None:
    if not path.startswith("/") or re.search(r"~(?![01])", path):
        return None
    return [part.replace("~1", "/").replace("~0", "~") for part in path.split("/")[1:]]


def _array_index(token: str, length: int) -> int | None:
    """RFC 6901 array index, bounded before integer conversion; '-' names no existing value."""
    if not re.fullmatch(r"0|[1-9][0-9]*", token) or len(token) > len(str(length)):
        return None
    index = int(token)
    return index if index < length else None


def _overlaps(first: list[str], second: list[str]) -> bool:
    shorter = min(len(first), len(second))
    return first[:shorter] == second[:shorter]


def _expected_parameters(
    arguments: Mapping[str, Any], modifications: object
) -> dict[str, Any] | None:
    """The tool arguments after a `modify` decision's modifications, or None if there are none.

    None means the modifications object is one the pinned text forbids (a wholesale replacement
    with edits, or a redaction whose target overlaps an override), cannot be applied (a redaction
    path that does not resolve inside the arguments), or yields arguments outside the restricted
    canonical profile.
    Each of these ends in a deny of the original with no new request (AC1-005).
    """
    if type(modifications) is not dict:
        return None
    wholesale = modifications.get("modified_content")
    redactions = modifications.get("redactions", [])
    overrides = modifications.get("parameter_overrides", {})
    if "modified_content" in modifications:
        if "redactions" in modifications or "parameter_overrides" in modifications:
            return None
        try:
            replaced = loads_json_strict(wholesale) if type(wholesale) is str else None
        except CanonicalizationError:
            return None
        return replaced if type(replaced) is dict else None
    if type(redactions) is not list or type(overrides) is not dict:
        return None
    if not redactions and not overrides:
        return None
    paths: list[list[str]] = []
    for item in redactions:
        path = item.get("path") if type(item) is dict else None
        parts = _pointer(path) if type(path) is str else None
        if not parts:
            return None
        paths.append(parts)
    if any(_overlaps(parts, [name]) for parts in paths for name in overrides):
        return None
    result = copy.deepcopy(dict(arguments))
    for name, value in overrides.items():
        result[name] = copy.deepcopy(value)
    for item, parts in zip(redactions, paths, strict=True):
        replacement = item.get("replacement", REDACTED)
        if type(replacement) is not str:
            return None
        container: Any = result
        for step in parts[:-1]:
            if type(container) is dict:
                container = container.get(step)
            elif type(container) is list:
                index = _array_index(step, len(container))
                container = container[index] if index is not None else None
            else:
                return None
        if type(container) is dict and parts[-1] in container:
            container[parts[-1]] = replacement
        elif type(container) is list:
            index = _array_index(parts[-1], len(container))
            if index is None:
                return None
            container[index] = replacement
        else:
            return None
    return result if digest_of(result) is not None else None


def entry_hash(entry: Mapping[str, Any]) -> str:
    """The `entry_hash` of an ACS ContextEntry under the pinned chain-hashing rule (section 8.2):
    SHA-256 of the RFC 8785 form of the entry without `entry_hash` and `previous_hash`, followed by
    the 32 bytes of `previous_hash`, or nothing for the first entry."""
    content = {
        name: value for name, value in entry.items() if name not in ("entry_hash", "previous_hash")
    }
    previous = entry.get("previous_hash")
    tail = bytes.fromhex(previous) if type(previous) is str else b""
    return hashlib.sha256(jcs.canonicalize(content) + tail).hexdigest()


def chain_problems(entries: list[Any]) -> list[tuple[str, str]]:
    """(path, message) for each entry whose hash or link the recomputation does not reproduce."""
    problems: list[tuple[str, str]] = []
    previous: str | None = None
    entry_ids: set[str] = set()
    for index, entry in enumerate(entries):
        if type(entry) is not dict:
            problems.append((f"/chain/{index}", "a ContextEntry is not an object"))
            continue
        entry_id = entry.get("entry_id")
        if type(entry_id) is str:
            if entry_id in entry_ids:
                problems.append((f"/chain/{index}/entry_id", "a ContextEntry identifier is repeated within the session"))
            entry_ids.add(entry_id)
        if entry.get("previous_hash") != previous:
            problems.append((f"/chain/{index}/previous_hash", "the link is not the prior head"))
        try:
            recomputed = entry_hash(entry)
        except (jcs.JcsError, ValueError):
            recomputed = None
        if recomputed != entry.get("entry_hash"):
            problems.append((f"/chain/{index}/entry_hash", "the hash is not the recomputed one"))
        previous = entry.get("entry_hash") if type(entry.get("entry_hash")) is str else None
    return problems


def _modifications_digest(result: Mapping[str, Any]) -> dict[str, str] | None:
    if "modifications" not in result:
        return None
    try:
        return jcs.digest(result["modifications"])
    except jcs.JcsError:
        return None


def deadline(record: Mapping[str, Any], disposition: str) -> int | None:
    """When the Guardian's ask or defer stops waiting, in nanoseconds since the epoch: the time
    the adapter observed its decision plus `ask_details.timeout_seconds` or
    `defer_details.resolution_timeout_ms`. None when the record lacks either or its timeout violates the pinned native schema."""
    received = instant(member(record, "guardian", "observed_at"))
    if disposition == "ask":
        seconds = integer(record, "guardian", "result", "ask_details", "timeout_seconds")
        span = None if seconds is None or seconds < 1 else seconds * _NANOSECONDS
    else:
        milliseconds = integer(
            record, "guardian", "result", "defer_details", "resolution_timeout_ms"
        )
        span = None if milliseconds is None or milliseconds < 0 else milliseconds * _MILLISECOND
    return None if received is None or span is None else received + span


def _failure(record: Mapping[str, Any], outcome: str | None) -> list[tuple[str, str]]:
    problems: list[tuple[str, str]] = []
    if text(record, "on_decision_failure") != "deny":
        problems.append(("/on_decision_failure", "a claim of this profile negotiates deny"))
    if text(record, "guardian", "status") == "failed":
        if obj(record, "release") is not None:
            problems.append(("/release", "a Guardian decision failure released the action"))
        if outcome == "admit":
            problems.append(("/response/outcome", "a Guardian decision failure ended in an admit"))
    return problems


def _expiry(
    record: Mapping[str, Any], disposition: str | None, outcome: str | None
) -> list[tuple[str, str]]:
    if disposition not in ("ask", "defer"):
        return []
    problems: list[tuple[str, str]] = []
    if outcome in ("hold", "challenge"):
        bound = deadline(record, disposition)
        if bound is None:
            problems.append(("/guardian/result", "a waiting response requires a valid Guardian timeout"))
        problems += deferral_problems(member(record, "response"), bound)
        expires = instant(member(record, "response", "expires_at"))
        released = instant(member(record, "release", "released_at"))
        if expires is not None and released is not None and released >= expires:
            problems.append(("/release/released_at", "the action went ahead after the expiry"))
    return problems


def _modification(record: Mapping[str, Any], disposition: str | None) -> list[tuple[str, str]]:
    request = obj(record, "request")
    if disposition != "modify":
        return new_request_problems(record)
    if request is None:
        return []
    if "modification_request" not in record and obj(record, "release") is None:
        # AC1-005: a modify that ends in deny of the original with no new request releases
        # nothing. A checker of the record cannot tell a modification that cannot be applied for
        # a reason the record does not show, such as a change of the target as the deployment
        # derives it, from one whose action did not go ahead; it reports only a modification
        # response that answers no new request.
        return modification_response_problems(record)
    arguments = member(request, "action", "parameters")
    effective = _expected_parameters(
        arguments if type(arguments) is dict else {},
        member(record, "guardian", "result", "modifications"),
    )
    modified = member(record, "modification_request")
    if effective is None:
        problems: list[tuple[str, str]] = []
        if modified is not None:
            problems.append(
                ("/modification_request", "an unusable modification gets no new request")
            )
        if obj(record, "release") is not None:
            problems.append(("/release", "an unusable modification releases nothing"))
        return problems
    problems = [
        ("/" + path, message)
        for path, message in modification_problems(request, modified, effective)
    ]
    if obj(record, "release") is not None and text(record, "release", "request_id") != text(
        record, "modification_request", "message_id"
    ):
        problems.append(
            ("/release/request_id", "a modification is released only under its new request")
        )
    return problems


def guardian_class(evaluator: str | None, carried: list[str | None], *, channel: str | None) -> str:
    """The class of a Guardian decision (AC1-004): `judgment` unless its evaluator is
    `deterministic`, so from an `agent` or `composite` evaluator or one that states none;
    `actor_supplied` when the decision point neither obtained it from the Guardian directly nor
    verified the Guardian's signature over it (`channel` neither `direct` nor `signed`), as for a
    decision that a hook point carried; and otherwise the least trusted class of the inputs its
    request carried."""
    if evaluator != DETERMINISTIC_EVALUATOR:
        return "judgment"
    if channel not in AUTHENTICATED_CHANNELS:
        return "actor_supplied"
    return least_trusted(item for item in carried if item is not None)


def _judgment(record: Mapping[str, Any], outcome: str | None) -> list[tuple[str, str]]:
    inputs = array(record, "inputs")
    evaluator = text(record, "guardian", "result", "metadata", "evaluator")
    channel = text(record, "guardian", "channel")
    # The class of each input of the record, by its `input_key`: a name in `derived_from` is
    # compared as input names are (DCMP2-053).
    classes = {
        input_key(name): text(item, "class")
        for item in inputs
        if (name := text(item, "input")) is not None
    }
    problems: list[tuple[str, str]] = []
    marked = [index for index, item in enumerate(inputs) if member(item, "guardian") is True]
    # The class that each marked input must have, by its `input_key`, in every decision basis that
    # the record holds (AC1-004).
    required: dict[str, str] = {}
    for index in marked:
        item = inputs[index]
        path = f"/inputs/{index}"
        derived = member(item, "derived_from")
        name = text(item, "input")
        if type(derived) is not list and text(record, "guardian", "status") == "decided":
            problems.append((path + "/derived_from", "a Guardian decision explicitly names every input its request carried, or an empty list"))
            continue
        if type(derived) is list:
            unknown = [
                offset
                for offset, name in enumerate(derived)
                if not isinstance(name, str) or input_key(name) not in classes
            ]
            problems.extend(
                (f"{path}/derived_from/{offset}", "the record lists no such input")
                for offset in unknown
            )
            expected = guardian_class(
                evaluator,
                [classes.get(input_key(name)) for name in derived if isinstance(name, str)],
                channel=channel,
            )
        else:
            # No Guardian decision exists after a failed exchange. Its unavailable
            # input is recorded without inventing request contents or derivation.
            expected = guardian_class(evaluator, [], channel=channel)
        if text(item, "class") != expected:
            problems.append((path + "/class", f"this input must be {expected}"))
        if name is not None:
            required[input_key(name)] = expected
    # AC1-004: a response that records the Guardian decision rests on it as one input, which the
    # record marks; an unmarked one would escape the class check above.
    if extension_entries(obj(record, "response"), DECISION_EXTENSION):
        if not marked:
            problems.append(("/inputs", "no input is marked as the Guardian's decision"))
        problems.extend(
            (f"/inputs/{index}/guardian", "another input is marked as the Guardian's decision")
            for index in marked[1:]
        )
    problems += basis_class_problems(record, ("modification_response",), required)
    return problems + input_problems(inputs, outcome)


def _signed_request_binding(record: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Consistency of the adapter's recorded authenticated context, not signature proof."""
    if text(record, "guardian", "channel") != "signed":
        return []
    params = obj(record, "guardian", "request_params")
    if text(record, "guardian", "status") == "failed":
        # A failed route asserts no verified decision. Retained submitted params still
        # bind their local digest, without inventing an unavailable signed result.
        guardian = obj(record, "guardian") or {}
        if "request_params" not in guardian and "request_digest" not in guardian:
            return []
        if params is None or "request_digest" not in guardian:
            return [("/guardian", "retained request params and their digest occur together")]
        try:
            expected = jcs.digest(params)
        except jcs.JcsError:
            return [("/guardian/request_params", "the request binding has no RFC 8785 canonical form")]
        if not same_digest(guardian.get("request_digest"), expected):
            return [("/guardian/request_digest", "the recorded digest does not bind this request")]
        return []
    context = obj(record, "guardian", "authenticated_context")
    request = obj(record, "request")
    if params is None or context is None or request is None:
        return [("/guardian", "a signed channel records the evaluated params and authenticated context")]
    problems: list[tuple[str, str]] = []
    try:
        params_digest, request_digest = jcs.digest(params), jcs.digest(request)
    except jcs.JcsError:
        return [("/guardian/request_params", "the request binding has no RFC 8785 canonical form")]
    for path, actual, expected in (
        ("/guardian/request_digest", member(record, "guardian", "request_digest"), params_digest),
        ("/guardian/authenticated_context/request_digest", context.get("request_digest"), params_digest),
        ("/guardian/authenticated_context/dcmp_request_digest", context.get("dcmp_request_digest"), request_digest),
    ):
        if not same_digest(actual, expected):
            problems.append((path, "the recorded digest does not bind this request"))
    for name, expected in (
        ("session_id", record.get("session_id")),
        ("request_id", member(record, "guardian", "result", "request_id")),
        ("method", record.get("hook")),
    ):
        if context.get(name) != expected:
            problems.append((f"/guardian/authenticated_context/{name}", "the authenticated context is not this session and step"))
    chain = array(record, "chain")
    if chain:
        step = next((entry for entry in chain if isinstance(entry, dict) and entry.get("step_id") == context.get("request_id")), None)
        if step is None or step.get("request_hash") != params_digest["value"]:
            problems.append(("/chain", "the signed step must commit to the evaluated request params"))
    return problems


def _recorded(record: Mapping[str, Any]) -> list[tuple[str, str]]:
    # A retained native chain remains evidence even when this step failed or
    # its decision record is incomplete. Do not discard its integrity findings.
    chain = array(record, "chain")
    chain_errors = chain_problems(chain)
    result = obj(record, "guardian", "result")
    response = obj(record, "response")
    if text(record, "guardian", "status") != "decided":
        return chain_errors
    if result is None:
        return [("/guardian/result", "a decided Guardian exchange retains its result")] + chain_errors
    if response is None:
        return chain_errors
    entries = extension_entries(response, DECISION_EXTENSION)
    values = extension_values(response, DECISION_EXTENSION)
    if len(entries) != 1 or len(values) != 1:
        return [("/response/extensions", "the response records the Guardian decision once")] + chain_errors
    value = values[0]
    problems: list[tuple[str, str]] = []
    for name, expected in (
        ("decision", result.get("decision")),
        ("request_id", result.get("request_id")),
        ("evaluator", member(result, "metadata", "evaluator")),
        ("chain_hash", result.get("chain_hash")),
        ("modifications_digest", _modifications_digest(result)),
    ):
        if value.get(name) != expected:
            problems.append(
                (f"/response/extensions/{name}", f"the recorded {name} is not the Guardian's")
            )
    if (member(record, "audit_profile") is True or (text(record, "guardian", "channel") == "signed" and array(record, "chain"))) and type(value.get("request_hash")) is not str:
        problems.append(("/response/extensions/request_hash", "ACS-Audit or a signed request chain records the request hash"))
    params = obj(record, "guardian", "request_params")
    if params is not None and "request_hash" in value:
        try:
            expected_hash = jcs.digest(params)["value"]
        except jcs.JcsError:
            expected_hash = None
        if expected_hash is None or value.get("request_hash") != expected_hash:
            problems.append(("/response/extensions/request_hash", "the recorded request hash does not match the evaluated request params"))
    if not chain:
        return problems
    problems += chain_errors
    step = next(
        (
            entry
            for entry in chain
            if type(entry) is dict and entry.get("step_id") == value.get("request_id")
        ),
        None,
    )
    if step is None or step.get("entry_hash") != value.get("chain_hash"):
        problems.append(
            ("/response/extensions/chain_hash", "the recorded head is not the step's chain head")
        )
    if step is not None and "request_hash" in value and step.get("request_hash") != value.get("request_hash"):
        problems.append(
            ("/response/extensions/request_hash", "the recorded request hash is not the step's")
        )
    return problems


def check(record: Mapping[str, Any]) -> list[Finding]:
    """The findings of an `ecl_acs_exchange_v1` record that its schema has accepted."""
    status = text(record, "guardian", "status")
    disposition = text(record, "guardian", "result", "decision") if status == "decided" else None
    outcome = text(record, "response", "outcome")
    candidates = exchanges(
        record, ("request", "response"), ("modification_request", "modification_response")
    )
    result = findings(FAILURE_RULE, _failure(record, outcome))
    result += findings(EXPIRY_RULE, _expiry(record, disposition, outcome))
    result += findings(MODIFICATION_RULE, _modification(record, disposition))
    result += findings(JUDGMENT_RULE, _judgment(record, outcome))
    permitted = PERMITTED_OUTCOMES.get(disposition or "")
    if permitted is not None and outcome not in permitted:
        result.append(
            Finding(OUTCOME_RULE, "/response/outcome", f"{disposition} cannot become {outcome}")
        )
    result += findings(RELEASE_RULE, release_problems(member(record, "release"), candidates))
    result += findings(RECORD_RULE, _recorded(record))
    result += findings(RECORD_RULE, _signed_request_binding(record))
    result += findings(BASIS_RULE, basis_problems(record, "guardian"))
    result += findings(BASIS_RULE, modification_basis_problems(record))
    result += findings(
        ONE_WAY_RULE,
        one_way_response_problems(
            record,
            (("request",), ("response",)),
            (("modification_request",), ("modification_response",)),
        ),
    )
    result += response_binding_findings(
        record, ("request", "response"), ("modification_request", "modification_response")
    )
    result += message_findings(
        record,
        ("request",),
        ("response",),
        ("modification_request",),
        ("modification_response",),
    )
    return result
