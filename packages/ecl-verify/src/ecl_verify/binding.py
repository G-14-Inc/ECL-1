"""Binding checks: do these decoded objects belong together?

A valid signature shows who signed an object, not that the objects fit. RC-3 let a response through
whose causal predecessor named its request but carried any digest at all. These checks close that
gap. Each reads decoded payloads, the JSON objects inside verified envelopes; it verifies no
signature and runs no schema check, so a caller does those first. As in `resources.object_findings`,
only a `dict` is a JSON object and only a `list` is an array; anything else is refused. A member is
read only when its type is exactly `dict`, `list`, `str` or `int`, so a subclass with a `__ne__` of
its own cannot decide a comparison, and a value that raises when it is compared is never compared.

Each check raises `BindingError` for the first rule that fails, in the order below, and returns None
when every rule holds. A member that a rule reads and that is missing or of the wrong type fails the
check with its general code (`ecl.error.request-binding-invalid.v1` for a response,
`ecl.error.decision-binding-invalid.v1` for the two event checks): never a KeyError or a TypeError.
A member that is there and does not match fails with the code named for the rule. Messages name
members and never quote values. tests/test_binding.py pins every rule, its code and the order.

The rules are those of DCMP-2 section 8 (DCMP2-044 to DCMP2-050) and EBMP-2 section 10
(EBMP2-047 to EBMP2-052); the bundle verifier applies the rest of section 10. Two of them are
parameters of the verification profile. Rule 5 of the response check allows the response
clock-skew allowance (DCMP2-047), zero unless the caller passes another. The state table of the
event check (rule 8) is the reference verification profile's,
`ecl.verification-profile.reference.v1`, whose dependency failures resolve to a fail-closed deny
(EBMP2-051).

`check_response_binding(request, response)`, request-binding-invalid unless a rule names another:

  0. the arguments are a decision_request and a decision_response.
  1. response.request_id is request.message_id.
  2. the same workflow_id, then the same root_trace_id.
  3. the same attempt: the decision point copies the request's (DCMP2-045).
  4. exactly one causal predecessor has the relation responds-to, and its id is request.message_id
     and its digest object_digest(request). Predecessors with another relation, or none, are
     allowed: a response after a challenge cites the challenge response (DCMP2-021). Any failure
     here is digest-mismatch.
  5. response.issued_at is not before request.issued_at less the response clock-skew allowance.
  6. for an admit only: the authorization
     a. has the audience that the request asked for (audience-mismatch);
     b. has as scope_digest the digest of {"request_id": message_id, "action": action}, computed as
        adapter.build_decision_response computes it (scope-mismatch);
     c. has the use_policy that the request asked for;
     d. lasts longer than nothing and no longer than requested_validity_seconds;
     d1. has max_uses absent or 1 if it is single_use; and, if the request gave max_uses, has one
         that is no greater;
     d2. is contained in the decision (DCMP2-015): it begins no earlier than the response's
         issued_at, ends no later than its expires_at when it has one, and ends no later than
         issued_at plus requested_validity_seconds, so that a window far ahead is refused even
         when the response has no expires_at.

`check_event_binding(event, *, request, response)` for an execution_released or execution_terminal
event, decision-binding-invalid unless a rule names another:

  0. the arguments are such an event, a decision_request, and a decision_response or None.
  1. event.action_id is request.action.action_id.
  1a. if the event repeats them: its operation, its parameters_digest and its target.uri are those
     of the request's action. Only the algorithm and the value of the digests are compared, and
     only the uri of a target: its version and digest change with the effect.
  2. with a response, response.request_id is request.message_id.
  3. the same workflow_id, then the same root_trace_id, as the request, and as the response when
     there is one.
  4. the same attempt as the request and, when there is a response, as the response.
  5. with a response, decision.uri is its message_id; without one, the event names no decision.
  6. decision.digest is object_digest(response). Any failure here is digest-mismatch.
  7. an event that carries authority has a response that admits, and authority.uri is that
     response's authorization_id.
  8. execution_released has a response that admits. execution_terminal is in a state that
     TERMINAL_STATE_OUTCOMES lists, and its response has an outcome that it lists for that state, or
     no response where it lists that.

`check_authority_event_binding(event, *, response)` for an authority_issued or authority_consumed
event, decision-binding-invalid unless a rule names another:

  0. the arguments are such an event and a decision_response.
  1. the response admits, and the event's authorization_id is its authorization_id.
  2. exactly one causal predecessor has the id response.message_id, and its digest is
     object_digest(response). Other predecessors are allowed. Any failure here is digest-mismatch.
  3. the same workflow_id, then the same root_trace_id.
  4. the same attempt.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any

from .canonical import object_digest
from .schema import rfc3339_utc_nanoseconds

REQUEST_BINDING_INVALID = "ecl.error.request-binding-invalid.v1"
DECISION_BINDING_INVALID = "ecl.error.decision-binding-invalid.v1"
DIGEST_MISMATCH = "ecl.error.digest-mismatch.v1"
AUDIENCE_MISMATCH = "ecl.error.audience-mismatch.v1"
SCOPE_MISMATCH = "ecl.error.scope-mismatch.v1"

_DIGEST_SUITE = "ecl.digest.sha-256.v1"
_RESPONDS_TO = "ecl.relation.responds-to.v1"
_OUTCOMES = frozenset({"admit", "deny", "hold", "challenge"})
_EXECUTION_EVENTS = frozenset({"execution_released", "execution_terminal"})
_AUTHORITY_EVENTS = frozenset({"authority_issued", "authority_consumed"})

_ADMIT: frozenset[str | None] = frozenset({"admit"})
# The outcomes that each terminal state may have in the response it is bound to (review B of the
# security contract), where None stands for no response at all. Only `denied` may have none, for a
# dependency failure, and it may also follow an admit, when the policy denied after admitting.
# That review does not list rolled_back and compensated: they follow an execution, which only an
# admit released, so they need one.
# Public because events.py builds terminal events by this table: one table, so that what the
# builders accept and what the event check accepts cannot drift apart.
TERMINAL_STATE_OUTCOMES: MappingProxyType[str, frozenset[str | None]] = MappingProxyType(
    {
        "succeeded": _ADMIT,
        "failed": _ADMIT,
        "partially_succeeded": _ADMIT,
        "timed_out": _ADMIT,
        "cancelled": _ADMIT,
        "unknown": _ADMIT,
        "rolled_back": _ADMIT,
        "compensated": _ADMIT,
        "expired_before_release": _ADMIT,
        "held": frozenset({"hold"}),
        "challenged": frozenset({"challenge"}),
        "denied": frozenset({"deny", "admit", None}),
    }
)

# Whole seconds or up to nine fractional digits, as the common schema's rfc3339Utc allows. The
# digits are ASCII: [0-9], not \d. Times are naive because they are all UTC.
_INSTANT = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z"
)
_EPOCH = datetime(1970, 1, 1)
_SECOND = timedelta(seconds=1)
_NANOSECONDS = 1_000_000_000


class BindingError(ValueError):
    """Objects that do not belong together, or an object that cannot be checked.

    `code` is a registered error: `ecl.error.request-binding-invalid.v1` or
    `ecl.error.decision-binding-invalid.v1` in general, and `ecl.error.digest-mismatch.v1`,
    `ecl.error.audience-mismatch.v1` or `ecl.error.scope-mismatch.v1` where the rule is named so.
    """

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code

    def __reduce__(self) -> tuple[Any, ...]:
        # The default would call BindingError(message) and lose the required code.
        return (_restore_error, (str(self), self.code))


def _restore_error(message: str, code: str) -> BindingError:
    return BindingError(message, code=code)


@dataclass(frozen=True)
class _Object:
    """A decoded object with its name for messages and the code that a malformed read raises."""

    value: dict[str, Any]
    name: str
    code: str

    def error(self, message: str, code: str | None = None) -> BindingError:
        return BindingError(f"{self.name}: {message}", code=code or self.code)

    def has(self, *path: str) -> bool:
        try:
            self.get(*path)
        except BindingError:
            return False
        return True

    def get(self, *path: str) -> Any:
        found: Any = self.value
        for step in path:
            if (
                type(found) is not dict
                or any(type(key) is not str for key in found)
                or step not in found
            ):
                raise self.error(f"{'.'.join(path)} is missing")
            found = found[step]
        return found

    def text(self, *path: str) -> str:
        found = self.get(*path)
        if type(found) is not str or not found:
            raise self.error(f"{'.'.join(path)} is not a non-empty string")
        return found

    def integer(self, *path: str) -> int:
        found = self.get(*path)
        if type(found) is not int:
            raise self.error(f"{'.'.join(path)} is not an integer")
        return found

    def array(self, *path: str) -> list[Any]:
        found = self.get(*path)
        if type(found) is not list:
            raise self.error(f"{'.'.join(path)} is not an array")
        return found

    def member(self, *path: str) -> _Object:
        return _read(self.get(*path), f"{self.name}.{'.'.join(path)}", self.code)

    def digest(self, *path: str) -> dict[str, Any]:
        """A digest member, whole. Compare it only with a digest that this module built."""
        found = self.member(*path)
        found.text("algorithm")
        found.text("value")
        return found.value

    def digest_pair(self, *path: str) -> tuple[str, str]:
        """The algorithm and the value of a digest member, and nothing else of it.

        For comparing two digests that a caller supplied: whatever else they hold is never compared.
        """
        found = self.member(*path)
        return found.text("algorithm"), found.text("value")

    def instant(self, *path: str) -> int:
        return _instant(self.text(*path), self, ".".join(path))


def _read(value: object, name: str, code: str) -> _Object:
    if type(value) is not dict:
        raise BindingError(f"{name} is not a JSON object", code=code)
    return _Object(value, name, code)


def _instant(text: str, owner: _Object, member: str) -> int:
    """The nanoseconds from 1970-01-01T00:00:00Z to `text`, an RFC 3339 UTC time.

    An integer, so that times which differ in the ninth fractional digit compare exactly, and the
    same on every interpreter: the shared parser `schema.rfc3339_utc_nanoseconds` reads one to
    nine fractional digits without `datetime.fromisoformat`'s version differences.
    """
    if _INSTANT.fullmatch(text) is None:
        raise owner.error(f"{member} is not an RFC 3339 UTC time")
    try:
        return rfc3339_utc_nanoseconds(text)
    except ValueError:
        raise owner.error(f"{member} is not a time that exists") from None


def _fingerprint(value: object, owner: _Object) -> dict[str, str]:
    """The digest object that names `value`, the form every digest member has.

    Canonicalization failures are refusals, including oversized integers and exceptions from
    executable in-process subclasses. Such subclasses cannot arrive through strict JSON decoding.
    """
    try:
        return {"algorithm": _DIGEST_SUITE, "value": object_digest(value)}
    except Exception as error:
        raise owner.error("cannot be canonicalized, so it has no digest") from error


def _scope_digest(request: _Object) -> dict[str, str]:
    """What adapter.build_decision_response puts in authorization.scope_digest."""
    scope = {"request_id": request.text("message_id"), "action": request.member("action").value}
    return _fingerprint(scope, request)


def _require_message(message: _Object, message_type: str) -> None:
    if message.text("message_type") != message_type:
        raise message.error(f"is not a {message_type}")


def _require_event(event: _Object, event_types: frozenset[str], kind: str) -> None:
    if event.text("object_type") != "event_record":
        raise event.error("is not an event record")
    if event.text("event_type") not in event_types:
        raise event.error(f"is not one of {', '.join(sorted(event_types))}")
    if event.text("event", "kind") != kind:
        raise event.error(f"event.kind is not {kind}")


def _same_text(left: _Object, right: _Object, *path: str) -> None:
    if left.text(*path) != right.text(*path):
        raise left.error(f"{'.'.join(path)} is not the {right.name}'s")


def _same_attempt(left: _Object, right: _Object) -> None:
    if left.integer("workflow", "attempt") != right.integer("workflow", "attempt"):
        raise left.error(f"workflow.attempt is not the {right.name}'s")


# --- check_response_binding ----------------------------------------------------------------------


def check_response_binding(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    *,
    response_clock_skew_seconds: int = 0,
) -> None:
    """Raise BindingError unless `response` is the answer to `request`; return None when it is.

    The rules and their codes are in the module docstring. Neither argument is changed.
    `response_clock_skew_seconds` is the verification profile's response clock-skew allowance
    (DCMP2-047); the reference verification profile declares zero.
    """
    if type(response_clock_skew_seconds) is not int or response_clock_skew_seconds < 0:
        raise ValueError("the response clock-skew allowance is a non-negative integer of seconds")
    asked = _read(request, "request", REQUEST_BINDING_INVALID)
    answer = _read(response, "response", REQUEST_BINDING_INVALID)
    _require_message(asked, "decision_request")
    _require_message(answer, "decision_response")
    _answers_the_request(asked, answer)
    _same_text(answer, asked, "workflow", "workflow_id")
    _same_text(answer, asked, "workflow", "root_trace_id")
    _same_attempt(answer, asked)
    _responds_to_the_request(asked, answer)
    _is_not_before_the_request(asked, answer, response_clock_skew_seconds * _NANOSECONDS)
    if _outcome(answer) == "admit":
        _has_the_audience_requested(asked, answer)
        _has_the_scope_of_the_action(asked, answer)
        _has_the_use_policy_requested(asked, answer)
        _lasts_no_longer_than_requested(asked, answer)
        _single_use_is_one_use(answer)
        _has_no_more_uses_than_requested(asked, answer)
        _begins_no_earlier_than_it_is_issued(answer)
        _ends_by_the_time_the_response_expires(answer)
        _ends_within_the_seconds_requested_of_issue(asked, answer)


def _answers_the_request(request: _Object, response: _Object) -> None:
    if response.text("request_id") != request.text("message_id"):
        raise response.error("request_id is not the request's message_id")


def _predecessors(owner: _Object) -> list[_Object]:
    """The causal predecessors of `owner`, each with the id and digest that the schema requires."""
    found = [
        _read(item, f"{owner.name}.workflow.causal_predecessors[{index}]", owner.code)
        for index, item in enumerate(owner.array("workflow", "causal_predecessors"))
    ]
    for item in found:
        item.text("id")
        item.digest("digest")
    return found


def _relation(predecessor: _Object) -> str | None:
    """The relation of a causal reference, or None when it has none. A relation must be text."""
    return predecessor.text("relation") if predecessor.has("relation") else None


def _responds_to_the_request(request: _Object, response: _Object) -> None:
    responding = [item for item in _predecessors(response) if _relation(item) == _RESPONDS_TO]
    if len(responding) != 1:
        raise response.error("does not have exactly one responds-to predecessor", DIGEST_MISMATCH)
    if responding[0].text("id") != request.text("message_id"):
        raise response.error("the responds-to predecessor is not the request", DIGEST_MISMATCH)
    if responding[0].digest("digest") != _fingerprint(request.value, request):
        raise response.error(
            "the responds-to predecessor's digest is not the request's", DIGEST_MISMATCH
        )


def _is_not_before_the_request(request: _Object, response: _Object, allowance: int) -> None:
    if response.instant("issued_at") < request.instant("issued_at") - allowance:
        raise response.error("issued_at is before the request's")


def _outcome(response: _Object) -> str:
    outcome = response.text("outcome")
    if outcome not in _OUTCOMES:
        raise response.error("outcome is not admit, deny, hold or challenge")
    return outcome


def _has_the_audience_requested(request: _Object, response: _Object) -> None:
    granted = response.text("authorization", "audience")
    if granted != request.text("authority_request", "audience"):
        raise response.error(
            "authorization.audience is not the audience requested", AUDIENCE_MISMATCH
        )


def _has_the_scope_of_the_action(request: _Object, response: _Object) -> None:
    if response.digest("authorization", "scope_digest") != _scope_digest(request):
        raise response.error(
            "authorization.scope_digest is not the digest of the request's action", SCOPE_MISMATCH
        )


def _has_the_use_policy_requested(request: _Object, response: _Object) -> None:
    granted = response.text("authorization", "use_policy")
    if granted != request.text("authority_request", "use_policy"):
        raise response.error("authorization.use_policy is not the use policy requested")


def _lasts_no_longer_than_requested(request: _Object, response: _Object) -> None:
    start = response.instant("authorization", "valid_from")
    end = response.instant("authorization", "valid_until")
    allowed = request.integer("authority_request", "requested_validity_seconds") * _NANOSECONDS
    if not 0 < end - start <= allowed:
        raise response.error("authorization window is empty, or longer than requested")


def _granted_uses(response: _Object) -> int | None:
    if not response.has("authorization", "max_uses"):
        return None
    return response.integer("authorization", "max_uses")


def _single_use_is_one_use(response: _Object) -> None:
    if response.text("authorization", "use_policy") != "single_use":
        return
    if _granted_uses(response) not in (None, 1):
        raise response.error("a single_use authorization has a max_uses other than 1")


def _has_no_more_uses_than_requested(request: _Object, response: _Object) -> None:
    if not request.has("authority_request", "max_uses"):
        return
    granted = _granted_uses(response)
    if granted is None or granted > request.integer("authority_request", "max_uses"):
        raise response.error("authorization.max_uses is missing, or more than the request's")


def _begins_no_earlier_than_it_is_issued(response: _Object) -> None:
    if response.instant("authorization", "valid_from") < response.instant("issued_at"):
        raise response.error("authorization.valid_from is before issued_at")


def _ends_by_the_time_the_response_expires(response: _Object) -> None:
    if not response.has("expires_at"):
        return
    if response.instant("authorization", "valid_until") > response.instant("expires_at"):
        raise response.error("authorization.valid_until is after expires_at")


def _ends_within_the_seconds_requested_of_issue(request: _Object, response: _Object) -> None:
    seconds = request.integer("authority_request", "requested_validity_seconds")
    limit = response.instant("issued_at") + seconds * _NANOSECONDS
    if response.instant("authorization", "valid_until") > limit:
        raise response.error(
            "authorization.valid_until is after issued_at plus the seconds requested"
        )


# --- check_event_binding -------------------------------------------------------------------------


def check_event_binding(
    event: Mapping[str, Any], *, request: Mapping[str, Any], response: Mapping[str, Any] | None
) -> None:
    """Raise BindingError unless the execution `event` records `request` and `response`.

    Return None when it does. `response` is None when the decision point gave none. The rules and
    their codes are in the module docstring. No argument is changed.

    The caller pairs the objects: `response` must be the response to `request` whenever there is one
    (rule 2 refuses a response that names another request, and no more than that), and the caller
    must also run `check_response_binding` on that pair, which this check does not.
    """
    recorded = _read(event, "event", DECISION_BINDING_INVALID)
    asked = _read(request, "request", DECISION_BINDING_INVALID)
    answer = None if response is None else _read(response, "response", DECISION_BINDING_INVALID)
    _require_event(recorded, _EXECUTION_EVENTS, "execution")
    _require_message(asked, "decision_request")
    if answer is not None:
        _require_message(answer, "decision_response")
    _records_the_action(recorded, asked)
    _repeats_the_operation(recorded, asked)
    _repeats_the_parameters(recorded, asked)
    _repeats_the_target(recorded, asked)
    if answer is not None:
        _answers_the_request(asked, answer)
    _same_text(recorded, asked, "workflow", "workflow_id")
    _same_text(recorded, asked, "workflow", "root_trace_id")
    if answer is not None:
        _same_text(recorded, answer, "workflow", "workflow_id")
        _same_text(recorded, answer, "workflow", "root_trace_id")
    _same_attempt(recorded, asked)
    if answer is not None:
        _same_attempt(recorded, answer)
    _names_the_response(recorded, answer)
    if answer is not None:
        _records_the_digest_of_the_response(recorded, answer)
    if recorded.has("event", "authority"):
        _authority_needs_a_response_that_admits(recorded, answer)
        _authority_is_the_authorization(recorded, answer)
    if recorded.text("event_type") == "execution_released":
        _release_needs_a_response_that_admits(recorded, answer)
    else:
        _state_agrees_with_the_outcome(recorded, answer)


def _records_the_action(event: _Object, request: _Object) -> None:
    if event.text("event", "action_id") != request.text("action", "action_id"):
        raise event.error("event.action_id is not the request's action")


def _repeats_the_operation(event: _Object, request: _Object) -> None:
    if not event.has("event", "operation"):
        return
    if event.text("event", "operation") != request.text("action", "operation"):
        raise event.error("event.operation is not the request's")


def _repeats_the_parameters(event: _Object, request: _Object) -> None:
    if not event.has("event", "parameters_digest"):
        return
    repeated = event.digest_pair("event", "parameters_digest")
    if repeated != request.digest_pair("action", "parameters_digest"):
        raise event.error("event.parameters_digest is not the request's")


def _repeats_the_target(event: _Object, request: _Object) -> None:
    # The uri only: the version and the digest of a target change with the effect.
    if not event.has("event", "target"):
        return
    if event.text("event", "target", "uri") != request.text("action", "target", "uri"):
        raise event.error("event.target.uri is not the request's")


def _names_the_response(event: _Object, response: _Object | None) -> None:
    if response is None:
        if event.has("event", "decision"):
            raise event.error("names a decision, and there is no response")
    elif event.text("event", "decision", "uri") != response.text("message_id"):
        raise event.error("event.decision is not the response")


def _records_the_digest_of_the_response(event: _Object, response: _Object) -> None:
    if event.digest("event", "decision", "digest") != _fingerprint(response.value, response):
        raise event.error("event.decision.digest is not the response's", DIGEST_MISMATCH)


def _admits(response: _Object | None) -> bool:
    return response is not None and response.text("outcome") == "admit"


def _authority_needs_a_response_that_admits(event: _Object, response: _Object | None) -> None:
    if not _admits(response):
        raise event.error("carries authority, and there is no response that admits")


def _authority_is_the_authorization(event: _Object, response: _Object | None) -> None:
    if response is None:
        raise event.error("carries authority, and there is no response")
    if event.text("event", "authority", "uri") != response.text(
        "authorization", "authorization_id"
    ):
        raise event.error("event.authority is not the response's authorization")


def _release_needs_a_response_that_admits(event: _Object, response: _Object | None) -> None:
    if not _admits(response):
        raise event.error("releases, and there is no response that admits")


def _state_agrees_with_the_outcome(event: _Object, response: _Object | None) -> None:
    state = event.text("event", "state")
    wanted = TERMINAL_STATE_OUTCOMES.get(state)
    if wanted is None:
        raise event.error("event.state is not a state that a terminal event may be in")
    outcome = None if response is None else response.text("outcome")
    if outcome not in wanted:
        raise event.error("event.state does not agree with the outcome of the response")


# --- check_authority_event_binding ---------------------------------------------------------------


def check_authority_event_binding(event: Mapping[str, Any], *, response: Mapping[str, Any]) -> None:
    """Raise BindingError unless the authority `event` records the authorization of `response`.

    Return None when it does. The rules and their codes are in the module docstring. No argument is
    changed.
    """
    recorded = _read(event, "event", DECISION_BINDING_INVALID)
    answer = _read(response, "response", DECISION_BINDING_INVALID)
    _require_event(recorded, _AUTHORITY_EVENTS, "authority")
    _require_message(answer, "decision_response")
    _records_an_authorization_that_was_granted(recorded, answer)
    _follows_the_response(recorded, answer)
    _same_text(recorded, answer, "workflow", "workflow_id")
    _same_text(recorded, answer, "workflow", "root_trace_id")
    _same_attempt(recorded, answer)


def _records_an_authorization_that_was_granted(event: _Object, response: _Object) -> None:
    if not _admits(response):
        raise event.error("records an authorization, and the response does not admit")
    granted = response.text("authorization", "authorization_id")
    if event.text("event", "authorization_id") != granted:
        raise event.error("event.authorization_id is not the response's")


def _follows_the_response(event: _Object, response: _Object) -> None:
    named = [
        item for item in _predecessors(event) if item.text("id") == response.text("message_id")
    ]
    if len(named) != 1:
        raise event.error("does not follow the response exactly once", DIGEST_MISMATCH)
    if named[0].digest("digest") != _fingerprint(response.value, response):
        raise event.error(
            "the digest of the response it follows is not the response's", DIGEST_MISMATCH
        )
