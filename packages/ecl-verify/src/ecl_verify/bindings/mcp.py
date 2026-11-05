"""Offline verification checks and read-only metadata for bindings.mcp."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from types import MappingProxyType
from typing import Any

from jsonschema.protocols import Validator

from ecl_verify.binding import BindingError, check_event_binding
from ecl_verify.canonical import same_json
from ecl_verify.semantic import Finding

from . import jcs
from .common import (
    ONE_WAY_RULE,
    SCHEMA_INVALID,
    array,
    binds,
    decoded_record,
    digest_of,
    extension_entries,
    extension_values,
    findings,
    instant,
    integer,
    is_encoded,
    member,
    message_findings,
    obj,
    one_way_response_problems,
    same_digest,
    text,
)

REVISION = "2026-07-28"

EXCHANGE_VERSION = "ecl_mcp_gateway_exchange_v1"

EXCHANGE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1"

BINDING_EXTENSION = "ecl.ext.mcp-binding.v1"

BINDING_SCHEMA = "https://externalcontrollayer.ai/ns/schema/extension/mcp-binding/1"

PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion"

SERVER_INFO_META = "io.modelcontextprotocol/serverInfo"

SIDE_EFFECTING = frozenset({"tools/call", "tasks/update"})

PASS_THROUGH = frozenset(
    {
        "server/discover",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        "subscriptions/listen",
    }
)

CALL_MEMBERS = frozenset({"jsonrpc", "id", "method", "params"})

SAFE_MAGNITUDE = 2**53 - 1

CLIENT_NOTIFICATIONS = frozenset({"notifications/cancelled"})

ERRORS: Mapping[str, int] = MappingProxyType(
    {
        "denied": -31001,
        "held": -31002,
        "challenged": -31003,
        "decision-unavailable": -31004,
        "decision-invalid": -31005,
        "authorization-unusable": -31006,
        "not-mapped": -31007,
        "unreviewed-change": -31008,
        "forward-failed": -31009,
        "obligation-unproven": -31010,
        "evidence-unavailable": -31011,
    }
)

MESSAGES: Mapping[str, str] = MappingProxyType(
    {
        "denied": "The request was denied.",
        "held": "The request is held.",
        "challenged": "The request needs an approval.",
        "decision-unavailable": "The decision service is unavailable.",
        "decision-invalid": "The decision could not be verified.",
        "authorization-unusable": "The authorization is not usable now.",
        "not-mapped": "The request has no reviewed mapping.",
        "unreviewed-change": "The tool changed and waits for review.",
        "forward-failed": "The server did not answer; the effect is unknown.",
        "obligation-unproven": "A pre-release obligation is not proven.",
        "evidence-unavailable": "The evidence of the release cannot be recorded.",
    }
)

REFUSAL_FOR_OUTCOME: Mapping[str, str] = MappingProxyType(
    {"deny": "denied", "hold": "held", "challenge": "challenged"}
)

INVALID_DECISION_REASONS = frozenset(
    {
        "ecl.error.dependency-response-invalid.v1",
        "ecl.error.integrity-invalid.v1",
        "ecl.error.request-binding-invalid.v1",
    }
)

SERVER_ERROR_CODE = -32603

CONTENT_PATHS: tuple[tuple[str, ...], ...] = (
    ("call",),
    ("tool_definition",),
    ("forwarded", "request"),
    ("server_response",),
    ("returned",),
)

CONTENT_DEFINITIONS: Mapping[tuple[str, ...], str] = MappingProxyType(
    {
        ("call",): "jsonRpcRequest",
        ("tool_definition",): "toolDefinition",
        ("forwarded", "request"): "jsonRpcRequest",
        ("server_response",): "jsonRpcResponse",
        ("returned",): "jsonRpcResponse",
    }
)

UNAVAILABLE = "ecl.error.dependency-unavailable.v1"

UNSUPPORTED = "ecl.error.binding-unsupported.v1"

UNREVIEWED = "ecl.error.control-change-unreviewed.v1"

EXPIRED = "ecl.error.expired.v1"

CLOCK_REGRESSED = "ecl.error.clock-regressed.v1"

REPLAY = "ecl.error.replay.v1"

OBLIGATION_UNPROVEN = "ecl.error.obligation-unproven.v1"

EVIDENCE_UNAVAILABLE = "ecl.error.evidence-unavailable.v1"

NON_RELEASE = frozenset({"denied", "held", "challenged", "expired_before_release"})

TABLE_CODES = frozenset(ERRORS.values())

DISCHARGE_EXTENSION = "ecl.ext.obligation-discharge.v1"

COUPLING_EXTENSION = "ecl.ext.consequence-coupling.v1"

VERIFY_WITNESS = "ecl.obligation.verify-witness.v1"

RECOVERY_CLASSES = frozenset({"not-released", "outcome-unknown", "outcome-recorded"})

FAILURE_RULE = "ecl.rule.mcp-decision-failure-not-forwarded.v1"

REVIEW_RULE = "ecl.rule.mcp-tool-mapped-and-reviewed.v1"

REQUEST_RULE = "ecl.rule.mcp-request-from-call.v1"

FORWARD_RULE = "ecl.rule.mcp-forward-requires-admit.v1"

OBLIGATION_RULE = "ecl.rule.mcp-obligations-discharged.v1"

REFUSAL_RULE = "ecl.rule.mcp-refusal-defined.v1"

RESULT_RULE = "ecl.rule.mcp-result-bound.v1"

RULES = (
    FAILURE_RULE,
    REVIEW_RULE,
    REQUEST_RULE,
    FORWARD_RULE,
    OBLIGATION_RULE,
    REFUSAL_RULE,
    RESULT_RULE,
)


class MappingError(ValueError):
    """The call cannot become a decision request; `cause` is its row of the error table."""

    def __init__(self, message: str, *, cause: str = "not-mapped") -> None:
        super().__init__(message)
        self.cause = cause


@dataclass(frozen=True)
class _ToolMapping:
    """A tool's mapping as declared with the Consequential Action Register (MG1-003).

    The target is the value of one argument, which must be a URI, or a fixed URI.
    """

    mapping_id: str
    server_id: str
    server_name: str
    server_version: str
    tool: str
    tool_definition_digest: Mapping[str, str]
    action_class: str
    operation: str
    risk_class: str
    evidence_profile: str
    target_argument: str | None = None
    target_uri: str | None = None

    @classmethod
    def from_record(cls, value: Mapping[str, Any]) -> _ToolMapping:
        return cls(
            mapping_id=value["mapping_id"],
            server_id=value["server_id"],
            server_name=value["server_name"],
            server_version=value["server_version"],
            tool=value["tool"],
            tool_definition_digest=dict(value["tool_definition_digest"]),
            action_class=value["action_class"],
            operation=value["operation"],
            risk_class=value["risk_class"],
            evidence_profile=value["evidence_profile"],
            target_argument=value.get("target_argument"),
            target_uri=value.get("target_uri"),
        )

    def target(self, arguments: Mapping[str, Any]) -> str | None:
        """The target URI the mapping derives from the call's arguments, or None."""
        if (self.target_argument is None) == (self.target_uri is None):
            return None
        if self.target_uri is not None:
            return self.target_uri
        found = arguments.get(str(self.target_argument))
        return found if type(found) is str and ":" in found else None


def tool_definition_digest(definition: Mapping[str, Any]) -> dict[str, str]:
    """The digest a mapping records for a tool definition as reviewed (MG1-003)."""
    return jcs.digest(dict(definition))


def changed(
    mapping: _ToolMapping, definition: Mapping[str, Any] | None, server: Mapping[str, Any] | None
) -> bool:
    """The tool definition or the server identity differs from the reviewed mapping (MG1-008)."""
    if definition is None or server is None:
        return True
    try:
        current = tool_definition_digest(definition)
    except jcs.JcsError:
        return True
    return (
        not same_digest(current, dict(mapping.tool_definition_digest))
        or server.get("name") != mapping.server_name
        or server.get("version") != mapping.server_version
        or definition.get("name") != mapping.tool
    )


def _expected_binding(
    mapping: _ToolMapping, params: Mapping[str, Any], *, method: str = "tools/call"
) -> dict[str, Any]:
    """The value of `ecl.ext.mcp-binding.v1` on a decision request (MG1-004): the server, tool,
    reviewed tool-definition digest and mapping, the digest of the call's complete `params`, its
    `_meta` included, which the gateway forwards exactly (MG1-005), and the digests of any input
    responses and request state. Raises jcs.JcsError for content without an RFC 8785 form."""
    value: dict[str, Any] = {
        "mcp_revision": REVISION,
        "method": method,
        "server_id": mapping.server_id,
        "server_name": mapping.server_name,
        "server_version": mapping.server_version,
        "tool": mapping.tool,
        "tool_definition_digest": dict(mapping.tool_definition_digest),
        "mapping_id": mapping.mapping_id,
        "params_digest": jcs.digest(dict(params)),
    }
    if "inputResponses" in params:
        value["input_responses_digest"] = jcs.digest(params["inputResponses"])
    if "requestState" in params:
        value["request_state_digest"] = jcs.digest(params["requestState"])
    return value


def arguments_of(call: Mapping[str, Any]) -> dict[str, Any]:
    """The call's `arguments`, read from their RFC 8785 canonical form as a record holds them
    (MG1-012), an empty object when the call has no `arguments` member; a MappingError when they
    are not an object, null included, or, so read, lie outside the restricted canonical profile.
    A floating-point number with an integral value, such as `2.0`, is an integer in RFC 8785
    form, so arguments that hold one are decided and bound as that integer (MG1-004); the call is
    forwarded in its RFC 8785 form, in which `2.0` is written `2`, the form that `params_digest`
    binds (MG1-005)."""
    params = member(call, "params")
    # An `arguments` of null is present and is not an object, so it is refused as a string would
    # be, not decided as if the call had none.
    if type(params) is not dict or "arguments" not in params:
        return {}
    arguments = params["arguments"]
    if type(arguments) is not dict:
        raise MappingError("the arguments are not an object")
    try:
        held = jcs.loads(jcs.canonicalize(arguments))
    except jcs.JcsError as error:
        raise MappingError("the arguments have no RFC 8785 form") from error
    if type(held) is not dict or digest_of(held) is None:
        raise MappingError("the arguments are outside the restricted canonical profile")
    return held


def _numbers(value: object, path: str) -> list[tuple[str, int | float]]:
    """(JSON Pointer, number) of each number in `value`, booleans excluded."""
    found: list[tuple[str, int | float]] = []
    pending: list[tuple[object, str]] = [(value, path)]
    while pending:
        item, where = pending.pop()
        if type(item) is dict:
            pending.extend(
                (child, f"{where}/{name.replace('~', '~0').replace('/', '~1')}")
                for name, child in item.items()
            )
        elif type(item) is list:
            pending.extend((child, f"{where}/{index}") for index, child in enumerate(item))
        elif type(item) in (int, float):
            found.append((where, item))  # type: ignore[arg-type]
    return sorted(found)


def numbers_in(value: object, path: str = "") -> list[tuple[str, int | float]]:
    """(JSON Pointer under `path`, number) of each number in `value`, booleans excluded, in the
    order of the pointers: what a gateway reads in every member of a request (MG1-004)."""
    return _numbers(value, path)


def unbound_problems(call: Mapping[str, Any], prefix: str = "/call") -> list[tuple[str, str]]:
    """(path, message) for each reason why MG1-004 has the gateway refuse a request with -31007,
    and not forward it, before any decision: a member other than `jsonrpc`, `id`, `method` and
    `params`, which no decision binds, and a number in `id` or `params` of magnitude greater than
    2^53 - 1, which RFC 8785 may not represent exactly. The gateway also refuses a number whose
    RFC 8785 form does not have the value written (`jcs.inexact_numbers`), which it sees in the
    text it receives; a record holds the call in canonical form, in which only the magnitude
    remains visible."""
    problems = [
        (f"{prefix}/{name.replace('~', '~0').replace('/', '~1')}", "no decision binds this member")
        for name in sorted(set(call) - CALL_MEMBERS)
    ]
    for name in ("id", "params"):
        if name not in call:
            continue
        problems.extend(
            (where, "the number's magnitude is greater than 2^53 - 1")
            for where, number in _numbers(call[name], f"{prefix}/{name}")
            if abs(number) > SAFE_MAGNITUDE
        )
    return problems


def _expected_returned(server_response: Mapping[str, Any]) -> dict[str, Any]:
    """The response a gateway returns for a forwarded request whose server answered (MG1-010):
    the server's response unchanged, except that a JSON-RPC error whose code is one of the error
    table's is returned with the code -32603, so that the governed AI system never reads a
    server's error as a refusal by the gateway."""
    result = copy.deepcopy(dict(server_response))
    error = result.get("error")
    if type(error) is dict and type(error.get("code")) is int and error["code"] in TABLE_CODES:
        result["error"] = {**error, "code": SERVER_ERROR_CODE}
    return result


def _expected_terminal(server_response: Mapping[str, Any] | None) -> tuple[str, str | None]:
    """The `execution_terminal` state and residual state for what the server returned (MG1-010).

    A complete result with `isError` false succeeded as the server reports it; a result with
    `isError` true, or a JSON-RPC error, failed; a request for input or a task handle leaves the
    effect unknown, as does no response at all.
    """
    if server_response is None:
        return "unknown", "no response from the server within the forwarding timeout"
    if "error" in server_response:
        return "failed", None
    result = server_response.get("result")
    if type(result) is not dict:
        return "unknown", "the server's response has neither a result nor an error"
    kind = result.get("resultType", "complete")
    if kind == "input_required":
        return "unknown", "the server asked for input; the retry is a new request"
    if kind == "task":
        return "unknown", "the server started a task; its later result is a new request"
    if kind != "complete":
        return "unknown", "the server's result type is not one this gateway reads"
    return ("failed", None) if result.get("isError") is True else ("succeeded", None)


@dataclass(frozen=True)
class _View:
    record: Mapping[str, Any]
    call: dict[str, Any]
    mapping: _ToolMapping | None
    request: dict[str, Any] | None
    response: dict[str, Any] | None
    status: str | None
    forwarded: dict[str, Any] | None
    released: dict[str, Any] | None = None
    recovery: dict[str, Any] | None = None

    @property
    def guard(self) -> int:
        """MG1-014: the record's release guard in nanoseconds, zero when it gives none."""
        milliseconds = integer(self.record, "release_guard_milliseconds")
        return 0 if milliseconds is None or milliseconds < 0 else milliseconds * 1_000_000

    def admitted(self) -> bool:
        return (
            self.status == "answered"
            and text(self.response, "outcome") == "admit"
            and binds(self.request, self.response)
        )


def _mapping(record: Mapping[str, Any]) -> _ToolMapping | None:
    value = obj(record, "mapping")
    if value is None:
        return None
    try:
        return _ToolMapping.from_record(value)
    except (KeyError, TypeError):
        return None


def _use_limit(response: object) -> int | None:
    if text(response, "authorization", "use_policy") == "single_use":
        return 1
    return integer(response, "authorization", "max_uses")


def _unusable(view: _View, at: int | None) -> str | None:
    """EXPIRED or REPLAY when an admit cannot be used at `at` and until the record's release
    guard after it (MG1-014), else None."""
    start = instant(member(view.response, "authorization", "valid_from"))
    end = instant(member(view.response, "authorization", "valid_until"))
    if at is None or start is None or end is None or not start <= at < end - view.guard:
        return EXPIRED
    limit = _use_limit(view.response)
    prior = integer(view.record, "prior_uses") or 0
    if limit is not None and prior + 1 > limit:
        return REPLAY
    return None


def _side_effecting(method: object) -> bool:
    """`method` names a request that MG1-002 sends to the Decision Layer. `refusal_cause` reads a
    call held in the encoded form of MG1-012 without holding it to the record schema's shape, as
    `check` does, so its method may be any JSON value."""
    return type(method) is str and method in SIDE_EFFECTING


def pre_release_obligations(response: object) -> tuple[list[tuple[str, str]], set[tuple[str, str]]]:
    """MG1-013 on an admit: what it leaves to Enforcement before the release, by (`obligation_id`,
    `type`), in order and each once: each obligation whose `satisfaction` is `before_release`, and
    each witness result of `ecl.ext.consequence-coupling.v1` whose `outcome` is
    `required_before_release`, named by the `uri` of its reference and the type
    `ecl.obligation.verify-witness.v1` (EBMP-2 EBMP2-070); and every obligation it carries, by the
    same keys, the deferred witnesses included."""
    required: list[tuple[str, str]] = []
    carried: set[tuple[str, str]] = set()
    for item in array(response, "obligations"):
        identifier, kind = text(item, "id"), text(item, "type")
        if identifier is None or kind is None:
            continue
        carried.add((identifier, kind))
        if member(item, "satisfaction") == "before_release" and (identifier, kind) not in required:
            required.append((identifier, kind))
    for value in extension_values(response, COUPLING_EXTENSION):
        witness = member(value, "witness_result")
        uri = text(witness, "reference", "uri")
        if member(witness, "outcome") == "required_before_release" and uri is not None:
            carried.add((uri, VERIFY_WITNESS))
            if (uri, VERIFY_WITNESS) not in required:
                required.append((uri, VERIFY_WITNESS))
    return required, carried


def repeated_obligation_ids(response: object) -> list[str]:
    """The ids that the response's obligation list names more than once: a gateway
    refuses such an admit before any use, as a response that fails its own rules (MG1-014)."""
    seen: set[str] = set()
    repeated: list[str] = []
    for item in array(response, "obligations"):
        identifier = text(item, "id")
        if identifier is None:
            continue
        if identifier in seen and identifier not in repeated:
            repeated.append(identifier)
        seen.add(identifier)
    return repeated


def discharge_problems(value: object, response: object, path: str) -> list[tuple[str, str]]:
    """(path, message) for each way the value of `ecl.ext.obligation-discharge.v1` at `path` fails to
    discharge what `response` leaves to Enforcement before the release (MG1-013): an entry that
    names an obligation the response does not carry or that another entry names, an entry whose
    `result` is not `satisfied`, and each pre-release obligation that no entry names."""
    required, carried = pre_release_obligations(response)
    problems: list[tuple[str, str]] = []
    named: set[tuple[str, str]] = set()
    for index, entry in enumerate(array(value, "obligations")):
        identifier, kind = text(entry, "obligation_id"), text(entry, "type")
        where = f"{path}/obligations/{index}"
        if identifier is None or kind is None or (identifier, kind) not in carried:
            problems.append((where, "names an obligation that the admit does not carry"))
            continue
        if (identifier, kind) in named:
            problems.append((where, "names an obligation that another entry names"))
            continue
        named.add((identifier, kind))
        if member(entry, "result") != "satisfied":
            problems.append((f"{where}/result", "records an obligation that was not met"))
    problems.extend(
        (path, f"no entry discharges the obligation {identifier} ({kind})")
        for identifier, kind in required
        if (identifier, kind) not in named
    )
    return problems


def _discharged(view: _View) -> bool:
    """The record shows a discharge of every pre-release obligation of its admit (MG1-013)."""
    required, _ = pre_release_obligations(view.response)
    if not required:
        return True
    value = obj(view.record, "obligation_discharge")
    return value is not None and not discharge_problems(value, view.response, "")


def refusal_cause(record: Mapping[str, Any]) -> tuple[str, str | None, str | None] | None:
    """(cause, reason, request_id) of the error table for a request the gateway refused, or None
     when nothing in the record required a refusal. The causes are tried in the order of MG1-006,
     and the first that holds is the one the gateway returns. A record cannot show that the
     gateway's evidence log failed (-31011, MG1-017): when the gateway returned that error, the cause
     is taken in its place in the order, after every earlier cause was found not to hold, or
     before an undischarged obligation when the terminal is `cancelled`: the use was then
     consumed, and the journal's failure cancelled the attempt before any proof was examined
    ."""
    record, _ = decoded_record(record, CONTENT_PATHS)
    view = _view(record)
    params = obj(view.call, "params")
    # An `arguments` member that is not an object, null included, is a cause of -31007, as the
    # gateway's `arguments_of` reads it: a null is not an absent member.
    present = params is not None and "arguments" in params
    arguments = params["arguments"] if params is not None and present else None
    if (
        view.mapping is None
        or unbound_problems(view.call)
        or not _side_effecting(view.call.get("method"))
        or member(params, "name") != view.mapping.tool
        or (present and (type(arguments) is not dict or digest_of(arguments) is None))
        or view.mapping.target(arguments if type(arguments) is dict else {}) is None
    ):
        return "not-mapped", UNSUPPORTED, None
    if changed(view.mapping, obj(record, "tool_definition"), obj(record, "server")):
        return "unreviewed-change", UNREVIEWED, None
    if view.status == "unavailable" or view.status is None:
        return "decision-unavailable", UNAVAILABLE, None
    if view.status == "invalid":
        reason = text(record, "decision", "error")
        return "decision-invalid", reason, None
    if not binds(view.request, view.response):
        return "decision-invalid", "ecl.error.request-binding-invalid.v1", None
    outcome = text(view.response, "outcome")
    request_id = text(view.response, "request_id")
    refused = REFUSAL_FOR_OUTCOME.get(outcome) if outcome is not None else None
    if refused is not None:
        reasons = member(view.response, "reasons")
        first = reasons[0] if type(reasons) is list and reasons else None
        return refused, text(first, "code"), request_id
    # MG1-017: once the use is consumed, a journal that fails cancels the attempt,
    # and that failure is the refusal's cause, whatever the gateway had still to discharge.
    if _journal_failed(record) and text(record, "terminal", "event", "state") == "cancelled":
        return "evidence-unavailable", EVIDENCE_UNAVAILABLE, request_id
    if not _discharged(view):
        return "obligation-unproven", OBLIGATION_UNPROVEN, request_id
    if _journal_failed(record):
        return "evidence-unavailable", EVIDENCE_UNAVAILABLE, request_id
    # MG1-014 and MG1-015: the write begins within the declared release guard after
    # the final observation, or not at all; a cancelled terminal observed later than the release
    # event plus the guard shows a write that could not begin in time.
    if _guard_exceeded(view):
        return "authorization-unusable", EXPIRED, request_id
    problem = _unusable(view, instant(member(record, "returned_at")))
    if problem is not None:
        return "authorization-unusable", problem, request_id
    return None


def _guard_exceeded(view: _View) -> bool:
    """A cancelled terminal observed later than the recorded release plus the record's release
    guard: the write could not begin within the guard (MG1-014), which the record shows."""
    if view.released is None or text(view.record, "terminal", "event", "state") != "cancelled":
        return False
    released_at = instant(member(view.released, "observed_at"))
    ended_at = instant(member(view.record, "terminal", "observed_at"))
    return released_at is not None and ended_at is not None and ended_at > released_at + view.guard


def _journal_failed(record: Mapping[str, Any]) -> bool:
    """The gateway returned -31011: its journal could not record an entry before the release
    (MG1-017), which the record itself cannot show."""
    return (
        member(record, "returned", "error", "code") == ERRORS["evidence-unavailable"]
        and member(record, "returned", "error", "data", "ecl", "code") == "evidence-unavailable"
    )


def _view(record: Mapping[str, Any]) -> _View:
    return _View(
        record=record,
        call=obj(record, "call") or {},
        mapping=_mapping(record),
        request=obj(record, "decision_request"),
        response=obj(record, "decision", "response"),
        status=text(record, "decision", "status"),
        forwarded=obj(record, "forwarded"),
        released=obj(record, "released"),
        recovery=obj(record, "recovery"),
    )


def _failure(view: _View) -> list[tuple[str, str]]:
    """MG1-007: a decision was sought, and the gateway forwarded although the decision service was
    unavailable, answered with no verified decision, or left no answer on record. A forward with
    no decision request at all is the concern of MG1-002 and MG1-005."""
    asked = view.status in ("unavailable", "invalid") or (
        view.status is None and view.request is not None
    )
    if view.forwarded is not None and asked:
        return [("/forwarded", "forwarded without a verified decision")]
    return []


def _review(view: _View) -> list[tuple[str, str]]:
    if view.forwarded is None:
        return []
    if not _side_effecting(view.call.get("method")):
        return [("/forwarded", "forwarded a request whose method has no mapping")]
    if view.mapping is None or member(view.call, "params", "name") != view.mapping.tool:
        return [("/forwarded", "forwarded a call to a tool that has no mapping")]
    if changed(view.mapping, obj(view.record, "tool_definition"), obj(view.record, "server")):
        return [("/forwarded", "forwarded a call to a tool whose change is not reviewed")]
    return []


def _request(view: _View) -> list[tuple[str, str]]:
    mapping, request = view.mapping, view.request
    if request is None:
        return []
    # MG1-004: a call with a member or a number that no decision can bind is refused, not decided.
    problems: list[tuple[str, str]] = unbound_problems(view.call)
    if mapping is None:
        return problems
    action = obj(request, "action") or {}
    for name, expected in (
        ("action_class", mapping.action_class),
        ("operation", mapping.operation),
        ("risk_class", mapping.risk_class),
        ("required_evidence_profile", mapping.evidence_profile),
    ):
        if action.get(name) != expected:
            problems.append((f"/decision_request/action/{name}", "not the mapping's"))
    params = obj(view.call, "params") or {}
    arguments = params.get("arguments", {})
    # MG1-004: the parameters are the call's arguments as the same JSON values, so a number never
    # stands for a boolean.
    if type(arguments) is not dict or not same_json(action.get("parameters"), arguments):
        problems.append(("/decision_request/action/parameters", "not the call's arguments"))
    elif not same_digest(action.get("parameters_digest"), digest_of(arguments)):
        problems.append(("/decision_request/action/parameters_digest", "not their digest"))
    if text(action, "target", "uri") != mapping.target(
        arguments if type(arguments) is dict else {}
    ):
        problems.append(("/decision_request/action/target", "not the target the mapping derives"))
    entries = extension_entries(request, BINDING_EXTENSION)
    values = extension_values(request, BINDING_EXTENSION)
    if len(entries) != 1 or len(values) != 1 or entries[0].get("critical") is not True:
        problems.append(("/decision_request/extensions", "the critical mcp-binding is missing"))
        return problems
    try:
        expected_value = _expected_binding(mapping, params, method=str(view.call.get("method")))
    except jcs.JcsError:
        expected_value = None
    if values[0] != expected_value:
        problems.append(
            ("/decision_request/extensions", "the mcp-binding does not name the call and mapping")
        )
    return problems


def _forward(view: _View) -> list[tuple[str, str]]:
    if view.forwarded is None:
        return []
    if not view.admitted():
        return [("/forwarded", "forwarded without an admit bound to the decision request")]
    problems: list[tuple[str, str]] = []
    forwarded_at = instant(member(view.forwarded, "forwarded_at"))
    problem = _unusable(view, forwarded_at)
    if problem is not None:
        problems.append(
            ("/forwarded/forwarded_at", "forwarded when the authorization was unusable")
        )
    # MG1-015: the forward's time is the final observation that the release event records.
    if view.released is not None and member(view.forwarded, "forwarded_at") != member(
        view.released, "observed_at"
    ):
        problems.append(
            ("/forwarded/forwarded_at", "not the observation that the release event records")
        )
    completed = instant(member(view.forwarded, "forward_completed_at"))
    if completed is not None and forwarded_at is not None and completed < forwarded_at:
        problems.append(
            ("/forwarded/forward_completed_at", "the send completed before the forward")
        )
    # MG1-015: the gateway's own observation of the write; the answer's arrival
    # after `valid_until` is not a late release.
    terminal = obj(view.record, "terminal")
    if any(
        value.get("released_after_valid_until") is True
        for value in extension_values(terminal, BINDING_EXTENSION)
    ):
        problems.append(
            ("/terminal/extensions", "the gateway observed the write at or after valid_until")
        )
    # MG1-014: the release event declares the guard that the record names.
    declared = integer(view.record, "release_guard_milliseconds")
    if (
        view.released is not None
        and declared is not None
        and integer(view.released, "event", "release_guard_ms") != declared
    ):
        problems.append(("/released/event/release_guard_ms", "not the record's release guard"))
    # MG1-014: an admit that names one obligation twice is refused before any use.
    if repeated_obligation_ids(view.response):
        problems.append(("/forwarded", "forwarded on an admit that names one obligation twice"))
    sent = obj(view.forwarded, "request") or {}
    bound = _admitted(view)
    # MG1-005: the gateway changes no member of the call, so each member is compared as the same
    # JSON value: an `id` of 1 forwarded as `true` is a changed member.
    problems.extend(
        (f"/forwarded/request/{name}", "not the call's")
        for name in ("jsonrpc", "id")
        if (name in sent) != (name in view.call)
        or not same_json(sent.get(name), view.call.get(name))
    )
    # MG1-005: exactly the call, so no member is added to it or removed from it.
    others = (set(sent) | set(view.call)) - {"jsonrpc", "id", "method", "params"}
    if any(
        name not in sent or name not in view.call or not same_json(sent[name], view.call[name])
        for name in others
    ):
        problems.append(("/forwarded/request", "adds, removes or changes a member of the call"))
    if not same_json(sent.get("method"), view.call.get("method")) or not bound.matches(
        "method", sent.get("method")
    ):
        problems.append(("/forwarded/request/method", "not the call's or not what the admit binds"))
    params = obj(sent, "params")
    for name in ("name", "arguments", "inputResponses", "requestState"):
        value = member(params, name)
        present = params is not None and name in params
        if not same_json(value, member(view.call, "params", name)) or not bound.matches(
            name, value, present=present
        ):
            problems.append(
                (f"/forwarded/request/params/{name}", "not the call's or not what the admit binds")
            )
    forwarded_params = member(sent, "params")
    if not same_json(forwarded_params, member(view.call, "params")) or not bound.binds_params(
        forwarded_params
    ):
        problems.append(("/forwarded/request/params", "not the call's or not what the admit binds"))
    return problems


@dataclass(frozen=True)
class _Bound:
    """What an admitted decision request binds of the request to forward (MG1-005): its method and
    tool from the request's `ecl.ext.mcp-binding.v1`, its arguments as `action.parameters`, the
    digest of its complete `params`, and the digests of any input responses and request state."""

    request: dict[str, Any] | None
    extension: dict[str, Any] | None

    def binds_params(self, params: object) -> bool:
        """The admitted request carries, as `params_digest`, the digest of the RFC 8785 form of
        `params` (MG1-004, MG1-005)."""
        if self.extension is None:
            # The request names no single binding; MG1-004's rule reports that.
            return True
        try:
            forwarded = jcs.digest(params) if type(params) is dict else None
        except jcs.JcsError:
            forwarded = None
        return forwarded is not None and same_digest(self.extension.get("params_digest"), forwarded)

    def matches(self, name: str, value: object, *, present: bool = True) -> bool:
        """`value`, the member `name` of the forwarded request's `params` (or its method), is what
        the admitted request binds, compared as the same JSON value."""
        if name == "arguments":
            parameters = member(self.request, "action", "parameters")
            return same_json(value if present else {}, parameters)
        if self.extension is None:
            # The request names no single binding; MG1-004's rule reports that, and only the
            # arguments can be compared here.
            return True
        if name == "method":
            return same_json(value, self.extension.get("method"))
        if name == "name":
            return same_json(value, self.extension.get("tool"))
        digest_name = {
            "inputResponses": "input_responses_digest",
            "requestState": "request_state_digest",
        }[name]
        if not present:
            return digest_name not in self.extension
        try:
            return same_digest(self.extension.get(digest_name), jcs.digest(value))
        except jcs.JcsError:
            return False


def _admitted(view: _View) -> _Bound:
    values = extension_values(view.request, BINDING_EXTENSION)
    return _Bound(view.request, values[0] if len(values) == 1 else None)


def _obligations(view: _View) -> list[tuple[str, str]]:
    """MG1-013: a forward on an admit that leaves obligations to Enforcement before the release
    rests on a release event that records the discharge of each of them."""
    if view.forwarded is None or not view.admitted():
        return []
    required, _ = pre_release_obligations(view.response)
    if not required:
        return []
    if view.released is None:
        return [("/released", "no release event records the discharge of the obligations")]
    entries = [
        (index, item)
        for index, item in enumerate(array(view.released, "extensions"))
        if type(item) is dict and item.get("id") == DISCHARGE_EXTENSION
    ]
    if len(entries) != 1 or type(entries[0][1].get("value")) is not dict:
        return [("/released/extensions", "the release records no single discharge")]
    index, entry = entries[0]
    problems = discharge_problems(
        entry["value"], view.response, f"/released/extensions/{index}/value"
    )
    held = obj(view.record, "obligation_discharge")
    if held is not None and not same_json(held, entry["value"]):
        problems.append(("/obligation_discharge", "not the discharge that the release records"))
    return problems


def _refusal(view: _View) -> list[tuple[str, str]]:
    if view.forwarded is not None or view.recovery is not None:
        # A recovered record holds no response returned to the governed AI system (MG1-016).
        return []
    returned = obj(view.record, "returned") or {}
    if "result" in returned or "error" not in returned:
        return [("/returned", "a request that was not forwarded got no error")]
    problems: list[tuple[str, str]] = []
    # A JSON-RPC error answers the call that has the same `id`, as the same JSON value.
    if (
        ("id" in returned) != ("id" in view.call)
        or not same_json(returned.get("id"), view.call.get("id"))
        or returned.get("jsonrpc") != "2.0"
    ):
        problems.append(("/returned/id", "the error does not answer the call"))
    cause = refusal_cause(view.record)
    if cause is None:
        return problems
    name, reason, request_id = cause
    data = member(returned, "error", "data", "ecl")
    expected: dict[str, Any] = {"code": name}
    if reason is not None:
        expected["reason"] = reason
    if request_id is not None:
        expected["request_id"] = request_id
    # MG1-014 step 5: a gateway refuses an authorization as unusable with
    # `ecl.error.clock-regressed.v1` when its clock readings disagreed, which the record cannot
    # show; a checker accepts that reason where the record shows the window as the cause.
    regressed = (
        {**expected, "reason": CLOCK_REGRESSED} if name == "authorization-unusable" else None
    )
    defined = data == expected or (regressed is not None and data == regressed)
    if member(returned, "error", "code") != ERRORS[name] or not defined:
        problems.append(("/returned/error", f"the cause {name} has another error"))
    return problems


def _recovered(view: _View, terminal: dict[str, Any] | None) -> list[tuple[str, str]]:
    """MG1-016: a recovered record claims only what its journal showed, and its terminal says when
    it was recovered; a record that is not recovered has no recovered terminal."""
    marked = [value.get("recovered_at") for value in extension_values(terminal, BINDING_EXTENSION)]
    if view.recovery is None:
        if any(item is not None for item in marked):
            return [("/terminal/extensions", "a terminal of recovery in a record that is not one")]
        return []
    if terminal is None:
        return [("/terminal", "a recovered record has no terminal event")]
    classification = text(view.recovery, "classification")
    state = text(terminal, "event", "state")
    at = member(view.recovery, "recovered_at")
    problems: list[tuple[str, str]] = []
    if classification == "outcome-recorded":
        if any(item is not None for item in marked):
            problems.append(("/terminal/extensions", "a recorded outcome is marked as recovered"))
        return problems
    if marked != [at]:
        problems.append(("/terminal/extensions", "the recovered terminal does not say when"))
    if classification == "outcome-unknown" and (
        view.forwarded is None or state != "unknown" or "server_response" in view.record
    ):
        problems.append(
            ("/terminal/event/state", "a released request of unknown outcome is not unknown")
        )
    if classification == "not-released" and (
        view.forwarded is not None or (state not in NON_RELEASE and state != "cancelled")
    ):
        problems.append(
            ("/terminal/event/state", "a request that was not released is recorded as released")
        )
    return problems


def _completion_problems(view: _View, terminal: dict[str, Any]) -> list[tuple[str, str]]:
    """MG1-015: the terminal of a forward records its completion as the record does. Whether the
    release was late is the gateway's own observation (`released_after_valid_until`), which the
    forward rule reads; it is not derived from the completion."""
    values = extension_values(terminal, BINDING_EXTENSION)
    completed = member(view.forwarded, "forward_completed_at")
    if len(values) != 1:
        return []
    if values[0].get("forward_completed_at") != completed:
        return [("/terminal/extensions", "the terminal does not record the forward's completion")]
    return []


def _result(view: _View) -> list[tuple[str, str]]:
    terminal = obj(view.record, "terminal")
    problems: list[tuple[str, str]] = _recovered(view, terminal)
    if view.forwarded is None:
        state = text(terminal, "event", "state")
        # MG1-014: a refusal after the authorization was consumed is a cancelled attempt, and a
        # cancelled attempt is one whose use the gateway consumed, or that recovery settled. A
        # journal that failed (MG1-017) may have recorded the consumed use and not the prepared
        # release, which the record then cannot show.
        consumed = view.record.get("prepared") is not None or view.released is not None
        unseen = view.recovery is not None or _journal_failed(view.record)
        allowed = (
            {"cancelled"} if consumed else (NON_RELEASE | {"cancelled"} if unseen else NON_RELEASE)
        )
        if terminal is not None and state not in allowed:
            problems.append(("/terminal/event/state", "a refused request is recorded as released"))
        return problems
    if view.recovery is not None:
        # The journal does not show what the governed AI system received (MG1-016).
        if terminal is not None and view.request is not None:
            try:
                check_event_binding(terminal, request=view.request, response=view.response)
            except BindingError as error:
                problems.append(("/terminal", f"the terminal event is not bound: {error.code}"))
        return problems
    server_response = obj(view.record, "server_response")
    returned = obj(view.record, "returned")
    # MG1-010: the response returned is the one the evidence binds, as the same JSON values, so
    # `false` returned as `0` is another response.
    if server_response is not None and not same_json(returned, _expected_returned(server_response)):
        problems.append(("/returned", "not the response the evidence binds, as MG1-010 returns it"))
    if server_response is None and member(returned, "error", "code") != ERRORS["forward-failed"]:
        problems.append(("/returned", "an unanswered forward is not reported as forward-failed"))
    if terminal is None:
        return [*problems, ("/terminal", "a forwarded request has no terminal evidence")]
    state, _ = _expected_terminal(server_response)
    if text(terminal, "event", "state") != state:
        problems.append(("/terminal/event/state", f"the server's response reads as {state}"))
    problems.extend(_completion_problems(view, terminal))
    values = extension_values(terminal, BINDING_EXTENSION)
    try:
        bound = None if server_response is None else jcs.digest(server_response)
    except jcs.JcsError:
        bound = None
    if server_response is not None and (
        len(values) != 1 or not same_digest(values[0].get("response_digest"), bound)
    ):
        problems.append(("/terminal/extensions", "the evidence does not bind the response"))
    if view.request is not None:
        try:
            check_event_binding(terminal, request=view.request, response=view.response)
        except BindingError as error:
            problems.append(("/terminal", f"the terminal event is not bound: {error.code}"))
    return problems


@cache
def _definition_validator(name: str) -> Validator:
    # validator_for builds a registry on every call. This validator is only ever read from.
    from ecl_verify.resources import validator_for

    return validator_for(EXCHANGE_SCHEMA).evolve(
        schema={"$ref": f"{EXCHANGE_SCHEMA}#/$defs/{name}"}
    )


def decoded_content_problems(
    record: Mapping[str, Any], decoded: Mapping[str, Any]
) -> list[tuple[str, str]]:
    """(path, message) for each member of `record` held in the encoded form of MG1-012 whose
    content, as `decoded` holds it, does not satisfy the definition that the record schema gives
    the same content held as itself: a call or a forwarded request with a null `id` or a
    `jsonrpc` of "1.0" fails `jsonRpcRequest` in either form."""
    problems: list[tuple[str, str]] = []
    for path, name in CONTENT_DEFINITIONS.items():
        if not is_encoded(member(record, *path)):
            continue
        if not _definition_validator(name).is_valid(member(decoded, *path)):
            problems.append(("/" + "/".join(path), f"the decoded content does not satisfy {name}"))
    return problems


def check(record: Mapping[str, Any]) -> list[Finding]:
    """The findings of an `ecl_mcp_gateway_exchange_v1` record that its schema has accepted.

    A member in the encoded form of MG1-012 is decoded first; a member that does not decode, or
    whose content does not satisfy the definition that the record schema gives the same content
    held as itself, fails the record's schema, and the profile's rules are then not applied.
    """
    decoded, problems = decoded_record(record, CONTENT_PATHS)
    if not problems:
        problems = decoded_content_problems(record, decoded)
    if problems:
        return findings(SCHEMA_INVALID, problems)
    view = _view(decoded)
    result = findings(FAILURE_RULE, _failure(view))
    result += findings(REVIEW_RULE, _review(view))
    result += findings(REQUEST_RULE, _request(view))
    result += findings(FORWARD_RULE, _forward(view))
    result += findings(OBLIGATION_RULE, _obligations(view))
    result += findings(REFUSAL_RULE, _refusal(view))
    result += findings(RESULT_RULE, _result(view))
    if view.status == "answered":
        # MG1-007: a decision held as answered is a verified decision response, which carries
        # exactly one decision basis and satisfies DCMP2-053 as any decision response does.
        result += findings(
            ONE_WAY_RULE,
            one_way_response_problems(decoded, (("decision_request",), ("decision", "response"))),
        )
    # MG1-007: each DCMP-2 message that the record holds satisfies the semantic rules of DCMP-2,
    # other than the response of a decision whose status is `invalid`: the gateway refused that
    # response, and the record keeps it as evidence of what it refused.
    held: tuple[tuple[str, ...], ...] = (("decision_request",),)
    if view.status != "invalid":
        held += (("decision", "response"),)
    result += message_findings(decoded, *held)
    return result
