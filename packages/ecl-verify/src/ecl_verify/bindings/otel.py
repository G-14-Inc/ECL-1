"""Offline verification checks and read-only metadata for bindings.otel."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ecl_verify.canonical import (
    CanonicalizationError,
    canonicalize,
    loads_json_strict,
    same_json,
)
from ecl_verify.semantic import Finding

from .common import array, findings, instant, member, obj, text

_DECIMAL = re.compile(r"-?(0|[1-9][0-9]{0,19})")

_FIXED64 = 2**64

_KEYED_HEX = re.compile(r"[0-9a-f]{64}")

PROFILE = "OTEL-EVIDENCE-EXPORT-1/1.0"

EXPORT_KEYS_VERSION = "ecl_otel_export_keys_v1"

MIN_EXPORT_KEY_BYTES = 32

OBJECT_DIGEST = "ecl.object.digest"

PARAMETERS_DIGEST = "ecl.action.parameters_digest"

KEY_ID = "ecl.export.key_id"

KEYED = frozenset({OBJECT_DIGEST, PARAMETERS_DIGEST, KEY_ID})

EXPORT_VERSION = "ecl_otel_export_record_v1"

EXPORT_SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/otel-export/1"

SCOPE_NAME = "ecl_verify.bindings.otel"

OUTCOME_REASON = "ecl.ext.outcome-reason.v1"

INFO, WARN, ERROR = 9, 13, 17

SEVERITY_TEXT = {INFO: "INFO", WARN: "WARN", ERROR: "ERROR"}

WARN_STATES = frozenset(
    {
        "denied",
        "held",
        "challenged",
        "expired_before_release",
        "rolled_back",
        "compensated",
    }
)

ERROR_STATES = frozenset({"failed", "partially_succeeded", "timed_out", "cancelled", "unknown"})

EMERGENCY_OPERATIONS = frozenset({"halt", "quarantine"})

DECLARED_ONLY = frozenset({"ecl.actor.id", "ecl.subject.id", "ecl.action.target"})

EXECUTION_KIND = "execution"

DECISION_KIND = "decision"

AUTHORITY_KIND = "authority"

REQUEST_KIND = "request"

TERMINAL_EVENT = "execution_terminal"

DECISION_REQUEST = "decision_request"

DECISION_RESPONSE = "decision_response"

REQUEST_ID_TYPES = frozenset({DECISION_RESPONSE, "challenge", "challenge_response"})

REQUEST_ID = "ecl.request.id"

_DCMP_ALL: dict[str, tuple[str, ...]] = {"ecl.issuer.id": ("issuer", "id")}

_DCMP_REQUEST: dict[str, tuple[str, ...]] = {
    "ecl.action.class": ("action", "action_class"),
    "ecl.actor.id": ("actor", "id"),
    "ecl.subject.id": ("subject", "id"),
}

_DCMP_RESPONSE: dict[str, tuple[str, ...]] = {
    "ecl.decision.id": ("decision_id",),
    "ecl.decision.outcome": ("outcome",),
    "ecl.decision.safe_state": ("safe_state",),
    "ecl.policy.id": ("policy", "id"),
    "ecl.policy.version": ("policy", "version"),
    "ecl.policy.digest": ("policy", "digest", "value"),
}

_EBMP_ONLY: dict[str, tuple[str, ...]] = {
    "ecl.producer.id": ("producer", "id"),
    "ecl.event.kind": ("event", "kind"),
    "ecl.event.state": ("event", "state"),
}

_EBMP_REQUEST: dict[str, tuple[str, ...]] = {REQUEST_ID: ("event", "request", "uri")}

_DCMP_ACTION: dict[str, tuple[str, ...]] = {
    "ecl.action.id": ("action", "action_id"),
    "ecl.action.operation": ("action", "operation"),
    "ecl.action.target": ("action", "target", "uri"),
}

_EBMP_ACTION: dict[str, tuple[str, ...]] = {
    "ecl.action.id": ("event", "action_id"),
    "ecl.action.operation": ("event", "operation"),
    "ecl.action.target": ("event", "target", "uri"),
}

TABLE = frozenset(
    {
        "ecl.export.profile",
        "ecl.protocol",
        "ecl.object.id",
        "ecl.object.type",
        *KEYED,
        "ecl.workflow.id",
        "ecl.workflow.root_trace_id",
        "ecl.workflow.attempt",
        "ecl.workflow.sequence",
        "ecl.evidence.bundle",
        "ecl.decision.reason_code",
        "ecl.authorization.id",
        "ecl.event.decision_id",
        "ecl.event.reason_code",
        REQUEST_ID,
        *_DCMP_ALL,
        *_DCMP_REQUEST,
        *_DCMP_RESPONSE,
        *_EBMP_ONLY,
        *_DCMP_ACTION,
    }
)

EXPORT_RULE = "ecl.rule.otel-export-after-evidence.v1"

MATCH_RULE = "ecl.rule.otel-record-matches-object.v1"

MINIMIZED_RULE = "ecl.rule.otel-record-minimized.v1"

SEVERITY_RULE = "ecl.rule.otel-severity-mapped.v1"

RULES = (EXPORT_RULE, MATCH_RULE, MINIMIZED_RULE, SEVERITY_RULE)


@dataclass(frozen=True)
class ExportKey:
    """A deployment's export key (OE1-010): a secret of at least 32 bytes that keys the digests of
    exported records and nothing else, and an identifier that is not derived from it. The key is
    left out of the representation, so that it does not reach a log by accident."""

    key_id: str
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.key_id) is not str or not 1 <= len(self.key_id) <= 256:
            raise ValueError("an export key identifier is a string of 1 to 256 characters")
        if type(self.key) is not bytes or len(self.key) < MIN_EXPORT_KEY_BYTES:
            raise ValueError(f"an export key has at least {MIN_EXPORT_KEY_BYTES} bytes")

    def digest(self, value: object) -> str:
        """HMAC-SHA-256 under the key of the restricted canonical JSON of `value`, hexadecimal."""
        return hmac.new(self.key, canonicalize(value), hashlib.sha256).hexdigest()


def load_export_keys(data: bytes) -> dict[str, ExportKey]:
    """The export keys of a key file, by identifier.

    The file is strict JSON: `{"schema_version": "ecl_otel_export_keys_v1", "keys": [...]}`, each
    key `{"key_id": ..., "key": ...}` with the key in canonical base64, at least 32 bytes, and
    every identifier once. A file that is not exactly that raises ValueError, whose message never
    holds key material.
    """
    value = loads_json_strict(data)
    if (
        type(value) is not dict
        or set(value) != {"schema_version", "keys"}
        or value["schema_version"] != EXPORT_KEYS_VERSION
        or type(value["keys"]) is not list
        or not value["keys"]
    ):
        raise ValueError(f"not an {EXPORT_KEYS_VERSION} document with at least one key")
    keys: dict[str, ExportKey] = {}
    for item in value["keys"]:
        if type(item) is not dict or set(item) != {"key_id", "key"} or type(item["key"]) is not str:
            raise ValueError("an export key entry has exactly a key_id and a key")
        try:
            material = base64.b64decode(item["key"], validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("an export key is base64") from error
        if base64.b64encode(material).decode("ascii") != item["key"]:
            raise ValueError("an export key is canonical base64")
        key = ExportKey(item["key_id"], material)
        if key.key_id in keys:
            raise ValueError("an export key identifier appears more than once")
        keys[key.key_id] = key
    return keys


def _pick(value: object, path: tuple[str, ...]) -> str | int | None:
    found = member(value, *path)
    return found if type(found) in (str, int) else None  # type: ignore[return-value]


def _event_kind(value: Mapping[str, Any]) -> str | None:
    """The kind of an EBMP-2 event, or None for any other object."""
    if value.get("protocol") == "DCMP-2":
        return None
    return text(value, "event", "kind")


def _parameters_digest(value: Mapping[str, Any]) -> object:
    """The parameters digest member of a decision request or an execution event, if any."""
    if value.get("protocol") == "DCMP-2":
        if value.get("message_type") != DECISION_REQUEST:
            return None
        return member(value, "action", "parameters_digest")
    if _event_kind(value) != EXECUTION_KIND:
        return None
    return member(value, "event", "parameters_digest")


def object_digest_hex(value: Mapping[str, Any]) -> str:
    """The hexadecimal SHA-256 of the restricted canonical JSON of an ECL object (IE1-001), which
    the bundle's references carry and which a log record never does (OE1-004)."""
    return hashlib.sha256(canonicalize(dict(value))).hexdigest()


def unkeyed_digests(value: Mapping[str, Any]) -> dict[str, str]:
    """The digests that anyone can compute from the object, by the attribute that would carry
    them: the SHA-256 of the object and the value of its parameters digest (OE1-004)."""
    found = {OBJECT_DIGEST: object_digest_hex(value)}
    parameters = member(_parameters_digest(value), "value")
    if type(parameters) is str:
        found[PARAMETERS_DIGEST] = parameters
    return found


def object_time(value: Mapping[str, Any]) -> str | None:
    """The time a record copies: a message's `issued_at` or an event's `observed_at`."""
    name = "issued_at" if value.get("protocol") == "DCMP-2" else "observed_at"
    found = value.get(name)
    return found if type(found) is str else None


def event_name(value: Mapping[str, Any]) -> str:
    if value.get("protocol") == "DCMP-2":
        return "ecl.dcmp." + str(value.get("message_type"))
    return "ecl.ebmp." + str(value.get("event_type"))


def _expected_attributes(
    value: Mapping[str, Any],
    *,
    bundle_id: str | None = None,
    export_key: ExportKey | None = None,
    declared: Iterable[str] = (),
) -> dict[str, str | int]:
    """The attribute table of OTEL-EVIDENCE-EXPORT-1 for one object, each the object's own value.

    With `export_key`, the object's digest and its parameters digest are keyed with it and the
    key is named (OE1-010); without one, no digest is exported (OE1-004). The identifiers of
    people and records are exported only when `declared` names them (OE1-005). A row applies only
    to the objects it names: the action rows to a decision request and to execution events, the
    rows of a decision to a decision response, the request's identifier to a decision response, a
    challenge, a challenge response and a request event, the event's decision to decision and
    execution events, the authorization to an admit and to authority events, and the reason code
    to a terminal event.
    """
    names = frozenset(declared)
    dcmp = value.get("protocol") == "DCMP-2"
    identifier = value.get("message_id") if dcmp else value.get("object_id")
    kind = value.get("message_type") if dcmp else value.get("event_type")
    result: dict[str, str | int] = {
        "ecl.export.profile": PROFILE,
        "ecl.protocol": str(value.get("protocol")),
        "ecl.object.id": str(identifier),
        "ecl.object.type": str(kind),
    }
    if export_key is not None:
        result[OBJECT_DIGEST] = export_key.digest(dict(value))
        result[KEY_ID] = export_key.key_id
        parameters = _parameters_digest(value)
        if type(parameters) is dict:
            result[PARAMETERS_DIGEST] = export_key.digest(parameters)
    for name, step in (
        ("ecl.workflow.id", "workflow_id"),
        ("ecl.workflow.root_trace_id", "root_trace_id"),
        ("ecl.workflow.attempt", "attempt"),
        ("ecl.workflow.sequence", "sequence"),
    ):
        found = _pick(value, ("workflow", step))
        if found is not None:
            result[name] = found
    if bundle_id is not None:
        result["ecl.evidence.bundle"] = bundle_id
    kind = _event_kind(value)
    message_type = value.get("message_type") if dcmp else None
    tables: list[dict[str, tuple[str, ...]]] = []
    if dcmp:
        tables.append(_DCMP_ALL)
        if message_type == DECISION_REQUEST:
            tables += [_DCMP_REQUEST, _DCMP_ACTION]
        if message_type == DECISION_RESPONSE:
            tables.append(_DCMP_RESPONSE)
        if message_type in REQUEST_ID_TYPES:
            tables.append({REQUEST_ID: ("request_id",)})
    else:
        tables.append(_EBMP_ONLY)
        if kind == EXECUTION_KIND:
            tables.append(_EBMP_ACTION)
        if kind == REQUEST_KIND:
            tables.append(_EBMP_REQUEST)
    for table in tables:
        for name, path in table.items():
            found = _pick(value, path)
            if found is not None and (name not in DECLARED_ONLY or name in names):
                result[name] = found
    if dcmp:
        authorization = None
        if message_type == DECISION_RESPONSE:
            reasons = value.get("reasons")
            first = reasons[0] if type(reasons) is list and reasons else None
            if text(first, "code") is not None:
                result["ecl.decision.reason_code"] = str(text(first, "code"))
            authorization = text(value, "authorization", "authorization_id")
    else:
        authorization = text(value, "event", "authorization_id") if kind == AUTHORITY_KIND else None
        if kind in (DECISION_KIND, EXECUTION_KIND):
            decision = text(value, "event", "decision", "uri")
            if decision is not None:
                result["ecl.event.decision_id"] = decision
        if value.get("event_type") == TERMINAL_EVENT:
            for item in array(value, "extensions"):
                if type(item) is dict and item.get("id") == OUTCOME_REASON:
                    code = text(item, "value", "code")
                    if code is not None:
                        result["ecl.event.reason_code"] = code
    if authorization is not None:
        result["ecl.authorization.id"] = authorization
    return result


def severity(value: Mapping[str, Any]) -> int:
    """The SeverityNumber of the severity table (OE1-008)."""
    if value.get("protocol") == "DCMP-2":
        outcome = value.get("outcome")
        if outcome in ("deny", "hold", "challenge"):
            return WARN
        if value.get("message_type") == "control" and text(value, "operation") in (
            EMERGENCY_OPERATIONS
        ):
            return ERROR
        return INFO
    if value.get("event_type") == "execution_terminal":
        state = text(value, "event", "state")
        if state in WARN_STATES:
            return WARN
        if state in ERROR_STATES:
            return ERROR
    return INFO


def _decimal(raw: object) -> int | None:
    """A decimal integer string of the OTLP JSON encoding as an integer, or None when it is not
    one: at most 20 digits, and no whitespace, sign other than a leading minus, digit separator or
    leading zero."""
    if type(raw) is not str or not _DECIMAL.fullmatch(raw):
        return None
    return int(raw)


def _fixed64(raw: object) -> int | None:
    """A `fixed64` of the OTLP JSON encoding, such as a timestamp, as an integer, or None when it is
    not decimal text of an integer from 0 to 2^64 - 1 (OE1-007)."""
    number = _decimal(raw)
    return number if number is not None and 0 <= number < _FIXED64 else None


def _attribute_map(log: Mapping[str, Any]) -> dict[str, object]:
    """The record's attributes by key: a `stringValue` as its string and an `intValue` that is
    decimal text as its exact integer (OE1-003, OE1-007). Any other AnyValue, such as a
    `bytesValue` that holds the same text or a `boolValue`, is kept as the AnyValue object, which
    equals no value that the attribute table copies. A key that appears more than once
    keeps its last attribute here, and `_match` reports the repetition."""
    result: dict[str, object] = {}
    for item in array(log, "attributes"):
        value = member(item, "value")
        if type(item) is not dict or type(value) is not dict or len(value) != 1:
            continue
        kind, raw = next(iter(value.items()))
        number = _decimal(raw) if kind == "intValue" else None
        if number is not None:
            result[str(item.get("key"))] = number
        elif kind == "stringValue":
            result[str(item.get("key"))] = raw
        else:
            result[str(item.get("key"))] = dict(value)
    return result


def _declared(record: Mapping[str, Any]) -> frozenset[str]:
    """The attribute names that the record's export policy declares."""
    return frozenset(
        name
        for item in array(record, "declared_attributes")
        if (name := text(item, "name")) is not None
    )


def _export(record: Mapping[str, Any], value: Mapping[str, Any]) -> list[tuple[str, str]]:
    problems: list[tuple[str, str]] = []
    attempted = instant(member(record, "export", "attempted_at"))
    recorded = instant(object_time(value))
    if attempted is None or recorded is None or attempted < recorded:
        problems.append(("/export/attempted_at", "the exporter read the object before its time"))
    after = obj(record, "evidence_after")
    if after is not None:
        try:
            same = canonicalize(after) == canonicalize(dict(value))
        except CanonicalizationError:
            same = False
        if not same:
            problems.append(("/evidence_after", "the evidence differs after the export"))
    return problems


def _match(
    record: Mapping[str, Any], value: Mapping[str, Any], export_keys: Mapping[str, ExportKey]
) -> list[tuple[str, str]]:
    log = obj(record, "log_record") or {}
    problems: list[tuple[str, str]] = []
    if log.get("eventName") != event_name(value):
        problems.append(("/log_record/eventName", "not the object's event name"))
    at = instant(object_time(value))
    if at is None or _fixed64(log.get("timeUnixNano")) != at:
        problems.append(("/log_record/timeUnixNano", "not the object's time"))
    # OE1-003, OE1-007: the observed time is a fixed64 of nanoseconds, so a decimal text of up to
    # 20 digits beyond 2^64 - 1 is no time at all (H10).
    observed = _fixed64(log.get("observedTimeUnixNano"))
    if at is not None and observed is None:
        problems.append(("/log_record/observedTimeUnixNano", "not a fixed64 time"))
    elif at is not None and observed is not None and observed < at:
        problems.append(("/log_record/observedTimeUnixNano", "earlier than the object's time"))
    actual = _attribute_map(log)
    declared = _declared(record)
    named = actual.get(KEY_ID)
    if named is not None and type(named) is not str:
        # OE1-010: the record carries the key's identifier, a string.
        problems.append(("/log_record/attributes", f"{KEY_ID} is not the identifier of a key"))
    key = export_keys.get(named) if type(named) is str else None
    # A record that names a key the caller does not hold: its keyed digests cannot be computed. The
    # parameters digest is among them only for an object that has one (OE1-010); on any other
    # object it copies nothing, as it does under a key the caller holds.
    unverifiable: frozenset[str] = frozenset()
    if named is not None and key is None:
        unverifiable = (
            KEYED if type(_parameters_digest(value)) is dict else KEYED - {PARAMETERS_DIGEST}
        )
    # An identifier of a person or record exported without its declaration is the concern of
    # OE1-005 (the minimization rule), not of this one.
    undeclared = DECLARED_ONLY - declared
    try:
        expected = _expected_attributes(
            value, bundle_id=text(record, "bundle_id"), export_key=key, declared=declared
        )
        unkeyed = unkeyed_digests(value)
    except CanonicalizationError:
        return [*problems, ("/object", "the object is outside the restricted canonical profile")]
    for name, item in sorted(expected.items()):
        if name == "ecl.evidence.bundle" and name not in actual:
            continue
        # An attribute holds the value it copies as the same JSON value, so a `boolValue` of true
        # is not an attempt of 1.
        if not same_json(actual.get(name), item):
            problems.append(("/log_record/attributes", f"{name} is not the object's value"))
    problems.extend(
        ("/log_record/attributes", f"{name} copies nothing in the object")
        for name in sorted((set(actual) & TABLE) - set(expected) - unverifiable - undeclared)
    )
    # OE1-010: with an export key, every record carries the keyed digest of the object and, where
    # the object has a parameters digest, the keyed parameters digest, under a key the caller does
    # not hold as under one it holds (H10).
    problems.extend(
        ("/log_record/attributes", f"{KEY_ID} is named without the keyed {name}")
        for name in (OBJECT_DIGEST, PARAMETERS_DIGEST)
        if name in unverifiable and name not in actual
    )
    # OE1-003, OE1-010: a keyed digest that the caller cannot compute is still held as the
    # stringValue that the table gives, an HMAC in lowercase hexadecimal, so that no other kind or
    # form, such as the object's SHA-256 as a bytesValue of its bytes, carries past OE1-004 a digest
    # that needs no key.
    problems.extend(
        ("/log_record/attributes", f"{name} is not an HMAC in lowercase hexadecimal")
        for name in sorted(unverifiable & {OBJECT_DIGEST, PARAMETERS_DIGEST})
        if name in actual
        and not (type(actual[name]) is str and _KEYED_HEX.fullmatch(str(actual[name])))
    )
    # OTLP: the attribute keys of a record are unique; the map above keeps only the last of a
    # repeated key, which would hide an earlier one from every comparison.
    keys = [item.get("key") for item in array(log, "attributes") if type(item) is dict]
    if len(keys) != len(set(map(str, keys))):
        problems.append(("/log_record/attributes", "an attribute key is repeated"))
    # OE1-004: a digest that needs no key, held as the stringValue that the table gives. In any
    # other kind it is refused above: under a key the caller holds as not the object's value,
    # without a key as copying nothing, and under a key the caller does not hold as not an HMAC
    # in lowercase hexadecimal.
    problems.extend(
        ("/log_record/attributes", f"{name} is a digest that needs no export key")
        for name, digest in sorted(unkeyed.items())
        if type(actual.get(name)) is str and actual.get(name) == digest
    )
    return problems


def _minimized(record: Mapping[str, Any]) -> list[tuple[str, str]]:
    log = obj(record, "log_record") or {}
    declared = _declared(record)
    problems = [
        ("/log_record/attributes", f"{name} is neither in the table nor declared")
        for name in sorted(_attribute_map(log))
        if name not in TABLE and name not in declared
    ]
    problems.extend(
        ("/log_record/attributes", f"{name} identifies a person or record and is not declared")
        for name in sorted(_attribute_map(log))
        if name in DECLARED_ONLY and name not in declared
    )
    if "body" in log and "body" not in declared:
        problems.append(("/log_record/body", "a body is exported without a declaration"))
    return problems


def check(
    record: Mapping[str, Any], export_keys: Mapping[str, ExportKey] | None = None
) -> list[Finding]:
    """The findings of an `ecl_otel_export_record_v1` record that its schema has accepted.

    `export_keys` are the export keys the caller holds, by identifier: a keyed digest is compared
    only when the record names one of them (OE1-010).
    """
    value = obj(record, "object")
    if value is None:
        return []
    result = findings(EXPORT_RULE, _export(record, value))
    result += findings(MATCH_RULE, _match(record, value, export_keys or {}))
    result += findings(MINIMIZED_RULE, _minimized(record))
    number = severity(value)
    if member(record, "log_record", "severityNumber") != number:
        result.append(
            Finding(SEVERITY_RULE, "/log_record/severityNumber", "not the severity table's")
        )
    if member(record, "log_record", "severityText") != SEVERITY_TEXT[number]:
        result.append(
            Finding(SEVERITY_RULE, "/log_record/severityText", "not the severity table's name")
        )
    return result
