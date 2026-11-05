/**
 * OTEL-EVIDENCE-EXPORT-1: copies of ECL decisions and evidence as OpenTelemetry log records.
 *
 * `logAttributes` is the profile's attribute table for one DCMP-2 message or EBMP-2 event,
 * `severity` its severity table, and `check` reads an `ecl_otel_export_record_v1` record (OE1-009)
 * that its schema has accepted and reports:
 *
 * - `ecl.rule.otel-export-after-evidence.v1` (OE1-001, OE1-002): the exporter read the object
 *   before its time, or the evidence differs after the export, failed or not;
 * - `ecl.rule.otel-record-matches-object.v1` (OE1-003, OE1-004, OE1-010): an event name, time,
 *   observed time earlier than the object's time or outside the range of a `fixed64`, attribute or
 *   keyed digest that is not the object's, an attribute held in another AnyValue kind than the
 *   table gives, an attribute key that appears more than once, a digest that needs no key, a key
 *   identifier that is not a string, or a record that names an export key without the keyed
 *   digests that the object has. A keyed digest is compared when the caller supplies the key that
 *   the record names; without it, the checker holds each keyed digest to its form, the
 *   `stringValue` of an HMAC in lowercase hexadecimal, and recognizes the digests that need no key;
 * - `ecl.rule.otel-record-minimized.v1` (OE1-005): an attribute or a body that is neither in the
 *   attribute table nor declared, or an identifier of a person or record exported without its
 *   declaration;
 * - `ecl.rule.otel-severity-mapped.v1` (OE1-008): a severity number or text other than the table's.
 *
 * An integer attribute (`intValue`) and a time are read as the exact integer that their decimal
 * text of at most 20 digits names; other text is not an integer. The identifiers of people and
 * records (`ecl.actor.id`, `ecl.subject.id`, `ecl.action.target`) belong to a record only when the
 * export policy declares them (OE1-005), and each row of the attribute table applies only to the
 * objects it names (K29).
 *
 * No record carries a digest that can be computed without a secret (OE1-004): with the
 * deployment's export key, the digests of the object and of its parameters are HMAC-SHA-256 under
 * that key and the record names the key (OE1-010); without one, the record carries no digest. The
 * keys come from an `ecl_otel_export_keys_v1` file (`loadExportKeys`).
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { equalBytes, fromCanonicalBase64, toHex } from "../crypto/bytes.js";
import { CanonicalizationError, canonicalize, objectDigest } from "../json/canonical.js";
import { parseStrictJson, StrictJsonError } from "../json/strict.js";
import { compareCodePoints, isObject, pythonStr } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import type { Finding } from "../semantic/rules.js";
import { array, at, findings, holds, instant, member, obj, text } from "./common.js";
import type { Problem } from "./common.js";
import { pyEquals, pySameJson, toPy } from "./pyjson.js";
import type { PyValue } from "./pyjson.js";

export const PROFILE = "OTEL-EVIDENCE-EXPORT-1/1.0";
export const EXPORT_KEYS_VERSION = "ecl_otel_export_keys_v1";
export const MIN_EXPORT_KEY_BYTES = 32;
export const OBJECT_DIGEST = "ecl.object.digest";
export const PARAMETERS_DIGEST = "ecl.action.parameters_digest";
export const KEY_ID = "ecl.export.key_id";
/** OE1-010: the attributes a record carries only with an export key. */
export const KEYED: ReadonlySet<string> = new Set([OBJECT_DIGEST, PARAMETERS_DIGEST, KEY_ID]);
export const EXPORT_VERSION = "ecl_otel_export_record_v1";
export const EXPORT_SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/otel-export/1";
const OUTCOME_REASON = "ecl.ext.outcome-reason.v1";
export const INFO = 9;
export const WARN = 13;
export const ERROR = 17;
/** The SeverityText of each SeverityNumber of the severity table (OE1-008). */
export const SEVERITY_TEXT: ReadonlyMap<number, string> = new Map([
  [INFO, "INFO"],
  [WARN, "WARN"],
  [ERROR, "ERROR"],
]);
/** OE1-005: the attributes that identify people and records, exported only when declared. */
export const DECLARED_ONLY: ReadonlySet<string> = new Set(["ecl.actor.id", "ecl.subject.id", "ecl.action.target"]);
/** The EBMP-2 event kinds that the attribute table's rows name (K29). */
const EXECUTION_KIND = "execution";
const REQUEST_KIND = "request";
const DECISION_KIND = "decision";
const AUTHORITY_KIND = "authority";
const TERMINAL_EVENT = "execution_terminal";
/** A decimal integer of the OTLP JSON encoding: a 64-bit field never needs more than 20 digits. */
const DECIMAL = /^-?(?:0|[1-9][0-9]{0,19})$/;
/** The range of an OTLP `fixed64`, such as a timestamp in nanoseconds (OE1-007). */
const FIXED64 = 2n ** 64n;
/** OE1-010: an HMAC-SHA-256 in lowercase hexadecimal. */
const KEYED_HEX = /^[0-9a-f]{64}$/;
const WARN_STATES = new Set(["denied", "held", "challenged", "expired_before_release", "rolled_back", "compensated"]);
const ERROR_STATES = new Set(["failed", "partially_succeeded", "timed_out", "cancelled", "unknown"]);
const EMERGENCY_OPERATIONS = new Set(["halt", "quarantine"]);
/**
 * The DCMP-2 message types that the attribute table's rows name. Each row applies only to the
 * objects it names, also when another message type holds the same member, such as the `safe_state`
 * of a control message.
 */
const DECISION_REQUEST = "decision_request";
const DECISION_RESPONSE = "decision_response";
/** OE1-004: the messages that identify their request by `request_id` (DCMP2-019, DCMP2-020). */
const REQUEST_ID_TYPES: ReadonlySet<string> = new Set([DECISION_RESPONSE, "challenge", "challenge_response"]);
export const REQUEST_ID = "ecl.request.id";
const DCMP_ALL: ReadonlyArray<readonly [string, readonly string[]]> = [["ecl.issuer.id", ["issuer", "id"]]];
const DCMP_REQUEST: ReadonlyArray<readonly [string, readonly string[]]> = [
  ["ecl.action.class", ["action", "action_class"]],
  ["ecl.actor.id", ["actor", "id"]],
  ["ecl.subject.id", ["subject", "id"]],
];
const DCMP_REQUEST_ID: ReadonlyArray<readonly [string, readonly string[]]> = [[REQUEST_ID, ["request_id"]]];
const DCMP_RESPONSE: ReadonlyArray<readonly [string, readonly string[]]> = [
  ["ecl.decision.id", ["decision_id"]],
  ["ecl.decision.outcome", ["outcome"]],
  ["ecl.decision.safe_state", ["safe_state"]],
  ["ecl.policy.id", ["policy", "id"]],
  ["ecl.policy.version", ["policy", "version"]],
  ["ecl.policy.digest", ["policy", "digest", "value"]],
];
const EBMP_ONLY: ReadonlyArray<readonly [string, readonly string[]]> = [
  ["ecl.producer.id", ["producer", "id"]],
  ["ecl.event.kind", ["event", "kind"]],
  ["ecl.event.state", ["event", "state"]],
];
/** OE1-004: a request event identifies its request by the reference it holds. */
const EBMP_REQUEST: ReadonlyArray<readonly [string, readonly string[]]> = [[REQUEST_ID, ["event", "request", "uri"]]];
const DCMP_ACTION: ReadonlyArray<readonly [string, readonly string[]]> = [
  ["ecl.action.id", ["action", "action_id"]],
  ["ecl.action.operation", ["action", "operation"]],
  ["ecl.action.target", ["action", "target", "uri"]],
];
const EBMP_ACTION: ReadonlyArray<readonly [string, readonly string[]]> = [
  ["ecl.action.id", ["event", "action_id"]],
  ["ecl.action.operation", ["event", "operation"]],
  ["ecl.action.target", ["event", "target", "uri"]],
];
/** The attribute table of OE1-003, OE1-004 and OE1-010. */
export const TABLE: ReadonlySet<string> = new Set([
  "ecl.export.profile",
  "ecl.protocol",
  "ecl.object.id",
  "ecl.object.type",
  ...KEYED,
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
  ...DCMP_ALL.map(([name]) => name),
  ...DCMP_REQUEST.map(([name]) => name),
  ...DCMP_RESPONSE.map(([name]) => name),
  ...EBMP_ONLY.map(([name]) => name),
  ...DCMP_ACTION.map(([name]) => name),
]);

export const EXPORT_RULE = "ecl.rule.otel-export-after-evidence.v1";
export const MATCH_RULE = "ecl.rule.otel-record-matches-object.v1";
export const MINIMIZED_RULE = "ecl.rule.otel-record-minimized.v1";
export const SEVERITY_RULE = "ecl.rule.otel-severity-mapped.v1";

/** An export key file that is not exactly an `ecl_otel_export_keys_v1` document (Python's ValueError). */
export class ExportKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExportKeyError";
  }
}

/**
 * A deployment's export key (OE1-010): a secret of at least 32 bytes that keys the digests of
 * exported records and nothing else, and an identifier that is not derived from it.
 */
export interface ExportKey {
  readonly keyId: string;
  readonly key: Uint8Array;
}

/** An export key, checked: an identifier of 1 to 256 characters and at least 32 bytes of key. */
export function exportKey(keyId: unknown, key: Uint8Array): ExportKey {
  if (typeof keyId !== "string" || [...keyId].length < 1 || [...keyId].length > 256) {
    throw new ExportKeyError("an export key identifier is a string of 1 to 256 characters");
  }
  if (key.length < MIN_EXPORT_KEY_BYTES) {
    throw new ExportKeyError(`an export key has at least ${MIN_EXPORT_KEY_BYTES} bytes`);
  }
  return { keyId, key };
}

/** HMAC-SHA-256 under the key of the restricted canonical JSON of `value`, hexadecimal. */
export function keyedDigest(key: ExportKey, value: JsonValue): string {
  return toHex(hmac(nobleSha256, key.key, canonicalize(value)));
}

/**
 * The export keys of a key file, by identifier. The file is strict JSON:
 * `{"schema_version": "ecl_otel_export_keys_v1", "keys": [...]}`, each key `{"key_id", "key"}`
 * with the key in canonical base64, at least 32 bytes, and every identifier once. Anything else
 * throws ExportKeyError, whose message never holds key material.
 */
export function loadExportKeys(data: Uint8Array | string): Map<string, ExportKey> {
  let value: JsonValue;
  try {
    value = parseStrictJson(data);
  } catch (error) {
    if (error instanceof StrictJsonError) {
      throw new ExportKeyError(`an export key file is strict JSON: ${error.message}`);
    }
    throw error;
  }
  const keys = isObject(value) ? value["keys"] : undefined;
  if (!isObject(value) || Object.keys(value).length !== 2 || value["schema_version"] !== EXPORT_KEYS_VERSION || !Array.isArray(keys) || keys.length === 0) {
    throw new ExportKeyError(`not an ${EXPORT_KEYS_VERSION} document with at least one key`);
  }
  const found = new Map<string, ExportKey>();
  for (const item of keys) {
    const material = isObject(item) ? item["key"] : undefined;
    if (!isObject(item) || Object.keys(item).length !== 2 || !Object.prototype.hasOwnProperty.call(item, "key_id") || typeof material !== "string") {
      throw new ExportKeyError("an export key entry has exactly a key_id and a key");
    }
    const bytes = fromCanonicalBase64(material);
    if (bytes === undefined) {
      throw new ExportKeyError("an export key is canonical base64");
    }
    const key = exportKey(item["key_id"], bytes);
    if (found.has(key.keyId)) {
      throw new ExportKeyError("an export key identifier appears more than once");
    }
    found.set(key.keyId, key);
  }
  return found;
}

/** A string or an integer member (never a boolean or another type), or null. */
function pick(value: JsonValue, path: readonly string[]): string | number | null {
  const found = member(value, ...path);
  return typeof found === "string" || (typeof found === "number" && Number.isInteger(found)) ? found : null;
}

/** The time a record copies: a message's `issued_at` or an event's `observed_at`. */
export function objectTime(value: JsonObject): string | null {
  const found = at(value, at(value, "protocol") === "DCMP-2" ? "issued_at" : "observed_at");
  return typeof found === "string" ? found : null;
}

/** The `EventName` of the record that copies an object (OE1-003). */
export function eventName(value: JsonObject): string {
  if (at(value, "protocol") === "DCMP-2") {
    return "ecl.dcmp." + pythonStr(at(value, "message_type"));
  }
  return "ecl.ebmp." + pythonStr(at(value, "event_type"));
}

/** The kind of an EBMP-2 event, or null for any other object. */
function eventKind(value: JsonObject): string | null {
  if (at(value, "protocol") === "DCMP-2") {
    return null;
  }
  return text(value, "event", "kind");
}

/** The parameters digest member of a decision request or an execution event, if any (or null). */
function parametersDigest(value: JsonObject): JsonValue {
  if (at(value, "protocol") === "DCMP-2") {
    return at(value, "message_type") === DECISION_REQUEST ? member(value, "action", "parameters_digest") : null;
  }
  if (eventKind(value) !== EXECUTION_KIND) {
    return null;
  }
  return member(value, "event", "parameters_digest");
}

/**
 * The digests that anyone can compute from the object, by the attribute that would carry them:
 * the SHA-256 of the object and the value of its parameters digest (OE1-004). A record carries
 * neither. Throws CanonicalizationError when the object is outside the restricted canonical profile.
 */
export function unkeyedDigests(value: JsonObject): Map<string, string> {
  const found = new Map<string, string>([[OBJECT_DIGEST, objectDigest(value)]]);
  const parameters = member(parametersDigest(value), "value");
  if (typeof parameters === "string") {
    found.set(PARAMETERS_DIGEST, parameters);
  }
  return found;
}

/**
 * The attribute table for one object, each the object's own value (OE1-003, OE1-004). With
 * `key`, the object's digest and its parameters digest are keyed with it and the key is named
 * (OE1-010); without one, no digest is exported. The identifiers of people and records are
 * exported only when `declared` names them (OE1-005). A row applies only to the objects it names:
 * the action rows to a decision request and to execution events, the rows of a decision to a
 * decision response, the request's identifier to a decision response, a challenge, a challenge
 * response and a request event, the event's decision to decision and execution events, the
 * authorization to an admit and to authority events, and the reason code to a terminal event.
 * Throws CanonicalizationError when a keyed digest cannot be computed because the object is
 * outside the restricted canonical profile.
 */
export function logAttributes(value: JsonObject, bundleId: string | null = null, key: ExportKey | null = null, declared: Iterable<string> = []): Map<string, string | number> {
  const names: ReadonlySet<string> = new Set(declared);
  const dcmp = at(value, "protocol") === "DCMP-2";
  const result = new Map<string, string | number>([
    ["ecl.export.profile", PROFILE],
    ["ecl.protocol", pythonStr(at(value, "protocol"))],
    ["ecl.object.id", pythonStr(at(value, dcmp ? "message_id" : "object_id"))],
    ["ecl.object.type", pythonStr(at(value, dcmp ? "message_type" : "event_type"))],
  ]);
  if (key !== null) {
    result.set(OBJECT_DIGEST, keyedDigest(key, value));
    result.set(KEY_ID, key.keyId);
    const parameters = parametersDigest(value);
    if (isObject(parameters)) {
      result.set(PARAMETERS_DIGEST, keyedDigest(key, parameters));
    }
  }
  for (const [name, step] of [
    ["ecl.workflow.id", "workflow_id"],
    ["ecl.workflow.root_trace_id", "root_trace_id"],
    ["ecl.workflow.attempt", "attempt"],
    ["ecl.workflow.sequence", "sequence"],
  ] as const) {
    const found = pick(value, ["workflow", step]);
    if (found !== null) {
      result.set(name, found);
    }
  }
  if (bundleId !== null) {
    result.set("ecl.evidence.bundle", bundleId);
  }
  const kind = eventKind(value);
  const messageType = dcmp ? at(value, "message_type") : null;
  const tables: ReadonlyArray<readonly [string, readonly string[]]>[] = [];
  if (dcmp) {
    tables.push(DCMP_ALL);
    if (messageType === DECISION_REQUEST) {
      tables.push(DCMP_REQUEST, DCMP_ACTION);
    }
    if (messageType === DECISION_RESPONSE) {
      tables.push(DCMP_RESPONSE);
    }
    if (typeof messageType === "string" && REQUEST_ID_TYPES.has(messageType)) {
      tables.push(DCMP_REQUEST_ID);
    }
  } else {
    tables.push(EBMP_ONLY);
    if (kind === EXECUTION_KIND) {
      tables.push(EBMP_ACTION);
    }
    if (kind === REQUEST_KIND) {
      tables.push(EBMP_REQUEST);
    }
  }
  for (const table of tables) {
    for (const [name, path] of table) {
      const found = pick(value, path);
      if (found !== null && (!DECLARED_ONLY.has(name) || names.has(name))) {
        result.set(name, found);
      }
    }
  }
  let authorization: string | null = null;
  if (dcmp) {
    if (messageType === DECISION_RESPONSE) {
      const reasons = at(value, "reasons");
      const first = Array.isArray(reasons) && reasons.length > 0 ? reasons[0] : null;
      const code = text(first, "code");
      if (code !== null) {
        result.set("ecl.decision.reason_code", code);
      }
      authorization = text(value, "authorization", "authorization_id");
    }
  } else {
    authorization = kind === AUTHORITY_KIND ? text(value, "event", "authorization_id") : null;
    if (kind === DECISION_KIND || kind === EXECUTION_KIND) {
      const decision = text(value, "event", "decision", "uri");
      if (decision !== null) {
        result.set("ecl.event.decision_id", decision);
      }
    }
    if (at(value, "event_type") === TERMINAL_EVENT) {
      for (const item of array(value, "extensions")) {
        if (isObject(item) && at(item, "id") === OUTCOME_REASON) {
          const code = text(item, "value", "code");
          if (code !== null) {
            result.set("ecl.event.reason_code", code);
          }
        }
      }
    }
  }
  if (authorization !== null) {
    result.set("ecl.authorization.id", authorization);
  }
  return result;
}

/** The SeverityNumber of the severity table (OE1-008). */
export function severity(value: JsonObject): number {
  if (at(value, "protocol") === "DCMP-2") {
    const outcome = at(value, "outcome");
    if (outcome === "deny" || outcome === "hold" || outcome === "challenge") {
      return WARN;
    }
    const operation = text(value, "operation");
    if (at(value, "message_type") === "control" && operation !== null && EMERGENCY_OPERATIONS.has(operation)) {
      return ERROR;
    }
    return INFO;
  }
  if (at(value, "event_type") === "execution_terminal") {
    const state = text(value, "event", "state");
    if (state !== null && WARN_STATES.has(state)) {
      return WARN;
    }
    if (state !== null && ERROR_STATES.has(state)) {
      return ERROR;
    }
  }
  return INFO;
}

/**
 * A decimal integer string of the OTLP JSON encoding as an integer, or null when it is not one: at
 * most 20 digits, and no whitespace, sign other than a leading minus, digit separator or leading
 * zero.
 */
function decimal(raw: unknown): bigint | null {
  return typeof raw === "string" && DECIMAL.test(raw) ? BigInt(raw) : null;
}

/**
 * A `fixed64` of the OTLP JSON encoding, such as a timestamp, as an integer, or null when it is not
 * decimal text of an integer from 0 to 2^64 - 1 (OE1-007).
 */
function fixed64(raw: unknown): bigint | null {
  const number = decimal(raw);
  return number !== null && number >= 0n && number < FIXED64 ? number : null;
}

/**
 * The record's attributes by key, as the reference reads them: a value of one member, a
 * `stringValue` as its string and an `intValue` that is decimal text as its exact integer, and any
 * other AnyValue as the AnyValue object itself; a later attribute of the same key replaces an
 * earlier, and `matchesObject` reports the repetition.
 */
function attributeMap(log: JsonValue): Map<string, PyValue> {
  const result = new Map<string, PyValue>();
  for (const item of array(log, "attributes")) {
    const value = member(item, "value");
    if (!isObject(item) || !isObject(value) || Object.keys(value).length !== 1) {
      continue;
    }
    const kind = Object.keys(value)[0] as string;
    const raw = value[kind] as JsonValue;
    const key = pythonStr(at(item, "key"));
    const number = kind === "intValue" ? decimal(raw) : null;
    // Only a stringValue holds a string and an intValue an integer: any other AnyValue
    // is kept as the AnyValue object, which equals no value that the attribute table copies.
    result.set(key, number !== null ? number : kind === "stringValue" ? toPy(raw) : toPy(value));
  }
  return result;
}

/** The attribute names that the record's export policy declares. */
function declaredNames(record: JsonObject): Set<string> {
  const names = new Set<string>();
  for (const item of array(record, "declared_attributes")) {
    const name = text(item, "name");
    if (name !== null) {
      names.add(name);
    }
  }
  return names;
}

function exportAfterEvidence(record: JsonObject, value: JsonObject): Problem[] {
  const problems: Problem[] = [];
  const attempted = instant(member(record, "export", "attempted_at"));
  const recorded = instant(objectTime(value));
  if (attempted === null || recorded === null || attempted < recorded) {
    problems.push(["/export/attempted_at", "the exporter read the object before its time"]);
  }
  const after = obj(record, "evidence_after");
  if (after !== null) {
    let same: boolean;
    try {
      same = equalBytes(canonicalize(after), canonicalize(value));
    } catch (error) {
      if (!(error instanceof CanonicalizationError)) {
        throw error;
      }
      same = false;
    }
    if (!same) {
      problems.push(["/evidence_after", "the evidence differs after the export"]);
    }
  }
  return problems;
}

function matchesObject(record: JsonObject, value: JsonObject, keys: ReadonlyMap<string, ExportKey>): Problem[] {
  const log = obj(record, "log_record") ?? {};
  const problems: Problem[] = [];
  if (!pyEquals(toPy(at(log, "eventName")), eventName(value))) {
    problems.push(["/log_record/eventName", "not the object's event name"]);
  }
  const time = instant(objectTime(value));
  if (time === null || fixed64(at(log, "timeUnixNano")) !== time) {
    problems.push(["/log_record/timeUnixNano", "not the object's time"]);
  }
  // OE1-003, OE1-007: the observed time is a fixed64 of nanoseconds, so a decimal text of up to 20
  // digits beyond 2^64 - 1 is no time at all.
  const observed = fixed64(at(log, "observedTimeUnixNano"));
  if (time !== null && observed === null) {
    problems.push(["/log_record/observedTimeUnixNano", "not a fixed64 time"]);
  } else if (time !== null && observed !== null && observed < time) {
    problems.push(["/log_record/observedTimeUnixNano", "earlier than the object's time"]);
  }
  const actual = attributeMap(log);
  const declared = declaredNames(record);
  const named = actual.get(KEY_ID) ?? null;
  if (named !== null && typeof named !== "string") {
    // OE1-010: the record carries the key's identifier, a string.
    problems.push(["/log_record/attributes", `${KEY_ID} is not the identifier of a key`]);
  }
  const key = typeof named === "string" ? (keys.get(named) ?? null) : null;
  // A record that names a key the caller does not hold: its keyed digests cannot be computed.
  // The parameters digest is among them only for an object that has one (OE1-010); on any other
  // object it copies nothing, as it does under a key the caller holds.
  const unverifiable: ReadonlySet<string> =
    named !== null && key === null
      ? isObject(parametersDigest(value))
        ? KEYED
        : new Set([...KEYED].filter((name) => name !== PARAMETERS_DIGEST))
      : new Set();
  // An identifier of a person or record exported without its declaration is the concern of
  // OE1-005 (the minimization rule), not of this one.
  const undeclared: ReadonlySet<string> = new Set([...DECLARED_ONLY].filter((name) => !declared.has(name)));
  let expected: Map<string, string | number>;
  let unkeyed: Map<string, string>;
  try {
    expected = logAttributes(value, text(record, "bundle_id"), key, declared);
    unkeyed = unkeyedDigests(value);
  } catch (error) {
    if (!(error instanceof CanonicalizationError)) {
      throw error;
    }
    return [...problems, ["/object", "the object is outside the restricted canonical profile"]];
  }
  for (const name of [...expected.keys()].sort(compareCodePoints)) {
    if (name === "ecl.evidence.bundle" && !actual.has(name)) {
      continue;
    }
    // An attribute holds the value it copies as the same JSON value, so a `boolValue` of true is
    // not an attempt of 1.
    if (!pySameJson(actual.get(name), toPy(expected.get(name) as string | number))) {
      problems.push(["/log_record/attributes", `${name} is not the object's value`]);
    }
  }
  for (const name of [...actual.keys()].filter((item) => TABLE.has(item) && !expected.has(item) && !unverifiable.has(item) && !undeclared.has(item)).sort(compareCodePoints)) {
    problems.push(["/log_record/attributes", `${name} copies nothing in the object`]);
  }
  // OE1-010: with an export key, every record carries the keyed digest of the object and, where the
  // object has a parameters digest, the keyed parameters digest, under a key the caller does not
  // hold as under one it holds.
  for (const name of [OBJECT_DIGEST, PARAMETERS_DIGEST]) {
    if (unverifiable.has(name) && !actual.has(name)) {
      problems.push(["/log_record/attributes", `${KEY_ID} is named without the keyed ${name}`]);
    }
  }
  // OE1-003, OE1-010: a keyed digest that the caller cannot compute is still held as the stringValue
  // that the table gives, an HMAC in lowercase hexadecimal, so that no other kind or form, such as the
  // object's SHA-256 as a bytesValue of its bytes, carries past OE1-004 a digest that needs no key.
  for (const name of [OBJECT_DIGEST, PARAMETERS_DIGEST].sort(compareCodePoints)) {
    const held = actual.get(name);
    if (unverifiable.has(name) && actual.has(name) && !(typeof held === "string" && KEYED_HEX.test(held))) {
      problems.push(["/log_record/attributes", `${name} is not an HMAC in lowercase hexadecimal`]);
    }
  }
  // OTLP: the attribute keys of a record are unique; the map above keeps only the last of a repeated
  // key, which would hide an earlier one from every comparison.
  const attributeKeys = array(log, "attributes")
    .filter((item) => isObject(item))
    .map((item) => pythonStr(at(item, "key")));
  if (new Set(attributeKeys).size !== attributeKeys.length) {
    problems.push(["/log_record/attributes", "an attribute key is repeated"]);
  }
  // OE1-004: a digest that needs no key, held as the stringValue that the table gives. In any other
  // kind it is refused above: under a key the caller holds as not the object's value, without a key
  // as copying nothing, and under a key the caller does not hold as not an HMAC in lowercase
  // hexadecimal.
  for (const [name, digest] of [...unkeyed.entries()].sort(([a], [b]) => compareCodePoints(a, b))) {
    const held = actual.get(name);
    if (typeof held === "string" && held === digest) {
      problems.push(["/log_record/attributes", `${name} is a digest that needs no export key`]);
    }
  }
  return problems;
}

function minimized(record: JsonObject): Problem[] {
  const log = obj(record, "log_record") ?? {};
  const declared = declaredNames(record);
  const names = [...attributeMap(log).keys()].sort(compareCodePoints);
  const problems: Problem[] = names
    .filter((name) => !TABLE.has(name) && !declared.has(name))
    .map((name): Problem => ["/log_record/attributes", `${name} is neither in the table nor declared`]);
  for (const name of names) {
    if (DECLARED_ONLY.has(name) && !declared.has(name)) {
      problems.push(["/log_record/attributes", `${name} identifies a person or record and is not declared`]);
    }
  }
  if (holds(log, "body") && !declared.has("body")) {
    problems.push(["/log_record/body", "a body is exported without a declaration"]);
  }
  return problems;
}

function severityMapped(record: JsonObject, value: JsonObject): Problem[] {
  const number = severity(value);
  const problems: Problem[] = [];
  if (!pyEquals(toPy(member(record, "log_record", "severityNumber")), BigInt(number))) {
    problems.push(["/log_record/severityNumber", "not the severity table's"]);
  }
  if (!pyEquals(toPy(member(record, "log_record", "severityText")), SEVERITY_TEXT.get(number) as string)) {
    problems.push(["/log_record/severityText", "not the severity table's name"]);
  }
  return problems;
}

/**
 * The rules of the profile, in the order the reference reports them, each given the record, the
 * object it copies and the export keys the caller holds. A rule added to the registry for this
 * profile is one function above and one row here.
 */
export const RULES: ReadonlyArray<readonly [string, (record: JsonObject, value: JsonObject, keys: ReadonlyMap<string, ExportKey>) => Problem[]]> = [
  [EXPORT_RULE, exportAfterEvidence],
  [MATCH_RULE, matchesObject],
  [MINIMIZED_RULE, (record) => minimized(record)],
  [SEVERITY_RULE, severityMapped],
];

/**
 * The findings of an `ecl_otel_export_record_v1` record that its schema has accepted. `keys` are
 * the export keys the caller holds, by identifier: a keyed digest is compared only when the record
 * names one of them (OE1-010).
 */
export function check(record: JsonObject, keys: ReadonlyMap<string, ExportKey> = new Map()): Finding[] {
  const value = obj(record, "object");
  if (value === null) {
    return [];
  }
  return RULES.flatMap(([rule, problems]) => findings(rule, problems(record, value, keys)));
}
