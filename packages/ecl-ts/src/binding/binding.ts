/**
 * Binding checks: do these decoded objects belong together? (DCMP-2 section 8, DCMP2-044 to
 * DCMP2-050; EBMP-2 section 10, EBMP2-047 to EBMP2-052.)
 *
 * Each check reads decoded payloads, verifies no signature and runs no schema check, and throws
 * BindingError for the first rule that fails, in the order the protocols list them. A member a
 * rule reads that is missing or of the wrong type fails with the check's general code
 * (`ecl.error.request-binding-invalid.v1` for a response, `ecl.error.decision-binding-invalid.v1`
 * for the event checks); a member that is present and does not match fails with the code named
 * for the rule. Two rules are parameters of the reference verification profile: the response
 * clock-skew allowance (DCMP2-047), zero unless the caller passes another, and the state-outcome
 * table of terminal events (EBMP2-051), whose dependency failures resolve to a fail-closed deny.
 */

import { objectDigest } from "../json/canonical.js";
import { isArray, isInteger, isObject, pythonEquals } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { InstantError, instantNanoseconds } from "../time.js";

export const REQUEST_BINDING_INVALID = "ecl.error.request-binding-invalid.v1";
export const DECISION_BINDING_INVALID = "ecl.error.decision-binding-invalid.v1";
export const DIGEST_MISMATCH = "ecl.error.digest-mismatch.v1";
export const AUDIENCE_MISMATCH = "ecl.error.audience-mismatch.v1";
export const SCOPE_MISMATCH = "ecl.error.scope-mismatch.v1";

const RESPONDS_TO = "ecl.relation.responds-to.v1";
const OUTCOMES = new Set(["admit", "deny", "hold", "challenge"]);
const EXECUTION_EVENTS = new Set(["execution_released", "execution_terminal"]);
const AUTHORITY_EVENTS = new Set(["authority_issued", "authority_consumed"]);
const NANOSECONDS = 1_000_000_000n;
const INSTANT = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$/;

const ADMIT: ReadonlySet<string | null> = new Set(["admit"]);
/**
 * The response outcomes each terminal state may have, null standing for no response. Only
 * `denied` may have none (a dependency failure), and it may also follow an admit.
 */
export const TERMINAL_STATE_OUTCOMES: Readonly<Record<string, ReadonlySet<string | null>>> = {
  succeeded: ADMIT,
  failed: ADMIT,
  partially_succeeded: ADMIT,
  timed_out: ADMIT,
  cancelled: ADMIT,
  unknown: ADMIT,
  rolled_back: ADMIT,
  compensated: ADMIT,
  expired_before_release: ADMIT,
  held: new Set(["hold"]),
  challenged: new Set(["challenge"]),
  denied: new Set(["deny", "admit", null]),
};

/** Objects that do not belong together, or an object that cannot be checked. */
export class BindingError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "BindingError";
    this.code = code;
  }
}

/** A decoded object, with its name for messages and the code that a malformed read raises. */
class Bound {
  readonly value: JsonObject;
  readonly name: string;
  readonly code: string;

  constructor(value: JsonObject, name: string, code: string) {
    this.value = value;
    this.name = name;
    this.code = code;
  }

  error(message: string, code?: string): BindingError {
    return new BindingError(`${this.name}: ${message}`, code ?? this.code);
  }

  has(...path: string[]): boolean {
    try {
      this.get(...path);
      return true;
    } catch (error) {
      if (error instanceof BindingError) {
        return false;
      }
      throw error;
    }
  }

  get(...path: string[]): JsonValue {
    let found: JsonValue = this.value;
    for (const step of path) {
      if (!isObject(found) || !Object.prototype.hasOwnProperty.call(found, step)) {
        throw this.error(`${path.join(".")} is missing`);
      }
      found = found[step] as JsonValue;
    }
    return found;
  }

  text(...path: string[]): string {
    const found = this.get(...path);
    if (typeof found !== "string" || found === "") {
      throw this.error(`${path.join(".")} is not a non-empty string`);
    }
    return found;
  }

  integer(...path: string[]): number {
    const found = this.get(...path);
    if (!isInteger(found)) {
      throw this.error(`${path.join(".")} is not an integer`);
    }
    return found;
  }

  array(...path: string[]): JsonValue[] {
    const found = this.get(...path);
    if (!isArray(found)) {
      throw this.error(`${path.join(".")} is not an array`);
    }
    return found;
  }

  member(...path: string[]): Bound {
    return read(this.get(...path), `${this.name}.${path.join(".")}`, this.code);
  }

  /** A digest member, whole. */
  digest(...path: string[]): JsonObject {
    const found = this.member(...path);
    found.text("algorithm");
    found.text("value");
    return found.value;
  }

  /** The algorithm and value of a digest member, and nothing else of it. */
  digestPair(...path: string[]): [string, string] {
    const found = this.member(...path);
    return [found.text("algorithm"), found.text("value")];
  }

  instant(...path: string[]): bigint {
    const text = this.text(...path);
    const member = path.join(".");
    if (!INSTANT.test(text)) {
      throw this.error(`${member} is not an RFC 3339 UTC time`);
    }
    try {
      return instantNanoseconds(text);
    } catch (error) {
      if (error instanceof InstantError) {
        throw this.error(`${member} is not a time that exists`);
      }
      throw error;
    }
  }
}

function read(value: JsonValue | undefined, name: string, code: string): Bound {
  if (!isObject(value)) {
    throw new BindingError(`${name} is not a JSON object`, code);
  }
  return new Bound(value, name, code);
}

function fingerprint(value: JsonValue, owner: Bound): JsonObject {
  try {
    return { algorithm: "ecl.digest.sha-256.v1", value: objectDigest(value) };
  } catch {
    throw owner.error("cannot be canonicalized, so it has no digest");
  }
}

function scopeDigest(request: Bound): JsonObject {
  const scope: JsonObject = { request_id: request.text("message_id"), action: request.member("action").value };
  return fingerprint(scope, request);
}

function requireMessage(message: Bound, messageType: string): void {
  if (message.text("message_type") !== messageType) {
    throw message.error(`is not a ${messageType}`);
  }
}

function requireEvent(event: Bound, eventTypes: ReadonlySet<string>, kind: string): void {
  if (event.text("object_type") !== "event_record") {
    throw event.error("is not an event record");
  }
  if (!eventTypes.has(event.text("event_type"))) {
    throw event.error(`is not one of ${[...eventTypes].sort().join(", ")}`);
  }
  if (event.text("event", "kind") !== kind) {
    throw event.error(`event.kind is not ${kind}`);
  }
}

function sameText(left: Bound, right: Bound, ...path: string[]): void {
  if (left.text(...path) !== right.text(...path)) {
    throw left.error(`${path.join(".")} is not the ${right.name}'s`);
  }
}

function sameAttempt(left: Bound, right: Bound): void {
  if (left.integer("workflow", "attempt") !== right.integer("workflow", "attempt")) {
    throw left.error(`workflow.attempt is not the ${right.name}'s`);
  }
}

function predecessors(owner: Bound): Bound[] {
  const found = owner.array("workflow", "causal_predecessors").map((entry, index) =>
    read(entry, `${owner.name}.workflow.causal_predecessors[${index}]`, owner.code),
  );
  for (const entry of found) {
    entry.text("id");
    entry.digest("digest");
  }
  return found;
}

function relation(predecessor: Bound): string | undefined {
  return predecessor.has("relation") ? predecessor.text("relation") : undefined;
}

function answersTheRequest(request: Bound, response: Bound): void {
  if (response.text("request_id") !== request.text("message_id")) {
    throw response.error("request_id is not the request's message_id");
  }
}

function admits(response: Bound | undefined): boolean {
  return response !== undefined && response.text("outcome") === "admit";
}

/**
 * Throw BindingError unless `response` is the answer to `request` (DCMP2-044 to DCMP2-050).
 * `responseClockSkewSeconds` is the verification profile's allowance (DCMP2-047).
 */
export function checkResponseBinding(request: JsonValue, response: JsonValue, responseClockSkewSeconds = 0): void {
  if (!Number.isInteger(responseClockSkewSeconds) || responseClockSkewSeconds < 0) {
    throw new RangeError("the response clock-skew allowance is a non-negative integer of seconds");
  }
  const asked = read(request, "request", REQUEST_BINDING_INVALID);
  const answer = read(response, "response", REQUEST_BINDING_INVALID);
  requireMessage(asked, "decision_request");
  requireMessage(answer, "decision_response");
  answersTheRequest(asked, answer);
  sameText(answer, asked, "workflow", "workflow_id");
  sameText(answer, asked, "workflow", "root_trace_id");
  sameAttempt(answer, asked);
  // 4: exactly one responds-to predecessor, the request, with the request's digest.
  const responding = predecessors(answer).filter((entry) => relation(entry) === RESPONDS_TO);
  const only = responding[0];
  if (responding.length !== 1 || only === undefined) {
    throw answer.error("does not have exactly one responds-to predecessor", DIGEST_MISMATCH);
  }
  if (only.text("id") !== asked.text("message_id")) {
    throw answer.error("the responds-to predecessor is not the request", DIGEST_MISMATCH);
  }
  if (!pythonEquals(only.digest("digest"), fingerprint(asked.value, asked))) {
    throw answer.error("the responds-to predecessor's digest is not the request's", DIGEST_MISMATCH);
  }
  // 5: not issued before the request, less the allowance.
  if (answer.instant("issued_at") < asked.instant("issued_at") - BigInt(responseClockSkewSeconds) * NANOSECONDS) {
    throw answer.error("issued_at is before the request's");
  }
  const outcome = answer.text("outcome");
  if (!OUTCOMES.has(outcome)) {
    throw answer.error("outcome is not admit, deny, hold or challenge");
  }
  if (outcome !== "admit") {
    return;
  }
  // 6a: the audience requested.
  const audience = answer.text("authorization", "audience");
  if (audience !== asked.text("authority_request", "audience")) {
    throw answer.error("authorization.audience is not the audience requested", AUDIENCE_MISMATCH);
  }
  // 6b: the scope digest of {"request_id", "action"}.
  if (!pythonEquals(answer.digest("authorization", "scope_digest"), scopeDigest(asked))) {
    throw answer.error("authorization.scope_digest is not the digest of the request's action", SCOPE_MISMATCH);
  }
  // 6c: the use policy requested.
  const usePolicy = answer.text("authorization", "use_policy");
  if (usePolicy !== asked.text("authority_request", "use_policy")) {
    throw answer.error("authorization.use_policy is not the use policy requested");
  }
  // 6d: lasts longer than nothing and no longer than requested.
  const start = answer.instant("authorization", "valid_from");
  const end = answer.instant("authorization", "valid_until");
  const allowed = BigInt(asked.integer("authority_request", "requested_validity_seconds")) * NANOSECONDS;
  if (!(end - start > 0n && end - start <= allowed)) {
    throw answer.error("authorization window is empty, or longer than requested");
  }
  // 6d1: single use is one use; no more uses than requested.
  const grantedUses = (): number | undefined => (answer.has("authorization", "max_uses") ? answer.integer("authorization", "max_uses") : undefined);
  if (answer.text("authorization", "use_policy") === "single_use") {
    const granted = grantedUses();
    if (granted !== undefined && granted !== 1) {
      throw answer.error("a single_use authorization has a max_uses other than 1");
    }
  }
  if (asked.has("authority_request", "max_uses")) {
    const granted = grantedUses();
    if (granted === undefined || granted > asked.integer("authority_request", "max_uses")) {
      throw answer.error("authorization.max_uses is missing, or more than the request's");
    }
  }
  // 6d2: contained in the decision.
  if (answer.instant("authorization", "valid_from") < answer.instant("issued_at")) {
    throw answer.error("authorization.valid_from is before issued_at");
  }
  if (answer.has("expires_at") && answer.instant("authorization", "valid_until") > answer.instant("expires_at")) {
    throw answer.error("authorization.valid_until is after expires_at");
  }
  const seconds = asked.integer("authority_request", "requested_validity_seconds");
  const limit = answer.instant("issued_at") + BigInt(seconds) * NANOSECONDS;
  if (answer.instant("authorization", "valid_until") > limit) {
    throw answer.error("authorization.valid_until is after issued_at plus the seconds requested");
  }
}

/**
 * Throw BindingError unless the execution `event` (execution_released or execution_terminal)
 * records `request` and `response` (EBMP2-047 to EBMP2-051). `response` is undefined when the
 * decision point gave none.
 */
export function checkEventBinding(event: JsonValue, request: JsonValue, response: JsonValue | undefined): void {
  const recorded = read(event, "event", DECISION_BINDING_INVALID);
  const asked = read(request, "request", DECISION_BINDING_INVALID);
  const answer = response === undefined ? undefined : read(response, "response", DECISION_BINDING_INVALID);
  requireEvent(recorded, EXECUTION_EVENTS, "execution");
  requireMessage(asked, "decision_request");
  if (answer !== undefined) {
    requireMessage(answer, "decision_response");
  }
  if (recorded.text("event", "action_id") !== asked.text("action", "action_id")) {
    throw recorded.error("event.action_id is not the request's action");
  }
  if (recorded.has("event", "operation") && recorded.text("event", "operation") !== asked.text("action", "operation")) {
    throw recorded.error("event.operation is not the request's");
  }
  if (recorded.has("event", "parameters_digest")) {
    const repeated = recorded.digestPair("event", "parameters_digest");
    const original = asked.digestPair("action", "parameters_digest");
    if (repeated[0] !== original[0] || repeated[1] !== original[1]) {
      throw recorded.error("event.parameters_digest is not the request's");
    }
  }
  if (recorded.has("event", "target") && recorded.text("event", "target", "uri") !== asked.text("action", "target", "uri")) {
    throw recorded.error("event.target.uri is not the request's");
  }
  if (answer !== undefined) {
    answersTheRequest(asked, answer);
  }
  sameText(recorded, asked, "workflow", "workflow_id");
  sameText(recorded, asked, "workflow", "root_trace_id");
  if (answer !== undefined) {
    sameText(recorded, answer, "workflow", "workflow_id");
    sameText(recorded, answer, "workflow", "root_trace_id");
  }
  sameAttempt(recorded, asked);
  if (answer !== undefined) {
    sameAttempt(recorded, answer);
  }
  if (answer === undefined) {
    if (recorded.has("event", "decision")) {
      throw recorded.error("names a decision, and there is no response");
    }
  } else if (recorded.text("event", "decision", "uri") !== answer.text("message_id")) {
    throw recorded.error("event.decision is not the response");
  }
  if (answer !== undefined && !pythonEquals(recorded.digest("event", "decision", "digest"), fingerprint(answer.value, answer))) {
    throw recorded.error("event.decision.digest is not the response's", DIGEST_MISMATCH);
  }
  if (recorded.has("event", "authority")) {
    if (!admits(answer)) {
      throw recorded.error("carries authority, and there is no response that admits");
    }
    if (answer === undefined) {
      throw recorded.error("carries authority, and there is no response");
    }
    if (recorded.text("event", "authority", "uri") !== answer.text("authorization", "authorization_id")) {
      throw recorded.error("event.authority is not the response's authorization");
    }
  }
  if (recorded.text("event_type") === "execution_released") {
    if (!admits(answer)) {
      throw recorded.error("releases, and there is no response that admits");
    }
  } else {
    const state = recorded.text("event", "state");
    const wanted = Object.prototype.hasOwnProperty.call(TERMINAL_STATE_OUTCOMES, state) ? TERMINAL_STATE_OUTCOMES[state] : undefined;
    if (wanted === undefined) {
      throw recorded.error("event.state is not a state that a terminal event may be in");
    }
    const outcome = answer === undefined ? null : answer.text("outcome");
    if (!wanted.has(outcome)) {
      throw recorded.error("event.state does not agree with the outcome of the response");
    }
  }
}

/**
 * Throw BindingError unless the authority `event` (authority_issued or authority_consumed)
 * records the authorization of `response` (EBMP2-052).
 */
export function checkAuthorityEventBinding(event: JsonValue, response: JsonValue): void {
  const recorded = read(event, "event", DECISION_BINDING_INVALID);
  const answer = read(response, "response", DECISION_BINDING_INVALID);
  requireEvent(recorded, AUTHORITY_EVENTS, "authority");
  requireMessage(answer, "decision_response");
  if (!admits(answer)) {
    throw recorded.error("records an authorization, and the response does not admit");
  }
  const granted = answer.text("authorization", "authorization_id");
  if (recorded.text("event", "authorization_id") !== granted) {
    throw recorded.error("event.authorization_id is not the response's");
  }
  const named = predecessors(recorded).filter((entry) => entry.text("id") === answer.text("message_id"));
  const only = named[0];
  if (named.length !== 1 || only === undefined) {
    throw recorded.error("does not follow the response exactly once", DIGEST_MISMATCH);
  }
  if (!pythonEquals(only.digest("digest"), fingerprint(answer.value, answer))) {
    throw recorded.error("the digest of the response it follows is not the response's", DIGEST_MISMATCH);
  }
  sameText(recorded, answer, "workflow", "workflow_id");
  sameText(recorded, answer, "workflow", "root_trace_id");
  sameAttempt(recorded, answer);
}
