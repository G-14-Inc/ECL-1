/**
 * ACS-BINDING-1: an OWASP ACS Guardian as a decision source, its hook points as enforcement
 * points.
 *
 * The pinned ACS text (specification version 0.1.0, repository release 0.1.2) lets an Observed
 * Agent proceed when its Guardian cannot answer; under this profile a decision failure at an ECL
 * enforcement point releases nothing (AC1-006). `check` reads an `ecl_acs_exchange_v1` record
 * (AC1-010) that its schema has accepted and reports each way the exchange weakened the guarantee:
 *
 * - `ecl.rule.acs-decision-failure-closed.v1` (AC1-006): a posture other than `deny`, or a
 *   decision failure that ended in an admit or a release;
 * - `ecl.rule.acs-expiry-no-release.v1` (AC1-007): an `ask` or `defer` whose ECL response outlasts
 *   the Guardian's deadline, expires into a safe state that permits a new effect, or whose action
 *   went ahead after it expired;
 * - `ecl.rule.acs-modification-new-request.v1` (AC1-005): a `modify` released the original action,
 *   or the modified action was not a new request for the original's action carrying the effective
 *   parameters as the same JSON values; a record of a `modify` holds a modification response
 *   without its new request; or a record of a decision failure, or of a Guardian decision other
 *   than `modify`, holds a new request, which only a modification has. A record of a `modify` that
 *   holds neither a new request nor a release is a deny of the original;
 * - `ecl.rule.acs-judgment-guardian.v1` (AC1-004): a Guardian decision from an `agent` or
 *   `composite` evaluator, or one that states no evaluator, is not classed `judgment`; a
 *   deterministic Guardian decision that a hook point carried (`guardian.channel` `hook`) is not
 *   classed `actor_supplied`; any other is not classed with the least trusted class of the inputs
 *   that its `derived_from` names; a response that records the Guardian decision has not exactly
 *   one input marked as it; or an `admit` rests on anything but `verifiable` inputs;
 * - `ecl.rule.acs-outcome-no-weaker.v1` (AC1-004): the ECL outcome is weaker than the mapping;
 * - `ecl.rule.acs-release-requires-admit.v1` (AC1-003): the action went ahead without an admit
 *   bound to the exact request, outside its window, or with other parameters;
 * - `ecl.rule.acs-decision-recorded.v1` (AC1-008, AC1-009): the ECL response does not record the
 *   Guardian decision and chain head that it depends on, or a recorded chain head is not the head
 *   that the recomputed ACS session chain has after that step;
 * - `ecl.rule.acs-inputs-match-basis.v1` (AC1-012): the record's inputs are not the inputs, classes
 *   and digests that the response records in `ecl.ext.decision-basis.v1`, or the decision basis of
 *   the modification response carries another `register` reference, compared member for member,
 *   or does not record the record's inputs with their declared class, required flag, source and
 *   `derived_from`.
 *
 * AC1-012 also holds the record's `response`, and its `modification_response`, to DCMP2-053: a
 * decision basis that one of them records and that breaks the one-way rule is reported under that
 * rule, `ecl.rule.decision-basis-one-way.v1`, which is the response's own rule and not one of the
 * profile's (`RULES`).
 */

import { concat, sha256, toHex } from "../crypto/bytes.js";
import { parseStrictJson, StrictJsonError } from "../json/strict.js";
import { isArray, isObject, pythonEquals } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { inputKey } from "../semantic/rules.js";
import type { Finding } from "../semantic/rules.js";
import {
  ONE_WAY_RULE,
  OUTCOMES,
  array,
  basisClassProblems,
  basisProblems,
  at,
  deferralProblems,
  digestOf,
  exchanges,
  extensionEntries,
  extensionValues,
  findings,
  holds,
  inputProblems,
  instant,
  integer,
  member,
  messageFindings,
  modificationBasisProblems,
  modificationProblems,
  modificationResponseProblems,
  newRequestProblems,
  obj,
  oneWayResponseProblems,
  releaseProblems,
  text,
} from "./common.js";
import type { Exchange, Problem } from "./common.js";
import { JcsError, jcsCanonicalize, jcsDigest } from "./jcs.js";

export const ACS_VERSION = "0.1.0";
export const EXCHANGE_VERSION = "ecl_acs_exchange_v1";
export const EXCHANGE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/acs-exchange/1";
export const DECISION_EXTENSION = "ecl.ext.acs-decision.v1";
/**
 * AC1-004: only a `deterministic` Guardian's decision can be anything but a judgment input, whether
 * its evaluator is `agent` or `composite` or not stated. It takes the least trusted class of the
 * inputs its request carried, which the record names in the `derived_from` of the Guardian's input
 * (Section 4.3 of the core standard), and is `actor_supplied` when it reached the decision point
 * through a channel that the governed AI system can write.
 */
export const DETERMINISTIC_EVALUATOR = "deterministic";
/**
 * AC1-004: how the decision point obtained the Guardian's decision (`guardian.channel`): from the
 * Guardian directly, by verifying the Guardian's signature over it under a key that the governed AI
 * system cannot use, or through a hook point, which runs in the Observed Agent and whose ACS-Core
 * HMAC is made under a key that the Observed Agent holds (ECL1N-0178).
 */
export const CHANNELS: readonly string[] = ["direct", "signed", "hook"];
const AUTHENTICATED_CHANNELS = new Set(["direct", "signed"]);

function authenticated(channel: string | null): boolean {
  return channel !== null && AUTHENTICATED_CHANNELS.has(channel);
}
// Section 4.3: the decision-input classes from most to least trusted.
const CLASSES = ["verifiable", "judgment", "actor_supplied"];

/** The least trusted of `classes`; `verifiable` for none. Other values are passed over. */
export function leastTrusted(classes: Iterable<string | null>): string {
  let rank = 0;
  for (const item of classes) {
    const found = item === null ? -1 : CLASSES.indexOf(item);
    if (found > rank) {
      rank = found;
    }
  }
  return CLASSES[rank] as string;
}

/**
 * The class of a Guardian decision (AC1-004): `judgment` unless its evaluator is `deterministic`,
 * so from an `agent` or `composite` evaluator or one that states none; `actor_supplied` when the
 * decision point neither obtained it from the Guardian directly nor verified the Guardian's
 * signature over it (`channel` neither `direct` nor `signed`), as for a decision that a hook point
 * carried; and otherwise the least trusted class of the inputs its request carried.
 */
export function guardianClass(evaluator: string | null, carried: Iterable<string | null>, channel: string | null): string {
  if (evaluator !== DETERMINISTIC_EVALUATOR) {
    return "judgment";
  }
  if (!authenticated(channel)) {
    return "actor_supplied";
  }
  return leastTrusted(carried);
}
const PERMITTED_OUTCOMES: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ["allow", new Set(OUTCOMES)],
  ["deny", new Set(["deny"])],
  ["modify", new Set(["deny"])],
  ["ask", new Set(["challenge", "hold", "deny"])],
  ["defer", new Set(["hold", "deny"])],
]);
export const REDACTED = "[REDACTED]";
const NANOSECONDS = 1_000_000_000n;
const MILLISECOND = 1_000_000n;

export const FAILURE_RULE = "ecl.rule.acs-decision-failure-closed.v1";
export const EXPIRY_RULE = "ecl.rule.acs-expiry-no-release.v1";
export const MODIFICATION_RULE = "ecl.rule.acs-modification-new-request.v1";
export const JUDGMENT_RULE = "ecl.rule.acs-judgment-guardian.v1";
export const OUTCOME_RULE = "ecl.rule.acs-outcome-no-weaker.v1";
export const RELEASE_RULE = "ecl.rule.acs-release-requires-admit.v1";
export const RECORD_RULE = "ecl.rule.acs-decision-recorded.v1";
export const BASIS_RULE = "ecl.rule.acs-inputs-match-basis.v1";

function defineMember(target: JsonObject, name: string, value: JsonValue): void {
  Object.defineProperty(target, name, { value, enumerable: true, writable: true, configurable: true });
}

function deepCopy(value: JsonValue): JsonValue {
  if (isArray(value)) {
    return value.map(deepCopy);
  }
  if (isObject(value)) {
    const copy: JsonObject = {};
    for (const name of Object.keys(value)) {
      defineMember(copy, name, deepCopy(value[name] as JsonValue));
    }
    return copy;
  }
  return value;
}

function pointer(path: string): string[] | null {
  if (!path.startsWith("/")) {
    return null;
  }
  return path
    .split("/")
    .slice(1)
    .map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"));
}

function overlaps(first: readonly string[], second: readonly string[]): boolean {
  const shorter = Math.min(first.length, second.length);
  for (let index = 0; index < shorter; index += 1) {
    if (first[index] !== second[index]) {
      return false;
    }
  }
  return true;
}

/**
 * The tool arguments after a `modify` decision's modifications, or null if there are none: null
 * means the modifications object is one the pinned text forbids (a wholesale replacement with
 * edits, or edits whose targets overlap), cannot be applied (a redaction path that does not
 * resolve inside the arguments), or yields arguments outside the restricted canonical profile.
 * Each of these ends in a deny of the original with no new request (AC1-005).
 */
export function effectiveParameters(argumentsValue: JsonObject, modifications: JsonValue): JsonObject | null {
  if (!isObject(modifications)) {
    return null;
  }
  const wholesale = at(modifications, "modified_content");
  const redactions = holds(modifications, "redactions") ? at(modifications, "redactions") : [];
  const overrides = holds(modifications, "parameter_overrides") ? at(modifications, "parameter_overrides") : {};
  if (wholesale !== null) {
    if (holds(modifications, "redactions") || holds(modifications, "parameter_overrides")) {
      return null;
    }
    if (typeof wholesale !== "string") {
      return null;
    }
    let replaced: JsonValue;
    try {
      replaced = parseStrictJson(wholesale);
    } catch (error) {
      if (error instanceof StrictJsonError) {
        return null;
      }
      throw error;
    }
    return isObject(replaced) ? replaced : null;
  }
  if (!isArray(redactions) || !isObject(overrides)) {
    return null;
  }
  const overrideNames = Object.keys(overrides);
  if (redactions.length === 0 && overrideNames.length === 0) {
    return null;
  }
  const paths: string[][] = [];
  for (const item of redactions) {
    const path = isObject(item) ? at(item, "path") : null;
    const parts = typeof path === "string" ? pointer(path) : null;
    if (parts === null || parts.length === 0) {
      return null;
    }
    paths.push(parts);
  }
  if (paths.some((parts) => overrideNames.some((name) => overlaps(parts, [name])))) {
    return null;
  }
  const result = deepCopy(argumentsValue) as JsonObject;
  for (const name of overrideNames) {
    defineMember(result, name, deepCopy(overrides[name] as JsonValue));
  }
  for (let index = 0; index < redactions.length; index += 1) {
    const item = redactions[index] as JsonObject;
    const parts = paths[index] as string[];
    const replacement = holds(item, "replacement") ? at(item, "replacement") : REDACTED;
    let container: JsonValue = result;
    for (const step of parts.slice(0, -1)) {
      container = isObject(container) ? at(container, step) : null;
    }
    const last = parts[parts.length - 1] as string;
    if (!isObject(container) || !holds(container, last)) {
      return null;
    }
    defineMember(container, last, replacement);
  }
  return digestOf(result) !== null ? result : null;
}

function hexBytes(text: string): Uint8Array | null {
  // Python's bytes.fromhex: pairs of hexadecimal digits, with whitespace allowed between pairs.
  const out: number[] = [];
  let index = 0;
  while (index < text.length) {
    const character = text[index] as string;
    if (/\s/.test(character) && character !== " " && character.charCodeAt(0) < 0x80) {
      index += 1;
      continue;
    }
    const pair = text.slice(index, index + 2);
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) {
      return null;
    }
    out.push(Number.parseInt(pair, 16));
    index += 2;
  }
  return new Uint8Array(out);
}

/**
 * The `entry_hash` of an ACS ContextEntry under the pinned chain-hashing rule (section 8.2):
 * SHA-256 of the RFC 8785 form of the entry without `entry_hash` and `previous_hash`, followed by
 * the 32 bytes of `previous_hash`, or nothing for the first entry. Null when it has no form.
 */
export function entryHash(entry: JsonObject): string | null {
  const content: JsonObject = {};
  for (const name of Object.keys(entry)) {
    if (name !== "entry_hash" && name !== "previous_hash") {
      defineMember(content, name, entry[name] as JsonValue);
    }
  }
  const previous = at(entry, "previous_hash");
  const tail = typeof previous === "string" ? hexBytes(previous) : new Uint8Array(0);
  if (tail === null) {
    return null;
  }
  try {
    return toHex(sha256(concat(jcsCanonicalize(content), tail)));
  } catch (error) {
    if (error instanceof JcsError) {
      return null;
    }
    throw error;
  }
}

/** Each chain entry whose hash or link the recomputation does not reproduce. */
export function chainProblems(entries: readonly JsonValue[]): Problem[] {
  const problems: Problem[] = [];
  let previous: string | null = null;
  entries.forEach((entry, index) => {
    if (!isObject(entry)) {
      problems.push([`/chain/${index}`, "a ContextEntry is not an object"]);
      return;
    }
    if (!pythonEquals(at(entry, "previous_hash"), previous)) {
      problems.push([`/chain/${index}/previous_hash`, "the link is not the prior head"]);
    }
    if (!pythonEquals(entryHash(entry), at(entry, "entry_hash"))) {
      problems.push([`/chain/${index}/entry_hash`, "the hash is not the recomputed one"]);
    }
    const hash = at(entry, "entry_hash");
    previous = typeof hash === "string" ? hash : null;
  });
  return problems;
}

/**
 * When the Guardian's ask or defer stops waiting, in nanoseconds since the epoch: the time the
 * adapter observed its decision plus `ask_details.timeout_seconds` or
 * `defer_details.resolution_timeout_ms`. Null when the record lacks either.
 */
export function deadline(record: JsonObject, disposition: string): bigint | null {
  const received = instant(member(record, "guardian", "observed_at"));
  let span: bigint | null;
  if (disposition === "ask") {
    const seconds = integer(record, "guardian", "result", "ask_details", "timeout_seconds");
    span = seconds === null ? null : BigInt(seconds) * NANOSECONDS;
  } else {
    const milliseconds = integer(record, "guardian", "result", "defer_details", "resolution_timeout_ms");
    span = milliseconds === null ? null : BigInt(milliseconds) * MILLISECOND;
  }
  return received === null || span === null ? null : received + span;
}

function modificationsDigest(result: JsonObject): JsonValue {
  if (!holds(result, "modifications")) {
    return null;
  }
  try {
    return jcsDigest(result["modifications"] as JsonValue);
  } catch (error) {
    if (error instanceof JcsError) {
      return null;
    }
    throw error;
  }
}

/** What every rule of the profile reads from one record. */
interface View {
  readonly record: JsonObject;
  readonly disposition: string | null;
  readonly outcome: string | null;
  readonly candidates: readonly Exchange[];
}

function failure(view: View): Problem[] {
  const { record } = view;
  const problems: Problem[] = [];
  if (text(record, "on_decision_failure") !== "deny") {
    problems.push(["/on_decision_failure", "a claim of this profile negotiates deny"]);
  }
  if (text(record, "guardian", "status") === "failed") {
    if (obj(record, "release") !== null) {
      problems.push(["/release", "a Guardian decision failure released the action"]);
    }
    if (view.outcome === "admit") {
      problems.push(["/response/outcome", "a Guardian decision failure ended in an admit"]);
    }
  }
  return problems;
}

function expiry(view: View): Problem[] {
  const { record, disposition, outcome } = view;
  if (disposition !== "ask" && disposition !== "defer") {
    return [];
  }
  const problems: Problem[] = [];
  if (outcome === "hold" || outcome === "challenge") {
    problems.push(...deferralProblems(member(record, "response"), deadline(record, disposition)));
    const expires = instant(member(record, "response", "expires_at"));
    const released = instant(member(record, "release", "released_at"));
    if (expires !== null && released !== null && released >= expires) {
      problems.push(["/release/released_at", "the action went ahead after the expiry"]);
    }
  }
  return problems;
}

function modification(view: View): Problem[] {
  const { record } = view;
  const request = obj(record, "request");
  if (view.disposition !== "modify") {
    return newRequestProblems(record);
  }
  if (request === null) {
    return [];
  }
  if (!Object.prototype.hasOwnProperty.call(record, "modification_request") && obj(record, "release") === null) {
    return modificationResponseProblems(record);
  }
  const argumentsValue = member(request, "action", "parameters");
  const effective = effectiveParameters(isObject(argumentsValue) ? argumentsValue : {}, member(record, "guardian", "result", "modifications"));
  const modified = member(record, "modification_request");
  if (effective === null) {
    const problems: Problem[] = [];
    if (modified !== null) {
      problems.push(["/modification_request", "an unusable modification gets no new request"]);
    }
    if (obj(record, "release") !== null) {
      problems.push(["/release", "an unusable modification releases nothing"]);
    }
    return problems;
  }
  const problems: Problem[] = modificationProblems(request, modified, effective).map(([path, message]): Problem => ["/" + path, message]);
  if (obj(record, "release") !== null && text(record, "release", "request_id") !== text(record, "modification_request", "message_id")) {
    problems.push(["/release/request_id", "a modification is released only under its new request"]);
  }
  return problems;
}

function judgment(view: View): Problem[] {
  const inputs = array(view.record, "inputs");
  const evaluator = text(view.record, "guardian", "result", "metadata", "evaluator");
  const channel = text(view.record, "guardian", "channel");
  // As the reference's dict comprehension: a later input with the same key wins. A name in
  // `derived_from` is compared as input names are (DCMP2-053).
  const classes = new Map<string, string | null>();
  for (const item of inputs) {
    const name = text(item, "input");
    if (name !== null) {
      classes.set(inputKey(name), text(item, "class"));
    }
  }
  const problems: Problem[] = [];
  const marked: number[] = [];
  inputs.forEach((item, index) => {
    if (member(item, "guardian") === true) {
      marked.push(index);
    }
  });
  // The class that each marked input must have, by its `inputKey`, in every decision basis that the
  // record holds (AC1-004).
  const required = new Map<string, string>();
  for (const index of marked) {
    const item = inputs[index] as JsonValue;
    const path = `/inputs/${index}`;
    const derived = member(item, "derived_from");
    const name = text(item, "input");
    let expected: string;
    if (evaluator !== DETERMINISTIC_EVALUATOR || !authenticated(channel)) {
      expected = guardianClass(evaluator, [], channel);
    } else if (!isArray(derived)) {
      const recordedClass = text(item, "class");
      if (recordedClass === "verifiable") {
        problems.push([path + "/derived_from", "a verifiable Guardian decision names the inputs its request carried"]);
      } else if (name !== null && recordedClass !== null) {
        required.set(inputKey(name), recordedClass);
      }
      continue;
    } else {
      derived.forEach((name, offset) => {
        if (typeof name !== "string" || !classes.has(inputKey(name))) {
          problems.push([`${path}/derived_from/${offset}`, "the record lists no such input"]);
        }
      });
      const carried = derived.filter((name): name is string => typeof name === "string").map((name) => classes.get(inputKey(name)) ?? null);
      expected = guardianClass(evaluator, carried, channel);
    }
    if (text(item, "class") !== expected) {
      problems.push([path + "/class", `this input must be ${expected}`]);
    }
    if (name !== null) {
      required.set(inputKey(name), expected);
    }
  }
  // AC1-004: a response that records the Guardian decision rests on it as one input, which the
  // record marks; an unmarked one would escape the class check above.
  if (extensionEntries(obj(view.record, "response"), DECISION_EXTENSION).length > 0) {
    if (marked.length === 0) {
      problems.push(["/inputs", "no input is marked as the Guardian's decision"]);
    }
    for (const index of marked.slice(1)) {
      problems.push([`/inputs/${index}/guardian`, "another input is marked as the Guardian's decision"]);
    }
  }
  problems.push(...basisClassProblems(view.record, ["modification_response"], required));
  return [...problems, ...inputProblems(inputs, view.outcome)];
}

function outcomeNoWeaker(view: View): Problem[] {
  const permitted = PERMITTED_OUTCOMES.get(view.disposition ?? "");
  if (permitted !== undefined && (view.outcome === null || !permitted.has(view.outcome))) {
    return [["/response/outcome", `${String(view.disposition)} cannot become ${view.outcome === null ? "None" : view.outcome}`]];
  }
  return [];
}

function release(view: View): Problem[] {
  return releaseProblems(member(view.record, "release"), view.candidates);
}

function recorded(view: View): Problem[] {
  const { record } = view;
  const result = obj(record, "guardian", "result");
  const response = obj(record, "response");
  if (text(record, "guardian", "status") !== "decided" || result === null || response === null) {
    return [];
  }
  const entries = extensionEntries(response, DECISION_EXTENSION);
  const values = extensionValues(response, DECISION_EXTENSION);
  if (entries.length !== 1 || values.length !== 1) {
    return [["/response/extensions", "the response records the Guardian decision once"]];
  }
  const value = values[0] as JsonObject;
  const problems: Problem[] = [];
  const expected: ReadonlyArray<readonly [string, JsonValue]> = [
    ["decision", at(result, "decision")],
    ["request_id", at(result, "request_id")],
    ["evaluator", member(result, "metadata", "evaluator")],
    ["chain_hash", at(result, "chain_hash")],
    ["modifications_digest", modificationsDigest(result)],
  ];
  for (const [name, wanted] of expected) {
    if (!pythonEquals(at(value, name), wanted)) {
      problems.push([`/response/extensions/${name}`, `the recorded ${name} is not the Guardian's`]);
    }
  }
  if (member(record, "audit_profile") === true && typeof at(value, "request_hash") !== "string") {
    problems.push(["/response/extensions/request_hash", "ACS-Audit records the request hash"]);
  }
  const chain = array(record, "chain");
  if (chain.length === 0) {
    return problems;
  }
  problems.push(...chainProblems(chain));
  const step = chain.find((entry) => isObject(entry) && pythonEquals(at(entry, "step_id"), at(value, "request_id")));
  if (step === undefined || !pythonEquals(member(step, "entry_hash"), at(value, "chain_hash"))) {
    problems.push(["/response/extensions/chain_hash", "the recorded head is not the step's chain head"]);
  } else if (holds(value, "request_hash") && !pythonEquals(member(step, "request_hash"), at(value, "request_hash"))) {
    problems.push(["/response/extensions/request_hash", "the recorded request hash is not the step's"]);
  }
  return problems;
}

/**
 * The rules of the profile, in the order the reference reports them. A rule added to the
 * registry for this profile is one function above and one row here.
 */
export const RULES: ReadonlyArray<readonly [string, (view: View) => Problem[]]> = [
  [FAILURE_RULE, failure],
  [EXPIRY_RULE, expiry],
  [MODIFICATION_RULE, modification],
  [JUDGMENT_RULE, judgment],
  [OUTCOME_RULE, outcomeNoWeaker],
  [RELEASE_RULE, release],
  [RECORD_RULE, recorded],
  [BASIS_RULE, (view) => [...basisProblems(view.record, "guardian"), ...modificationBasisProblems(view.record)]],
];

/** The findings of an `ecl_acs_exchange_v1` record that its schema has accepted. */
export function check(record: JsonObject): Finding[] {
  const status = text(record, "guardian", "status");
  const view: View = {
    record,
    disposition: status === "decided" ? text(record, "guardian", "result", "decision") : null,
    outcome: text(record, "response", "outcome"),
    candidates: exchanges(record, ["request", "response"], ["modification_request", "modification_response"]),
  };
  return [
    ...RULES.flatMap(([rule, problems]) => findings(rule, problems(view))),
    ...findings(ONE_WAY_RULE, oneWayResponseProblems(record, [["request"], ["response"]], [["modification_request"], ["modification_response"]])),
    ...messageFindings(record, ["request"], ["response"], ["modification_request"], ["modification_response"]),
  ];
}
