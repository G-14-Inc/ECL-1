/**
 * What the five binding profiles share: reading records, digests, decision pairs and releases.
 *
 * The checkers read exchange records, JSON objects that an adapter retains for audit. A record
 * embeds the DCMP-2 messages and EBMP-2 events of one exchange as decoded payloads; the record's
 * schema has already validated their shape, and a signature, where there is one, is the bundle
 * verifier's to check. These helpers read a member that is missing, or of another type, as null
 * (Python's None), and a check that cannot be made because of it is a finding of the rule that
 * needed it. Where the reference compares with Python's `==`, so do these helpers
 * (`pythonEquals`); where a profile requires the same JSON values, they compare with `sameJson`, as
 * the reference does with `same_json`, under which a boolean never equals a number.
 */

import { BindingError, checkResponseBinding } from "../binding/binding.js";
import { equalBytes, fromCanonicalBase64 } from "../crypto/bytes.js";
import { CanonicalizationError, objectDigest } from "../json/canonical.js";
import { compareCodePoints, isArray, isInteger, isObject, pythonEquals } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { requestProblems } from "../evidence/decision-basis.js";
import { objectFindings } from "../semantic/object.js";
import { inputKey, oneWayProblems } from "../semantic/rules.js";
import type { Finding } from "../semantic/rules.js";
import { InstantError, instantNanoseconds } from "../time.js";
import { JcsError, jcsCanonicalize } from "./jcs.js";

export const DIGEST_SUITE = "ecl.digest.sha-256.v1";
/**
 * MG1-012: the only member of a record member that holds bound content outside the restricted
 * profile, encoded as the canonical base64 of its RFC 8785 bytes.
 */
export const ENCODED = "rfc8785";
export const MODIFICATION_OF = "ecl.relation.modification-of.v1";
export const OUTCOMES: readonly string[] = ["admit", "deny", "hold", "challenge"];
/**
 * The safe states that permit no new effect of the governed action: the registry marks the first
 * three `permits_new_effects: false`, and the restricted state permits only bounded diagnosis,
 * recovery and safe-shutdown operations, none of which is the action that waits. A fail-open or
 * degraded state can let the action through, so neither may decide an expiry (DCMP2-041).
 */
export const NO_EFFECT_SAFE_STATES: ReadonlySet<string> = new Set([
  "ecl.state.fail-closed.v1",
  "ecl.state.quarantine.v1",
  "ecl.state.emergency-halt.v1",
  "ecl.state.restricted.v1",
]);

/** ECL1N-0181: the registered extension in which a decision response records its basis. */
export const DECISION_BASIS = "ecl.ext.decision-basis.v1";
/**
 * DCMP2-053: the rule under which a binding checker reports a decision basis, recorded by a
 * decision response that a record embeds, that breaks the one-way rule (AB1-013, AC1-012,
 * MG1-007). It is the rule of the response itself, not one of the profile's own rules.
 */
export const ONE_WAY_RULE = "ecl.rule.decision-basis-one-way.v1";

/** One reason a record breaks a rule: a JSON Pointer into the record, and why. */
export type Problem = readonly [path: string, message: string];

const hasOwn = (value: object, key: string): boolean => Object.prototype.hasOwnProperty.call(value, key);

/** The member at `path` of nested objects, or null when a step is not there (Python's None). */
export function member(value: unknown, ...path: string[]): JsonValue {
  let found: unknown = value;
  for (const step of path) {
    if (!isObject(found) || !hasOwn(found, step)) {
      return null;
    }
    found = found[step];
  }
  return found as JsonValue;
}

/** Whether `value` is an object that holds `key` (Python's `key in value` for a dict). */
export function holds(value: unknown, key: string): boolean {
  return isObject(value) && hasOwn(value, key);
}

/** `dict.get(key)` of an object: the member, or null. */
export function at(value: JsonObject, key: string): JsonValue {
  return hasOwn(value, key) ? (value[key] as JsonValue) : null;
}

export function text(value: unknown, ...path: string[]): string | null {
  const found = member(value, ...path);
  return typeof found === "string" ? found : null;
}

export function integer(value: unknown, ...path: string[]): number | null {
  const found = member(value, ...path);
  return isInteger(found) ? found : null;
}

export function obj(value: unknown, ...path: string[]): JsonObject | null {
  const found = member(value, ...path);
  return isObject(found) ? found : null;
}

export function array(value: unknown, ...path: string[]): JsonValue[] {
  const found = member(value, ...path);
  return isArray(found) ? found : [];
}

/** An ECL instant in nanoseconds since the epoch, or null when it is not one. */
export function instant(value: unknown): bigint | null {
  try {
    return instantNanoseconds(value);
  } catch (error) {
    if (error instanceof InstantError) {
      return null;
    }
    throw error;
  }
}

/**
 * The `ecl.digest.sha-256.v1` digest of the restricted canonical JSON of `value` (IE1-001), or null
 * when `value` is outside that profile.
 */
export function digestOf(value: JsonValue): JsonObject | null {
  try {
    return { algorithm: DIGEST_SUITE, value: objectDigest(value) };
  } catch (error) {
    if (error instanceof CanonicalizationError) {
      return null;
    }
    throw error;
  }
}

/** A record member in the encoded form of MG1-012 that does not decode as that form requires. */
export class ContentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContentError";
  }
}

/** Set an own member, so that a name such as `__proto__` stays an ordinary member. */
function define(target: JsonObject, name: string, value: JsonValue): void {
  Object.defineProperty(target, name, { value, enumerable: true, writable: true, configurable: true });
}

/** A copy of an object's own members (a shallow copy). */
function copyObject(value: JsonObject): JsonObject {
  const copy: JsonObject = {};
  for (const name of Object.keys(value)) {
    define(copy, name, value[name] as JsonValue);
  }
  return copy;
}

/** A deep copy of a JSON value. */
export function copyJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map(copyJson);
  }
  if (isObject(value)) {
    const copy: JsonObject = {};
    for (const name of Object.keys(value)) {
      define(copy, name, copyJson(value[name] as JsonValue));
    }
    return copy;
  }
  return value;
}

/** `value` has the shape of the encoded form: an object whose only member is `rfc8785`. */
export function isEncoded(value: unknown): value is JsonObject {
  return isObject(value) && Object.keys(value).length === 1 && hasOwn(value, ENCODED);
}

const contentDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * The content that a record member holds: the member itself, or what its encoded form decodes to.
 * An encoded member decodes only when its text is canonical base64, its bytes are the RFC 8785
 * canonical form of a JSON object, and that object lies outside the restricted profile, since
 * content within the profile is held as itself; otherwise ContentError.
 */
export function decodeContent(value: JsonValue): JsonValue {
  if (!isEncoded(value)) {
    return value;
  }
  const encoded = value[ENCODED];
  if (typeof encoded !== "string") {
    throw new ContentError("the encoded content is not a string");
  }
  const data = fromCanonicalBase64(encoded);
  if (data === undefined) {
    throw new ContentError("the encoded content is not canonical base64");
  }
  let content: JsonValue;
  let canonical: Uint8Array;
  try {
    content = JSON.parse(contentDecoder.decode(data)) as JsonValue;
    canonical = jcsCanonicalize(content);
  } catch (error) {
    if (error instanceof JcsError || error instanceof SyntaxError || error instanceof TypeError || error instanceof RangeError) {
      throw new ContentError("the encoded bytes are not I-JSON with an RFC 8785 form");
    }
    throw error;
  }
  if (!equalBytes(canonical, data)) {
    throw new ContentError("the encoded bytes are not the RFC 8785 canonical form of the content");
  }
  if (!isObject(content)) {
    throw new ContentError("the encoded content is not a JSON object");
  }
  if (digestOf(content) !== null) {
    throw new ContentError("content within the restricted profile is held as itself");
  }
  return content;
}

/**
 * A copy of `record` with the member at each of `paths` replaced by the content it holds, and a
 * problem for each member whose encoded form does not decode (MG1-012).
 */
export function decodedRecord(record: JsonObject, paths: ReadonlyArray<readonly string[]>): [JsonObject, Problem[]] {
  const result = copyObject(record);
  const problems: Problem[] = [];
  for (const path of paths) {
    let parent: JsonObject | null = result;
    for (const step of path.slice(0, -1)) {
      const found: JsonValue = hasOwn(parent, step) ? (parent[step] as JsonValue) : null;
      if (!isObject(found)) {
        parent = null;
        break;
      }
      const copied = copyObject(found);
      define(parent, step, copied);
      parent = copied;
    }
    const last = path[path.length - 1] as string;
    if (parent === null || !hasOwn(parent, last)) {
      continue;
    }
    try {
      define(parent, last, decodeContent(parent[last] as JsonValue));
    } catch (error) {
      if (!(error instanceof ContentError)) {
        throw error;
      }
      problems.push(["/" + path.join("/"), error.message]);
    }
  }
  return [result, problems];
}

/** Two digest objects name the same algorithm and value, and both are digest objects. */
export function sameDigest(left: unknown, right: unknown): boolean {
  const algorithm = text(left, "algorithm");
  const digest = text(left, "value");
  return isObject(left) && isObject(right) && algorithm !== null && digest !== null && algorithm === text(right, "algorithm") && digest === text(right, "value");
}

/** `response` is bound to `request` under DCMP2-044 to DCMP2-050 (binding/binding.ts). */
export function binds(request: unknown, response: unknown): boolean {
  if (!isObject(request) || !isObject(response)) {
    return false;
  }
  try {
    checkResponseBinding(request, response);
  } catch (error) {
    if (error instanceof BindingError) {
      return false;
    }
    throw error;
  }
  return true;
}

/** The values of the extensions with this identifier that `value` carries. */
export function extensionValues(value: unknown, identifier: string): JsonObject[] {
  const found: JsonObject[] = [];
  for (const item of array(value, "extensions")) {
    if (isObject(item) && pythonEquals(at(item, "id"), identifier)) {
      const content = at(item, "value");
      if (isObject(content)) {
        found.push(content);
      }
    }
  }
  return found;
}

/** The whole extension entries with this identifier, with their `critical` flags. */
export function extensionEntries(value: unknown, identifier: string): JsonObject[] {
  return array(value, "extensions").filter((item): item is JsonObject => isObject(item) && pythonEquals(at(item, "id"), identifier));
}

/** A decision request of a record and the response to it, if the record has one. */
export class Exchange {
  constructor(
    readonly request: JsonObject,
    readonly response: JsonObject | null,
  ) {}

  get requestId(): string | null {
    return text(this.request, "message_id");
  }

  get outcome(): string | null {
    return text(this.response, "outcome");
  }

  admits(): boolean {
    return this.outcome === "admit" && binds(this.request, this.response);
  }
}

/** The (request, response) pairs that the record holds under the given member names. */
export function exchanges(record: JsonObject, ...pairs: ReadonlyArray<readonly [string, string]>): Exchange[] {
  const found: Exchange[] = [];
  for (const [requestName, responseName] of pairs) {
    const request = obj(record, requestName);
    if (request !== null) {
      found.push(new Exchange(request, obj(record, responseName)));
    }
  }
  return found;
}

/**
 * Each reason a recorded release is not one an admit authorized. A release names the request it
 * went ahead under, the parameters digest it released and its time. The request must be one the
 * record holds; its response must admit and be bound to it; the digest must be the request's; and
 * the time must lie in the authorization's window, from `valid_from` until before `valid_until`.
 */
export function releaseProblems(release: JsonValue, candidates: readonly Exchange[]): Problem[] {
  if (release === null) {
    return [];
  }
  if (!isObject(release)) {
    return [["/release", "the release record is not an object"]];
  }
  const named = text(release, "request_id");
  const exchange = candidates.find((item) => item.requestId === named);
  if (exchange === undefined) {
    return [["/release/request_id", "the release names no decision request of the record"]];
  }
  if (exchange.response === null || exchange.outcome !== "admit") {
    return [["/release/request_id", "the action was released without an admit"]];
  }
  if (!binds(exchange.request, exchange.response)) {
    return [["/release/request_id", "the admit is not bound to the exact request"]];
  }
  const problems: Problem[] = [];
  if (!sameDigest(member(release, "parameters_digest"), member(exchange.request, "action", "parameters_digest"))) {
    problems.push(["/release/parameters_digest", "the released parameters are not the admitted ones"]);
  }
  const released = instant(member(release, "released_at"));
  const start = instant(member(exchange.response, "authorization", "valid_from"));
  const end = instant(member(exchange.response, "authorization", "valid_until"));
  if (released === null || start === null || end === null || !(start <= released && released < end)) {
    problems.push(["/release/released_at", "the release lies outside the authorization's window"]);
  }
  return problems;
}

/**
 * AB1-004, AC1-005: the members of a decision request that the new request for a modification keeps
 * from the original; in its action, only action_id, parameters and parameters_digest change. Its
 * message_id, times, workflow and extensions are its own.
 */
export const UNCHANGED_BY_MODIFICATION: readonly string[] = ["issuer", "actor", "subject", "delegation_chain", "authority_request", "constraints", "integrity_policy"];
const CHANGED_IN_MODIFIED_ACTION: ReadonlySet<string> = new Set(["action_id", "parameters", "parameters_digest"]);

/**
 * Each way `modified` is not the new request for a modification (AB1-004, AC1-005): it has its own
 * message_id; it carries `parameters` as `action.parameters`, as the same JSON values (`sameJson`,
 * so a boolean never stands for a number), with their digest; it names the
 * original request as a causal predecessor by id and digest with the relation
 * `ecl.relation.modification-of.v1`; and it describes the original's action, keeping the members
 * of `UNCHANGED_BY_MODIFICATION` and every member of its action other than action_id, parameters
 * and parameters_digest. Paths are relative to the record, without the leading slash.
 */
export function modificationProblems(original: JsonObject, modified: JsonValue, parameters: JsonValue): Problem[] {
  if (!isObject(modified)) {
    return [["modification_request", "the modification has no new decision request"]];
  }
  const problems: Problem[] = [];
  const identifier = text(modified, "message_id");
  if (identifier === null || identifier === text(original, "message_id")) {
    problems.push(["modification_request/message_id", "the new request reuses the id"]);
  }
  const actual = member(modified, "action", "parameters");
  if (!isObject(parameters) || !sameJson(actual, parameters)) {
    problems.push(["modification_request/action/parameters", "the parameters are not the modified ones"]);
  }
  const expectedDigest = digestOf(actual);
  if (expectedDigest === null || !sameDigest(member(modified, "action", "parameters_digest"), expectedDigest)) {
    problems.push(["modification_request/action/parameters_digest", "the digest is not that of the parameters"]);
  }
  const originalDigest = digestOf(original);
  const originalId = text(original, "message_id");
  const linked = array(modified, "workflow", "causal_predecessors").some(
    (item) => isObject(item) && pythonEquals(at(item, "id"), originalId) && pythonEquals(at(item, "relation"), MODIFICATION_OF) && sameDigest(at(item, "digest"), originalDigest),
  );
  if (!linked) {
    problems.push(["modification_request/workflow/causal_predecessors", "the new request does not name the original as modification-of"]);
  }
  for (const name of UNCHANGED_BY_MODIFICATION) {
    if (!sameJson(member(original, name), member(modified, name))) {
      problems.push([`modification_request/${name}`, `the new request changes the original's ${name}`]);
    }
  }
  const before = obj(original, "action") ?? {};
  const after = obj(modified, "action") ?? {};
  // In the order of Python's sorted(): by code point.
  const names = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort(compareCodePoints);
  for (const name of names) {
    if (!CHANGED_IN_MODIFIED_ACTION.has(name) && !sameJson(at(before, name), at(after, name))) {
      problems.push([`modification_request/action/${name}`, `the new request changes the action's ${name}`]);
    }
  }
  return problems;
}

/**
 * Each member of a new request that a record holds although its decision is not a modification
 * (AB1-004, AC1-005), as the reference's `new_request_problems`: only a MODIFY or a `modify` has a
 * new request, so the record of any other decision, or of a decision failure, holds no
 * `modification_request` and no `modification_response`.
 */
export function newRequestProblems(record: JsonObject): Problem[] {
  return ["modification_request", "modification_response"]
    .filter((name) => hasOwn(record, name))
    .map((name): Problem => ["/" + name, "only a modification has a new decision request"]);
}

/**
 * A modification response that a record of a modification holds without the new request it
 * answers (AB1-004, AC1-005), as the reference's `modification_response_problems`. A record of a
 * modification that holds neither a new request nor a release shows a deny of the original with
 * no new request, which releases nothing.
 */
export function modificationResponseProblems(record: JsonObject): Problem[] {
  return hasOwn(record, "modification_response") ? [["/modification_response", "a modification response answers no new request"]] : [];
}

/**
 * A hold or challenge whose expiry could release the action: it must carry `expires_at`, no later
 * than the deadline of the deferral or approval when there is one, and a `safe_state` that
 * permits no new effect (DCMP2-018, DCMP2-041).
 */
export function deferralProblems(response: JsonValue, deadline: bigint | null): Problem[] {
  const problems: Problem[] = [];
  const expires = instant(member(response, "expires_at"));
  if (expires === null || (deadline !== null && expires > deadline)) {
    problems.push(["/response/expires_at", "the response outlasts the deadline it maps"]);
  }
  const safeState = text(response, "safe_state");
  if (safeState === null || !NO_EFFECT_SAFE_STATES.has(safeState)) {
    problems.push(["/response/safe_state", "the safe state on expiry permits a new effect"]);
  }
  return problems;
}

/**
 * Each way the inputs break the one-way rule of the core standard. The inputs are entries of the
 * decision basis (`ecl.ext.decision-basis.v1`), each with the member its profile adds. Inputs at
 * the positions in `judgmentRequired` must be `judgment`. Only an available `verifiable` input
 * supports an outcome, whatever the outcome (ECL1N-0181), and an `admit` rests on at least one
 * (DCMP2-053).
 */
export function inputProblems(inputs: readonly JsonValue[], outcome: string | null, judgmentRequired: readonly number[] = []): Problem[] {
  const problems: Problem[] = judgmentRequired
    .filter((index) => text(inputs[index], "class") !== "judgment")
    .map((index): Problem => [`/inputs/${index}/class`, "this input must be judgment"]);
  const supporting: Array<[number, JsonValue]> = [];
  inputs.forEach((item, index) => {
    if (text(item, "effect") === "supports") {
      supporting.push([index, item]);
    }
  });
  for (const [index, item] of supporting) {
    if (text(item, "class") !== "verifiable" || text(item, "status") !== "available") {
      problems.push([`/inputs/${index}/effect`, "only a verifiable input can be the basis of admit"]);
    }
  }
  if (outcome === "admit" && !supporting.some(([, item]) => text(item, "class") === "verifiable")) {
    problems.push(["/inputs", "the admit rests on no verifiable input"]);
  }
  return problems;
}

/**
 * Each way a decision response of the record breaks DCMP2-053 (AB1-013, AC1-012, MG1-007), as the
 * reference's `one_way_response_problems`. Each exchange names the path of a decision request in
 * the record and the path of the decision response that answers it. Each response carries exactly
 * one value of `ecl.ext.decision-basis.v1`, since a response without one shows no basis that a
 * checker of the record could see. Each response is checked as a decision response is checked on
 * its own, with its outcome and `evaluated_at`: the one-way check (`oneWayProblems`) runs on each
 * value that it carries. With the request that the record holds, `requestProblems` refuses an
 * input recorded as `verifiable` whose `source` is the request's `actor`, and a request recorded as
 * received before it was issued, as an evidence verifier does with the request of a signed bundle
 * under the reference verification profile. A response that the record does not hold has nothing
 * to check.
 */
export function oneWayResponseProblems(
  record: JsonObject,
  ...exchanges: ReadonlyArray<readonly [readonly string[], readonly string[]]>
): Problem[] {
  const problems: Problem[] = [];
  for (const [requestPath, responsePath] of exchanges) {
    const response = obj(record, ...responsePath);
    if (response === null || text(response, "message_type") !== "decision_response") {
      continue;
    }
    const request = obj(record, ...requestPath);
    const admit = text(response, "outcome") === "admit";
    const prefix = `/${responsePath.join("/")}/extensions`;
    const carried: Array<[number, JsonObject]> = [];
    array(response, "extensions").forEach((item, index) => {
      if (isObject(item) && pythonEquals(at(item, "id"), DECISION_BASIS)) {
        carried.push([index, item]);
      }
    });
    if (carried.length !== 1) {
      problems.push([prefix, "the decision response does not carry exactly one decision basis"]);
    }
    for (const [index, item] of carried) {
      const value = at(item, "value");
      if (!isObject(value)) {
        continue;
      }
      for (const [where, message] of oneWayProblems(value, admit, at(response, "outcome"), at(response, "evaluated_at"))) {
        problems.push([`${prefix}/${index}/value${where}`, message]);
      }
      if (request !== null) {
        for (const [where, message] of requestProblems(value, request)) {
          problems.push([`${prefix}/${index}/value${where}`, message]);
        }
      }
    }
  }
  return problems;
}

/**
 * Each entry of a decision basis that the response at `responsePath` records whose input a profile
 * gives a class (`required`, keyed by `inputKey`) and that records another class (AB1-006,
 * AC1-004), as the reference's `basis_class_problems`. The class that a profile gives an input
 * holds in every decision basis that the record holds, the modification response's included,
 * whose `admit` releases the modified action (AB1-004, AC1-005).
 */
export function basisClassProblems(record: JsonObject, responsePath: readonly string[], required: ReadonlyMap<string, string>): Problem[] {
  const response = obj(record, ...responsePath);
  const problems: Problem[] = [];
  if (response === null || required.size === 0) {
    return problems;
  }
  const prefix = `/${responsePath.join("/")}/extensions`;
  array(response, "extensions").forEach((item, index) => {
    if (!isObject(item) || !pythonEquals(at(item, "id"), DECISION_BASIS)) {
      return;
    }
    array(at(item, "value"), "inputs").forEach((entry, position) => {
      const name = text(entry, "input");
      const expected = name === null ? undefined : required.get(inputKey(name));
      if (expected !== undefined && text(entry, "class") !== expected) {
        problems.push([`${prefix}/${index}/value/inputs/${position}/class`, `this input must be ${expected}, as the record's inputs class it`]);
      }
    });
  });
  return problems;
}

/** The value of the one `ecl.ext.decision-basis.v1` that the response at `name` carries, with its
 * position among the response's extensions, or null when it carries none, more than one, or a value
 * that is not an object. */
function singleBasis(record: JsonObject, name: string): [number, JsonObject] | null {
  const found: Array<[number, JsonValue]> = [];
  array(obj(record, name), "extensions").forEach((item, index) => {
    if (isObject(item) && pythonEquals(at(item, "id"), DECISION_BASIS)) {
      found.push([index, at(item, "value")]);
    }
  });
  if (found.length !== 1) {
    return null;
  }
  const [index, value] = found[0] as [number, JsonValue];
  return isObject(value) ? [index, value] : null;
}

/** The input keys of the names in an entry's `derived_from`, an absent one naming no input. */
function derivedKeys(entry: JsonValue): Set<string> {
  const keys = new Set<string>();
  for (const name of array(entry, "derived_from")) {
    if (typeof name === "string") {
      keys.add(inputKey(name));
    }
  }
  return keys;
}

/**
 * Each way the decision basis of the record's `modification_response` disagrees with the record
 * (AB1-013, AC1-012), as the reference's
 * `modification_basis_problems`: it carries the `register` reference of the basis of the
 * `response`, member for member, and records the record's `inputs`, each once, compared as input
 * names are (`inputKey`), each with the `class`, `required`, `source` and `derived_from` that the
 * record's input gives it. The status, effect, reference and times of an entry describe the new
 * decision and may differ. A record whose `response` or `modification_response` does not carry
 * exactly one decision basis is left to `oneWayResponseProblems`, which reports it.
 */
export function modificationBasisProblems(record: JsonObject): Problem[] {
  const first = singleBasis(record, "response");
  const second = singleBasis(record, "modification_response");
  if (first === null || second === null) {
    return [];
  }
  const [index, value] = second;
  const prefix = `/modification_response/extensions/${index}/value`;
  const problems: Problem[] = [];
  if (!sameJson(at(value, "register"), at(first[1], "register"))) {
    problems.push([prefix + "/register", "the modification response carries another register reference"]);
  }
  // As the reference's dict comprehension: a later input with the same key wins, in the place of
  // the first.
  const declared = new Map<string, JsonValue>();
  for (const item of array(record, "inputs")) {
    const name = text(item, "input");
    if (name !== null) {
      declared.set(inputKey(name), item);
    }
  }
  const listed = new Set<string>();
  array(value, "inputs").forEach((entry, position) => {
    const name = text(entry, "input");
    if (name === null) {
      return;
    }
    const key = inputKey(name);
    listed.add(key);
    const item = declared.get(key);
    const path = `${prefix}/inputs/${position}`;
    if (item === undefined) {
      problems.push([path + "/input", "the record lists no such input"]);
      return;
    }
    for (const field of ["class", "required"]) {
      if (!sameJson(member(entry, field), member(item, field))) {
        problems.push([`${path}/${field}`, `the ${field} is not the one the record's inputs give`]);
      }
    }
    const source = text(entry, "source");
    const given = text(item, "source");
    if (source === null || given === null || inputKey(source) !== inputKey(given)) {
      problems.push([path + "/source", "the source is not the one the record's inputs give"]);
    }
    const derived = derivedKeys(entry);
    const expected = derivedKeys(item);
    if (derived.size !== expected.size || [...derived].some((key) => !expected.has(key))) {
      problems.push([path + "/derived_from", "derived_from is not the one the record's inputs give"]);
    }
  });
  for (const [key, item] of declared) {
    if (!listed.has(key)) {
      problems.push([prefix + "/inputs", `the modification response does not record the input ${pythonText(text(item, "input"))}`]);
    }
  }
  return problems;
}

/** A string as Python's f-string writes it: None for null. */
function pythonText(value: string | null): string {
  return value === null ? "None" : value;
}

/**
 * The findings of the semantic rules of DCMP-2 for each DCMP-2 message that the record holds at one
 * of `paths` (AB1-013, AC1-012, MG1-007), at the message's place in the record, as the reference's
 * `message_findings`. The one-way rule of a decision basis is left to `oneWayResponseProblems`,
 * which applies it with the record's requests.
 */
export function messageFindings(record: JsonObject, ...paths: ReadonlyArray<readonly string[]>): Finding[] {
  const result: Finding[] = [];
  for (const path of paths) {
    const message = obj(record, ...path);
    if (message === null || text(message, "protocol") !== "DCMP-2") {
      continue;
    }
    // Each rule that the message fails is reported once, at the message's place in the record,
    // with the first of its findings as the message, as the reference's `message_findings`.
    const first = new Map<string, string>();
    for (const item of objectFindings(message)) {
      if (item.ruleId !== ONE_WAY_RULE && !first.has(item.ruleId)) {
        first.set(item.ruleId, item.message);
      }
    }
    for (const rule of [...first.keys()].sort()) {
      result.push({ ruleId: rule, path: `/${path.join("/")}`, message: first.get(rule) as string });
    }
  }
  return result;
}

/** Two JSON values are equal as the reference's `same_json` compares them: the same type, so a
 * boolean never equals a number. */
export function sameJson(left: JsonValue | undefined, right: JsonValue | undefined): boolean {
  if (left === undefined || right === undefined) {
    return left === right;
  }
  if (isArray(left) || isArray(right)) {
    return isArray(left) && isArray(right) && left.length === right.length && left.every((item, index) => sameJson(item, right[index]));
  }
  if (isObject(left) || isObject(right)) {
    if (!isObject(left) || !isObject(right)) {
      return false;
    }
    const keys = Object.keys(left);
    return keys.length === Object.keys(right).length && keys.every((key) => Object.prototype.hasOwnProperty.call(right, key) && sameJson(left[key], right[key]));
  }
  return typeof left === typeof right && left === right;
}

/**
 * Each way the record's `inputs` disagree with the decision basis that its `response` records in
 * `ecl.ext.decision-basis.v1` (AB1-013, AC1-012).
 *
 * Each input of the record, without the member `marker` that its profile adds, equals the entry of
 * the basis whose `input` is the same, and each entry appears in the record exactly once. A
 * response that does not carry the extension records no inputs. One that carries it more than
 * once, or whose value has no `inputs` array, agrees with no record. A record without a response
 * has nothing to agree with.
 */
export function basisProblems(record: JsonObject, marker: string): Problem[] {
  const response = obj(record, "response");
  if (response === null) {
    return [];
  }
  const extensions = array(response, "extensions");
  const positions: number[] = [];
  extensions.forEach((item, index) => {
    if (isObject(item) && at(item, "id") === DECISION_BASIS) {
      positions.push(index);
    }
  });
  if (positions.length > 1) {
    return [["/response/extensions", "the response records its decision basis more than once"]];
  }
  let entries: JsonValue[] = [];
  let prefix = "/response/extensions";
  const position = positions[0];
  if (position !== undefined) {
    prefix = `/response/extensions/${position}/value/inputs`;
    const listed = member(extensions[position], "value", "inputs");
    if (!isArray(listed)) {
      return [[prefix, "the decision basis has no inputs array"]];
    }
    entries = listed;
  }
  const problems: Problem[] = [];
  // Each entry's position under the name it gives, in the order the names first appear.
  const named = new Map<string, number[]>();
  entries.forEach((entry, index) => {
    const name = text(entry, "input");
    if (name === null) {
      problems.push([`${prefix}/${index}`, "the decision-basis entry names no input"]);
    } else {
      const found = named.get(name);
      if (found === undefined) {
        named.set(name, [index]);
      } else {
        found.push(index);
      }
    }
  });
  const listedNames = new Set<string>();
  array(record, "inputs").forEach((item, index) => {
    const path = `/inputs/${index}`;
    const name = text(item, "input");
    if (name !== null && listedNames.has(name)) {
      problems.push([path + "/input", "the record lists this input more than once"]);
      return;
    }
    if (name !== null) {
      listedNames.add(name);
    }
    const matches = name !== null ? (named.get(name) ?? []) : [];
    if (matches.length !== 1) {
      problems.push([path + "/input", matches.length === 0 ? "the response's decision basis does not record this input" : "the response's decision basis records this input more than once"]);
      return;
    }
    const entry = entries[matches[0] as number];
    const own: JsonObject = {};
    if (isObject(item)) {
      for (const [key, value] of Object.entries(item)) {
        if (key !== marker) {
          define(own, key, value as JsonValue);
        }
      }
    }
    const recorded: JsonObject = isObject(entry) ? entry : {};
    const keys = [...new Set([...Object.keys(own), ...Object.keys(recorded)])].sort();
    for (const key of keys) {
      const inOwn = Object.prototype.hasOwnProperty.call(own, key);
      const inRecorded = Object.prototype.hasOwnProperty.call(recorded, key);
      if (inOwn !== inRecorded || !sameJson(own[key], recorded[key])) {
        problems.push([`${path}/${key}`, `the ${key} is not the one the response records`]);
      }
    }
  });
  for (const [name, matched] of named) {
    if (!listedNames.has(name)) {
      for (const index of matched) {
        problems.push([`${prefix}/${index}/input`, "the record does not list this input"]);
      }
    }
  }
  return problems;
}

/** The findings of one rule for its problems. */
export function findings(ruleId: string, problems: readonly Problem[]): Finding[] {
  return problems.map(([path, message]) => ({ ruleId, path, message }));
}
