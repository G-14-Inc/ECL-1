/**
 * The decision basis in signed evidence (DCMP2-053, ECL1N-0178, ECL1N-0181).
 *
 * - `ecl.rule.decision-basis-required.v1`: every decision response carries its decision basis in
 *   `ecl.ext.decision-basis.v1`; a response without that record is refused.
 * - `ecl.rule.decision-basis-matches-register.v1`: checked against a Consequential Action Register
 *   that the caller supplies, a decision basis names that register version and lists exactly the
 *   inputs that it declares for the request's action class, each once, with the declared class,
 *   required flag, `derived_from` and source, the source compared as input names are; and no input
 *   recorded as available was obtained after its declared deadline, counted from the value's
 *   `received_at`, or has a value older than its declared maximum age at the response's
 *   `evaluated_at` (ECL1N-0182).
 * - `ecl.rule.decision-basis-one-way.v1` with the request in hand (`requestProblems`): no input
 *   whose `source` is the request's `actor` is recorded as `verifiable` (`actorSourceProblems`),
 *   and the request was not received before it was issued, less the response clock-skew allowance
 *   (DCMP2-047).
 * - `ecl.rule.register-declarations-consistent.v1`: a register that breaks it is refused before any
 *   decision basis is checked against it (`registerDocumentProblems`, DCMP2-053).
 *
 * Input names compare by `inputKey` (DCMP2-053).
 */

import { objectDigest } from "../json/canonical.js";
import { get, isArray, isObject, isString, pythonEquals } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { eclSchemas } from "../schema/validator.js";
import { inputKey, registerDocumentProblems } from "../semantic/rules.js";
import { InstantError, instantNanoseconds } from "../time.js";

export const DECISION_BASIS = "ecl.ext.decision-basis.v1";
export const REQUIRED_RULE = "ecl.rule.decision-basis-required.v1";
export const REGISTER_RULE = "ecl.rule.decision-basis-matches-register.v1";
export const REGISTER_SCHEMA = "https://externalcontrollayer.ai/ns/schema/action-register/1";
export const REGISTER_DOCUMENT_RULE = "ecl.rule.register-declarations-consistent.v1";
const DIGEST_SUITE = "ecl.digest.sha-256.v1";

/**
 * The problems of a register that a verifier refuses as a usage error (DCMP2-053): its schema
 * errors, or else the first finding of the register declarations rule; none for a register that a
 * decision basis can be checked against.
 */
export function registerUsageProblems(register: JsonValue): string[] {
  const schema = registerSchemaProblems(register);
  if (schema.length > 0 || !isObject(register)) {
    return schema;
  }
  return registerDocumentProblems(register).map(([path, message]) => `${path}: ${message}`);
}

function instantOrNull(value: JsonValue | undefined): bigint | null {
  try {
    return instantNanoseconds(value);
  } catch (error) {
    if (error instanceof InstantError) {
      return null;
    }
    throw error;
  }
}

function derivedKeys(entry: JsonObject): Set<string> {
  const derived = get(entry, "derived_from");
  return new Set(isArray(derived) ? derived.filter((name): name is string => isString(name)).map(inputKey) : []);
}

function sameKeys(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  return left.size === right.size && [...left].every((key) => right.has(key));
}

/**
 * (path below the value, message) for each entry that a decision-basis value records as
 * `verifiable` while its `source` is the request's `actor`, the governed AI system that requested
 * the action (DCMP2-053): an input that the governed AI system produces is `actor_supplied` (ECL-1
 * Section 4.3, ECL1N-0178). Names compare by `inputKey`; a verifier that holds the request applies
 * it under `ecl.rule.decision-basis-one-way.v1`, as the reference's `actor_source_problems`.
 */
export function actorSourceProblems(value: JsonObject, request: JsonObject): Array<[string, string]> {
  const actor = get(request, "actor");
  const actorId = isObject(actor) ? get(actor, "id") : undefined;
  const inputs = get(value, "inputs");
  if (!isString(actorId) || !isArray(inputs)) {
    return [];
  }
  const key = inputKey(actorId);
  const problems: Array<[string, string]> = [];
  inputs.forEach((item, position) => {
    if (isObject(item) && get(item, "class") === "verifiable") {
      const source = get(item, "source");
      if (isString(source) && inputKey(source) === key) {
        problems.push([`/inputs/${position}/class`, "an input whose source is the requesting actor cannot be verifiable"]);
      }
    }
  });
  return problems;
}

/**
 * (path below the value, message) for each way a decision-basis value breaks DCMP2-053 with the
 * request it answers, as the reference's `request_problems` reports them: an input recorded as
 * `verifiable` whose `source` is the request's `actor` (`actorSourceProblems`), and a
 * `received_at` earlier than the request's `issued_at` by more than `skewSeconds`, the response
 * clock-skew allowance of the verification profile (DCMP2-047), zero in the reference profile.
 */
export function requestProblems(value: JsonObject, request: JsonObject, skewSeconds = 0): Array<[string, string]> {
  const problems = actorSourceProblems(value, request);
  const received = instantOrNull(get(value, "received_at"));
  const issued = instantOrNull(get(request, "issued_at"));
  if (received !== null && issued !== null && received < issued - BigInt(Math.max(skewSeconds, 0)) * 1_000_000_000n) {
    problems.push(["/received_at", "the request was received before it was issued"]);
  }
  return problems;
}

/** The `ecl.digest.sha-256.v1` digest of a register document's restricted canonical JSON. */
export function registerDigest(register: JsonObject): JsonObject {
  return { algorithm: DIGEST_SUITE, value: objectDigest(register) };
}

/** The `register` member that names a register document (ECL1N-0181). */
export function registerReference(register: JsonObject): JsonObject {
  const reference: JsonObject = { uri: String(register["register_id"]) };
  const version = get(register, "register_version");
  if (isString(version)) {
    reference["version"] = version;
  }
  reference["digest"] = registerDigest(register);
  return reference;
}

/** The schema errors of a register document as messages; none when it satisfies its schema. */
export function registerSchemaProblems(register: JsonValue): string[] {
  if (!isObject(register)) {
    return ["the register is not a JSON object"];
  }
  return eclSchemas()
    .errors(REGISTER_SCHEMA, register)
    .map((error) => `${error.path}: ${error.message}`.slice(0, 200));
}

/** The decision inputs that the register declares for `actionClass`; none without an entry. */
export function declaredInputs(register: JsonObject, actionClass: string): JsonObject[] {
  const entries = get(register, "entries");
  if (!isArray(entries)) {
    return [];
  }
  const entry = entries.find((item) => isObject(item) && pythonEquals(get(item, "action_class_id"), actionClass));
  const declared = entry === undefined ? undefined : get(entry, "decision_inputs");
  if (!isArray(declared)) {
    return [];
  }
  return declared.filter((item): item is JsonObject => isObject(item));
}

/** (index, value) of each occurrence of the extension on a message. */
export function basisValues(message: JsonObject): Array<[number, JsonValue | undefined]> {
  const extensions = get(message, "extensions");
  if (!isArray(extensions)) {
    return [];
  }
  const found: Array<[number, JsonValue | undefined]> = [];
  extensions.forEach((item, index) => {
    if (isObject(item) && pythonEquals(get(item, "id"), DECISION_BASIS)) {
      found.push([index, get(item, "value")]);
    }
  });
  return found;
}

/**
 * (path below the value, message) for each way a decision basis disagrees with the register that
 * a verifier holds, as the reference's `register_problems` reports them. A register without an
 * entry for the class declares no input for it; an input that it declares twice matches no record.
 * `evaluatedAt` is the response's, which the maximum-age check needs.
 */
export function registerProblems(value: JsonObject, register: JsonObject, actionClass: JsonValue | undefined, evaluatedAt?: JsonValue): Array<[string, string]> {
  const problems: Array<[string, string]> = [];
  const named = get(value, "register");
  if (!isObject(named) || !pythonEquals(get(named, "uri"), get(register, "register_id"))) {
    problems.push(["/register/uri", "the record names another register"]);
  } else if (!pythonEquals(get(named, "digest"), registerDigest(register))) {
    problems.push(["/register/digest", "the record names another version of the register"]);
  }
  if (
    Object.prototype.hasOwnProperty.call(register, "register_version") &&
    isObject(named) &&
    Object.prototype.hasOwnProperty.call(named, "version") &&
    !pythonEquals(get(named, "version"), get(register, "register_version"))
  ) {
    problems.push(["/register/version", "the record names another register version"]);
  }
  const inputs = get(value, "inputs");
  if (!isArray(inputs)) {
    return problems;
  }
  const declared = new Map<string, JsonObject>();
  const repeated = new Set<string>();
  for (const item of isString(actionClass) ? declaredInputs(register, actionClass) : []) {
    const name = get(item, "input");
    if (!isString(name)) {
      continue;
    }
    const key = inputKey(name);
    if (declared.has(key)) {
      repeated.add(key);
    } else {
      declared.set(key, item);
    }
  }
  const decided = instantOrNull(evaluatedAt);
  const received = instantOrNull(get(value, "received_at"));
  const listed = new Set<string>();
  inputs.forEach((item, position) => {
    const path = `/inputs/${position}`;
    const name = isObject(item) ? get(item, "input") : undefined;
    if (!isObject(item) || !isString(name)) {
      return;
    }
    const key = inputKey(name);
    listed.add(key);
    const declaration = declared.get(key);
    if (declaration === undefined) {
      problems.push([path + "/input", "the register does not declare this input for the action class"]);
      return;
    }
    if (repeated.has(key)) {
      problems.push([path + "/input", "the register declares this input more than once"]);
      return;
    }
    if (!pythonEquals(get(item, "class"), get(declaration, "class"))) {
      problems.push([path + "/class", "the class is not the one the register declares"]);
    }
    if (get(item, "required") !== get(declaration, "required")) {
      problems.push([path + "/required", "the required flag is not the one the register declares"]);
    }
    const recordedSource = get(item, "source");
    const declaredSource = get(declaration, "source");
    if (!(isString(recordedSource) && isString(declaredSource) && inputKey(recordedSource) === inputKey(declaredSource))) {
      problems.push([path + "/source", "the source is not the one the register declares"]);
    }
    if (!sameKeys(derivedKeys(item), derivedKeys(declaration))) {
      problems.push([path + "/derived_from", "the inputs it is computed from are not the ones the register declares"]);
    }
    if (!pythonEquals(get(item, "status"), "available")) {
      return;
    }
    const deadline = get(declaration, "deadline_milliseconds");
    const obtained = instantOrNull(get(item, "obtained_at"));
    if (typeof deadline === "number" && Number.isInteger(deadline) && obtained !== null && received !== null && obtained - received > BigInt(deadline) * 1_000_000n) {
      problems.push([path + "/obtained_at", "the input was obtained after its declared deadline"]);
    }
    const maximumAge = get(declaration, "maximum_age_seconds");
    const valueAt = instantOrNull(get(item, "value_at"));
    if (typeof maximumAge === "number" && Number.isInteger(maximumAge) && valueAt !== null && decided !== null && decided - valueAt > BigInt(maximumAge) * 1_000_000_000n) {
      problems.push([path + "/value_at", "the input's value is older than its declared maximum age"]);
    }
  });
  for (const [key, declaration] of declared) {
    if (!listed.has(key)) {
      problems.push(["/inputs", `the record does not list the declared input ${String(get(declaration, "input"))}`]);
    }
  }
  return problems;
}
