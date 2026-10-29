/**
 * The semantic rules of DCMP-2, EBMP-2, the registered control extensions and the adapter binding:
 * the cross-member checks that JSON Schema cannot express. They run on any object, valid under its
 * schema or not, and reach the same findings as the reference's SemanticValidator, including on
 * malformed input: a check that cannot read the value it needs reports one
 * `ecl.error.schema-invalid.v1` finding instead of its own.
 *
 * Each check is one entry of the tables in `validate`: a rule added to the registry gets one
 * function here and one row there, in the order the reference runs its checks.
 */

import { CanonicalizationError, objectDigest } from "../json/canonical.js";
import {
  compareCodePoints,
  get,
  has,
  inList,
  isArray,
  isInteger,
  isObject,
  isPythonInt,
  isString,
  pythonEquals,
  pythonRepr,
  schemaEquals,
  truthy,
} from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { activeExtensionVersions, allocatedExtensionVersions, composableExtensions, extensionValueSchemas, knownExtensions } from "../registry/registries.js";
import { eclSchemas } from "../schema/validator.js";
import type { SchemaSet } from "../schema/validator.js";
import { InstantError, instantNanoseconds } from "../time.js";
import {
  hashKey,
  inSet,
  isMalformedInputError,
  item,
  pythonSet,
  PythonTypeError,
  str,
} from "./python.js";

/** A rule a value breaks: the registered rule or error identifier, where, and why. */
export interface Finding {
  readonly ruleId: string;
  readonly path: string;
  readonly message: string;
}

export const SCHEMA_INVALID = "ecl.error.schema-invalid.v1";

const EVENT_KINDS: Record<string, readonly [string, ReadonlySet<string> | null]> = {
  request_received: ["request", null],
  decision_recorded: ["decision", null],
  authority_issued: ["authority", new Set(["issued", "active"])],
  authority_consumed: ["authority", new Set(["consumed", "revoked", "expired", "superseded"])],
  release_prepared: ["execution", new Set(["prepared"])],
  execution_released: ["execution", new Set(["released"])],
  execution_observed: ["execution", new Set(["running"])],
  execution_terminal: ["execution", null],
  human_intervention: ["intervention", null],
  verification: ["verification", null],
  safe_state_transition: ["state", null],
  fleet_transition: ["state", null],
  lifecycle_transition: ["lifecycle", null],
};
const UNCERTAIN_STATES = new Set(["partially_succeeded", "timed_out", "cancelled", "unknown"]);
const TERMINAL_STATES = new Set([
  "succeeded",
  "failed",
  "partially_succeeded",
  "cancelled",
  "timed_out",
  "rolled_back",
  "compensated",
  "unknown",
  "denied",
  "held",
  "challenged",
  "expired_before_release",
]);
const EMERGENCY_OPERATIONS = new Set(["halt", "quarantine"]);
const COUPLING = "ecl.ext.consequence-coupling.v1";
const APPROVAL_RECORD = "ecl.ext.approval-record.v1";
const CONTROL_CHANGE = "ecl.ext.control-change.v1";
/**
 * DCMP2-053, ECL1N-0179 and ECL1N-0182: the one-way rule. An input that the governed AI system
 * controls as an assertion, or a judgment about meaning or risk, only makes an outcome stricter,
 * and an input that was not available supports nothing.
 */
export const DECISION_BASIS = "ecl.ext.decision-basis.v1";
export const DECISION_BASIS_RULE = "ecl.rule.decision-basis-one-way.v1";
const RESTRICTING_ONLY_CLASSES = new Set(["actor_supplied", "judgment"]);
/** The decision outcomes in the strictness order of ECL-1 Section 4.3, least strict first. */
const OUTCOMES: readonly string[] = ["admit", "challenge", "hold", "deny"];
/** ECL1N-0178: the rule a register document satisfies beyond its schema. */
export const REGISTER_DOCUMENT_RULE = "ecl.rule.register-declarations-consistent.v1";
export const REGISTER_SCHEMA_VERSION = "ecl_action_register_v1";
/** DCMP2-055: a declared budget debit is written without a sign. */
const BUDGET_DEBIT_RULE = "ecl.rule.budget-debit-non-negative.v1";
const PERMITTING_RESULTS: ReadonlyArray<readonly [string, ReadonlySet<string>]> = [
  ["budget_result", new Set(["authorized"])],
  ["witness_result", new Set(["satisfied", "required_before_release"])],
  ["quorum_result", new Set(["met"])],
];
const DISABLING_CHANGES = new Set(["disable", "bypass", "auto_approve"]);
const APPROVAL_OPERATIONS = new Set(["approve", "reject"]);
const DERIVED_OPERATIONS = new Set(["redact", "supersede"]);
/** DCMP2-013: the members of an admit's authorization that bind its release authority. */
const AUTHORITY_MEMBERS = ["authorization_id", "audience", "scope_digest", "valid_from", "valid_until", "use_policy"];
const PROTOCOLS = new Set(["DCMP-2", "EBMP-2"]);
/**
 * XR1-010: one object carries each extension identifier at one version, unless the registry entry
 * of that identifier declares its versions composable.
 */
export const EXTENSION_VERSION_RULE = "ecl.rule.extension-single-version.v1";

function finding(ruleId: string, path: string, message: string): Finding {
  return { ruleId, path, message };
}

/** Sort findings by rule, path and message, by code point, as the reference sorts them. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => compareCodePoints(a.ruleId, b.ruleId) || compareCodePoints(a.path, b.path) || compareCodePoints(a.message, b.message),
  );
}

function time(value: JsonValue | undefined): bigint {
  return instantNanoseconds(value);
}

/** (index, value) of each well-formed occurrence of one extension. */
function extensionValues(value: JsonObject, identifier: string): Array<[number, JsonObject]> {
  const extensions = get(value, "extensions");
  if (!isArray(extensions)) {
    return [];
  }
  const found: Array<[number, JsonObject]> = [];
  extensions.forEach((extension, index) => {
    const extensionValue = get(extension, "value");
    if (isObject(extension) && pythonEquals(get(extension, "id"), identifier) && isObject(extensionValue)) {
      found.push([index, extensionValue]);
    }
  });
  return found;
}

/** The extensions list of the reference's extension checks: absent, or a list of objects. */
function extensionList(value: JsonObject): JsonObject[] | undefined {
  const extensions = get(value, "extensions");
  if (extensions === undefined || extensions === null) {
    return undefined;
  }
  if (!isArray(extensions)) {
    throw new PythonTypeError("extensions must be an array");
  }
  return extensions.map((extension) => {
    if (!isObject(extension)) {
      throw new PythonTypeError("extension entries must be objects");
    }
    return extension;
  });
}

/** Validates ECL cross-member semantics against a registry snapshot. */
export class SemanticValidator {
  private readonly known: ReadonlySet<string>;
  private readonly valueSchemas: ReadonlyMap<string, string>;
  private readonly schemas: SchemaSet;
  private readonly allocated: ReadonlyMap<string, ReadonlySet<number>> | undefined;
  private readonly composable: ReadonlySet<string>;
  private readonly active: ReadonlyMap<string, ReadonlySet<number>> | undefined;

  /**
   * `known` names the allocated identifiers, whatever their status (XR1-017). `allocated` gives
   * the versions the registry allocates for each identifier; `undefined` interprets every version
   * of a known identifier. `composable` names the identifiers
   * whose versions the registry declares composable (XR1-010). `active` gives the versions of the
   * active entries the consumer implements, the only occurrences it knows (XR1-006); `undefined`
   * falls back to `known` and `allocated`.
   */
  constructor(
    known: Iterable<string> = knownExtensions(),
    valueSchemas: ReadonlyMap<string, string> = extensionValueSchemas(),
    schemas: SchemaSet = eclSchemas(),
    allocated: ReadonlyMap<string, ReadonlySet<number>> | undefined = allocatedExtensionVersions(),
    composable: Iterable<string> = composableExtensions(),
    active: ReadonlyMap<string, ReadonlySet<number>> | undefined = activeExtensionVersions(),
  ) {
    this.known = new Set(known);
    this.valueSchemas = valueSchemas;
    this.schemas = schemas;
    this.allocated = allocated;
    this.composable = new Set(composable);
    this.active = active;
  }

  private isKnown(identifier: JsonValue | undefined): boolean {
    return typeof identifier === "string" && this.known.has(identifier);
  }

  /**
   * Whether a consumer can interpret this occurrence (XR1-006): an active entry of its identifier
   * and version that the consumer implements, or, without that snapshot, a known identifier at a
   * version that the registry allocated for it (XR1-003, XR1-009).
   */
  private interpretable(identifier: JsonValue | undefined, version: JsonValue | undefined): boolean {
    if (this.active !== undefined) {
      return typeof identifier === "string" && isInteger(version) && (this.active.get(identifier)?.has(version) ?? false);
    }
    if (!this.isKnown(identifier)) {
      return false;
    }
    const versions = this.allocated?.get(identifier as string);
    if (versions === undefined) {
      return true;
    }
    return isInteger(version) && versions.has(version);
  }

  /** XR1-023: a registered extension's value validates against its registered schema. */
  private extensionValueSchemas(value: JsonObject): Finding[] {
    const findings: Finding[] = [];
    const extensions = get(value, "extensions");
    if (!isArray(extensions)) {
      return findings;
    }
    extensions.forEach((extension, index) => {
      if (!isObject(extension)) {
        return;
      }
      const identifier = get(extension, "id");
      const schema = typeof identifier === "string" ? this.valueSchemas.get(identifier) : undefined;
      if (schema === undefined || !has(extension, "value")) {
        return;
      }
      if (!this.schemas.isValid(schema, extension["value"] as JsonValue)) {
        findings.push(
          finding("ecl.rule.extension-value-valid.v1", `/extensions/${index}/value`, `value of ${str(identifier)} does not match its registered schema`),
        );
      }
    });
    return findings;
  }

  /** DCMP2-052: an admit carries only permitting consequence-coupling results. */
  private static couplingResults(value: JsonObject): Finding[] {
    if (!pythonEquals(get(value, "message_type"), "decision_response") || !pythonEquals(get(value, "outcome"), "admit")) {
      return [];
    }
    const findings: Finding[] = [];
    const obligations = get(value, "obligations");
    const deferred = isArray(obligations) && obligations.some((entry) => isObject(entry) && pythonEquals(get(entry, "satisfaction"), "before_release"));
    for (const [index, coupling] of extensionValues(value, COUPLING)) {
      for (const [member, permitting] of PERMITTING_RESULTS) {
        const result = get(coupling, member);
        if (!isObject(result)) {
          continue;
        }
        const outcome = get(result, "outcome");
        if (!inSet(outcome, permitting)) {
          findings.push(finding("ecl.rule.coupling-results-permit-admit.v1", `/extensions/${index}/value/${member}/outcome`, `an admit cannot carry ${member} outcome ${str(outcome)}`));
        } else if (pythonEquals(outcome, "required_before_release") && !deferred) {
          findings.push(finding("ecl.rule.coupling-results-permit-admit.v1", `/extensions/${index}/value/${member}/outcome`, "a deferred witness check needs a before_release obligation"));
        }
      }
      if (has(coupling, "blocker_reason")) {
        findings.push(finding("ecl.rule.coupling-results-permit-admit.v1", `/extensions/${index}/value/blocker_reason`, "an admit cannot carry a blocker reason"));
      }
    }
    return findings;
  }

  /**
   * DCMP2-053: each input once; no actor_supplied or judgment input, and no input that was not
   * available or was computed from one that was not, supports an outcome; no input computed from
   * one that is not verifiable is verifiable, and none is computed from itself; an admit rests on
   * at least one verifiable input that supports it and on no required input that was not
   * available; the outcome is no less strict than a recorded verifiable-only outcome; and no input
   * obtained after the decision is recorded as available. The value schema is checked first, by
   * the extension-value rule (XR1-023); this rule reads only the members it needs
   * (`oneWayProblems`, the reference's `ecl_reference.decision_basis.one_way_problems`).
   */
  private static decisionBasis(value: JsonObject): Finding[] {
    if (!pythonEquals(get(value, "message_type"), "decision_response")) {
      return [];
    }
    const outcome = get(value, "outcome");
    const admit = pythonEquals(outcome, "admit");
    const findings: Finding[] = [];
    for (const [index, basis] of extensionValues(value, DECISION_BASIS)) {
      for (const [path, message] of oneWayProblems(basis, admit, outcome, get(value, "evaluated_at"))) {
        findings.push(finding(DECISION_BASIS_RULE, `/extensions/${index}/value${path}`, message));
      }
    }
    return findings;
  }

  /**
   * ECL1N-0178: a Consequential Action Register declares each action class once and each input of
   * a class once, names in `derived_from` only other inputs of the class, declares no input
   * computed from one that is not verifiable as verifiable, and computes no input from itself
   * (`registerDocumentProblems`, the reference's `register_document_problems`).
   */
  private static registerDeclarations(value: JsonObject): Finding[] {
    return registerDocumentProblems(value).map(([path, message]) => finding(REGISTER_DOCUMENT_RULE, path, message));
  }

  /** EBMP2-063: an approval or rejection respects its recorded minimum review time. */
  private static approvalRecords(value: JsonObject): Finding[] {
    const event = get(value, "event");
    if (
      !pythonEquals(get(value, "event_type"), "human_intervention") ||
      !isObject(event) ||
      !inSet(get(event, "operation"), APPROVAL_OPERATIONS) ||
      !isString(get(event, "issued_at"))
    ) {
      return [];
    }
    const findings: Finding[] = [];
    for (const [index, record] of extensionValues(value, APPROVAL_RECORD)) {
      const presented = get(record, "presented_at");
      const minimum = get(record, "minimum_review_seconds");
      if (!isString(presented) || !isInteger(minimum)) {
        continue;
      }
      if (time(item(event, "issued_at")) < time(presented) + BigInt(minimum) * 1_000_000_000n) {
        findings.push(finding("ecl.rule.approval-review-time-respected.v1", `/extensions/${index}/value/presented_at`, "the decision came sooner than the minimum review time after presentation"));
      }
    }
    return findings;
  }

  /** EBMP2-064: a control change has approvers other than its requester and, when it switches a
   * control off, an expiry after it takes effect. */
  private static controlChanges(value: JsonObject): Finding[] {
    const findings: Finding[] = [];
    for (const [index, change] of extensionValues(value, CONTROL_CHANGE)) {
      const approvers = get(change, "approved_by");
      if (isArray(approvers) && inList(get(change, "requested_by") ?? null, approvers)) {
        findings.push(finding("ecl.rule.control-change-approved-and-bounded.v1", `/extensions/${index}/value/approved_by`, "the requester of a control change cannot approve it"));
      }
      const effective = get(change, "effective_at");
      const expires = get(change, "expires_at");
      if (inSet(get(change, "change"), DISABLING_CHANGES) && isString(effective)) {
        if (!isString(expires) || time(expires) <= time(effective)) {
          findings.push(finding("ecl.rule.control-change-approved-and-bounded.v1", `/extensions/${index}/value/expires_at`, `a ${str(get(change, "change"))} change must expire after it takes effect`));
        }
      }
    }
    return findings;
  }

  private static extensions(value: JsonObject): Finding[] {
    const findings: Finding[] = [];
    const extensions = extensionList(value);
    if (extensions === undefined) {
      return findings;
    }
    const seen = new Set<string>();
    extensions.forEach((extension, index) => {
      const identifier = get(extension, "id");
      const version = get(extension, "version");
      if (typeof identifier !== "string" || !isPythonInt(version)) {
        throw new PythonTypeError("extension id and version have invalid types");
      }
      const key = identifier + "\u0000" + String(Number(version));
      if (seen.has(key)) {
        findings.push(finding("ecl.rule.extension-identifiers-unique.v1", `/extensions/${index}`, `duplicate extension allocation ${identifier} version ${Number(version)}`));
      }
      seen.add(key);
    });
    return findings;
  }

  /**
   * XR1-010: an object carries each extension identifier at one version only, unless the registry
   * declares the identifier's versions composable. A version the consumer does not know is a
   * version all the same, so it conflicts with a known one. An entry whose identifier is not a
   * string or whose version is not an integer is left to the schema and to the duplicate-pair
   * rule (XR1-009).
   */
  private extensionVersions(value: JsonObject): Finding[] {
    const findings: Finding[] = [];
    const extensions = extensionList(value);
    if (extensions === undefined) {
      return findings;
    }
    const first = new Map<string, number>();
    extensions.forEach((extension, index) => {
      const identifier = get(extension, "id");
      const version = get(extension, "version");
      if (typeof identifier !== "string" || !isInteger(version) || this.composable.has(identifier)) {
        return;
      }
      const earlier = first.get(identifier);
      if (earlier === undefined) {
        first.set(identifier, version);
      } else if (version !== earlier) {
        findings.push(finding(EXTENSION_VERSION_RULE, `/extensions/${index}`, `extension ${identifier} appears at version ${earlier} and at version ${version}`));
      }
    });
    return findings;
  }

  /** XR1-017: an `ecl.*` extension identifier must be allocated in the registry snapshot. */
  private extensionNamespace(value: JsonObject): Finding[] {
    const findings: Finding[] = [];
    const extensions = extensionList(value);
    if (extensions === undefined) {
      return findings;
    }
    extensions.forEach((extension, index) => {
      const identifier = get(extension, "id");
      if (typeof identifier === "string" && identifier.startsWith("ecl.") && !this.known.has(identifier)) {
        findings.push(finding("ecl.rule.extension-namespace-allocated.v1", `/extensions/${index}/id`, `unallocated ECL extension identifier ${identifier}`));
      }
    });
    return findings;
  }

  private criticalExtensions(value: JsonObject): Finding[] {
    const findings: Finding[] = [];
    const extensions = extensionList(value);
    if (extensions === undefined) {
      return findings;
    }
    extensions.forEach((extension, index) => {
      const identifier = get(extension, "id");
      const version = get(extension, "version");
      if (truthy(get(extension, "critical")) && !this.interpretable(identifier, version)) {
        findings.push(finding("ecl.rule.unknown-critical-extension-rejected.v1", `/extensions/${index}/id`, `unknown critical extension ${str(identifier)} version ${str(version)}`));
      }
    });
    return findings;
  }

  private static selfCausation(value: JsonObject): Finding[] {
    const messageId = get(value, "message_id");
    const objectId = truthy(messageId) ? messageId : get(value, "object_id");
    const workflow = get(value, "workflow");
    if (workflow === undefined || workflow === null) {
      return [];
    }
    if (!isObject(workflow)) {
      throw new PythonTypeError("workflow must be an object");
    }
    const listed = get(workflow, "causal_predecessors");
    const predecessors = truthy(listed) ? listed : [];
    if (!isArray(predecessors)) {
      throw new PythonTypeError("causal_predecessors must be an array");
    }
    if (truthy(objectId) && predecessors.some((entry) => isObject(entry) && pythonEquals(get(entry, "id"), objectId))) {
      return [finding("ecl.rule.message-cannot-cause-itself.v1", "/workflow/causal_predecessors", "an object cannot name itself as a causal predecessor")];
    }
    return [];
  }

  private static integrityPolicy(value: JsonObject): Finding[] {
    const policy = get(value, "integrity_policy");
    if (!isObject(policy)) {
      return [];
    }
    const required = truthy(get(policy, "required"));
    const threshold = get(policy, "threshold");
    const requiredKeysValue = get(policy, "required_key_ids");
    const eligibleKeysValue = get(policy, "eligible_key_ids");
    const requiredKeys = truthy(requiredKeysValue) ? requiredKeysValue : [];
    const eligibleKeys = truthy(eligibleKeysValue) ? eligibleKeysValue : [];
    if (!isArray(requiredKeys) || !isArray(eligibleKeys)) {
      throw new PythonTypeError("integrity key identifiers must be arrays");
    }
    let invalid: boolean;
    if (!isInteger(threshold)) {
      invalid = true;
    } else if (required && threshold < 1) {
      invalid = true;
    } else if (!required && threshold !== 0) {
      invalid = true;
    } else if (threshold < requiredKeys.length) {
      invalid = true;
    } else if (eligibleKeys.length > 0) {
      const requiredSet = pythonSet(requiredKeys);
      const eligibleSet = pythonSet(eligibleKeys);
      invalid = [...requiredSet].some((key) => !eligibleSet.has(key));
    } else {
      invalid = false;
    }
    if (invalid) {
      return [finding("ecl.rule.integrity-threshold-consistent.v1", "/integrity_policy", "integrity required flag, threshold, eligible keys, and required keys are inconsistent")];
    }
    return [];
  }

  // DCMP2-043: each DCMP-2 rule is checked on its own and only on input members of the types the
  // schema requires, so that a member one rule cannot read leaves the other rules' findings.

  /** DCMP2-032: a message's `expires_at` is later than its `issued_at`. */
  private static messageExpiry(value: JsonObject): Finding[] {
    const issuedAt = get(value, "issued_at");
    const expiresAt = get(value, "expires_at");
    if (!(isString(issuedAt) && issuedAt !== "" && isString(expiresAt) && expiresAt !== "")) {
      return [];
    }
    if (time(expiresAt) <= time(issuedAt)) {
      return [finding("ecl.rule.expiry-after-issue.v1", "/expires_at", "expires_at must be later than issued_at")];
    }
    return [];
  }

  /** DCMP2-007, for a decision request. */
  private static requestParameters(value: JsonObject): Finding[] {
    if (!pythonEquals(get(value, "message_type"), "decision_request")) {
      return [];
    }
    return SemanticValidator.parametersDigest(value);
  }

  /** DCMP2-055: a request's declared budget debit is written without a sign. */
  private static budgetDebit(value: JsonObject): Finding[] {
    if (!pythonEquals(get(value, "message_type"), "decision_request")) {
      return [];
    }
    const action = get(value, "action");
    const debit = isObject(action) ? get(action, "budget_debit") : undefined;
    const amount = isObject(debit) ? get(debit, "amount") : undefined;
    if (isString(amount) && amount.startsWith("-")) {
      return [finding(BUDGET_DEBIT_RULE, "/action/budget_debit/amount", "a declared budget debit cannot be negative")];
    }
    return [];
  }

  /** DCMP2-025: a halt or quarantine is declared on the emergency control plane. */
  private static controlPlane(value: JsonObject): Finding[] {
    if (!pythonEquals(get(value, "message_type"), "control")) {
      return [];
    }
    const authority = get(value, "authority");
    const plane = isObject(authority) ? get(authority, "plane") : undefined;
    if (inSet(get(value, "operation"), EMERGENCY_OPERATIONS) && !pythonEquals(plane, "emergency")) {
      return [finding("ecl.rule.emergency-control-plane-required.v1", "/authority/plane", "halt and quarantine require the emergency control plane")];
    }
    return [];
  }

  /**
   * DCMP2-013: an admit carries an authorization object with every member that binds its release
   * authority; how those members bind the request is DCMP2-044 to DCMP2-050.
   */
  private static admitAuthority(value: JsonObject): Finding[] {
    if (!pythonEquals(get(value, "message_type"), "decision_response") || !pythonEquals(get(value, "outcome"), "admit")) {
      return [];
    }
    const authorization = get(value, "authorization");
    if (isObject(authorization) && AUTHORITY_MEMBERS.every((member) => has(authorization, member))) {
      return [];
    }
    return [finding("ecl.rule.admit-requires-valid-authority.v1", "/authorization", "admit requires an authorization with its identifier, audience, scope digest, validity interval and use policy")];
  }

  /** DCMP2-012: a response whose outcome is not admit carries no authorization object. */
  private static nonAdmitAuthority(value: JsonObject): Finding[] {
    if (!pythonEquals(get(value, "message_type"), "decision_response") || pythonEquals(get(value, "outcome"), "admit")) {
      return [];
    }
    const authorization = get(value, "authorization");
    if (isObject(authorization) && truthy(authorization)) {
      return [finding("ecl.rule.non-admit-prohibits-authority.v1", "/authorization", "a non-admit response cannot issue authority")];
    }
    return [];
  }

  /** DCMP2-032: an authorization's `valid_until` is later than its `valid_from`. */
  private static authorityInterval(value: JsonObject): Finding[] {
    if (!pythonEquals(get(value, "message_type"), "decision_response")) {
      return [];
    }
    const authorization = get(value, "authorization");
    if (!isObject(authorization)) {
      return [];
    }
    const start = get(authorization, "valid_from");
    const end = get(authorization, "valid_until");
    if (!(isString(start) && isString(end))) {
      return [];
    }
    if (time(end) <= time(start)) {
      return [finding("ecl.rule.expiry-after-issue.v1", "/authorization/valid_until", "authority validity interval is empty or reversed")];
    }
    return [];
  }

  /** DCMP2-007: in-band parameters hash to `parameters_digest` (SHA-256, canonical JSON). */
  private static parametersDigest(value: JsonObject): Finding[] {
    const action = get(value, "action");
    if (!isObject(action) || !has(action, "parameters")) {
      return [];
    }
    const expected = { algorithm: "ecl.digest.sha-256.v1", value: objectDigest(action["parameters"] as JsonValue) };
    if (!pythonEquals(get(action, "parameters_digest"), expected)) {
      return [finding("ecl.rule.parameters-digest-matches.v1", "/action/parameters_digest", "parameters_digest is not the SHA-256 digest of the canonical in-band parameters")];
    }
    return [];
  }

  private static ebmp(value: JsonObject): Finding[] {
    const findings: Finding[] = [];
    if (!pythonEquals(get(value, "object_type"), "event_record")) {
      return findings;
    }
    const eventType = get(value, "event_type");
    const rawEvent = get(value, "event");
    const event = truthy(rawEvent) ? rawEvent : {};
    if (!isObject(event)) {
      throw new PythonTypeError("event must be an object");
    }
    const expected = typeof eventType === "string" && Object.prototype.hasOwnProperty.call(EVENT_KINDS, eventType) ? EVENT_KINDS[eventType] : undefined;
    if (expected !== undefined) {
      const [kind, states] = expected;
      if (!pythonEquals(get(event, "kind"), kind)) {
        findings.push(finding("ecl.rule.event-type-kind-consistent.v1", "/event/kind", `event_type ${String(eventType)} requires event kind ${kind}`));
      } else if (states !== null && !inSet(get(event, "state"), states)) {
        findings.push(finding("ecl.rule.event-type-kind-consistent.v1", "/event/state", `event_type ${String(eventType)} cannot carry state ${str(get(event, "state"))}`));
      }
    }
    const state = get(event, "state");
    const terminal = pythonEquals(eventType, "execution_terminal");
    if (terminal && !inSet(state, TERMINAL_STATES)) {
      findings.push(finding("ecl.rule.terminal-execution-state-consistent.v1", "/event/state", `execution_terminal cannot carry non-terminal state ${str(state)}`));
    }
    if (!terminal && inSet(state, TERMINAL_STATES)) {
      findings.push(finding("ecl.rule.terminal-execution-state-consistent.v1", "/event/state", "terminal execution state requires event_type execution_terminal"));
    }
    const residual = get(event, "residual_state");
    if (terminal && inSet(state, UNCERTAIN_STATES) && !(isArray(get(event, "side_effects")) && isString(residual) && residual.length > 0)) {
      findings.push(finding("ecl.rule.terminal-execution-state-consistent.v1", "/event", `${str(state)} requires side_effects and a non-empty residual_state (EBMP2-013)`));
    }
    if (pythonEquals(eventType, "lifecycle_transition")) {
      const operation = get(event, "operation");
      if (inSet(operation, DERIVED_OPERATIONS) && !truthy(get(event, "derived_artifact"))) {
        findings.push(finding("ecl.rule.lifecycle-derived-artifact-required.v1", "/event/derived_artifact", `${str(operation)} requires a derived artifact reference`));
      }
      // EBMP2-040 and EL1-014: a redaction also references its redaction manifest.
      if (pythonEquals(operation, "redact") && !truthy(get(event, "redaction_manifest"))) {
        findings.push(finding("ecl.rule.lifecycle-derived-artifact-required.v1", "/event/redaction_manifest", "redact requires a redaction manifest reference"));
      }
    }
    return findings;
  }

  /** The semantic findings for `value`, sorted. Raises only where the reference raises. */
  validate(value: JsonValue): Finding[] {
    if (!isObject(value)) {
      return [finding(SCHEMA_INVALID, "/", "semantic validation requires an object")];
    }
    const findings: Finding[] = [];
    const guarded = (name: string, check: (target: JsonObject) => Finding[]): void => {
      try {
        findings.push(...check(value));
      } catch (error) {
        if (!isMalformedInputError(error)) {
          throw error;
        }
        findings.push(finding(SCHEMA_INVALID, "/", `${name} semantic check rejected malformed input: ${(error as Error).message}`));
      }
    };
    // The checks of every object, then those of its protocol, in the reference's order. A rule
    // added to the registry is one more row of the table its objects belong to.
    const common: ReadonlyArray<readonly [string, (target: JsonObject) => Finding[]]> = [
      ["extension uniqueness", (target) => SemanticValidator.extensions(target)],
      ["extension versions", (target) => this.extensionVersions(target)],
      ["extension namespace", (target) => this.extensionNamespace(target)],
      ["critical extension", (target) => this.criticalExtensions(target)],
      ["self-causation", (target) => SemanticValidator.selfCausation(target)],
      ["integrity policy", (target) => SemanticValidator.integrityPolicy(target)],
    ];
    const dcmp: ReadonlyArray<readonly [string, (target: JsonObject) => Finding[]]> = [
      ["message expiry", (target) => SemanticValidator.messageExpiry(target)],
      ["parameters digest", (target) => SemanticValidator.requestParameters(target)],
      ["budget debit", (target) => SemanticValidator.budgetDebit(target)],
      ["emergency control plane", (target) => SemanticValidator.controlPlane(target)],
      ["admit authority", (target) => SemanticValidator.admitAuthority(target)],
      ["non-admit authority", (target) => SemanticValidator.nonAdmitAuthority(target)],
      ["authority interval", (target) => SemanticValidator.authorityInterval(target)],
      ["consequence coupling", (target) => SemanticValidator.couplingResults(target)],
      ["decision basis", (target) => SemanticValidator.decisionBasis(target)],
    ];
    const ebmp: ReadonlyArray<readonly [string, (target: JsonObject) => Finding[]]> = [
      ["EBMP-2", (target) => SemanticValidator.ebmp(target)],
      ["approval record", (target) => SemanticValidator.approvalRecords(target)],
      ["control change", (target) => SemanticValidator.controlChanges(target)],
    ];
    for (const [name, check] of common) {
      guarded(name, check);
    }
    const protocol = get(value, "protocol");
    if (typeof protocol === "string" && inSet(protocol, PROTOCOLS)) {
      guarded("extension value", (target) => this.extensionValueSchemas(target));
    }
    if (pythonEquals(protocol, "DCMP-2")) {
      for (const [name, check] of dcmp) {
        guarded(name, check);
      }
    } else if (pythonEquals(protocol, "EBMP-2")) {
      for (const [name, check] of ebmp) {
        guarded(name, check);
      }
    } else if (pythonEquals(get(value, "schema_version"), "ecl_adapter_binding_v1")) {
      guarded("adapter binding", adapterBindingFindings);
    } else if (pythonEquals(get(value, "schema_version"), REGISTER_SCHEMA_VERSION)) {
      guarded("register declarations", (target) => SemanticValidator.registerDeclarations(target));
    }
    return sortFindings(findings);
  }
}

const ADAPTER_RULE = "ecl.rule.adapter-source-binding-valid.v1";
const RESPONSIBILITIES = ["Decision", "Authority", "Enforcement", "Provenance", "Verification", "Fleet"];
// EBMP2-069: the media type each derived-object protocol names, the prefix of a binding identity,
// and the one authority boundary the schema allows.
const ADAPTER_MEDIA_TYPES = new Map([
  ["DCMP-2", "application/vnd.ecl.dcmp+json"],
  ["EBMP-2", "application/vnd.ecl.ebmp+json"],
]);
const ADAPTER_BINDING_PREFIX = "https://externalcontrollayer.ai/ns/adapter-binding/sha256/";
const ADAPTER_AUTHORITY_BOUNDARY: JsonObject = {
  native_authoritative_for_effects: true,
  ecl_is_portable_evidence_only: true,
  inbound_requires_native_reevaluation: true,
  conflict_disposition: "fail_closed_no_release",
};
const ARRAY_INDEX = /^(?:0|[1-9][0-9]*)$/;

/** The entries of an array member when every entry is an object; undefined otherwise. */
function objectEntries(value: JsonObject, member: string): JsonObject[] | undefined {
  const entries = get(value, member);
  return isArray(entries) && entries.every(isObject) ? (entries as JsonObject[]) : undefined;
}

/** One member of every entry, when each is a string; undefined otherwise. */
function entryStrings(entries: JsonObject[] | undefined, member: string): string[] | undefined {
  if (entries === undefined) {
    return undefined;
  }
  const values = entries.map((entry) => get(entry, member));
  return values.every(isString) ? (values as string[]) : undefined;
}

/** One member of every entry, when each is an array of strings; undefined otherwise. */
function entryStringLists(entries: JsonObject[] | undefined, member: string): string[][] | undefined {
  if (entries === undefined) {
    return undefined;
  }
  const values = entries.map((entry) => get(entry, member));
  return values.every((item) => isArray(item) && item.every(isString)) ? (values as string[][]) : undefined;
}

/** Whether a JSON Pointer's first reference token is an array index (RFC 6901, section 4) less than `count`. */
function namesDerivedObject(pointer: string, count: number): boolean {
  if (!pointer.startsWith("/")) {
    return false;
  }
  const token = pointer.split("/")[1] ?? "";
  return ARRAY_INDEX.test(token) && token.length <= String(count).length && Number(token) < count;
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

/**
 * EBMP2-069: the conditions of a native adapter binding that the binding alone shows. On a
 * schema-invalid binding each condition is checked only when every member it names is present
 * with the JSON type that the schema requires (DCMP2-043).
 */
export function adapterBindingFindings(value: JsonObject): Finding[] {
  const findings: Finding[] = [];
  const fail = (path: string, message: string): void => {
    findings.push(finding(ADAPTER_RULE, path, message));
  };
  const objects = objectEntries(value, "ecl_objects");
  const objectIds = entryStrings(objects, "object_id");
  const accounting = objectEntries(value, "field_accounting");

  // 1. The digest of the binding without binding_digest.
  const supplied = get(value, "binding_digest");
  if (isObject(supplied)) {
    const body: JsonObject = {};
    for (const key of Object.keys(value)) {
      if (key !== "binding_digest") {
        Object.defineProperty(body, key, { value: value[key], enumerable: true, writable: true, configurable: true });
      }
    }
    try {
      const expected = { algorithm: "ecl.digest.sha-256.v1", value: objectDigest(body) };
      if (!pythonEquals(supplied, expected)) {
        fail("/binding_digest", "binding body digest does not match the canonical binding body");
      }
    } catch (error) {
      if (!(error instanceof CanonicalizationError)) {
        throw error;
      }
      fail("/binding_digest", `binding body is outside the restricted canonical profile: ${error.message}`);
    }
  }

  // 2. The binding identity binds the source and the derived-object list.
  const source = get(value, "source");
  const bindingId = get(value, "binding_id");
  if (isObject(source) && isString(bindingId) && objectIds !== undefined) {
    const sourceDigest = get(source, "object_digest");
    const seedValues = [get(source, "system"), get(source, "contract"), get(source, "object_id")];
    if (isObject(sourceDigest)) {
      seedValues.push(get(sourceDigest, "value"));
    }
    if (seedValues.length === 4 && seedValues.every(isString)) {
      const [system, contract, objectId, objectDigestValue] = seedValues as string[];
      const seed: JsonObject = {
        system: system as string,
        contract: contract as string,
        object_id: objectId as string,
        object_digest: objectDigestValue as string,
        ecl_object_ids: objectIds,
      };
      let expectedId: string | undefined;
      try {
        expectedId = ADAPTER_BINDING_PREFIX + objectDigest(seed);
      } catch (error) {
        if (!(error instanceof CanonicalizationError)) {
          throw error;
        }
        expectedId = undefined;
      }
      if (bindingId !== expectedId) {
        fail("/binding_id", "binding identity does not bind the source and derived-object set");
      }
    }
  }

  // 3. Distinct derived objects.
  if (objectIds !== undefined && new Set(objectIds).size !== objectIds.length) {
    fail("/ecl_objects", "derived ECL object identifiers are not unique");
  }

  // 4. The media type that each derived object's protocol names.
  const protocols = entryStrings(objects, "protocol");
  const mediaTypes = entryStrings(objects, "media_type");
  if (protocols !== undefined && mediaTypes !== undefined) {
    protocols.forEach((protocol, index) => {
      if (ADAPTER_MEDIA_TYPES.get(protocol) !== mediaTypes[index]) {
        fail(`/ecl_objects/${index}/media_type`, "derived-object protocol and media type disagree");
      }
    });
  }

  // 5. Each source field is accounted once.
  const sourcePaths = entryStrings(accounting, "source_path");
  if (sourcePaths !== undefined && new Set(sourcePaths).size !== sourcePaths.length) {
    fail("/field_accounting", "a source field is accounted more than once");
  }

  // 6. The loss class follows from the dispositions.
  const dispositions = entryStrings(accounting, "disposition");
  const lossClass = get(value, "loss_class");
  if (dispositions !== undefined && isString(lossClass)) {
    const expectedLoss = dispositions.includes("rejected") ? "rejected" : dispositions.includes("retained_source_only") ? "loss_accounted" : "lossless";
    if (lossClass !== expectedLoss) {
      fail("/loss_class", "loss class does not match per-field accounting");
    }
  }

  // 7. Every target path begins with the index of a derived object.
  const targetLists = entryStringLists(accounting, "target_paths");
  const derivedTargets = entryStrings(objectEntries(value, "derived_fields"), "target_path");
  if (objects !== undefined && targetLists !== undefined && derivedTargets !== undefined) {
    targetLists.forEach((targets, index) => {
      if (!targets.every((target) => namesDerivedObject(target, objects.length))) {
        fail(`/field_accounting/${index}`, "target path does not name a bound derived-object index");
      }
    });
    derivedTargets.forEach((target, index) => {
      if (!namesDerivedObject(target, objects.length)) {
        fail(`/derived_fields/${index}`, "target path does not name a bound derived-object index");
      }
    });
  }

  // 8. Each responsibility's coverage names exactly the derived objects that list it.
  const listed = entryStringLists(objects, "responsibilities");
  const coverage = get(value, "responsibility_coverage");
  if (
    objectIds !== undefined &&
    listed !== undefined &&
    isObject(coverage) &&
    RESPONSIBILITIES.every((responsibility) => {
      const disposition = get(coverage, responsibility);
      const ids = get(disposition, "object_ids");
      return isObject(disposition) && isString(get(disposition, "status")) && isArray(ids) && ids.every(isString);
    })
  ) {
    for (const responsibility of RESPONSIBILITIES) {
      const disposition = get(coverage, responsibility) as JsonObject;
      const expectedIds = objectIds.filter((_identifier, index) => (listed[index] as string[]).includes(responsibility));
      const represented = get(disposition, "status") === "represented";
      if (represented !== expectedIds.length > 0 || !sameStrings(get(disposition, "object_ids") as string[], expectedIds)) {
        fail(`/responsibility_coverage/${responsibility}`, "responsibility coverage disagrees with derived-object metadata");
      }
    }
  }

  // 9. The fail-closed authority boundary, the one value the schema allows, compared as the same
  // JSON value, as the reference's `same_json` compares it: 1 is not `true`.
  const boundary = get(value, "authority_boundary");
  if (isObject(boundary) && !schemaEquals(boundary, ADAPTER_AUTHORITY_BOUNDARY)) {
    fail("/authority_boundary", "adapter authority boundary is not the exact fail-closed boundary");
  }
  return sortFindings(findings);
}

// hashKey is re-exported for callers that need Python set semantics on registry values.
export { hashKey };

/** `name` with the two hexadecimal digits of every percent-encoding in upper case. */
function percentUpper(name: string): string {
  const hex = /^[0-9A-Fa-f]$/;
  let result = "";
  let index = 0;
  while (index < name.length) {
    if (name[index] === "%" && index + 2 < name.length && hex.test(name[index + 1] as string) && hex.test(name[index + 2] as string)) {
      result += "%" + name.slice(index + 1, index + 3).toUpperCase();
      index += 3;
    } else {
      result += name[index];
      index += 1;
    }
  }
  return result;
}

/**
 * The form in which DCMP2-053 compares an input name, an entry's `source` with its declared source
 * and with the request's `actor`, as the reference's `input_key` gives it: the case normalization
 * of RFC 3986 section 6.2.2.1 and RFC 8141 section 3.1, in ASCII only. The URI scheme is
 * lowercased; so are, for a URN, its namespace identifier and, for an `http` or `https` URI, its
 * host (the authority after any user information, port included); then the two hexadecimal digits
 * of every percent-encoding are uppercased. No other normalization is applied.
 */
export function inputKey(name: string): string {
  const lower = (text: string): string => text.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  const colon = name.indexOf(":");
  if (colon <= 0) {
    return percentUpper(name);
  }
  const scheme = lower(name.slice(0, colon));
  let rest = name.slice(colon);
  if (scheme === "urn") {
    const end = name.indexOf(":", colon + 1);
    if (end !== -1) {
      rest = ":" + lower(name.slice(colon + 1, end)) + name.slice(end);
    }
  } else if ((scheme === "http" || scheme === "https") && rest.startsWith("://")) {
    const start = 3;
    let end = rest.length;
    for (const delimiter of ["/", "?", "#"]) {
      const found = rest.indexOf(delimiter, start);
      if (found !== -1 && found < end) {
        end = found;
      }
    }
    const at = rest.lastIndexOf("@", end - 1);
    const host = at >= start ? at + 1 : start;
    rest = rest.slice(0, host) + lower(rest.slice(host, end)) + rest.slice(end);
  }
  return percentUpper(scheme + rest);
}

/** An ECL instant in nanoseconds, or null for a value that is not one (left to the schema). */
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

function derivedNames(entry: JsonObject): string[] {
  const derived = get(entry, "derived_from");
  return isArray(derived) ? derived.filter((name): name is string => isString(name)) : [];
}

/**
 * The keys of the entries that `entry` is computed from, directly or through other entries: the
 * names its `derived_from` gives, other than its own, followed through the entries they name, as
 * the reference's `_sources` finds them.
 */
function derivedSources(entry: JsonObject, byKey: ReadonlyMap<string, JsonObject>): Set<string> {
  const own = get(entry, "input");
  const ownKey = isString(own) ? inputKey(own) : undefined;
  const pending = derivedNames(entry)
    .map(inputKey)
    .filter((key) => key !== ownKey && byKey.has(key));
  const seen = new Set<string>();
  while (pending.length > 0) {
    const key = pending.pop() as string;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    for (const source of derivedNames(byKey.get(key) as JsonObject).map(inputKey)) {
      if (byKey.has(source) && !seen.has(source)) {
        pending.push(source);
      }
    }
  }
  return seen;
}

/**
 * (path below the value, message) for each way a decision-basis value breaks DCMP2-053, as the
 * reference's `one_way_problems` reports them. `outcome` and `evaluatedAt` are the response's,
 * when the caller has the response: with them the value's `verifiable_only_outcome`,
 * `received_at` and each entry's `obtained_at` are checked against the decision too. Members of
 * another shape are left to the value schema (XR1-023); this never throws for a value of any shape.
 */
export function oneWayProblems(value: JsonObject, admit: boolean, outcome?: JsonValue, evaluatedAt?: JsonValue): Array<[string, string]> {
  const inputs = get(value, "inputs");
  if (!isArray(inputs)) {
    return [];
  }
  const entries: Array<[number, JsonObject]> = [];
  inputs.forEach((entry, position) => {
    if (isObject(entry)) {
      entries.push([position, entry]);
    }
  });
  const problems: Array<[string, string]> = [];
  const byKey = new Map<string, JsonObject>();
  for (const [position, entry] of entries) {
    const name = get(entry, "input");
    if (isString(name)) {
      const key = inputKey(name);
      if (byKey.has(key)) {
        problems.push([`/inputs/${position}/input`, "the record lists this input more than once"]);
      } else {
        byKey.set(key, entry);
      }
    }
  }
  const decided = instantOrNull(evaluatedAt);
  for (const [position, entry] of entries) {
    const path = `/inputs/${position}`;
    const supports = pythonEquals(get(entry, "effect"), "supports");
    const inputClass = get(entry, "class") ?? null;
    const status = get(entry, "status") ?? null;
    const available = pythonEquals(status, "available");
    if (supports && inSet(inputClass, RESTRICTING_ONLY_CLASSES)) {
      problems.push([path + "/effect", `an input of class ${pythonRepr(inputClass)} can only make an outcome stricter`]);
    }
    if (supports && !available) {
      problems.push([path + "/effect", `an input whose status is ${pythonRepr(status)} cannot support an outcome`]);
    }
    if (admit && get(entry, "required") === true && !available) {
      problems.push([path + "/status", `an admit cannot proceed while a required input is ${pythonRepr(status)}`]);
    }
    const own = get(entry, "input");
    const ownKey = isString(own) ? inputKey(own) : undefined;
    const derived = get(entry, "derived_from");
    if (isArray(derived)) {
      derived.forEach((name, offset) => {
        const source = isString(name) ? inputKey(name) : undefined;
        if (source === undefined || source === ownKey || !byKey.has(source)) {
          problems.push([`${path}/derived_from/${offset}`, "the record lists no other input with this name"]);
        } else if (pythonEquals(get(entry, "class"), "verifiable") && !pythonEquals(get(byKey.get(source), "class"), "verifiable")) {
          problems.push([path + "/class", `an input computed from an input of class ${pythonRepr(get(byKey.get(source), "class") ?? null)} cannot be verifiable`]);
        }
      });
    }
    const sources = derivedSources(entry, byKey);
    if (ownKey !== undefined && sources.has(ownKey)) {
      problems.push([path + "/derived_from", "the input is computed from itself through other inputs"]);
    }
    const unavailable = [...sources].some((key) => key !== ownKey && !pythonEquals(get(byKey.get(key), "status"), "available"));
    if (unavailable && available && supports) {
      problems.push([path + "/effect", "an input computed from an input that was not available cannot support an outcome"]);
    }
    if (unavailable && available && admit && get(entry, "required") === true) {
      problems.push([path + "/status", "an admit cannot proceed while a required input is computed from an input that was not available"]);
    }
    const obtained = instantOrNull(get(entry, "obtained_at"));
    if (available && decided !== null && obtained !== null && obtained > decided) {
      problems.push([path + "/status", "an input obtained after the decision was not available"]);
    }
    const described = instantOrNull(get(entry, "value_at"));
    if (described !== null && obtained !== null && described > obtained) {
      problems.push([path + "/value_at", "the input's value describes a time after it was obtained"]);
    }
    if (described !== null && decided !== null && described > decided) {
      problems.push([path + "/value_at", "the input's value describes a time after the decision"]);
    }
    if (available && has(value, "received_at") && !(has(entry, "obtained_at") && has(entry, "value_at"))) {
      problems.push([path, "a record that gives when the request was received gives when each available input was obtained and the time its value describes"]);
    }
  }
  if (admit && !entries.some(([, entry]) => pythonEquals(get(entry, "class"), "verifiable") && pythonEquals(get(entry, "effect"), "supports"))) {
    problems.push(["/inputs", "an admit records no verifiable input that supports it"]);
  }
  if (!has(value, "received_at") && entries.some(([, entry]) => has(entry, "obtained_at"))) {
    problems.push(["/received_at", "a record that gives when an input was obtained gives when the request was received"]);
  }
  const received = instantOrNull(get(value, "received_at"));
  if (received !== null && decided !== null && received > decided) {
    problems.push(["/received_at", "the request was received after the decision"]);
  }
  const recorded = get(value, "verifiable_only_outcome");
  if (isString(recorded) && OUTCOMES.includes(recorded) && isString(outcome) && OUTCOMES.includes(outcome) && OUTCOMES.indexOf(outcome) < OUTCOMES.indexOf(recorded)) {
    problems.push(["/verifiable_only_outcome", `the outcome ${pythonRepr(outcome)} is less strict than the verifiable-only outcome ${pythonRepr(recorded)}`]);
  }
  if (isString(recorded) && OUTCOMES.includes(recorded)) {
    problems.push(...verifiableOnlyProblems(recorded, entries, byKey));
  }
  return problems;
}

/**
 * DCMP2-053 on a recorded `verifiable_only_outcome`, as the reference's `_verifiable_only_problems`
 * gives it: an input supports only a verifiable-only `admit` (ECL1N-0181), and a verifiable-only
 * `admit` rests on at least one `verifiable` input that supports it and on no required `verifiable`
 * input that was not available, an input computed from one that was not available counting as not
 * available. A required `actor_supplied` or `judgment` input does not change the verifiable-only
 * outcome; whether it was available affects only the decision's outcome.
 */
function verifiableOnlyProblems(recorded: string, entries: ReadonlyArray<[number, JsonObject]>, byKey: ReadonlyMap<string, JsonObject>): Array<[string, string]> {
  const problems: Array<[string, string]> = [];
  if (recorded !== "admit") {
    for (const [position, entry] of entries) {
      if (pythonEquals(get(entry, "effect"), "supports")) {
        problems.push([`/inputs/${position}/effect`, `no input supports an outcome whose verifiable-only outcome is ${pythonRepr(recorded)}`]);
      }
    }
    return problems;
  }
  if (!entries.some(([, entry]) => pythonEquals(get(entry, "class"), "verifiable") && pythonEquals(get(entry, "effect"), "supports"))) {
    problems.push(["/verifiable_only_outcome", "a verifiable-only admit records no verifiable input that supports it"]);
  }
  for (const [position, entry] of entries) {
    if (get(entry, "required") !== true || !pythonEquals(get(entry, "class"), "verifiable")) {
      continue;
    }
    const own = get(entry, "input");
    const ownKey = isString(own) ? inputKey(own) : undefined;
    const unavailable =
      !pythonEquals(get(entry, "status"), "available") ||
      [...derivedSources(entry, byKey)].some((key) => key !== ownKey && !pythonEquals(get(byKey.get(key), "status"), "available"));
    if (unavailable) {
      problems.push([`/inputs/${position}/status`, "a verifiable-only admit cannot have a required verifiable input that was not available"]);
    }
  }
  return problems;
}

/** The register document rule for the `decision_inputs` of one action entry. */
function declarationProblems(declared: readonly JsonValue[], base: string): Array<[string, string]> {
  const problems: Array<[string, string]> = [];
  const entries: Array<[number, JsonObject]> = [];
  declared.forEach((item, position) => {
    if (isObject(item)) {
      entries.push([position, item]);
    }
  });
  const byKey = new Map<string, JsonObject>();
  for (const [position, item] of entries) {
    const name = get(item, "input");
    if (isString(name)) {
      const key = inputKey(name);
      if (byKey.has(key)) {
        problems.push([`${base}/${position}/input`, "the register declares this input more than once for the action class"]);
      } else {
        byKey.set(key, item);
      }
    }
  }
  for (const [position, item] of entries) {
    const path = `${base}/${position}`;
    const own = get(item, "input");
    const ownKey = isString(own) ? inputKey(own) : undefined;
    const derived = get(item, "derived_from");
    if (isArray(derived)) {
      derived.forEach((name, offset) => {
        const source = isString(name) ? inputKey(name) : undefined;
        if (source === undefined || source === ownKey || !byKey.has(source)) {
          problems.push([`${path}/derived_from/${offset}`, "the register declares no other input of the action class with this name"]);
        } else if (pythonEquals(get(item, "class"), "verifiable") && !pythonEquals(get(byKey.get(source), "class"), "verifiable")) {
          problems.push([path + "/class", `an input computed from an input of class ${pythonRepr(get(byKey.get(source), "class") ?? null)} cannot be verifiable`]);
        }
      });
    }
    if (ownKey !== undefined && derivedSources(item, byKey).has(ownKey)) {
      problems.push([path + "/derived_from", "the input is computed from itself through other inputs"]);
    }
  }
  return problems;
}

/**
 * (path, message) for each way a register document breaks
 * `ecl.rule.register-declarations-consistent.v1` (ECL1N-0178), as the reference's
 * `register_document_problems` reports them. Members of another shape are left to the register
 * schema; this never throws for a value of any shape.
 */
export function registerDocumentProblems(register: JsonObject): Array<[string, string]> {
  const problems: Array<[string, string]> = [];
  const entries = get(register, "entries");
  if (!isArray(entries)) {
    return problems;
  }
  const classes = new Set<string>();
  entries.forEach((entry, index) => {
    if (!isObject(entry)) {
      return;
    }
    const path = `/entries/${index}`;
    const actionClass = get(entry, "action_class_id");
    if (isString(actionClass)) {
      if (classes.has(actionClass)) {
        problems.push([path + "/action_class_id", "the register declares this action class more than once"]);
      } else {
        classes.add(actionClass);
      }
    }
    const declared = get(entry, "decision_inputs");
    if (isArray(declared)) {
      problems.push(...declarationProblems(declared, path + "/decision_inputs"));
    }
  });
  return problems;
}
