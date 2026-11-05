/**
 * MCP-GATEWAY-1: an ECL enforcement point between a governed AI system and its MCP servers. The
 * pinned MCP revision is 2026-07-28.
 *
 * `check` reads an `ecl_mcp_gateway_exchange_v1` record (MG1-012) that its schema has accepted and
 * reports each way the gateway weakened the guarantee:
 *
 * - `ecl.rule.mcp-decision-failure-not-forwarded.v1` (MG1-007): forwarded when the decision
 *   service was asked and was unavailable or answered with no verified decision;
 * - `ecl.rule.mcp-tool-mapped-and-reviewed.v1` (MG1-002, MG1-003, MG1-008): forwarded a request
 *   whose method has no mapping, a call to a tool with no mapping, or a call to a tool whose
 *   definition or server identity differs from the reviewed one;
 * - `ecl.rule.mcp-request-from-call.v1` (MG1-003, MG1-004): a decision request whose class,
 *   operation, target or evidence profile is not the mapping's, whose parameters are not the
 *   call's arguments, or that lacks the critical `ecl.ext.mcp-binding.v1` naming them and the
 *   digest of the call's complete `params`;
 * - `ecl.rule.mcp-forward-requires-admit.v1` (MG1-005, MG1-014, MG1-015): forwarded without a
 *   verified admit bound to the request, outside its window, within the release guard of its end,
 *   beyond its uses, with a `forwarded_at` other than the release event's observation, with a send
 *   that completed before the forward, with a write that the gateway itself observed at or after
 *   `valid_until` (`released_after_valid_until`), with a release event that declares another guard
 *   than the record's `release_guard_milliseconds`, on an admit that names one obligation twice,
 *   or as anything but exactly the
 *   call that the admitted request binds: another method, tool, arguments, input responses or
 *   request state, a `params` object other than the call's or than the one whose digest the
 *   admitted request carries, or a member added to or removed from the call;
 * - `ecl.rule.mcp-obligations-discharged.v1` (MG1-013): forwarded on an admit that leaves a
 *   pre-release obligation or a deferred state witness to Enforcement, with no release event that
 *   records a discharge of each, or a discharge that names an obligation the admit does not carry,
 *   names one twice, records a result other than `satisfied`, or differs from the record's
 *   `obligation_discharge`;
 * - `ecl.rule.mcp-refusal-defined.v1` (MG1-006): a request not forwarded got a result, or an error
 *   other than the one the error table gives for the first cause that holds;
 * - `ecl.rule.mcp-result-bound.v1` (MG1-010, MG1-014 to MG1-016): the evidence does not bind the
 *   server's response by digest, the governed AI system got another response, a server error with
 *   a code of the error table reached it unchanged, the terminal state misreads the response, the
 *   terminal does not record the forward's completion as the record does, a refused request is
 *   recorded as released, or a recovered record claims an outcome that its journal could not show.
 *
 * MG1-007 also holds the decision response that a record holds as answered to DCMP2-053: a
 * decision basis that it records and that breaks the one-way rule is reported under that rule,
 * `ecl.rule.decision-basis-one-way.v1`, which is the response's own rule and not one of the
 * profile's (`RULES`).
 *
 * A record may hold MCP content in the encoded form of MG1-012; `check` decodes it first and
 * reports a member that does not decode as a schema failure, with no finding of the profile's
 * rules. A decoded member has no shape that the record's schema checked, so the rules read any
 * JSON value there.
 */

import { BindingError, checkEventBinding } from "../binding/binding.js";
import { isInteger, isObject, pythonEquals, pythonStr } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { recordSchemas } from "../schema/validator.js";
import { SCHEMA_INVALID } from "../semantic/rules.js";
import type { Finding } from "../semantic/rules.js";
import {
  ONE_WAY_RULE,
  array,
  at,
  binds,
  copyJson,
  decodedRecord,
  digestOf,
  extensionEntries,
  extensionValues,
  findings,
  holds,
  instant,
  integer,
  isEncoded,
  member,
  messageFindings,
  obj,
  oneWayResponseProblems,
  sameDigest,
  sameJson,
  text,
} from "./common.js";
import type { Problem } from "./common.js";
import { JcsError, jcsDigest } from "./jcs.js";

export const REVISION = "2026-07-28";
export const EXCHANGE_VERSION = "ecl_mcp_gateway_exchange_v1";
export const EXCHANGE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1";
export const BINDING_EXTENSION = "ecl.ext.mcp-binding.v1";
/** MG1-002: the requests a gateway always sends to the Decision Layer before forwarding. */
const SIDE_EFFECTING = new Set(["tools/call", "tasks/update"]);
/** The error table of MG1-006: outside the range that JSON-RPC 2.0 reserves. */
export const ERRORS: ReadonlyMap<string, number> = new Map([
  ["denied", -31001],
  ["held", -31002],
  ["challenged", -31003],
  ["decision-unavailable", -31004],
  ["decision-invalid", -31005],
  ["authorization-unusable", -31006],
  ["not-mapped", -31007],
  ["unreviewed-change", -31008],
  ["forward-failed", -31009],
  ["obligation-unproven", -31010],
  ["evidence-unavailable", -31011],
]);
const REFUSAL_FOR_OUTCOME: ReadonlyMap<string, string> = new Map([
  ["deny", "denied"],
  ["hold", "held"],
  ["challenge", "challenged"],
]);
const UNAVAILABLE = "ecl.error.dependency-unavailable.v1";
const UNSUPPORTED = "ecl.error.binding-unsupported.v1";
const UNREVIEWED = "ecl.error.control-change-unreviewed.v1";
const EXPIRED = "ecl.error.expired.v1";
// MG1-014 step 5: the wall clock regressed or disagreed with the monotonic clock.
const CLOCK_REGRESSED = "ecl.error.clock-regressed.v1";
const REPLAY = "ecl.error.replay.v1";
const OBLIGATION_UNPROVEN = "ecl.error.obligation-unproven.v1";
const EVIDENCE_UNAVAILABLE = "ecl.error.evidence-unavailable.v1";
const NON_RELEASE = new Set(["denied", "held", "challenged", "expired_before_release"]);
/**
 * MG1-013: the record of the pre-release obligations that the gateway discharged, the coupling
 * extension whose deferred witness it discharges too, and the type that names that witness.
 */
const DISCHARGE_EXTENSION = "ecl.ext.obligation-discharge.v1";
const COUPLING_EXTENSION = "ecl.ext.consequence-coupling.v1";
const VERIFY_WITNESS = "ecl.obligation.verify-witness.v1";
/** MG1-010: the code that replaces a server error's code when that code is one of the error table's. */
export const SERVER_ERROR_CODE = -32603;
/**
 * MG1-004: the members of a request; a request with any other member is refused with -31007,
 * because no decision binds it.
 */
export const CALL_MEMBERS: ReadonlySet<string> = new Set(["jsonrpc", "id", "method", "params"]);
/**
 * MG1-004: the largest magnitude of a number that every RFC 8785 implementation keeps exactly (RFC
 * 7493 section 2.2); a request whose `id` or `params` holds a larger one is refused with -31007.
 */
const SAFE_MAGNITUDE = 9007199254740991;

/** The JSON Pointer form of one member name. */
function pointerName(name: string): string {
  return name.replace(/~/g, "~0").replace(/\//g, "~1");
}

/** [JSON Pointer, number] of each number in `value`, booleans excluded, sorted as the reference. */
function numbersIn(value: JsonValue | undefined, path: string): Array<[string, number]> {
  const found: Array<[string, number]> = [];
  const pending: Array<[JsonValue | undefined, string]> = [[value, path]];
  while (pending.length > 0) {
    const [item, where] = pending.pop() as [JsonValue | undefined, string];
    if (Array.isArray(item)) {
      item.forEach((child, index) => pending.push([child, `${where}/${index}`]));
    } else if (isObject(item)) {
      for (const [name, child] of Object.entries(item)) {
        pending.push([child, `${where}/${pointerName(name)}`]);
      }
    } else if (typeof item === "number") {
      found.push([where, item]);
    }
  }
  return found.sort((left, right) => pythonOrder(left[0], right[0]));
}

/**
 * Each reason why MG1-004 has the gateway refuse a request with -31007, and not forward it, before
 * any decision, as the reference's `unbound_problems`: a member other than `jsonrpc`, `id`,
 * `method` and `params`, which no decision binds, and a number in `id` or `params` of magnitude
 * greater than 2^53 - 1, which RFC 8785 may not represent exactly.
 */
export function unboundProblems(call: JsonObject, prefix = "/call"): Problem[] {
  const problems: Problem[] = Object.keys(call)
    .filter((name) => !CALL_MEMBERS.has(name))
    .sort(pythonOrder)
    .map((name) => [`${prefix}/${pointerName(name)}`, "no decision binds this member"] as const);
  for (const name of ["id", "params"]) {
    if (!holds(call, name)) {
      continue;
    }
    for (const [where, value] of numbersIn(call[name], `${prefix}/${name}`)) {
      if (Math.abs(value) > SAFE_MAGNITUDE) {
        problems.push([where, "the number's magnitude is greater than 2^53 - 1"]);
      }
    }
  }
  return problems;
}

/** Python's order of strings: by code point. */
function pythonOrder(left: string, right: string): number {
  const a = [...left].map((character) => character.codePointAt(0) as number);
  const b = [...right].map((character) => character.codePointAt(0) as number);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) {
      return (a[index] as number) - (b[index] as number);
    }
  }
  return a.length - b.length;
}
const TABLE_CODES: ReadonlySet<number> = new Set(ERRORS.values());
/** MG1-012: the record members that hold MCP content, which may be in the encoded form. */
export const CONTENT_PATHS: ReadonlyArray<readonly string[]> = [["call"], ["tool_definition"], ["forwarded", "request"], ["server_response"], ["returned"]];
/**
 * MG1-012: the definition of the record schema that each member's content satisfies when it is held
 * as itself, and so also when it is held in the encoded form.
 */
export const CONTENT_DEFINITIONS: ReadonlyArray<readonly [readonly string[], string]> = [
  [["call"], "jsonRpcRequest"],
  [["tool_definition"], "toolDefinition"],
  [["forwarded", "request"], "jsonRpcRequest"],
  [["server_response"], "jsonRpcResponse"],
  [["returned"], "jsonRpcResponse"],
];

export const FAILURE_RULE = "ecl.rule.mcp-decision-failure-not-forwarded.v1";
export const REVIEW_RULE = "ecl.rule.mcp-tool-mapped-and-reviewed.v1";
export const REQUEST_RULE = "ecl.rule.mcp-request-from-call.v1";
export const FORWARD_RULE = "ecl.rule.mcp-forward-requires-admit.v1";
export const OBLIGATION_RULE = "ecl.rule.mcp-obligations-discharged.v1";
export const REFUSAL_RULE = "ecl.rule.mcp-refusal-defined.v1";
export const RESULT_RULE = "ecl.rule.mcp-result-bound.v1";

/** A tool's mapping as declared with the Consequential Action Register (MG1-003). */
interface ToolMapping {
  readonly mappingId: JsonValue;
  readonly serverId: JsonValue;
  readonly serverName: JsonValue;
  readonly serverVersion: JsonValue;
  readonly tool: JsonValue;
  readonly toolDefinitionDigest: JsonObject;
  readonly actionClass: JsonValue;
  readonly operation: JsonValue;
  readonly riskClass: JsonValue;
  readonly evidenceProfile: JsonValue;
  readonly targetArgument: JsonValue;
  readonly targetUri: JsonValue;
}

const MAPPING_MEMBERS = ["mapping_id", "server_id", "server_name", "server_version", "tool", "tool_definition_digest", "action_class", "operation", "risk_class", "evidence_profile"];

function readMapping(record: JsonObject): ToolMapping | null {
  const value = obj(record, "mapping");
  if (value === null || !MAPPING_MEMBERS.every((name) => holds(value, name))) {
    return null;
  }
  const digest = at(value, "tool_definition_digest");
  if (!isObject(digest)) {
    return null;
  }
  return {
    mappingId: at(value, "mapping_id"),
    serverId: at(value, "server_id"),
    serverName: at(value, "server_name"),
    serverVersion: at(value, "server_version"),
    tool: at(value, "tool"),
    toolDefinitionDigest: digest,
    actionClass: at(value, "action_class"),
    operation: at(value, "operation"),
    riskClass: at(value, "risk_class"),
    evidenceProfile: at(value, "evidence_profile"),
    targetArgument: at(value, "target_argument"),
    targetUri: at(value, "target_uri"),
  };
}

/** The target URI the mapping derives from the call's arguments, or null. */
function target(mapping: ToolMapping, argumentsValue: JsonObject): JsonValue {
  if ((mapping.targetArgument === null) === (mapping.targetUri === null)) {
    return null;
  }
  if (mapping.targetUri !== null) {
    return mapping.targetUri;
  }
  const found = at(argumentsValue, pythonStr(mapping.targetArgument));
  return typeof found === "string" && found.includes(":") ? found : null;
}

/** The tool definition or the server identity differs from the reviewed mapping (MG1-008). */
function changed(mapping: ToolMapping, definition: JsonObject | null, server: JsonObject | null): boolean {
  if (definition === null || server === null) {
    return true;
  }
  let current: JsonObject;
  try {
    current = jcsDigest(definition);
  } catch (error) {
    if (error instanceof JcsError) {
      return true;
    }
    throw error;
  }
  return (
    !sameDigest(current, mapping.toolDefinitionDigest) ||
    !pythonEquals(at(server, "name"), mapping.serverName) ||
    !pythonEquals(at(server, "version"), mapping.serverVersion) ||
    !pythonEquals(at(definition, "name"), mapping.tool)
  );
}

/**
 * The value of `ecl.ext.mcp-binding.v1` on a decision request (MG1-004): the server, tool, reviewed
 * tool-definition digest and mapping, the digest of the call's complete `params`, its `_meta`
 * included, which the gateway forwards exactly (MG1-005), and the digests of any input responses and
 * request state. Throws JcsError.
 */
function bindingValue(mapping: ToolMapping, params: JsonObject, method: string): JsonObject {
  const value: JsonObject = {
    mcp_revision: REVISION,
    method,
    server_id: mapping.serverId,
    server_name: mapping.serverName,
    server_version: mapping.serverVersion,
    tool: mapping.tool,
    tool_definition_digest: mapping.toolDefinitionDigest,
    mapping_id: mapping.mappingId,
    params_digest: jcsDigest(params),
  };
  if (holds(params, "inputResponses")) {
    value["input_responses_digest"] = jcsDigest(params["inputResponses"] as JsonValue);
  }
  if (holds(params, "requestState")) {
    value["request_state_digest"] = jcsDigest(params["requestState"] as JsonValue);
  }
  return value;
}

/** What every rule of the profile reads from one record. */
interface View {
  readonly record: JsonObject;
  readonly call: JsonObject;
  readonly mapping: ToolMapping | null;
  readonly request: JsonObject | null;
  readonly response: JsonObject | null;
  readonly status: string | null;
  readonly forwarded: JsonObject | null;
  readonly released: JsonObject | null;
  readonly recovery: JsonObject | null;
}

function view(record: JsonObject): View {
  return {
    record,
    call: obj(record, "call") ?? {},
    mapping: readMapping(record),
    request: obj(record, "decision_request"),
    response: obj(record, "decision", "response"),
    status: text(record, "decision", "status"),
    forwarded: obj(record, "forwarded"),
    released: obj(record, "released"),
    recovery: obj(record, "recovery"),
  };
}

/** MG1-014: the record's release guard in nanoseconds, zero when it gives none. */
function guard(current: View): bigint {
  const milliseconds = integer(current.record, "release_guard_milliseconds");
  return milliseconds === null || milliseconds < 0 ? 0n : BigInt(milliseconds) * 1_000_000n;
}

function admitted(current: View): boolean {
  return current.status === "answered" && text(current.response, "outcome") === "admit" && binds(current.request, current.response);
}

function useLimit(response: JsonValue): number | null {
  if (text(response, "authorization", "use_policy") === "single_use") {
    return 1;
  }
  return integer(response, "authorization", "max_uses");
}

/**
 * EXPIRED or REPLAY when an admit cannot be used at `time` and until the record's release guard
 * after it (MG1-014), else null.
 */
/**
 * A cancelled terminal observed later than the recorded release plus the record's release guard:
 * the write could not begin within the guard (MG1-014), which the record shows.
 */
function guardExceeded(current: View): boolean {
  if (current.released === null || text(current.record, "terminal", "event", "state") !== "cancelled") {
    return false;
  }
  const releasedAt = instant(member(current.released, "observed_at"));
  const endedAt = instant(member(current.record, "terminal", "observed_at"));
  return releasedAt !== null && endedAt !== null && endedAt > releasedAt + guard(current);
}

function unusable(current: View, time: bigint | null): string | null {
  const start = instant(member(current.response, "authorization", "valid_from"));
  const end = instant(member(current.response, "authorization", "valid_until"));
  if (time === null || start === null || end === null || !(start <= time && time < end - guard(current))) {
    return EXPIRED;
  }
  const limit = useLimit(current.response);
  const prior = integer(current.record, "prior_uses") ?? 0;
  if (limit !== null && prior + 1 > limit) {
    return REPLAY;
  }
  return null;
}

/** `method` names a request that MG1-002 sends to the Decision Layer. */
function sideEffecting(method: JsonValue): boolean {
  return typeof method === "string" && SIDE_EFFECTING.has(method);
}

/** The key of an obligation, as the reference's (`obligation_id`, `type`) pair. */
function obligationKey(identifier: string, kind: string): string {
  return JSON.stringify([identifier, kind]);
}

/**
 * MG1-013 on an admit: what it leaves to Enforcement before the release, by (`obligation_id`,
 * `type`), in order and each once: each obligation whose `satisfaction` is `before_release`, and
 * each witness result of `ecl.ext.consequence-coupling.v1` whose `outcome` is
 * `required_before_release`, named by the `uri` of its reference and the type
 * `ecl.obligation.verify-witness.v1` (EBMP-2 EBMP2-070); and the keys of every obligation it
 * carries, the deferred witnesses included.
 */
export function preReleaseObligations(response: JsonValue): [Array<readonly [string, string]>, Set<string>] {
  const required: Array<readonly [string, string]> = [];
  const keys = new Set<string>();
  const carried = new Set<string>();
  const add = (identifier: string, kind: string, needed: boolean): void => {
    const key = obligationKey(identifier, kind);
    carried.add(key);
    if (needed && !keys.has(key)) {
      keys.add(key);
      required.push([identifier, kind]);
    }
  };
  for (const item of array(response, "obligations")) {
    const identifier = text(item, "id");
    const kind = text(item, "type");
    if (identifier === null || kind === null) {
      continue;
    }
    add(identifier, kind, pythonEquals(member(item, "satisfaction"), "before_release"));
  }
  for (const value of extensionValues(response, COUPLING_EXTENSION)) {
    const witness = member(value, "witness_result");
    const uri = text(witness, "reference", "uri");
    if (pythonEquals(member(witness, "outcome"), "required_before_release") && uri !== null) {
      add(uri, VERIFY_WITNESS, true);
    }
  }
  return [required, carried];
}

/**
 * (path, message) for each way the value of `ecl.ext.obligation-discharge.v1` at `path` fails to
 * discharge what `response` leaves to Enforcement before the release (MG1-013): an entry that names
 * an obligation the response does not carry or that another entry names, an entry whose `result`
 * is not `satisfied`, and each pre-release obligation that no entry names.
 */
/** The ids that the response's obligation list names more than once. */
export function repeatedObligationIds(response: JsonValue): string[] {
  const seen = new Set<string>();
  const repeated: string[] = [];
  for (const item of array(response, "obligations")) {
    const identifier = text(item, "id");
    if (identifier === null) {
      continue;
    }
    if (seen.has(identifier) && !repeated.includes(identifier)) {
      repeated.push(identifier);
    }
    seen.add(identifier);
  }
  return repeated;
}

export function dischargeProblems(value: JsonValue, response: JsonValue, path: string): Problem[] {
  const [required, carried] = preReleaseObligations(response);
  const problems: Problem[] = [];
  const named = new Set<string>();
  array(value, "obligations").forEach((entry, index) => {
    const identifier = text(entry, "obligation_id");
    const kind = text(entry, "type");
    const where = `${path}/obligations/${index}`;
    if (identifier === null || kind === null || !carried.has(obligationKey(identifier, kind))) {
      problems.push([where, "names an obligation that the admit does not carry"]);
      return;
    }
    const key = obligationKey(identifier, kind);
    if (named.has(key)) {
      problems.push([where, "names an obligation that another entry names"]);
      return;
    }
    named.add(key);
    if (!pythonEquals(member(entry, "result"), "satisfied")) {
      problems.push([`${where}/result`, "records an obligation that was not met"]);
    }
  });
  for (const [identifier, kind] of required) {
    if (!named.has(obligationKey(identifier, kind))) {
      problems.push([path, `no entry discharges the obligation ${identifier} (${kind})`]);
    }
  }
  return problems;
}

/**
 * The gateway returned -31011: its journal could not record an entry before the release (MG1-017),
 * which the record itself cannot show.
 */
function journalFailed(record: JsonObject): boolean {
  return (
    pythonEquals(member(record, "returned", "error", "code"), ERRORS.get("evidence-unavailable") as number) &&
    pythonEquals(member(record, "returned", "error", "data", "ecl", "code"), "evidence-unavailable")
  );
}

/** The record shows a discharge of every pre-release obligation of its admit (MG1-013). */
function discharged(current: View): boolean {
  const [required] = preReleaseObligations(current.response);
  if (required.length === 0) {
    return true;
  }
  const value = obj(current.record, "obligation_discharge");
  return value !== null && dischargeProblems(value, current.response, "").length === 0;
}

/**
 * The response a gateway returns for a forwarded request whose server answered (MG1-010): the
 * server's response unchanged, except that a JSON-RPC error whose code is one of the error
 * table's is returned with the code -32603, so that the governed AI system never reads a server's
 * error as a refusal by the gateway.
 */
export function returnedFor(serverResponse: JsonObject): JsonObject {
  const result = copyJson(serverResponse) as JsonObject;
  const error = at(result, "error");
  if (isObject(error)) {
    const code = at(error, "code");
    if (isInteger(code) && TABLE_CODES.has(code)) {
      const replaced = copyJson(error) as JsonObject;
      Object.defineProperty(replaced, "code", { value: SERVER_ERROR_CODE, enumerable: true, writable: true, configurable: true });
      Object.defineProperty(result, "error", { value: replaced, enumerable: true, writable: true, configurable: true });
    }
  }
  return result;
}

/**
 * (cause, reason, request_id) of the error table for a request the gateway refused, or null when
 * nothing in the record required a refusal. The causes are tried in the order of MG1-006, and the
 * first that holds is the one the gateway returns. A record cannot show that the gateway's evidence
 * log failed (-31011, MG1-017): when the gateway returned that error, the cause is taken in its
 * place in the order, after every earlier cause was found not to hold.
 */
export function refusalCause(original: JsonObject): readonly [string, string | null, string | null] | null {
  const [record] = decodedRecord(original, CONTENT_PATHS);
  const current = view(record);
  const params = obj(current.call, "params");
  // An `arguments` member that is not an object, null included, is a cause of -31007: a null is
  // not an absent member.
  const argumentsPresent = holds(params, "arguments");
  const argumentsValue = member(params, "arguments");
  const method = at(current.call, "method");
  if (
    current.mapping === null ||
    unboundProblems(current.call).length > 0 ||
    !sideEffecting(method) ||
    !pythonEquals(member(params, "name"), current.mapping.tool) ||
    (argumentsPresent && (!isObject(argumentsValue) || digestOf(argumentsValue) === null)) ||
    target(current.mapping, isObject(argumentsValue) ? argumentsValue : {}) === null
  ) {
    return ["not-mapped", UNSUPPORTED, null];
  }
  if (changed(current.mapping, obj(record, "tool_definition"), obj(record, "server"))) {
    return ["unreviewed-change", UNREVIEWED, null];
  }
  if (current.status === "unavailable" || current.status === null) {
    return ["decision-unavailable", UNAVAILABLE, null];
  }
  if (current.status === "invalid") {
    return ["decision-invalid", text(record, "decision", "error"), null];
  }
  if (!binds(current.request, current.response)) {
    return ["decision-invalid", "ecl.error.request-binding-invalid.v1", null];
  }
  const outcome = text(current.response, "outcome");
  const requestId = text(current.response, "request_id");
  const refused = outcome !== null ? REFUSAL_FOR_OUTCOME.get(outcome) : undefined;
  if (refused !== undefined) {
    const reasons = member(current.response, "reasons");
    const first = Array.isArray(reasons) && reasons.length > 0 ? reasons[0] : null;
    return [refused, text(first, "code"), requestId];
  }
  // MG1-017: once the use is consumed, a journal that fails cancels the attempt,
  // and that failure is the refusal's cause, whatever the gateway had still to discharge.
  if (journalFailed(record) && text(record, "terminal", "event", "state") === "cancelled") {
    return ["evidence-unavailable", EVIDENCE_UNAVAILABLE, requestId];
  }
  if (!discharged(current)) {
    return ["obligation-unproven", OBLIGATION_UNPROVEN, requestId];
  }
  if (journalFailed(record)) {
    return ["evidence-unavailable", EVIDENCE_UNAVAILABLE, requestId];
  }
  // MG1-014 and MG1-015: the write begins within the declared release guard after
  // the final observation, or not at all; a cancelled terminal observed later than the release
  // event plus the guard shows a write that could not begin in time.
  if (guardExceeded(current)) {
    return ["authorization-unusable", EXPIRED, requestId];
  }
  const problem = unusable(current, instant(member(record, "returned_at")));
  if (problem !== null) {
    return ["authorization-unusable", problem, requestId];
  }
  return null;
}

/**
 * The `execution_terminal` state for what the server returned (MG1-010): a complete result with
 * `isError` false succeeded as the server reports it; a result with `isError` true, or a JSON-RPC
 * error, failed; a request for input or a task handle leaves the effect unknown, as does no
 * response at all.
 */
export function terminalState(serverResponse: JsonObject | null): string {
  if (serverResponse === null) {
    return "unknown";
  }
  if (holds(serverResponse, "error")) {
    return "failed";
  }
  const result = at(serverResponse, "result");
  if (!isObject(result)) {
    return "unknown";
  }
  const kind = holds(result, "resultType") ? at(result, "resultType") : "complete";
  if (pythonEquals(kind, "input_required") || pythonEquals(kind, "task") || !pythonEquals(kind, "complete")) {
    return "unknown";
  }
  return at(result, "isError") === true ? "failed" : "succeeded";
}

/**
 * MG1-007: a decision was sought, and the gateway forwarded although the decision service was
 * unavailable, answered with no verified decision, or left no answer on record. A forward with no
 * decision request at all is the concern of MG1-002 and MG1-005.
 */
function failure(current: View): Problem[] {
  const asked = current.status === "unavailable" || current.status === "invalid" || (current.status === null && current.request !== null);
  if (current.forwarded !== null && asked) {
    return [["/forwarded", "forwarded without a verified decision"]];
  }
  return [];
}

function review(current: View): Problem[] {
  if (current.forwarded === null) {
    return [];
  }
  if (!sideEffecting(at(current.call, "method"))) {
    return [["/forwarded", "forwarded a request whose method has no mapping"]];
  }
  if (current.mapping === null || !pythonEquals(member(current.call, "params", "name"), current.mapping.tool)) {
    return [["/forwarded", "forwarded a call to a tool that has no mapping"]];
  }
  if (changed(current.mapping, obj(current.record, "tool_definition"), obj(current.record, "server"))) {
    return [["/forwarded", "forwarded a call to a tool whose change is not reviewed"]];
  }
  return [];
}

function requestFromCall(current: View): Problem[] {
  const { mapping, request } = current;
  if (request === null) {
    return [];
  }
  // MG1-004: a call with a member or a number that no decision can bind is refused, not decided.
  const problems: Problem[] = [...unboundProblems(current.call)];
  if (mapping === null) {
    return problems;
  }
  const action = obj(request, "action") ?? {};
  const fromMapping: ReadonlyArray<readonly [string, JsonValue]> = [
    ["action_class", mapping.actionClass],
    ["operation", mapping.operation],
    ["risk_class", mapping.riskClass],
    ["required_evidence_profile", mapping.evidenceProfile],
  ];
  for (const [name, expected] of fromMapping) {
    if (!pythonEquals(at(action, name), expected)) {
      problems.push([`/decision_request/action/${name}`, "not the mapping's"]);
    }
  }
  const params = obj(current.call, "params") ?? {};
  const argumentsValue = holds(params, "arguments") ? at(params, "arguments") : {};
  // MG1-004: the parameters are the call's arguments as the same JSON values, so a number never
  // stands for a boolean.
  if (!isObject(argumentsValue) || !sameJson(at(action, "parameters"), argumentsValue)) {
    problems.push(["/decision_request/action/parameters", "not the call's arguments"]);
  } else if (!sameDigest(at(action, "parameters_digest"), digestOf(argumentsValue))) {
    problems.push(["/decision_request/action/parameters_digest", "not their digest"]);
  }
  if (!pythonEquals(text(action, "target", "uri"), target(mapping, isObject(argumentsValue) ? argumentsValue : {}))) {
    problems.push(["/decision_request/action/target", "not the target the mapping derives"]);
  }
  const entries = extensionEntries(request, BINDING_EXTENSION);
  const values = extensionValues(request, BINDING_EXTENSION);
  if (entries.length !== 1 || values.length !== 1 || at(entries[0] as JsonObject, "critical") !== true) {
    problems.push(["/decision_request/extensions", "the critical mcp-binding is missing"]);
    return problems;
  }
  let expectedValue: JsonObject | null;
  try {
    expectedValue = bindingValue(mapping, params, pythonStr(at(current.call, "method")));
  } catch (error) {
    if (!(error instanceof JcsError)) {
      throw error;
    }
    expectedValue = null;
  }
  if (!pythonEquals(values[0], expectedValue)) {
    problems.push(["/decision_request/extensions", "the mcp-binding does not name the call and mapping"]);
  }
  return problems;
}

function forward(current: View): Problem[] {
  const { forwarded } = current;
  if (forwarded === null) {
    return [];
  }
  if (!admitted(current)) {
    return [["/forwarded", "forwarded without an admit bound to the decision request"]];
  }
  const problems: Problem[] = [];
  const forwardedAt = instant(member(forwarded, "forwarded_at"));
  if (unusable(current, forwardedAt) !== null) {
    problems.push(["/forwarded/forwarded_at", "forwarded when the authorization was unusable"]);
  }
  // MG1-015: the forward's time is the final observation that the release event records.
  if (current.released !== null && !pythonEquals(member(forwarded, "forwarded_at"), member(current.released, "observed_at"))) {
    problems.push(["/forwarded/forwarded_at", "not the observation that the release event records"]);
  }
  const completed = instant(member(forwarded, "forward_completed_at"));
  if (completed !== null && forwardedAt !== null && completed < forwardedAt) {
    problems.push(["/forwarded/forward_completed_at", "the send completed before the forward"]);
  }
  // MG1-015: the gateway's own observation of the write; the answer's arrival after
  // `valid_until` is not a late release.
  const terminal = obj(current.record, "terminal");
  if (extensionValues(terminal, BINDING_EXTENSION).some((value) => at(value, "released_after_valid_until") === true)) {
    problems.push(["/terminal/extensions", "the gateway observed the write at or after valid_until"]);
  }
  // MG1-014: the release event declares the guard that the record names.
  const declared = integer(current.record, "release_guard_milliseconds");
  if (current.released !== null && declared !== null && integer(current.released, "event", "release_guard_ms") !== declared) {
    problems.push(["/released/event/release_guard_ms", "not the record's release guard"]);
  }
  // MG1-014: an admit that names one obligation twice is refused before any use.
  if (repeatedObligationIds(current.response).length > 0) {
    problems.push(["/forwarded", "forwarded on an admit that names one obligation twice"]);
  }
  const sent = obj(forwarded, "request") ?? {};
  const bound = boundBy(current);
  // MG1-005: the gateway changes no member of the call, so each member is compared as the same JSON
  // value: an `id` of 1 forwarded as `true` is a changed member.
  for (const name of ["jsonrpc", "id"]) {
    if (holds(sent, name) !== holds(current.call, name) || !sameJson(at(sent, name), at(current.call, name))) {
      problems.push([`/forwarded/request/${name}`, "not the call's"]);
    }
  }
  // MG1-005: exactly the call, so no member is added to it or removed from it.
  const compared = new Set(["jsonrpc", "id", "method", "params"]);
  const others = [...new Set([...Object.keys(sent), ...Object.keys(current.call)])].filter((name) => !compared.has(name));
  if (others.some((name) => !holds(sent, name) || !holds(current.call, name) || !sameJson(at(sent, name), at(current.call, name)))) {
    problems.push(["/forwarded/request", "adds, removes or changes a member of the call"]);
  }
  if (!sameJson(at(sent, "method"), at(current.call, "method")) || !bound.matches("method", at(sent, "method"))) {
    problems.push(["/forwarded/request/method", "not the call's or not what the admit binds"]);
  }
  const params = obj(sent, "params");
  for (const name of ["name", "arguments", "inputResponses", "requestState"]) {
    const value = member(params, name);
    const present = params !== null && holds(params, name);
    if (!sameJson(value, member(current.call, "params", name)) || !bound.matches(name, value, present)) {
      problems.push([`/forwarded/request/params/${name}`, "not the call's or not what the admit binds"]);
    }
  }
  const forwardedParams = member(sent, "params");
  if (!sameJson(forwardedParams, member(current.call, "params")) || !bound.bindsParams(forwardedParams)) {
    problems.push(["/forwarded/request/params", "not the call's or not what the admit binds"]);
  }
  return problems;
}

const DIGEST_MEMBERS: ReadonlyMap<string, string> = new Map([
  ["inputResponses", "input_responses_digest"],
  ["requestState", "request_state_digest"],
]);

/**
 * What an admitted decision request binds of the request to forward (MG1-005): its method and
 * tool from the request's `ecl.ext.mcp-binding.v1`, its arguments as `action.parameters`, the
 * digest of its complete `params`, and the digests of any input responses and request state.
 */
class Bound {
  constructor(
    readonly request: JsonObject | null,
    readonly extension: JsonObject | null,
  ) {}

  /** The admitted request carries, as `params_digest`, the digest of the RFC 8785 form of `params`
   * (MG1-004, MG1-005). */
  bindsParams(params: JsonValue): boolean {
    if (this.extension === null) {
      // The request names no single binding; MG1-004's rule reports that.
      return true;
    }
    let forwarded: JsonObject | null = null;
    if (isObject(params)) {
      try {
        forwarded = jcsDigest(params);
      } catch (error) {
        if (!(error instanceof JcsError)) {
          throw error;
        }
      }
    }
    return forwarded !== null && sameDigest(at(this.extension, "params_digest"), forwarded);
  }

  /** `value`, the member `name` of the forwarded request's `params` (or its method), is what the
   * admitted request binds, compared as the same JSON value. */
  matches(name: string, value: JsonValue, present = true): boolean {
    if (name === "arguments") {
      return sameJson(present ? value : {}, member(this.request, "action", "parameters"));
    }
    if (this.extension === null) {
      // The request names no single binding; MG1-004's rule reports that, and only the arguments
      // can be compared here.
      return true;
    }
    if (name === "method") {
      return sameJson(value, at(this.extension, "method"));
    }
    if (name === "name") {
      return sameJson(value, at(this.extension, "tool"));
    }
    const digestName = DIGEST_MEMBERS.get(name) as string;
    if (!present) {
      return !holds(this.extension, digestName);
    }
    try {
      return sameDigest(at(this.extension, digestName), jcsDigest(value));
    } catch (error) {
      if (error instanceof JcsError) {
        return false;
      }
      throw error;
    }
  }
}

function boundBy(current: View): Bound {
  const values = extensionValues(current.request, BINDING_EXTENSION);
  return new Bound(current.request, values.length === 1 ? (values[0] as JsonObject) : null);
}

/**
 * MG1-013: a forward on an admit that leaves obligations to Enforcement before the release rests on
 * a release event that records the discharge of each of them.
 */
function obligations(current: View): Problem[] {
  if (current.forwarded === null || !admitted(current)) {
    return [];
  }
  const [required] = preReleaseObligations(current.response);
  if (required.length === 0) {
    return [];
  }
  if (current.released === null) {
    return [["/released", "no release event records the discharge of the obligations"]];
  }
  const entries: Array<readonly [number, JsonObject]> = [];
  array(current.released, "extensions").forEach((item, index) => {
    if (isObject(item) && pythonEquals(at(item, "id"), DISCHARGE_EXTENSION)) {
      entries.push([index, item]);
    }
  });
  const only = entries.length === 1 ? (entries[0] as readonly [number, JsonObject]) : null;
  if (only === null || !isObject(at(only[1], "value"))) {
    return [["/released/extensions", "the release records no single discharge"]];
  }
  const [index, entry] = only;
  const value = at(entry, "value");
  const problems = dischargeProblems(value, current.response, `/released/extensions/${index}/value`);
  const held = obj(current.record, "obligation_discharge");
  if (held !== null && !sameJson(held, value)) {
    problems.push(["/obligation_discharge", "not the discharge that the release records"]);
  }
  return problems;
}

function refusal(current: View): Problem[] {
  if (current.forwarded !== null || current.recovery !== null) {
    // A recovered record holds no response returned to the governed AI system (MG1-016).
    return [];
  }
  const returned = obj(current.record, "returned") ?? {};
  if (holds(returned, "result") || !holds(returned, "error")) {
    return [["/returned", "a request that was not forwarded got no error"]];
  }
  const problems: Problem[] = [];
  // A JSON-RPC error answers the call that has the same `id`, as the same JSON value.
  if (holds(returned, "id") !== holds(current.call, "id") || !sameJson(at(returned, "id"), at(current.call, "id")) || !pythonEquals(at(returned, "jsonrpc"), "2.0")) {
    problems.push(["/returned/id", "the error does not answer the call"]);
  }
  const cause = refusalCause(current.record);
  if (cause === null) {
    return problems;
  }
  const [name, reason, requestId] = cause;
  const data = member(returned, "error", "data", "ecl");
  const expected: JsonObject = { code: name };
  if (reason !== null) {
    expected["reason"] = reason;
  }
  if (requestId !== null) {
    expected["request_id"] = requestId;
  }
  // MG1-014 step 5: a gateway refuses an authorization as unusable with
  // `ecl.error.clock-regressed.v1` when its clock readings disagreed, which the record cannot show;
  // a checker accepts that reason where the record shows the window as the cause.
  const regressed: JsonObject | null = name === "authorization-unusable" ? { ...expected, reason: CLOCK_REGRESSED } : null;
  if (!pythonEquals(member(returned, "error", "code"), ERRORS.get(name) as number) || !(pythonEquals(data, expected) || (regressed !== null && pythonEquals(data, regressed)))) {
    problems.push(["/returned/error", `the cause ${name} has another error`]);
  }
  return problems;
}

/**
 * MG1-016: a recovered record claims only what its journal showed, and its terminal says when it
 * was recovered; a record that is not recovered has no recovered terminal.
 */
function recovered(current: View, terminal: JsonObject | null): Problem[] {
  const marked = extensionValues(terminal, BINDING_EXTENSION).map((value) => at(value, "recovered_at"));
  if (current.recovery === null) {
    if (marked.some((item) => item !== null)) {
      return [["/terminal/extensions", "a terminal of recovery in a record that is not one"]];
    }
    return [];
  }
  if (terminal === null) {
    return [["/terminal", "a recovered record has no terminal event"]];
  }
  const classification = text(current.recovery, "classification");
  const state = text(terminal, "event", "state");
  const recoveredAt = member(current.recovery, "recovered_at");
  const problems: Problem[] = [];
  if (classification === "outcome-recorded") {
    if (marked.some((item) => item !== null)) {
      problems.push(["/terminal/extensions", "a recorded outcome is marked as recovered"]);
    }
    return problems;
  }
  if (!(marked.length === 1 && pythonEquals(marked[0], recoveredAt))) {
    problems.push(["/terminal/extensions", "the recovered terminal does not say when"]);
  }
  if (classification === "outcome-unknown" && (current.forwarded === null || state !== "unknown" || holds(current.record, "server_response"))) {
    problems.push(["/terminal/event/state", "a released request of unknown outcome is not unknown"]);
  }
  if (classification === "not-released" && (current.forwarded !== null || state === null || (!NON_RELEASE.has(state) && state !== "cancelled"))) {
    problems.push(["/terminal/event/state", "a request that was not released is recorded as released"]);
  }
  return problems;
}

/**
 * MG1-015: the terminal of a forward records its completion as the record does. Whether the
 * release was late is the gateway's own observation (`released_after_valid_until`), which the
 * forward rule reads; it is not derived from the completion.
 */
function completionProblems(current: View, terminal: JsonObject): Problem[] {
  const values = extensionValues(terminal, BINDING_EXTENSION);
  const completed = member(current.forwarded, "forward_completed_at");
  if (values.length !== 1) {
    return [];
  }
  const value = values[0] as JsonObject;
  if (!pythonEquals(at(value, "forward_completed_at"), completed)) {
    return [["/terminal/extensions", "the terminal does not record the forward's completion"]];
  }
  return [];
}

function resultBound(current: View): Problem[] {
  const terminal = obj(current.record, "terminal");
  const problems: Problem[] = recovered(current, terminal);
  if (current.forwarded === null) {
    const state = text(terminal, "event", "state");
    // MG1-014: a refusal after the authorization was consumed is a cancelled attempt, and a
    // cancelled attempt is one whose use the gateway consumed, or that recovery settled. A journal
    // that failed (MG1-017) may have recorded the consumed use and not the prepared release, which
    // the record then cannot show.
    const consumed = member(current.record, "prepared") !== null || current.released !== null;
    const unseen = current.recovery !== null || journalFailed(current.record);
    const allowed: ReadonlySet<string> = consumed ? new Set(["cancelled"]) : unseen ? new Set([...NON_RELEASE, "cancelled"]) : NON_RELEASE;
    if (terminal !== null && (state === null || !allowed.has(state))) {
      problems.push(["/terminal/event/state", "a refused request is recorded as released"]);
    }
    return problems;
  }
  if (current.recovery !== null) {
    // The journal does not show what the governed AI system received (MG1-016).
    if (terminal !== null && current.request !== null) {
      try {
        checkEventBinding(terminal, current.request, current.response ?? undefined);
      } catch (error) {
        if (!(error instanceof BindingError)) {
          throw error;
        }
        problems.push(["/terminal", `the terminal event is not bound: ${error.code}`]);
      }
    }
    return problems;
  }
  const serverResponse = obj(current.record, "server_response");
  const returned = obj(current.record, "returned");
  // MG1-010: the response returned is the one the evidence binds, as the same JSON values, so
  // `false` returned as `0` is another response.
  if (serverResponse !== null && !sameJson(returned, returnedFor(serverResponse))) {
    problems.push(["/returned", "not the response the evidence binds, as MG1-010 returns it"]);
  }
  if (serverResponse === null && !pythonEquals(member(returned, "error", "code"), ERRORS.get("forward-failed") as number)) {
    problems.push(["/returned", "an unanswered forward is not reported as forward-failed"]);
  }
  if (terminal === null) {
    return [...problems, ["/terminal", "a forwarded request has no terminal evidence"]];
  }
  const state = terminalState(serverResponse);
  if (text(terminal, "event", "state") !== state) {
    problems.push(["/terminal/event/state", `the server's response reads as ${state}`]);
  }
  problems.push(...completionProblems(current, terminal));
  const values = extensionValues(terminal, BINDING_EXTENSION);
  let bound: JsonObject | null = null;
  if (serverResponse !== null) {
    try {
      bound = jcsDigest(serverResponse);
    } catch (error) {
      if (!(error instanceof JcsError)) {
        throw error;
      }
    }
  }
  if (serverResponse !== null && (values.length !== 1 || !sameDigest(at(values[0] as JsonObject, "response_digest"), bound))) {
    problems.push(["/terminal/extensions", "the evidence does not bind the response"]);
  }
  if (current.request !== null) {
    try {
      checkEventBinding(terminal, current.request, current.response ?? undefined);
    } catch (error) {
      if (!(error instanceof BindingError)) {
        throw error;
      }
      problems.push(["/terminal", `the terminal event is not bound: ${error.code}`]);
    }
  }
  return problems;
}

/**
 * The rules of the profile, in the order the reference reports them. A rule added to the
 * registry for this profile is one function above and one row here.
 */
export const RULES: ReadonlyArray<readonly [string, (current: View) => Problem[]]> = [
  [FAILURE_RULE, failure],
  [REVIEW_RULE, review],
  [REQUEST_RULE, requestFromCall],
  [FORWARD_RULE, forward],
  [OBLIGATION_RULE, obligations],
  [REFUSAL_RULE, refusal],
  [RESULT_RULE, resultBound],
];

/**
 * The path and message of each member of `record` held in the encoded form of MG1-012 whose
 * content, as `decoded` holds it, does not satisfy the definition that the record schema gives the
 * same content held as itself: a call or a forwarded request with a null `id` or a `jsonrpc` of
 * "1.0" fails `jsonRpcRequest` in either form.
 */
export function decodedContentProblems(record: JsonObject, decoded: JsonObject): Problem[] {
  const problems: Problem[] = [];
  for (const [path, name] of CONTENT_DEFINITIONS) {
    if (!isEncoded(member(record, ...path))) {
      continue;
    }
    if (!recordSchemas().isValid(`${EXCHANGE_SCHEMA}#/$defs/${name}`, member(decoded, ...path) as JsonValue)) {
      problems.push(["/" + path.join("/"), `the decoded content does not satisfy ${name}`]);
    }
  }
  return problems;
}

/**
 * The findings of an `ecl_mcp_gateway_exchange_v1` record that its schema has accepted. A member
 * in the encoded form of MG1-012 is decoded first; a member that does not decode, or whose content
 * does not satisfy the definition that the record schema gives the same content held as itself,
 * fails the record's schema, and the profile's rules are then not applied.
 */
export function check(record: JsonObject): Finding[] {
  const [decoded, decoding] = decodedRecord(record, CONTENT_PATHS);
  const problems = decoding.length > 0 ? decoding : decodedContentProblems(record, decoded);
  if (problems.length > 0) {
    return findings(SCHEMA_INVALID, problems);
  }
  const current = view(decoded);
  const found = RULES.flatMap(([rule, check]) => findings(rule, check(current)));
  if (current.status === "answered") {
    // MG1-007: a decision held as answered is a verified decision response, which carries exactly
    // one decision basis and satisfies DCMP2-053 as any decision response does.
    found.push(...findings(ONE_WAY_RULE, oneWayResponseProblems(decoded, [["decision_request"], ["decision", "response"]])));
  }
  // MG1-007: each DCMP-2 message that the record holds satisfies the semantic rules of DCMP-2,
  // other than the response of a decision whose status is `invalid`: the gateway refused that
  // response, and the record keeps it as evidence of what it refused.
  const held: string[][] = [["decision_request"]];
  if (current.status !== "invalid") {
    held.push(["decision", "response"]);
  }
  found.push(...messageFindings(decoded, ...held));
  return found;
}
