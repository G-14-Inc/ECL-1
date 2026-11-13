/**
 * OAUTH-AUTHORITY-1: one ECL admit as one sender-constrained OAuth 2.0 access token.
 *
 * `check` reads an `ecl_oauth_presentation_v1` record (OA1-010) that its schema has accepted and
 * reports:
 *
 * - `ecl.rule.oauth-token-expresses-admit.v1` (OA1-001 to OA1-004, OA1-006, OA1-008): the token was
 *   issued for something other than a verified admit, its entry, audience, lifetime, subject, actor
 *   or confirmation key does not express that admit, or it lacks the `iss`, `client_id` or `jti`
 *   string that RFC 9068 requires;
 * - `ecl.rule.oauth-token-signature-checked.v1` (OA1-007): a resource server accepted a token
 *   that it cannot read under the strict JSON profile, or whose signature, algorithm, key, header
 *   or issuer it should have refused;
 * - `ecl.rule.oauth-presentation-checked.v1` (OA1-002 to OA1-005): a resource server accepted a
 *   presentation to another audience, outside the token's validity with the clock-skew allowance
 *   or outside its entry's window, without a valid proof of possession, for another target,
 *   operation or parameter digest, or beyond its uses;
 * - `ecl.rule.oauth-refusal-named.v1` (OA1-011): a resource server refused a presentation with
 *   another code than the one the presentation table gives for the first check it fails.
 *
 * The checks of the presentation table, in its order, are `refusalProblems`: the token's JWS
 * checks (`signatureProblems`) and then the resource server's other checks (`presentationChecks`).
 * The token's segments are read under the strict JSON profile (`jose.ts`), so every number in a
 * claim is an integer, and the claims are compared with the admit as Python compares them
 * (`pyjson.ts`).
 */

import { ERROR_CODES } from "../generated/registries.js";
import { sha256Hex, utf8 } from "../crypto/bytes.js";
import { isObject, pythonStr } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import type { Finding } from "../semantic/rules.js";
import { urlsplit } from "../schema/formats.js";
import { ONE_WAY_RULE, array, at, binds, digestOf, findings, holds, instant, integer, member, messageFindings, obj, oneWayResponseProblems, sameDigest, text } from "./common.js";
import type { Problem } from "./common.js";
import { b64urlDecode, decodeJws, isPyObject, JoseError, tokenHash, verifyDpop, verifyJws } from "./jose.js";
import { pyEquals, pyIn, pySameJson, toPy } from "./pyjson.js";
import type { PyObject, PyValue } from "./pyjson.js";

export const PRESENTATION_VERSION = "ecl_oauth_presentation_v1";
export const PRESENTATION_SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/oauth-presentation/1";
export const DETAILS_TYPE = "https://externalcontrollayer.ai/ns/authorization-details/action/1";
export const DEFAULT_MAX_LIFETIME = 300;
export const DEFAULT_PROOF_WINDOW = 60;
/**
 * OA1-004: a DPoP proof's `jti` has 1 to 256 characters, as a presentation record holds it in
 * `seen_dpop_jti`.
 */
export const MAX_JTI_CHARACTERS = 256;
/**
 * OA1-001: the claims of RFC 9068, Section 2.2 that a JWT access token carries as strings, beside
 * `aud`, `sub`, `iat` and `exp`, which the issuer's checks compare with the admit.
 */
const TOKEN_STRING_CLAIMS = ["client_id", "iss", "jti"] as const;
/** OA1-003: the clock-skew allowance a resource server applies to `nbf` and `exp`, zero by default. */
export const DEFAULT_CLOCK_SKEW = 0;
const NANOSECONDS = 1_000_000_000n;
export const AUDIENCE_MISMATCH = "ecl.error.audience-mismatch.v1";
export const SCOPE_MISMATCH = "ecl.error.scope-mismatch.v1";
export const EXPIRED = "ecl.error.expired.v1";
export const REPLAY = "ecl.error.replay.v1";
export const INTEGRITY_INVALID = "ecl.error.integrity-invalid.v1";
export const BINDING_UNSUPPORTED = "ecl.error.binding-unsupported.v1";

export const ISSUE_RULE = "ecl.rule.oauth-token-expresses-admit.v1";
export const SIGNATURE_RULE = "ecl.rule.oauth-token-signature-checked.v1";
export const PRESENTATION_RULE = "ecl.rule.oauth-presentation-checked.v1";
export const REFUSAL_RULE = "ecl.rule.oauth-refusal-named.v1";

/** A reason a resource server must refuse a presentation, with the error code it refuses with. */
export type CodedProblem = readonly [path: string, message: string, code: string];

function own(value: PyObject, name: string): PyValue | undefined {
  return Object.prototype.hasOwnProperty.call(value, name) ? value[name] : undefined;
}

/** Python's `type(x) is int` for a claim. */
function pyInt(value: PyValue | undefined): bigint | null {
  return typeof value === "bigint" ? value : null;
}

/** Project the entry table's members; callers verify the admit and supported use policy separately. */
export function authorizationDetailsEntry(request: JsonObject, response: JsonObject, withDecision = true): JsonObject {
  const authorization = response["authorization"] as JsonObject;
  const action = request["action"] as JsonObject;
  const entry: JsonObject = {
    type: DETAILS_TYPE,
    locations: [authorization["audience"] as JsonValue],
    actions: [action["operation"] as JsonValue],
    identifier: (action["target"] as JsonObject)["uri"] as JsonValue,
    authorization_id: authorization["authorization_id"] as JsonValue,
    request_id: request["message_id"] as JsonValue,
    action_id: action["action_id"] as JsonValue,
    action_class: action["action_class"] as JsonValue,
    scope_digest: authorization["scope_digest"] as JsonValue,
    parameters_digest: action["parameters_digest"] as JsonValue,
    use_policy: authorization["use_policy"] as JsonValue,
    valid_from: authorization["valid_from"] as JsonValue,
    valid_until: authorization["valid_until"] as JsonValue,
  };
  if (holds(authorization, "max_uses")) {
    entry["max_uses"] = authorization["max_uses"] as JsonValue;
  }
  if (withDecision) {
    entry["decision"] = { uri: response["message_id"] as JsonValue, digest: digestOf(response) };
  }
  return entry;
}

/** `sub`, and `act.sub` when the subject differs from the actor (OA1-006). */
export function subjectAndActor(request: JsonObject): [string, string | null] {
  const actor = pythonStr(member(request, "actor", "id"));
  const subject = text(request, "subject", "id");
  if (subject === null || subject === actor) {
    return [actor, null];
  }
  return [subject, actor];
}

/** The digest an admit's `authorization.token_reference` carries for its token (OA1-008). */
export function tokenReferenceDigest(token: string): JsonObject {
  return { algorithm: "ecl.digest.sha-256.v1", value: sha256Hex(utf8(token)) };
}

function entries(claims: PyObject): PyValue[] {
  const listed = own(claims, "authorization_details");
  if (!Array.isArray(listed)) {
    return [];
  }
  return listed.filter((item) => isPyObject(item) && own(item, "type") === DETAILS_TYPE);
}

/** Each way a token fails to express its admit (the issuer's side). */
function validThumbprint(value: PyValue | undefined): boolean {
  if (typeof value !== "string" || value.length !== 43) return false;
  try { return b64urlDecode(value).length === 32; }
  catch (error) { if (error instanceof JoseError) return false; throw error; }
}

export function issueProblems(request: JsonObject, response: JsonObject, token: string, maxLifetime: number): Problem[] {
  if (at(response, "outcome") !== "admit" || !binds(request, response)) {
    return [["/token", "the token was issued for something other than a verified admit"]];
  }
  const obligations = at(response, "obligations");
  if (!Array.isArray(obligations) || obligations.length !== 0) {
    return [["/response/obligations", "OAuth profile 1.0 cannot carry obligations"]];
  }
  let claims: PyObject;
  try {
    claims = decodeJws(token).claims;
  } catch (error) {
    if (error instanceof JoseError) {
      return [["/token", "the token is not a compact JWS"]];
    }
    throw error;
  }
  const problems: Problem[] = [];
  const found = entries(claims);
  const expected = toPy(authorizationDetailsEntry(request, response, false));
  if (found.length !== 1) {
    problems.push(["/token/authorization_details", "not exactly one ECL entry"]);
  } else {
    const entry: PyObject = {};
    // The entry may name the decision; a `decision` of null is present and names none, so it is
    // not taken for an entry without one.
    let named = false;
    let decision: PyValue = null;
    for (const name of Object.keys(found[0] as PyObject)) {
      if (name === "decision") {
        named = true;
        decision = (found[0] as PyObject)[name] as PyValue;
      } else {
        Object.defineProperty(entry, name, { value: (found[0] as PyObject)[name], enumerable: true, writable: true, configurable: true });
      }
    }
    // OA1-001: the entry's members are the admit's as the same JSON values, so `true` is not a
    // `max_uses` of 1.
    if (!pySameJson(entry, expected)) {
      problems.push(["/token/authorization_details", "the entry is not the admit's"]);
    }
    if (named && !pyEquals(decision, toPy({ uri: at(response, "message_id"), digest: digestOf(response) }))) {
      problems.push(["/token/authorization_details", "the entry names another decision"]);
    }
  }
  if (!pyEquals(own(claims, "aud"), toPy(member(response, "authorization", "audience")))) {
    problems.push(["/token/aud", "not the authorization's audience as a single value"]);
  }
  const start = instant(member(response, "authorization", "valid_from"));
  const end = instant(member(response, "authorization", "valid_until"));
  const issued = pyInt(own(claims, "iat"));
  const begins = pyInt(holds(claims as unknown as JsonObject, "nbf") ? own(claims, "nbf") : own(claims, "iat"));
  const expires = pyInt(own(claims, "exp"));
  if (
    issued === null ||
    begins === null ||
    expires === null ||
    start === null ||
    end === null ||
    begins * NANOSECONDS < start ||
    expires * NANOSECONDS > end ||
    begins >= expires ||
    !(0n < expires - issued && expires - issued <= BigInt(maxLifetime))
  ) {
    problems.push(["/token/exp", "the token's validity is not inside the window and bound"]);
  }
  const [subject, actor] = subjectAndActor(request);
  const act = own(claims, "act");
  let malformedActor = false;
  if (act !== undefined) {
    let nested: PyValue | undefined = act;
    while (true) {
      if (!isPyObject(nested)) { malformedActor = true; break; }
      if (own(nested, "act") === undefined) break;
      nested = own(nested, "act");
    }
  }
  if (!pyEquals(own(claims, "sub"), subject) || malformedActor || ((actor !== null || act !== undefined) && !pyEquals(isPyObject(act) ? own(act, "sub") : null, member(request, "actor", "id")))) {
    problems.push(["/token/act", "the subject and actor are not the request's"]);
  }
  const confirmation = own(claims, "cnf");
  const confirmationKeys = isPyObject(confirmation) ? Object.keys(confirmation) : [];
  // OA1-004: one key, named by a string; a `jkt` or `x5t#S256` of null names no key.
  if (
    !isPyObject(confirmation) ||
    confirmationKeys.length !== 1 ||
    (confirmationKeys[0] !== "jkt" && confirmationKeys[0] !== "x5t#S256") ||
    !validThumbprint(own(confirmation, confirmationKeys[0] as string))
  ) {
    problems.push(["/token/cnf", "the token is not sender-constrained by one key"]);
  }
  const reference = member(response, "authorization", "token_reference", "digest");
  if (reference !== null && !sameDigest(reference, tokenReferenceDigest(token))) {
    problems.push(["/token", "the admit's token_reference names another token"]);
  }
  // OA1-001: the token is a JWT access token of RFC 9068, whose Section 2.2 requires `iss`,
  // `client_id` and `jti`, each a string (RFC 7519, Sections 4.1.1 and 4.1.7; RFC 8693, Section
  // 4.3).
  for (const name of TOKEN_STRING_CLAIMS) {
    if (typeof own(claims, name) !== "string") {
      problems.push([`/token/${name}`, `the token carries no ${name} string, which RFC 9068 requires`]);
    }
  }
  return problems;
}

/** When a resource server should refuse the token's JWS (OA1-007). */
export function signatureProblems(token: string, keys: ReadonlyMap<string, PyObject>, issuer: JsonValue): Problem[] {
  let claims: PyObject;
  try {
    [, claims] = verifyJws(token, keys);
  } catch (error) {
    if (error instanceof JoseError) {
      return [["/token", `the token fails the ${error.reason} check`]];
    }
    throw error;
  }
  if (!pyEquals(own(claims, "iss"), toPy(issuer))) {
    return [["/token/iss", "the token's issuer is not the configured one"]];
  }
  return [];
}

/**
 * The `htu` of a request URI (RFC 9449 section 4.3): the URI without its query and fragment, or
 * null when the URI cannot be split.
 */
function htu(uri: string): string | null {
  const parts = urlsplit(uri);
  if (parts === undefined || parts.scheme === "") {
    return null;
  }
  // OA1-004 preserves every other character, including an empty authority's slashes.
  return parts.scheme + uri.slice(uri.indexOf(":")).split(/[?#]/, 1)[0];
}

function possession(record: JsonObject, claims: PyObject, token: string, presentation: JsonObject, presented: bigint | null): CodedProblem[] {
  const cnf = own(claims, "cnf");
  const confirmation: PyObject = isPyObject(cnf) ? cnf : {};
  const confirmationNames = Object.keys(confirmation);
  if (confirmationNames.length !== 1 || !["jkt", "x5t#S256"].includes(confirmationNames[0] as string)
    || !validThumbprint(own(confirmation, confirmationNames[0] as string))) {
    return [["/token/cnf", "the token is not sender-constrained by one key", INTEGRITY_INVALID]];
  }
  if (own(confirmation, "x5t#S256") !== undefined) {
    // The bound thumbprint is a string: a null one is not matched by a presentation that carries no
    // client certificate.
    const bound = own(confirmation, "x5t#S256");
    if (!validThumbprint(bound) || !pyEquals(toPy(at(presentation, "client_certificate_sha256")), bound)) {
      return [["/presentation", "the client certificate is not the bound one", INTEGRITY_INVALID]];
    }
    return [];
  }
  const proof = at(presentation, "dpop_proof");
  if (own(confirmation, "jkt") === undefined || typeof proof !== "string") {
    return [["/presentation/dpop_proof", "no proof of possession", INTEGRITY_INVALID]];
  }
  let proofClaims: PyObject;
  let key: string;
  try {
    [, proofClaims, key] = verifyDpop(proof);
  } catch (error) {
    if (error instanceof JoseError) {
      return [["/presentation/dpop_proof", `the proof fails the ${error.reason} check`, INTEGRITY_INVALID]];
    }
    throw error;
  }
  const problems: CodedProblem[] = [];
  const window = BigInt(integer(record, "dpop_proof_window_seconds") || DEFAULT_PROOF_WINDOW);
  const issued = pyInt(own(proofClaims, "iat"));
  const method = at(presentation, "method");
  const uri = at(presentation, "uri");
  const targetUri = typeof uri === "string" ? htu(uri) : null;
  const bound =
    pyEquals(key, own(confirmation, "jkt")) &&
    pyEquals(own(proofClaims, "htm"), toPy(method)) &&
    targetUri !== null &&
    pyEquals(own(proofClaims, "htu"), targetUri) &&
    pyEquals(own(proofClaims, "ath"), tokenHash(token)) &&
    issued !== null &&
    presented !== null &&
    !(abs(presented - issued * NANOSECONDS) > window * NANOSECONDS);
  if (!bound) {
    problems.push(["/presentation/dpop_proof", "the proof does not bind this request", INTEGRITY_INVALID]);
  }
  // OA1-004: the proof's `jti` is a string of 1 to 256 characters that the resource server has not
  // accepted; a proof without one, with one of another type or with one that no
  // presentation record can hold among the `jti` values seen cannot be checked for
  // replay. Characters are code points, as the record schema counts them.
  const jti = own(proofClaims, "jti");
  if (typeof jti !== "string" || [...jti].length < 1 || [...jti].length > MAX_JTI_CHARACTERS) {
    problems.push(["/presentation/dpop_proof", "the proof carries no jti string of 1 to 256 characters", INTEGRITY_INVALID]);
  } else if (pyIn(jti, toPy(array(presentation, "seen_dpop_jti")) as PyValue[])) {
    problems.push(["/presentation/dpop_proof", "the proof's jti was seen before", REPLAY]);
  }
  return problems;
}

function abs(value: bigint): bigint {
  return value < 0n ? -value : value;
}

/**
 * (path, message, error code) for each reason a resource server must refuse the presentation
 * (OA1-002 to OA1-005), in the order a resource server checks them.
 */
export function presentationChecks(record: JsonObject): CodedProblem[] {
  const token = text(record, "token") ?? "";
  let claims: PyObject;
  try {
    claims = decodeJws(token).claims;
  } catch (error) {
    if (error instanceof JoseError) {
      return [["/token", "the token is not a compact JWS", INTEGRITY_INVALID]];
    }
    throw error;
  }
  const presentation = obj(record, "presentation") ?? {};
  const found = entries(claims);
  const entry: PyObject = found.length === 1 ? (found[0] as PyObject) : {};
  const maxUses = own(entry, "max_uses");
  const problems: CodedProblem[] = [];
  if (!pyEquals(own(claims, "aud"), toPy(at(record, "resource_server")))) {
    problems.push(["/token/aud", "the token is for another audience", AUDIENCE_MISMATCH]);
  }
  const presented = instant(at(presentation, "presented_at"));
  if (!withinValidity(record, claims, found, presented)) {
    problems.push(["/presentation/presented_at", "outside the token's validity", EXPIRED]);
  }
  if (found.length === 1 && (own(entry, "use_policy") !== "single_use" ||
      (maxUses !== undefined && pyInt(maxUses) !== 1n))) {
    return [...problems, ["/token/authorization_details", "only single_use with max_uses absent or 1 is supported", BINDING_UNSUPPORTED]];
  }
  problems.push(...possession(record, claims, token, presentation, presented));
  const actions = own(entry, "actions");
  if (
    !pyEquals(toPy(at(presentation, "target")), own(entry, "identifier")) ||
    !pyIn(toPy(at(presentation, "operation")), Array.isArray(actions) ? actions : []) ||
    !sameDigestPy(toPy(at(presentation, "parameters_digest")), own(entry, "parameters_digest"))
  ) {
    problems.push(["/presentation", "another target, operation or parameter digest", SCOPE_MISMATCH]);
  }
  const used = integer(presentation, "use_count");
  if (used !== 1) {
    problems.push(["/presentation/use_count", "beyond the entry's use policy", REPLAY]);
  }
  return problems;
}

/**
 * Each reason a resource server must refuse the presentation (OA1-002 to OA1-005), in the order
 * a resource server checks them, without the error codes.
 */
export function presentationProblems(record: JsonObject): Problem[] {
  return presentationChecks(record).map(([path, message]): Problem => [path, message]);
}

/**
 * OA1-003: the time of presentation lies within the token's validity, widened by the declared
 * clock-skew allowance, and, when the token carries one ECL entry, within that entry's window, to
 * which no allowance applies.
 */
function withinValidity(record: JsonObject, claims: PyObject, found: readonly PyValue[], presented: bigint | null): boolean {
  const skew = BigInt(integer(record, "clock_skew_seconds") || DEFAULT_CLOCK_SKEW);
  const begins = pyInt(own(claims, "nbf") !== undefined ? own(claims, "nbf") : own(claims, "iat"));
  const expires = pyInt(own(claims, "exp"));
  if (presented === null || begins === null || expires === null || begins >= expires) {
    return false;
  }
  if (!((begins - skew) * NANOSECONDS <= presented && presented < (expires + skew) * NANOSECONDS)) {
    return false;
  }
  if (found.length !== 1) {
    return true;
  }
  const start = instant(member(found[0], "valid_from"));
  const end = instant(member(found[0], "valid_until"));
  return start !== null && end !== null && start <= presented && presented < end;
}

/**
 * (path, message, code) of each check of the presentation table that the presentation fails, in
 * the table's order (OA1-011): the token's JWS checks (OA1-007), then the resource server's checks
 * of audience, validity, proof of possession, scope and uses.
 */
export function refusalProblems(record: JsonObject): CodedProblem[] {
  const signature = recordSignatureProblems(record);
  if (signature.length > 0) {
    return signature.map(([path, message]): CodedProblem => [path, message, INTEGRITY_INVALID]);
  }
  return presentationChecks(record);
}

/**
 * A refusal names the code of the first check of the presentation table that fails; a refusal of
 * a presentation that fails no check may name any registered error.
 */
function refusal(record: JsonObject): Problem[] {
  const first = refusalProblems(record)[0];
  if (first === undefined) {
    if (!ERROR_CODES.some((entry) => entry.id === member(record, "result", "error"))) {
      return [["/result/error", "a refusal must name a registered error code"]];
    }
    return [];
  }
  const expected = first[2];
  if (!pyEquals(toPy(member(record, "result", "error")), expected)) {
    return [["/result/error", `the first check that fails gives ${expected}`]];
  }
  return [];
}

/** `same_digest` over values that may come from a token: both digest objects of equal text. */
function sameDigestPy(left: PyValue | undefined, right: PyValue | undefined): boolean {
  if (!isPyObject(left) || !isPyObject(right)) {
    return false;
  }
  const algorithm = own(left, "algorithm");
  const value = own(left, "value");
  return typeof algorithm === "string" && typeof value === "string" && algorithm === own(right, "algorithm") && value === own(right, "value");
}

function recordSignatureProblems(record: JsonObject): Problem[] {
  // OA1-007: no key map may silently select one of several entries with the same kid.
  const seen = new Set<string>();
  const problems: Problem[] = [];
  array(record, "issuer_keys", "keys").forEach((entry, index) => {
    const keyId = text(entry, "kid");
    if (keyId === null) return; // Entry shape and member types are checked by the schema.
    if (seen.has(keyId)) {
      problems.push([`/issuer_keys/keys/${index}/kid`, "issuer key identifiers must be distinct"]);
    }
    seen.add(keyId);
  });
  if (problems.length > 0) return problems;
  return signatureProblems(text(record, "token") ?? "", issuerKeys(record), at(record, "issuer"));
}

function issuerKeys(record: JsonObject): Map<string, PyObject> {
  const keys = new Map<string, PyObject>();
  for (const item of array(record, "issuer_keys", "keys")) {
    if (isObject(item) && typeof at(item, "kid") === "string") {
      keys.set(at(item, "kid") as string, toPy(item) as PyObject);
    }
  }
  return keys;
}

/**
 * The rules of the profile in the order the reference reports them: the issuer's side always, the
 * resource server's checks when the presentation was accepted, and the refusal's code when it was
 * refused. A rule added to the registry for this profile is one function above and one row in the
 * table it belongs to.
 */
export const ISSUER_RULES: ReadonlyArray<readonly [string, (record: JsonObject, request: JsonObject, response: JsonObject, token: string) => Problem[]]> = [
  [ISSUE_RULE, (record, request, response, token) => issueProblems(request, response, token, integer(record, "max_token_lifetime_seconds") || DEFAULT_MAX_LIFETIME)],
];
export const ACCEPTANCE_RULES: ReadonlyArray<readonly [string, (record: JsonObject, token: string) => Problem[]]> = [
  [SIGNATURE_RULE, (record) => recordSignatureProblems(record)],
  [PRESENTATION_RULE, (record) => presentationProblems(record)],
];
export const REFUSAL_RULES: ReadonlyArray<readonly [string, (record: JsonObject) => Problem[]]> = [[REFUSAL_RULE, (record) => refusal(record)]];

/** The findings of an `ecl_oauth_presentation_v1` record that its schema has accepted. */
export function check(record: JsonObject): Finding[] {
  const request = obj(record, "request");
  const response = obj(record, "response");
  const token = text(record, "token");
  if (request === null || response === null || token === null) {
    return [];
  }
  const result = ISSUER_RULES.flatMap(([rule, problems]) => findings(rule, problems(record, request, response, token)));
  result.push(...findings(ONE_WAY_RULE, oneWayResponseProblems(record, [["request"], ["response"]])));
  result.push(...messageFindings(record, ["request"], ["response"]));
  const accepted = member(record, "result", "accepted");
  if (accepted === false) {
    return [...result, ...REFUSAL_RULES.flatMap(([rule, problems]) => findings(rule, problems(record)))];
  }
  if (accepted !== true) {
    return result;
  }
  if (holds(obj(record, "result") ?? {}, "error")) result.push(...findings(REFUSAL_RULE, [["/result/error", "an accepted presentation must not carry an error"]]));
  return [...result, ...ACCEPTANCE_RULES.flatMap(([rule, problems]) => findings(rule, problems(record, token)))];
}
