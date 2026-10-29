/**
 * ECL-IE-1 integrity envelopes (INTEGRITY-ENVELOPE-1).
 *
 * The payload travels as canonical base64 with its SHA-256 digest (IE1-005, IE1-006). The
 * signing input is the DSSE v1 pre-authentication encoding of the payload type and the exact
 * payload bytes (IE1-009 to IE1-011); the bytes are verified as transported and only then proved
 * canonical. The signed payload carries its own integrity policy (IE1-012 to IE1-015), which an
 * envelope cannot weaken, and the verifier's context must match the trust policy it names.
 * Verification follows the seven steps of IE1-040, and each refusal carries the code of its step.
 */

import { concat, fromCanonicalBase64, sha256Hex, utf8 } from "../crypto/bytes.js";
import { SignatureEncodingError, verifySignature } from "../crypto/signatures.js";
import { CanonicalizationError, canonicalize } from "../json/canonical.js";
import { equalBytes } from "../crypto/bytes.js";
import { MAX_JSON_NODES, NODE_BUDGET_MESSAGE, parseStrictJson, StrictJsonError } from "../json/strict.js";
import { get, isArray, isInteger, isObject, pythonEquals, pythonStr, schemaEquals, truthy } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { InstantError, instantMicroseconds } from "../time.js";

export const INTEGRITY_INVALID = "ecl.error.integrity-invalid.v1";
export const SIGNATURE_POLICY_INVALID = "ecl.error.signature-policy-invalid.v1";
export const REVOKED = "ecl.error.revoked.v1";
export const EXPIRED = "ecl.error.expired.v1";
export const THRESHOLD_NOT_MET = "ecl.error.threshold-not-met.v1";
export const RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1";
export const MAX_INTEGRITY_PAYLOAD_BYTES = 64 * 1024 * 1024;
export const MAX_SIGNATURE_BYTES = 16 * 1024;
export const MAX_SIGNATURE_COUNT = 32;
export const MAX_POLICY_LIST_ENTRIES = 64;
/** The declared limits apply to the envelope as received (IE1-040, step 2): the base64 text. */
const MAX_ENCODED_PAYLOAD_CHARACTERS = Math.floor((MAX_INTEGRITY_PAYLOAD_BYTES + 2) / 3) * 4;
const MAX_ENCODED_SIGNATURE_CHARACTERS = Math.floor((MAX_SIGNATURE_BYTES + 2) / 3) * 4;

/** IE1-040, step 6: why a signature does not count, in the order of the checks that find it. */
type Reason = "unacceptable" | "revoked" | "expired" | "unverified";

/** IE1-040, step 7: the earliest reason that some signature has decides the code. */
const REASON_CODES: readonly (readonly [Reason, string])[] = [
  ["unacceptable", SIGNATURE_POLICY_INVALID],
  ["revoked", REVOKED],
  ["expired", EXPIRED],
  ["unverified", SIGNATURE_POLICY_INVALID],
];
export const TRUSTED_TIME_CLAIM = "ecl.claim.trusted-time.v1";
export const TIME_ATTESTATION_TYPE = "application/vnd.ecl.time-attestation+json";

export const PROTOCOL_MEDIA_TYPES: Readonly<Record<string, string>> = {
  "DCMP-2": "application/vnd.ecl.dcmp+json",
  "EBMP-2": "application/vnd.ecl.ebmp+json",
};

/** A malformed or unverifiable envelope. `code` is the registered error. */
export class IntegrityError extends Error {
  readonly code: string;

  constructor(message: string, code: string = INTEGRITY_INVALID) {
    super(message);
    this.name = "IntegrityError";
    this.code = code;
  }
}

/**
 * A payload refused at the value budget that its caller passed as `maxNodes`: a resource limit,
 * which a bundle verifier that passes the nodes remaining of its budget reads as the bundle's
 * payload node limit (EBMP2-062).
 */
export class PayloadNodeBudgetError extends IntegrityError {
  constructor(message: string) {
    super(message, RESOURCE_LIMIT);
    this.name = "PayloadNodeBudgetError";
  }
}

function policyError(message: string, code: string = SIGNATURE_POLICY_INVALID): IntegrityError {
  return new IntegrityError(message, code);
}

function limitError(message: string): IntegrityError {
  return new IntegrityError(message, RESOURCE_LIMIT);
}

/** A verification key: one trusted key, as a keyring holds it. */
export interface VerificationKey {
  readonly keyId: string;
  readonly suiteId: string;
  /** Raw public key bytes: 32 for Ed25519, the 65-byte SEC 1 point for P-256. */
  readonly publicKey: Uint8Array;
  readonly trustPolicyIds: readonly string[];
  /** The payload types the key may sign; empty means any. */
  readonly purposes: readonly string[];
  readonly validFrom: string | undefined;
  readonly validUntil: string | undefined;
  /**
   * The key's TRUST-POLICY-1 purposes, when it comes from a trust policy: a DCMP-2 message then
   * counts only under a key that holds the purpose IE1-039 gives its message type (TP1-010).
   * Absent or empty, the key is checked by payload type alone, as one built by hand is.
   */
  readonly rolePurposes?: readonly string[];
}

/**
 * TP1-010 and IE1-039: the purpose a key holds to sign each DCMP-2 message type. A decision point
 * answers a request with a response or a challenge, a requester answers a challenge, and the
 * control plane issues control messages.
 */
const ROLE_PURPOSES: Readonly<Record<string, string>> = {
  decision_request: "ecl.purpose.decision-request.v1",
  challenge_response: "ecl.purpose.decision-request.v1",
  decision_response: "ecl.purpose.decision-response.v1",
  challenge: "ecl.purpose.decision-response.v1",
  control: "ecl.purpose.control.v1",
};

/** The purpose that the signer of a DCMP-2 message must hold (IE1-039), or undefined. */
export function rolePurpose(payload: JsonValue): string | undefined {
  if (!isObject(payload) || get(payload, "protocol") !== "DCMP-2") {
    return undefined;
  }
  const messageType = get(payload, "message_type");
  return typeof messageType === "string" && Object.prototype.hasOwnProperty.call(ROLE_PURPOSES, messageType) ? ROLE_PURPOSES[messageType] : undefined;
}

/** A revocation of one key from an effective time on. */
export interface KeyRevocation {
  readonly keyId: string;
  readonly effectiveAt: string;
  readonly reason: string;
}

/** The trust policy and time under which an envelope is verified. */
export interface VerificationContext {
  readonly trustPolicyId: string;
  readonly trustPolicyVersion: string;
  readonly trustPolicyDigest: string;
  readonly trustPolicyEpoch: number;
  readonly evaluatedAt: string;
  readonly verificationTimePolicy: string;
  readonly revocationPolicy: string;
  readonly allowedSuites: readonly string[];
  readonly prohibitedSuites: readonly string[];
  readonly revocations: readonly KeyRevocation[];
}

/** A verified envelope. */
export interface VerificationResult {
  readonly payload: JsonValue;
  readonly validKeyIds: readonly string[];
  readonly evaluatedAt: string;
  readonly trustPolicyId: string;
  readonly trustPolicyVersion: string;
  readonly trustPolicyEpoch: number;
  readonly verificationTimePolicy: string;
  readonly revocationPolicy: string;
}

function isAscii(text: string): boolean {
  return /^[\x00-\x7f]*$/.test(text);
}

/** The DSSE v1 pre-authentication encoding: "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload. */
export function signingInput(payloadType: string, payload: Uint8Array): Uint8Array {
  if (typeof payloadType !== "string" || !(payload instanceof Uint8Array)) {
    throw new IntegrityError("signing input requires a string type and byte payload");
  }
  if (!isAscii(payloadType)) {
    throw new IntegrityError("payload_type must be ASCII");
  }
  const type = utf8(payloadType);
  return concat(utf8(`DSSEv1 ${type.length} `), type, utf8(` ${payload.length} `), payload);
}

/** The payload bytes, after checking canonical base64 and the declared digest. */
export function decodePayload(envelope: JsonValue): Uint8Array {
  if (!isObject(envelope)) {
    throw new IntegrityError("integrity envelope must be an object");
  }
  const encoded = get(envelope, "payload");
  if (typeof encoded !== "string" || !isAscii(encoded)) {
    throw new IntegrityError("payload is not valid canonical base64");
  }
  if (encoded.length > MAX_ENCODED_PAYLOAD_CHARACTERS) {
    throw limitError("payload exceeds the integrity byte budget");
  }
  const payload = fromCanonicalBase64(encoded);
  if (payload === undefined) {
    throw new IntegrityError("payload is not canonical base64");
  }
  const digest = sha256Hex(payload);
  const rawDeclared = get(envelope, "payload_digest");
  const declared = truthy(rawDeclared) ? rawDeclared : {};
  if (!isObject(declared)) {
    throw new IntegrityError("payload digest must be an object");
  }
  if (!pythonEquals(get(declared, "algorithm"), "ecl.digest.sha-256.v1")) {
    throw new IntegrityError("unsupported or missing payload digest suite");
  }
  if (!pythonEquals(get(declared, "value"), digest)) {
    throw new IntegrityError("payload digest mismatch");
  }
  return payload;
}

/** The payload as a JSON value, after proving that its bytes are canonical ECL JSON. */
/**
 * The payload of `envelope` as strict, canonical ECL JSON (IE1-040, step 3), parsed with the value
 * budget `maxNodes` (IE1-037, check 3), so that no value is built beyond it (IE1-029). A refusal at
 * that budget is a `PayloadNodeBudgetError`.
 */
export function decodeCanonicalJsonPayload(envelope: JsonValue, maxNodes: number = MAX_JSON_NODES): JsonValue {
  const payload = decodePayload(envelope);
  let value: JsonValue;
  try {
    value = parseStrictJson(payload, { maxNodes });
    if (!equalBytes(canonicalize(value), payload)) {
      throw new IntegrityError("payload is not canonical ECL JSON");
    }
  } catch (error) {
    // A declared limit of the strict parser is a resource limit (IE1-040, step 3); any other
    // refusal leaves the payload outside canonical strict JSON.
    if (error instanceof StrictJsonError) {
      if (error.ruleId === RESOURCE_LIMIT && error.message === NODE_BUDGET_MESSAGE) {
        throw new PayloadNodeBudgetError(error.message);
      }
      throw new IntegrityError(error.message, error.ruleId === RESOURCE_LIMIT ? RESOURCE_LIMIT : INTEGRITY_INVALID);
    }
    if (error instanceof CanonicalizationError) {
      throw new IntegrityError(error.message);
    }
    throw error;
  }
  return value;
}

function decodeSignature(value: JsonValue | undefined): Uint8Array {
  if (typeof value !== "string" || !isAscii(value)) {
    throw new IntegrityError("signature is not valid canonical base64");
  }
  if (value.length > MAX_ENCODED_SIGNATURE_CHARACTERS) {
    throw limitError("signature exceeds the integrity byte budget");
  }
  const decoded = fromCanonicalBase64(value);
  if (decoded === undefined) {
    throw new IntegrityError("signature is not canonical base64");
  }
  return decoded;
}

function micros(value: string): bigint {
  try {
    return instantMicroseconds(value);
  } catch (error) {
    if (error instanceof InstantError) {
      throw new IntegrityError(`invalid UTC timestamp: ${JSON.stringify(value)}`);
    }
    throw error;
  }
}

function validateContext(policy: JsonObject, context: VerificationContext): bigint {
  const trust = get(policy, "trust_policy");
  if (!isObject(trust)) {
    throw policyError("signed payload lacks a trust policy reference");
  }
  // A digest that is not an object, absent or of any other type, names no digest suite (IE1-040,
  // step 4), as the reference refuses it.
  const declared = get(trust, "digest");
  if (!isObject(declared)) {
    throw policyError("trust policy digest suite is unsupported");
  }
  const observed: JsonValue[] = [get(trust, "id") ?? null, get(trust, "version") ?? null, get(declared, "value") ?? null, get(trust, "epoch") ?? null];
  const expected: JsonValue[] = [context.trustPolicyId, context.trustPolicyVersion, context.trustPolicyDigest, context.trustPolicyEpoch];
  if (!pythonEquals(get(declared, "algorithm"), "ecl.digest.sha-256.v1")) {
    throw policyError("trust policy digest suite is unsupported");
  }
  // Each member as the same JSON value, as the reference's `same_json` compares it, so an epoch of
  // `true` is not epoch 1. The members are strings and an integer, which
  // `schemaEquals` compares exactly.
  if (!schemaEquals(observed, expected)) {
    throw policyError("verification context does not match signed trust policy");
  }
  if (!pythonEquals(get(policy, "verification_time_policy"), context.verificationTimePolicy)) {
    throw policyError("verification context does not match signed verification-time policy");
  }
  if (!pythonEquals(get(policy, "revocation_policy"), context.revocationPolicy)) {
    throw policyError("verification context does not match signed revocation policy");
  }
  return micros(context.evaluatedAt);
}

/**
 * Why a key cannot count for this payload at `evaluatedAt` (IE1-040, step 6 (a) to (c)): not
 * acceptable for the trust policy, payload type or role, revoked, or outside its validity
 * interval, in that order; undefined when it can count.
 */
function keyIneligibility(key: VerificationKey, payloadType: string, context: VerificationContext, evaluatedAt: bigint, role: string | undefined): Reason | undefined {
  if (key.trustPolicyIds.length > 0 && !key.trustPolicyIds.includes(context.trustPolicyId)) {
    return "unacceptable";
  }
  if (key.purposes.length > 0 && !key.purposes.includes(payloadType)) {
    return "unacceptable";
  }
  if (role !== undefined && key.rolePurposes !== undefined && key.rolePurposes.length > 0 && !key.rolePurposes.includes(role)) {
    return "unacceptable";
  }
  for (const revocation of context.revocations) {
    if (revocation.keyId === key.keyId && evaluatedAt >= micros(revocation.effectiveAt)) {
      return "revoked";
    }
  }
  if (key.validFrom !== undefined && evaluatedAt < micros(key.validFrom)) {
    return "expired";
  }
  if (key.validUntil !== undefined && evaluatedAt >= micros(key.validUntil)) {
    return "expired";
  }
  return undefined;
}

function policyStringSet(policy: JsonObject, name: string): Set<string> {
  const raw = get(policy, name);
  if (!isArray(raw) || raw.some((entry) => typeof entry !== "string" || entry === "")) {
    throw policyError(`${name} must be an array of identifiers`);
  }
  const set = new Set(raw as string[]);
  if (set.size !== raw.length) {
    throw policyError(`${name} contains duplicate identifiers`);
  }
  return set;
}

/**
 * Verify an envelope's signatures against the integrity policy bound inside its payload, with
 * the keys of `keyring`, under `context`, in the order of IE1-040. Throws IntegrityError, whose
 * `code` is the code of the step that fails: resource-limit-exceeded for a declared limit,
 * integrity-invalid for a malformed envelope, payload or signature encoding, signature-policy-
 * invalid for a policy that cannot hold, and for signatures that do not meet the policy the code
 * of the earliest reason a signature has (signature-policy-invalid, revoked, expired), or
 * threshold-not-met. Step 1, the envelope schema, is the caller's.
 *
 * `keyTimes`, when given, evaluates the key of each signature it names at its own instant instead
 * of the context's `evaluatedAt` (IE1-034: a signature that a trusted-time countersignature covers
 * is evaluated at its attested time, any other at the object's own time); step 7 then counts each
 * signature as evaluated at its own instant.
 */
export function verifyEnvelope(envelope: JsonValue, keyring: ReadonlyMap<string, VerificationKey>, context: VerificationContext, keyTimes?: ReadonlyMap<string, string>): VerificationResult {
  if (!isObject(envelope)) {
    throw new IntegrityError("integrity envelope must be an object");
  }
  // Step 2: the declared limits that the envelope as received shows.
  const encoded = get(envelope, "payload");
  if (typeof encoded === "string" && encoded.length > MAX_ENCODED_PAYLOAD_CHARACTERS) {
    throw limitError("payload exceeds the integrity byte budget");
  }
  const signatures = get(envelope, "signatures");
  if (isArray(signatures)) {
    if (signatures.length > MAX_SIGNATURE_COUNT) {
      throw limitError("integrity signature set exceeds the verifier budget");
    }
    for (const item of signatures) {
      const value = isObject(item) ? get(item, "signature") : undefined;
      if (typeof value === "string" && value.length > MAX_ENCODED_SIGNATURE_CHARACTERS) {
        throw limitError("signature exceeds the integrity byte budget");
      }
    }
  }
  // Step 3: the payload's encoding, digest, canonical form and media type.
  const payloadBytes = decodePayload(envelope);
  const payload = decodeCanonicalJsonPayload(envelope);
  const payloadType = get(envelope, "payload_type");
  if (typeof payloadType !== "string") {
    throw new IntegrityError("integrity envelope lacks a valid payload_type");
  }
  if ([...payloadType].length > 255 || !isAscii(payloadType)) {
    throw new IntegrityError("integrity envelope payload_type is invalid");
  }
  const rawProtocol = isObject(payload) ? get(payload, "protocol") : undefined;
  const protocol = typeof rawProtocol === "string" ? rawProtocol : undefined;
  const expectedType = protocol !== undefined && Object.prototype.hasOwnProperty.call(PROTOCOL_MEDIA_TYPES, protocol) ? PROTOCOL_MEDIA_TYPES[protocol] : undefined;
  if (expectedType !== undefined && payloadType !== expectedType) {
    throw new IntegrityError(`integrity envelope payload_type does not match the signed ${protocol} payload`);
  }
  const claimed = Object.keys(PROTOCOL_MEDIA_TYPES).find((identifier) => PROTOCOL_MEDIA_TYPES[identifier] === payloadType);
  if (claimed !== undefined && protocol !== claimed) {
    throw new IntegrityError(`integrity envelope payload does not match the claimed ${claimed} media type`);
  }
  const policy = isObject(payload) ? get(payload, "integrity_policy") : undefined;
  if (!isObject(policy)) {
    throw new IntegrityError("signed payload lacks integrity_policy");
  }
  // Step 4: the payload-bound policy, its lists' declared limit first.
  for (const name of ["accepted_suites", "eligible_key_ids", "required_key_ids"]) {
    const raw = get(policy, name);
    if (isArray(raw) && raw.length > MAX_POLICY_LIST_ENTRIES) {
      throw limitError(`${name} exceeds the policy resource budget`);
    }
  }
  // The policy requires integrity when `required` is the JSON value true; the number 1 is not.
  if (get(policy, "required") !== true) {
    throw policyError("an integrity envelope cannot elevate a payload that declares integrity optional");
  }
  const threshold = get(policy, "threshold");
  if (!isInteger(threshold) || threshold < 1) {
    throw policyError("integrity threshold must be at least one");
  }
  const acceptedSuites = policyStringSet(policy, "accepted_suites");
  const eligibleKeys = policyStringSet(policy, "eligible_key_ids");
  const requiredKeys = policyStringSet(policy, "required_key_ids");
  if (acceptedSuites.size === 0) {
    throw policyError("accepted_suites cannot be empty");
  }
  if (requiredKeys.size > 0 && threshold < requiredKeys.size) {
    throw policyError("threshold cannot be lower than required key count");
  }
  const evaluatedAt = validateContext(policy, context);
  const role = rolePurpose(payload);
  const allowed = new Set(context.allowedSuites);
  const prohibited = new Set(context.prohibitedSuites);
  // Step 5: every signature entry names a key and a suite, each pair once.
  if (!isArray(signatures) || signatures.length === 0) {
    throw new IntegrityError("integrity signature set is missing");
  }
  const entries: (readonly [string, string, JsonObject])[] = [];
  const observed = new Set<string>();
  for (const entry of signatures) {
    if (!isObject(entry)) {
      throw new IntegrityError("integrity signature entry must be an object");
    }
    const rawKeyId = get(entry, "key_id");
    const rawSuiteId = get(entry, "suite_id");
    const keyId = truthy(rawKeyId) ? pythonStr(rawKeyId) : "";
    const suiteId = truthy(rawSuiteId) ? pythonStr(rawSuiteId) : "";
    if (keyId === "" || suiteId === "") {
      throw new IntegrityError("integrity signature identity is incomplete");
    }
    const identity = JSON.stringify([keyId, suiteId]);
    if (observed.has(identity)) {
      throw new IntegrityError("duplicate signature identity");
    }
    observed.add(identity);
    entries.push([keyId, suiteId, entry]);
  }
  // Step 6: each signature in turn.
  const message = signingInput(payloadType, payloadBytes);
  const valid = new Set<string>();
  const reasons = new Set<Reason>();
  for (const [keyId, suiteId, entry] of entries) {
    // (a) an acceptable key for this suite, payload and policy.
    const key = keyring.get(keyId);
    if (
      !acceptedSuites.has(suiteId) ||
      !allowed.has(suiteId) ||
      prohibited.has(suiteId) ||
      (eligibleKeys.size > 0 && !eligibleKeys.has(keyId)) ||
      key === undefined ||
      key.suiteId !== suiteId ||
      key.keyId !== keyId
    ) {
      reasons.add("unacceptable");
      continue;
    }
    // (a) to (c): the key's trust policy, payload type, role, revocation and validity.
    const own = keyTimes?.get(keyId);
    const reason = keyIneligibility(key, payloadType, context, own === undefined ? evaluatedAt : micros(own), role);
    if (reason !== undefined) {
      reasons.add(reason);
      continue;
    }
    // (d) and (e): the signature's encoding, then the signature itself.
    if (!Object.prototype.hasOwnProperty.call(entry, "signature")) {
      throw new IntegrityError("integrity signature bytes are missing");
    }
    const signature = decodeSignature(entry["signature"]);
    let verified: boolean;
    try {
      verified = verifySignature(suiteId, key.publicKey, message, signature);
    } catch (error) {
      if (error instanceof SignatureEncodingError) {
        throw new IntegrityError(error.message);
      }
      throw error;
    }
    if (!verified) {
      reasons.add("unverified");
      continue;
    }
    valid.add(keyId);
  }
  // Step 7: every required key and at least the threshold of keys counted.
  const missing = [...requiredKeys].filter((keyId) => !valid.has(keyId)).sort();
  if (missing.length > 0 || valid.size < threshold) {
    const code = REASON_CODES.find(([reason]) => reasons.has(reason))?.[1] ?? THRESHOLD_NOT_MET;
    if (missing.length > 0) {
      throw policyError(`required signatures are missing or invalid: ${JSON.stringify(missing)}`, code);
    }
    throw policyError(`signature threshold not met: valid=${valid.size} required=${threshold}`, code);
  }
  return {
    payload,
    validKeyIds: [...valid].sort(),
    evaluatedAt: context.evaluatedAt,
    trustPolicyId: context.trustPolicyId,
    trustPolicyVersion: context.trustPolicyVersion,
    trustPolicyEpoch: context.trustPolicyEpoch,
    verificationTimePolicy: context.verificationTimePolicy,
    revocationPolicy: context.revocationPolicy,
  };
}
