/**
 * Trust policies (TRUST-POLICY-1): which keys a verifier trusts, for which purposes, on whose
 * behalf, and when. The caller of a verifier supplies the policy; an evidence bundle never does
 * (IE1-022, TP1-001).
 *
 * `TrustPolicy.load` refuses anything else with a TrustPolicyError whose `code` says which layer
 * failed: `ecl.error.schema-invalid.v1` for bytes that are not UTF-8 strict JSON of the schema's
 * shape (TP1-002), `ecl.error.resource-limit-exceeded.v1` for more than 256 KiB or a document past
 * the strict parser's nesting or value limits (TP1-007, IE1-037), and
 * `ecl.error.semantic-invalid.v1` for a document that cannot hold (TP1-003): a key id or public key twice, a suite this version does not carry, a public key
 * that does not decode for its suite (for Ed25519: not canonical, or of small order), a validity
 * end not after its start, an unregistered purpose or revocation policy, a key that carries the
 * purposes of more than one role (TP1-009), or a revocation of an unknown key or of a key twice.
 */

import { fromCanonicalBase64, equalBytes } from "../crypto/bytes.js";
import { publicKeyProblem } from "../crypto/signatures.js";
import { objectDigest } from "../json/canonical.js";
import { parseStrictJson, StrictJsonError } from "../json/strict.js";
import { get } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { activeIds } from "../registry/registries.js";
import { eclSchemas } from "../schema/validator.js";
import { instantMicroseconds } from "../time.js";
import type { KeyRevocation, VerificationContext, VerificationKey } from "../integrity/envelope.js";
import { PROTOCOL_MEDIA_TYPES, TIME_ATTESTATION_TYPE } from "../integrity/envelope.js";

export const SCHEMA_INVALID = "ecl.error.schema-invalid.v1";
export const SEMANTIC_INVALID = "ecl.error.semantic-invalid.v1";
export const RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1";
export const TRUST_POLICY_SCHEMA = "https://externalcontrollayer.ai/ns/schema/trust-policy/1";
export const MAX_TRUST_POLICY_BYTES = 256 * 1024;

export const PURPOSE_DECISION_REQUEST = "ecl.purpose.decision-request.v1";
export const PURPOSE_DECISION_RESPONSE = "ecl.purpose.decision-response.v1";
export const PURPOSE_EVIDENCE_EVENT = "ecl.purpose.evidence-event.v1";
export const PURPOSE_OBSERVATION = "ecl.purpose.observation.v1";
export const PURPOSE_TRUSTED_TIME = "ecl.purpose.trusted-time.v1";
export const PURPOSE_CONTROL = "ecl.purpose.control.v1";
/**
 * EBMP2-070: the approval purpose qualifies a key that holds the evidence-event purpose
 * as an approval service's, so that a verifier admits a human intervention event as the proof of an
 * approval obligation only when every key that signed it holds this purpose (MG1-013). A qualifying
 * purpose lets a key sign no payload by itself.
 */
export const PURPOSE_APPROVAL = "ecl.purpose.approval.v1";
export const QUALIFYING_PURPOSES: readonly string[] = [PURPOSE_APPROVAL];

/**
 * The payload types each purpose may sign (the keyring keeps DCMP-2 and EBMP-2 keys apart): a
 * request, a response and a control message are DCMP-2 objects (IE1-039).
 */
export const PURPOSE_PAYLOAD_TYPES: Readonly<Record<string, string>> = {
  [PURPOSE_DECISION_REQUEST]: PROTOCOL_MEDIA_TYPES["DCMP-2"] as string,
  [PURPOSE_DECISION_RESPONSE]: PROTOCOL_MEDIA_TYPES["DCMP-2"] as string,
  [PURPOSE_CONTROL]: PROTOCOL_MEDIA_TYPES["DCMP-2"] as string,
  [PURPOSE_EVIDENCE_EVENT]: PROTOCOL_MEDIA_TYPES["EBMP-2"] as string,
  [PURPOSE_OBSERVATION]: PROTOCOL_MEDIA_TYPES["EBMP-2"] as string,
  [PURPOSE_TRUSTED_TIME]: TIME_ATTESTATION_TYPE,
};

/**
 * TP1-009: the purposes that each belong to one component role: the requester of a decision, the
 * decision point, the control plane, an observer and a time authority (ECL1N-0157). A key carries
 * at most one of them. The evidence-event purpose is no role of its own: a requester, a decision
 * point or another component records its evidence with it, so it may accompany one of these.
 */
export const ROLE_PURPOSES: readonly string[] = [PURPOSE_DECISION_REQUEST, PURPOSE_DECISION_RESPONSE, PURPOSE_CONTROL, PURPOSE_OBSERVATION, PURPOSE_TRUSTED_TIME];

/**
 * The role purposes among `purposes` when there is more than one of them (TP1-009), in the order of
 * ROLE_PURPOSES; empty when the purposes belong to one role at most.
 */
export function roleConflict(purposes: readonly string[]): string[] {
  const roles = ROLE_PURPOSES.filter((purpose) => purposes.includes(purpose));
  return roles.length > 1 ? roles : [];
}

const MAX_TEXT = 200;

function cut(text: string): string {
  return text.length <= MAX_TEXT ? text : text.slice(0, MAX_TEXT - 1) + "…";
}

/** A trust policy that cannot be used. `code` is the registered error. */
export class TrustPolicyError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(cut(message));
    this.name = "TrustPolicyError";
    this.code = code;
  }
}

function schemaError(message: string): TrustPolicyError {
  return new TrustPolicyError(message, SCHEMA_INVALID);
}

function semanticError(message: string): TrustPolicyError {
  return new TrustPolicyError(message, SEMANTIC_INVALID);
}

/** One key of a trust policy. */
export interface TrustedKey {
  readonly keyId: string;
  readonly suiteId: string;
  /** Raw public key: 32 bytes, or the 65-byte SEC 1 point. */
  readonly publicKey: Uint8Array;
  readonly principal: string;
  readonly purposes: readonly string[];
  readonly validFrom: string;
  readonly validUntil: string | undefined;
}

/** The reference an object embeds as `integrity_policy.trust_policy`. */
export interface TrustPolicyReference {
  readonly id: string;
  readonly version: string;
  readonly digest: { readonly algorithm: string; readonly value: string };
  readonly epoch: number;
}

function parse(data: Uint8Array | string): JsonValue {
  const size = typeof data === "string" ? new TextEncoder().encode(data).length : data.length;
  if (size > MAX_TRUST_POLICY_BYTES) {
    throw new TrustPolicyError(`a trust policy is at most ${MAX_TRUST_POLICY_BYTES} bytes`, RESOURCE_LIMIT);
  }
  try {
    return parseStrictJson(data, { maxBytes: MAX_TRUST_POLICY_BYTES });
  } catch (error) {
    // A declared limit is TP1-007's error; any other strict refusal is TP1-002's.
    if (error instanceof StrictJsonError && error.ruleId === RESOURCE_LIMIT) {
      throw new TrustPolicyError(error.message, RESOURCE_LIMIT);
    }
    if (error instanceof StrictJsonError) {
      throw schemaError(error.kind === "encoding" ? "a trust policy is UTF-8 JSON, without a byte order mark" : error.message);
    }
    throw error;
  }
}

/** A loaded trust policy. Make one with `TrustPolicy.load`; it cannot be changed. */
export class TrustPolicy {
  readonly policyId: string;
  readonly version: string;
  readonly epoch: number;
  readonly revocationPolicy: string;
  readonly keys: readonly TrustedKey[];
  readonly revocations: readonly KeyRevocation[];
  /** The SHA-256 of the policy's canonical JSON: whitespace and member order aside, it covers every member. */
  readonly digest: string;
  /** The document as loaded. */
  readonly document: JsonObject;

  private constructor(document: JsonObject, keys: TrustedKey[], revocations: KeyRevocation[]) {
    this.document = document;
    this.policyId = document["policy_id"] as string;
    this.version = document["version"] as string;
    this.epoch = document["epoch"] as number;
    this.revocationPolicy = document["revocation_policy"] as string;
    this.keys = Object.freeze(keys);
    this.revocations = Object.freeze(revocations);
    this.digest = objectDigest(document);
    Object.freeze(this);
  }

  /**
   * The policy in `data` (UTF-8 bytes, or text): strict JSON, then the schema, then the semantic
   * checks. Throws TrustPolicyError and never returns a partly checked policy.
   */
  static load(data: Uint8Array | string): TrustPolicy {
    const document = parse(data);
    const errors = eclSchemas().errors(TRUST_POLICY_SCHEMA, document, 1);
    const first = errors[0];
    if (first !== undefined) {
      throw schemaError(`the trust policy does not satisfy ${TRUST_POLICY_SCHEMA}: ${first.path}: ${first.keyword}: ${first.message}`);
    }
    const policy = document as JsonObject;
    const revocationPolicy = policy["revocation_policy"] as string;
    if (!activeIds("vocabulary", "category", "revocation_policy").has(revocationPolicy)) {
      throw semanticError(`${revocationPolicy} is not an active revocation policy of the vocabulary registry`);
    }
    const keys = loadKeys(policy["keys"] as JsonObject[]);
    const revocations = loadRevocations(policy["revocations"] as JsonObject[], new Set(keys.map((key) => key.keyId)));
    return new TrustPolicy(policy, keys, revocations);
  }

  /** The policy as an object embeds it: `{"id", "version", "digest", "epoch"}`. */
  reference(): TrustPolicyReference {
    return {
      id: this.policyId,
      version: this.version,
      digest: { algorithm: "ecl.digest.sha-256.v1", value: this.digest },
      epoch: this.epoch,
    };
  }

  /** The key with this id, or undefined. */
  key(keyId: string): TrustedKey | undefined {
    return this.keys.find((key) => key.keyId === keyId);
  }

  /**
   * The keyring that `verifyEnvelope` reads: one verification key per key, whose purposes become
   * the payload types it may sign and, as `rolePurposes`, the roles it holds. So `verifyEnvelope`
   * keeps DCMP-2 and EBMP-2 keys apart and, within the DCMP-2 media type, counts a decision request
   * only under a key that holds the decision-request purpose and a decision response only under one
   * that holds the decision-response purpose (TP1-010). Separating an evidence event from an
   * observation, both EBMP-2, is the bundle verifier's, which knows where each object sits.
   */
  keyring(): Map<string, VerificationKey> {
    const ring = new Map<string, VerificationKey>();
    for (const key of this.keys) {
      // A qualifying purpose (the approval purpose) lets the key sign no payload by itself.
      const types = new Set(key.purposes.filter((purpose) => !QUALIFYING_PURPOSES.includes(purpose)).map((purpose) => PURPOSE_PAYLOAD_TYPES[purpose] as string));
      ring.set(key.keyId, {
        keyId: key.keyId,
        suiteId: key.suiteId,
        publicKey: key.publicKey,
        trustPolicyIds: [this.policyId],
        purposes: [...types].sort(),
        validFrom: key.validFrom,
        validUntil: key.validUntil,
        rolePurposes: [...key.purposes].sort(),
      });
    }
    return ring;
  }

  /** The context for `verifyEnvelope` at `evaluatedAt`, under the object's own time policy. */
  verificationContext(evaluatedAt: string, timePolicy: string): VerificationContext {
    if (!activeIds("vocabulary", "category", "verification_time_policy").has(timePolicy)) {
      throw semanticError(`${JSON.stringify(timePolicy)} is not a verification-time policy of the vocabulary registry`);
    }
    return {
      trustPolicyId: this.policyId,
      trustPolicyVersion: this.version,
      trustPolicyDigest: this.digest,
      trustPolicyEpoch: this.epoch,
      evaluatedAt,
      verificationTimePolicy: timePolicy,
      revocationPolicy: this.revocationPolicy,
      allowedSuites: [...new Set(this.keys.map((key) => key.suiteId))].sort(),
      prohibitedSuites: [],
      revocations: this.revocations,
    };
  }
}

function loadKeys(items: JsonObject[]): TrustedKey[] {
  const suites = activeIds("algorithm-suites", "kind", "signature");
  const purposes = activeIds("vocabulary", "category", "key_purpose");
  const ids = new Set<string>();
  const holders: Array<[Uint8Array, string]> = [];
  const keys: TrustedKey[] = [];
  for (const item of items) {
    const key = loadKey(item, suites, purposes);
    if (ids.has(key.keyId)) {
      throw semanticError(`key_id ${key.keyId} appears twice in the trust policy`);
    }
    ids.add(key.keyId);
    const holder = holders.find(([bytes]) => equalBytes(bytes, key.publicKey));
    if (holder !== undefined) {
      throw semanticError(`keys ${holder[1]} and ${key.keyId} have the same public key`);
    }
    holders.push([key.publicKey, key.keyId]);
    keys.push(key);
  }
  return keys;
}

function loadKey(item: JsonObject, suites: ReadonlySet<string>, purposes: ReadonlySet<string>): TrustedKey {
  const keyId = item["key_id"] as string;
  const suiteId = item["suite_id"] as string;
  if (!suites.has(suiteId)) {
    throw semanticError(`key ${keyId}: ${suiteId} is not an active signature suite of the algorithm-suites registry`);
  }
  const raw = fromCanonicalBase64(item["public_key"] as string);
  if (raw === undefined) {
    throw semanticError(`key ${keyId}: public_key is not canonical standard base64`);
  }
  const problem = publicKeyProblem(suiteId, raw);
  if (problem !== undefined) {
    throw semanticError(`key ${keyId}: ${problem}`);
  }
  const listed = item["purposes"] as string[];
  for (const purpose of listed) {
    if (!purposes.has(purpose)) {
      throw semanticError(`key ${keyId}: ${purpose} is not an active key purpose of the vocabulary registry`);
    }
    if (!Object.prototype.hasOwnProperty.call(PURPOSE_PAYLOAD_TYPES, purpose) && !QUALIFYING_PURPOSES.includes(purpose)) {
      throw semanticError(`key ${keyId}: ${purpose} has no payload type in this library`);
    }
  }
  if (!listed.some((purpose) => Object.prototype.hasOwnProperty.call(PURPOSE_PAYLOAD_TYPES, purpose))) {
    throw semanticError(`key ${keyId}: carries no purpose that signs a payload type, only a qualifying one`);
  }
  const roles = roleConflict(listed);
  if (roles.length > 0) {
    throw semanticError(`key ${keyId}: one key carries the purposes of more than one role: ${roles.join(", ")} (TP1-009)`);
  }
  const validFrom = item["valid_from"] as string;
  const validUntil = get(item, "valid_until") as string | undefined;
  if (validUntil !== undefined && instantMicroseconds(validUntil) <= instantMicroseconds(validFrom)) {
    throw semanticError(`key ${keyId}: valid_until must be later than valid_from`);
  }
  return {
    keyId,
    suiteId,
    publicKey: raw,
    principal: item["principal"] as string,
    purposes: Object.freeze([...listed]),
    validFrom,
    validUntil,
  };
}

function loadRevocations(items: JsonObject[], held: ReadonlySet<string>): KeyRevocation[] {
  const revoked = new Set<string>();
  for (const item of items) {
    const keyId = item["key_id"] as string;
    if (!held.has(keyId)) {
      throw semanticError(`revocation names ${keyId}, which is not a key of this policy`);
    }
    if (revoked.has(keyId)) {
      throw semanticError(`revocation of ${keyId} appears twice in the trust policy`);
    }
    revoked.add(keyId);
  }
  return items.map((item) => ({
    keyId: item["key_id"] as string,
    effectiveAt: item["effective_at"] as string,
    reason: item["reason"] as string,
  }));
}
