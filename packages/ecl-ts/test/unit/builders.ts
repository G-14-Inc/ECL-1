/**
 * Test builders that sign: ECL-IE-1 envelopes over canonical payloads, and trusted-time
 * countersignatures (IE1-032, IE1-033), with Ed25519 keys derived from the seeds the repository's
 * tests and generators use. Test code only: the library verifies and never signs.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256Hex, toBase64 } from "../../src/crypto/bytes.js";
import { canonicalize } from "../../src/json/canonical.js";
import type { JsonObject, JsonValue } from "../../src/json/value.js";
import { decodePayload, signingInput, TIME_ATTESTATION_TYPE, TRUSTED_TIME_CLAIM } from "../../src/integrity/envelope.js";

export const ED25519 = "ecl.sig.ed25519.v1";

/** A signing key: its identifier and its 32-byte Ed25519 seed. */
export interface Signer {
  readonly keyId: string;
  readonly seed: Uint8Array;
}

/** The seed `start`, `start + 1`, ..., `start + 31`, as the Python tests write `bytes(range(...))`. */
export function seed(start: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => start + index);
}

/** The canonical base64 of a signer's raw public key, as a trust policy carries it. */
export function publicKey(signer: Signer): string {
  return toBase64(ed25519.getPublicKey(signer.seed));
}

/** One signature entry over `payloadType` and `payload`. */
export function signature(signer: Signer, payloadType: string, payload: Uint8Array): JsonObject {
  return { key_id: signer.keyId, suite_id: ED25519, signature: toBase64(ed25519.sign(signingInput(payloadType, payload), signer.seed)) };
}

/** An envelope over the canonical bytes of `value`, signed by each of `signers` in order. */
export function signEnvelope(value: JsonValue, payloadType: string, signers: readonly Signer[]): JsonObject {
  const payload = canonicalize(value);
  return {
    envelope_version: "ECL-IE-1",
    payload_type: payloadType,
    payload: toBase64(payload),
    payload_digest: { algorithm: "ecl.digest.sha-256.v1", value: sha256Hex(payload) },
    signatures: signers.map((signer) => signature(signer, payloadType, payload)),
  };
}

/** `envelope` with its signatures replaced by those of `signers` over the same payload. */
export function resign(envelope: JsonObject, signers: readonly Signer[]): JsonObject {
  const payload = decodePayload(envelope);
  return { ...envelope, signatures: signers.map((signer) => signature(signer, envelope["payload_type"] as string, payload)) };
}

/** The bytes of a canonical base64 signature value. */
function signatureBytes(text: string): Uint8Array {
  return Uint8Array.from(Buffer.from(text, "base64"));
}

/**
 * The `covered` member of a time attestation over `envelope` (IE1-033): the payload type and
 * digest and, in envelope order, each signature's key, suite and SHA-256 of its bytes. `only`
 * restricts the signatures to those of the given key identifiers.
 */
export function covered(envelope: JsonObject, only?: readonly string[]): JsonObject {
  const signatures = (envelope["signatures"] as JsonObject[])
    .filter((item) => only === undefined || only.includes(item["key_id"] as string))
    .map((item) => ({
      key_id: item["key_id"] as string,
      suite: item["suite_id"] as string,
      signature_digest: { algorithm: "ecl.digest.sha-256.v1", value: sha256Hex(signatureBytes(item["signature"] as string)) },
    }));
  return { media_type: envelope["payload_type"] as JsonValue, digest: envelope["payload_digest"] as JsonValue, signatures };
}

/** What a time authority attests and how it signs: IE1-033's members besides `covered`. */
export interface Attestation {
  readonly authority: Signer;
  readonly issuer: string;
  readonly issuedAt: string;
  /** The `integrity_policy.trust_policy` reference of the attestation. */
  readonly trustPolicy: JsonObject;
  /** The `covered` member; by default `covered(envelope)`. */
  readonly covered?: JsonObject;
  readonly attestationId?: string;
}

/** `envelope` with one more trusted-time countersignature (IE1-032), its artifact version raised. */
export function countersign(envelope: JsonObject, attestation: Attestation): JsonObject {
  const identifier = attestation.attestationId ?? `urn:example:time-attestation:${(envelope["payload_digest"] as JsonObject)["value"] as string}`.slice(0, 64);
  const statement: JsonObject = {
    schema_version: "ecl_time_attestation_v1",
    attestation_id: identifier,
    claim: TRUSTED_TIME_CLAIM,
    covered: attestation.covered ?? covered(envelope),
    issuer: { id: attestation.issuer, type: "ecl.principal.service.v1", trust_domain: "urn:example:trust-domain:time" },
    issued_at: attestation.issuedAt,
    integrity_policy: {
      accepted_suites: [ED25519],
      eligible_key_ids: [attestation.authority.keyId],
      required: true,
      required_key_ids: [attestation.authority.keyId],
      revocation_policy: "ecl.revocation.offline-bundle.v1",
      threshold: 1,
      trust_policy: attestation.trustPolicy,
      verification_time_policy: "ecl.time.issued-at.v1",
    },
  };
  const entry: JsonObject = { counter_id: identifier, claim: TRUSTED_TIME_CLAIM, attestation: signEnvelope(statement, TIME_ATTESTATION_TYPE, [attestation.authority]) };
  const existing = (envelope["countersignatures"] as JsonValue[] | undefined) ?? [];
  const version = (envelope["envelope_artifact_version"] as number | undefined) ?? 1;
  return { ...envelope, envelope_artifact_version: version + 1, countersignatures: [...existing, entry] };
}
