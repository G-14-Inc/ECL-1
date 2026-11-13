import assert from "node:assert/strict";
import { test } from "node:test";
import {
  IntegrityError, TrustPolicy, fromCanonicalBase64, verifyEd25519, verifyEnvelope,
} from "../../src/index.js";
import type { JsonObject, VerificationContext, VerificationKey } from "../../src/index.js";
import { bytes, json } from "./helpers.js";

const keyId = "urn:example:key:vector-ed";
const boundary = "2026-11-10T12:00:00.000000500Z";
const at = (offset: number): string => `2026-11-10T12:00:00.${String(500 + offset).padStart(9, "0")}Z`;

for (const kind of ["validFrom", "validUntil", "revocation"] as const) {
  for (const offset of [-1, 0, 1]) {
    for (const ownTime of [false, true]) {
      test(`direct ${kind}, offset ${offset} ns, key override ${ownTime}`, () => {
        const policy = TrustPolicy.load(bytes("conformance/suites/envelope/trust-policy.json"));
        const keys = new Map(policy.keyring());
        let context: VerificationContext = policy.verificationContext(ownTime ? "2026-11-10T12:00:01Z" : at(offset), "ecl.time.issued-at.v1");
        let expected: string | undefined;
        if (kind === "revocation") {
          context = { ...context, revocations: [{ keyId, effectiveAt: boundary, reason: "synthetic test" }] };
          expected = offset < 0 ? undefined : "ecl.error.revoked.v1";
        } else {
          keys.set(keyId, { ...keys.get(keyId) as VerificationKey, [kind]: boundary });
          expected = (kind === "validFrom" ? offset >= 0 : offset < 0) ? undefined : "ecl.error.expired.v1";
        }
        const verify = () => verifyEnvelope(json("conformance/suites/envelope/envelope-valid-ed25519-signed.json"), keys, context, ownTime ? new Map([[keyId, at(offset)]]) : undefined);
        if (expected === undefined) assert.ok(verify().validKeyIds.includes(keyId));
        else assert.throws(verify, (error: unknown) => error instanceof IntegrityError && error.code === expected);
      });
    }
  }
}

test("direct Ed25519 verification enforces the loaded-policy key domain", () => {
  const forged = new Uint8Array(64); forged[0] = 1;
  for (let index = 0; index < 14; index += 1) {
    const policy = json(`conformance/suites/trust-policy/trust-policy-invalid-small-order-${String(index).padStart(2, "0")}.json`);
    const key = (policy["keys"] as JsonObject[]).find((item) => item["key_id"] === keyId) as JsonObject;
    const raw = fromCanonicalBase64(key["public_key"] as string) as Uint8Array;
    assert.equal(verifyEd25519(raw, new Uint8Array([1, 2, 3]), forged), false, `key ${index}`);
  }
});
