import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ED25519_SUITE,
  P256_SUITE,
  SignatureEncodingError,
  TrustPolicy,
  TrustPolicyError,
  UnsupportedSuiteError,
  decodePayload,
  fromCanonicalBase64,
  publicKeyProblem,
  signingInput,
  toBase64,
  verifyEd25519,
  verifyP256,
  verifySignature,
} from "../../src/index.js";
import type { JsonObject } from "../../src/index.js";
import { bytes, hex, json, suite } from "./helpers.js";

const decoder = new TextDecoder();

test("DSSE v1 pre-authentication encoding", () => {
  const encoded = signingInput("http://example.com/HelloWorld", new TextEncoder().encode("hello world"));
  assert.equal(decoder.decode(encoded), "DSSEv1 29 http://example.com/HelloWorld 11 hello world");
  assert.equal(decoder.decode(signingInput("application/vnd.ecl.dcmp+json", new Uint8Array())), "DSSEv1 29 application/vnd.ecl.dcmp+json 0 ");
});

test("canonical base64 only", () => {
  assert.deepEqual(fromCanonicalBase64("aGk="), new TextEncoder().encode("hi"));
  assert.equal(toBase64(new TextEncoder().encode("hi")), "aGk=");
  for (const text of ["aGk", "aGl=", "aG k=", "aGk==", "a===", "aGk=\n", "!!!!", "aGk=aGk="]) {
    assert.equal(fromCanonicalBase64(text), undefined, text);
  }
  assert.deepEqual(fromCanonicalBase64(""), new Uint8Array());
});

test("Ed25519: RFC 8032 section 7.1 tests 1 and 2", () => {
  const cases = [
    ["d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"],
    ["3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"],
  ] as const;
  for (const [key, message, signature] of cases) {
    assert.equal(verifyEd25519(hex(key), hex(message), hex(signature)), true);
    const changed = hex(signature);
    changed[0] = (changed[0] as number) ^ 1;
    assert.equal(verifyEd25519(hex(key), hex(message), changed), false);
    assert.equal(verifyEd25519(hex(key), new Uint8Array([1]), hex(signature)), false);
  }
});

test("Ed25519: the 14 small-order encodings and the bad point are refused as keys", () => {
  let count = 0;
  for (const vector of suite("trust-policy")) {
    if (!vector.id.startsWith("trust-policy-invalid-small-order") && vector.id !== "trust-policy-invalid-bad-point") {
      continue;
    }
    const document = json(vector.path);
    const problems = (document["keys"] as JsonObject[]).map((key) => {
      const raw = fromCanonicalBase64(key["public_key"] as string);
      assert.ok(raw !== undefined);
      return publicKeyProblem(key["suite_id"] as string, raw);
    });
    assert.ok(problems.some((problem) => problem !== undefined), vector.id);
    assert.throws(() => TrustPolicy.load(bytes(vector.path)), (error: unknown) => error instanceof TrustPolicyError && error.code === vector.expected_primary_id);
    count += /^trust-policy-invalid-small-order-[0-9]{2}$/.test(vector.id) ? 1 : 0;
  }
  assert.equal(count, 14);
});

test("Ed25519: the cofactorless equation, canonical S, and no torsion in R", () => {
  const policy = json("conformance/suites/envelope/trust-policy.json");
  const keys = new Map<string, Uint8Array>();
  for (const key of policy["keys"] as JsonObject[]) {
    if (key["suite_id"] === ED25519_SUITE) {
      keys.set(key["key_id"] as string, fromCanonicalBase64(key["public_key"] as string) as Uint8Array);
    }
  }
  const expected: Record<string, boolean> = {
    "envelope-valid-mixed-order": true,
    "envelope-invalid-mixed-order": false,
    "envelope-invalid-torsion-r": false,
    "envelope-invalid-noncanonical-s": false,
    "envelope-valid-ed25519-signed": true,
  };
  for (const [name, accepted] of Object.entries(expected)) {
    const envelope = json(`conformance/suites/envelope/${name}.json`);
    const signature = (envelope["signatures"] as JsonObject[])[0] as JsonObject;
    const key = keys.get(signature["key_id"] as string) as Uint8Array;
    // The mixed-order key is accepted by the trust policy: it is not of small order.
    assert.equal(publicKeyProblem(ED25519_SUITE, key), undefined, name);
    const message = signingInput(envelope["payload_type"] as string, decodePayload(envelope));
    assert.equal(verifyEd25519(key, message, fromCanonicalBase64(signature["signature"] as string) as Uint8Array), accepted, name);
  }
});

test("P-256: minimal DER and low S, or refusal before the curve check", () => {
  const policy = json("conformance/suites/envelope/trust-policy.json");
  const key = (policy["keys"] as JsonObject[]).find((item) => item["suite_id"] === P256_SUITE) as JsonObject;
  const raw = fromCanonicalBase64(key["public_key"] as string) as Uint8Array;
  assert.equal(publicKeyProblem(P256_SUITE, raw), undefined);
  const low = json("conformance/suites/envelope/envelope-valid-p256-low-s.json");
  const high = json("conformance/suites/envelope/envelope-invalid-p256-high-s.json");
  const message = signingInput(low["payload_type"] as string, decodePayload(low));
  const signatureOf = (envelope: JsonObject): Uint8Array =>
    fromCanonicalBase64(((envelope["signatures"] as JsonObject[])[0] as JsonObject)["signature"] as string) as Uint8Array;
  assert.equal(verifyP256(raw, message, signatureOf(low)), true);
  assert.throws(() => verifyP256(raw, message, signatureOf(high)), SignatureEncodingError);
  const der = signatureOf(low);
  // A non-minimal length, a negative integer and trailing data are refused.
  const longForm = new Uint8Array([0x30, 0x81, der[1] as number, ...der.subarray(2)]);
  assert.throws(() => verifyP256(raw, message, longForm), SignatureEncodingError);
  assert.throws(() => verifyP256(raw, message, new Uint8Array([...der, 0])), SignatureEncodingError);
  assert.throws(() => verifyP256(raw, message, hex("30060201ff020101")), SignatureEncodingError);
  assert.throws(() => verifyP256(raw, message, hex("300702020001020101")), SignatureEncodingError);
  assert.equal(verifyP256(raw, message, hex("3006020100020101")), false);
  assert.equal(publicKeyProblem(P256_SUITE, new Uint8Array([0x02, ...raw.subarray(1)])), "the public key is not a point on P-256");
});

test("ML-DSA-65 is recognized and refused as not implemented, never verified", () => {
  assert.throws(() => verifySignature("ecl.sig.ml-dsa-65.v1", new Uint8Array(1952), new Uint8Array(), new Uint8Array(3309)), UnsupportedSuiteError);
  assert.throws(() => verifySignature("ecl.sig.unknown.v1", new Uint8Array(), new Uint8Array(), new Uint8Array()), SignatureEncodingError);
  assert.match(publicKeyProblem("ecl.sig.ml-dsa-65.v1", new Uint8Array(1952)) as string, /not supported by trust policy v1/);
});
