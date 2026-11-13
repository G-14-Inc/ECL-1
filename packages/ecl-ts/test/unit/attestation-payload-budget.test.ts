import assert from "node:assert/strict";
import { test } from "node:test";
import {
  TrustPolicy, canonicalize, decodeCanonicalJsonPayload, reportToJson, sha256Hex, toBase64, verifyBundle,
} from "../../src/index.js";
import type { JsonObject, JsonValue } from "../../src/index.js";
import { MAX_TOTAL_PAYLOAD_NODES } from "../../src/evidence/verify.js";
import { bytes, json } from "./helpers.js";

const suite = "conformance/suites/evidence-bundle";
const resource = "ecl.error.resource-limit-exceeded.v1";
const invalidTime = "ecl.error.trusted-time-invalid.v1";
function fixture(): [JsonObject, TrustPolicy] {
  return [json(`${suite}/bundle-valid-trusted-time.json`), TrustPolicy.load(bytes(`${suite}/trust-policy-time-authority.json`))];
}
function entries(bundle: JsonObject): JsonObject[] { return bundle["envelopes"] as JsonObject[]; }
function counter(envelope: JsonObject): JsonObject { return (envelope["countersignatures"] as JsonObject[])[0] as JsonObject; }
function attestation(envelope: JsonObject): JsonObject { return counter(envelope)["attestation"] as JsonObject; }
function replacePayload(envelope: JsonObject, payload: JsonValue): void {
  const raw = canonicalize(payload); envelope["payload"] = toBase64(raw);
  (envelope["payload_digest"] as JsonObject)["value"] = sha256Hex(raw);
}
function nodes(value: JsonValue): number {
  return 1 + (Array.isArray(value) ? value.reduce<number>((sum, item) => sum + nodes(item), 0)
    : value !== null && typeof value === "object" ? Object.values(value).reduce<number>((sum, item) => sum + nodes(item), 0) : 0);
}
function total(bundle: JsonObject): number {
  return entries(bundle).reduce((sum, e) => sum + nodes(decodeCanonicalJsonPayload(e))
    + (e["countersignatures"] as JsonObject[]).reduce((count, entry) => count + nodes(decodeCanonicalJsonPayload(entry["attestation"] as JsonObject)), 0), 0);
}
function result(bundle: JsonObject, policy: TrustPolicy): JsonObject {
  return reportToJson(verifyBundle(bundle, policy, { now: "2026-10-01T00:00:00Z" }));
}
test("valid trusted-time control remains verified", () => { assert.equal(result(...fixture())["verdict"], "verified"); });
test("attestation depth refusal retains an earlier payload check", () => {
  const [bundle, policy] = fixture(); const outer = entries(bundle)[0] as JsonObject;
  (outer["payload_digest"] as JsonObject)["value"] = "0".repeat(64);
  const a = attestation(outer); const raw = new TextEncoder().encode("[".repeat(257) + "0" + "]".repeat(257));
  a["payload"] = toBase64(raw); (a["payload_digest"] as JsonObject)["value"] = sha256Hex(raw);
  const report = result(bundle, policy);
  assert.equal(report["primary"], resource);
  assert.equal((report["envelope_checks"] as JsonValue[]).length, 1);
});
for (const offset of [-1, 0, 1]) {
  test(`attestation aggregate budget, offset ${offset}`, () => {
    const [bundle, policy] = fixture(); const a = attestation(entries(bundle)[0] as JsonObject);
    const statement = decodeCanonicalJsonPayload(a) as JsonObject;
    statement["padding"] = []; replacePayload(a, statement);
    statement["padding"] = Array(MAX_TOTAL_PAYLOAD_NODES + offset - total(bundle)).fill(0) as JsonValue[];
    replacePayload(a, statement);
    assert.equal(total(bundle), MAX_TOTAL_PAYLOAD_NODES + offset);
    assert.equal(result(bundle, policy)["primary"], offset > 0 ? resource : invalidTime);
  });
}
for (const malformedOuter of [false, true]) {
  test(`split attestation budget, malformed outer ${malformedOuter}`, () => {
    const [bundle, policy] = fixture();
    for (const e of entries(bundle).slice(0, malformedOuter ? 1 : 2)) {
      const a = attestation(e); const statement = decodeCanonicalJsonPayload(a) as JsonObject;
      statement["padding"] = Array(malformedOuter ? 100001 : 50000).fill(0) as JsonValue[];
      replacePayload(a, statement);
    }
    if (malformedOuter) ((entries(bundle)[0] as JsonObject)["payload_digest"] as JsonObject)["value"] = "0".repeat(64);
    assert.equal(result(bundle, policy)["primary"], resource);
  });
}
for (const registered of [false, true]) {
  test(`future instant from registered claim ${registered}`, () => {
    const [bundle, policy] = fixture(); const entry = counter(entries(bundle)[0] as JsonObject);
    const a = entry["attestation"] as JsonObject; const statement = decodeCanonicalJsonPayload(a) as JsonObject;
    statement["issued_at"] = "2099-01-01T00:00:00Z"; replacePayload(a, statement);
    if (!registered) entry["claim"] = "ecl.claim.unregistered.v1";
    assert.equal(result(bundle, policy)["primary"], registered ? "ecl.error.clock-regressed.v1" : invalidTime);
  });
}
test("failed attestation signatures retain IE1-034 classification", () => {
  for (const size of [20000, 21848, 21852]) {
    const [bundle, policy] = fixture(); const a = attestation(entries(bundle)[0] as JsonObject);
    ((a["signatures"] as JsonObject[])[0] as JsonObject)["signature"] = "A".repeat(size);
    assert.equal(result(bundle, policy)["primary"], invalidTime);
  }
});
