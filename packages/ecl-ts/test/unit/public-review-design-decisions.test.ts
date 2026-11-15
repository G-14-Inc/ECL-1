import assert from "node:assert/strict";
import test from "node:test";
import { TrustPolicy, parseStrictJson, verifyBundle } from "../../src/index.js";
import { BindingError, checkResponseBinding } from "../../src/binding/binding.js";
import { primaryFinding } from "../../src/evidence/verify.js";
import { objectFindings } from "../../src/semantic/object.js";
import type { JsonObject } from "../../src/json/value.js";
import { bytes, json } from "./helpers.js";

interface Vector {
  id: string; path: string; trust_policy_path: string; evaluated_at: string;
  expected_verdict: string; expected_primary_id?: string;
}
const manifest = json("conformance/suites/public-review-design-decisions/manifest.json") as unknown as { vectors: Vector[] };
const historicalIds = new Set(["bundle-invalid-continuation-second-of-one-challenge", "bundle-invalid-continuation-second-of-one-challenge-approval-absent"]);
const historical = (json("conformance/suites/evidence-bundle/manifest.json") as unknown as { vectors: Vector[] }).vectors.filter(v => historicalIds.has(v.id));
const requestError = "ecl.error.request-binding-invalid.v1";
function payloads(vector: Vector): JsonObject[] {
  return (json(vector.path)["envelopes"] as JsonObject[]).map(e => JSON.parse(Buffer.from(e["payload"] as string, "base64").toString("utf8")) as JsonObject);
}
for (const vector of [...manifest.vectors, ...historical]) {
  test(`signed design contract: ${vector.id}`, () => {
    const report = verifyBundle(parseStrictJson(bytes(vector.path)), TrustPolicy.load(bytes(vector.trust_policy_path)), { now: vector.evaluated_at });
    assert.equal(report.verdict, vector.expected_verdict);
    assert.equal(primaryFinding(report), vector.expected_primary_id ?? null);
    if (vector.expected_verdict === "invalid") {
      assert.equal(report.findings.length, 1);
      assert.equal(report.findings[0]?.code, vector.expected_primary_id);
    } else {
      assert.deepEqual(report.findings, []);
    }
    if (vector.id.includes("approval-absent") && vector.expected_verdict === "incomplete") {
      assert.ok(!report.scope.established.includes("bindings"));
      assert.ok(!report.scope.established.includes("causal-completeness"));
      assert.ok(report.unresolvedPredecessorIds.length > 0);
    }
    for (const payload of payloads(vector)) assert.deepEqual(objectFindings(payload), []);
  });
}
for (const vector of manifest.vectors.filter(v => v.id.startsWith("request-expiry-"))) {
  test(`pair request expiry: ${vector.id}`, () => {
    const [request, response] = payloads(vector) as [JsonObject, JsonObject];
    if (vector.expected_verdict === "invalid") {
      for (const skew of [0, 1]) assert.throws(() => checkResponseBinding(request, response, skew), (error: unknown) => error instanceof BindingError && error.code === requestError && error.message.includes("evaluated_at"));
    } else {
      checkResponseBinding(request, response);
    }
  });
}
test("request expiry preserves first failure order", () => {
  const vector = manifest.vectors.find(v => v.id === "request-expiry-admit-equal")!;
  const [request, response] = payloads(vector) as [JsonObject, JsonObject];
  (response["authorization"] as JsonObject)["audience"] = "urn:example:wrong-audience";
  const badDigest = structuredClone(response);
  ((((badDigest["workflow"] as JsonObject)["causal_predecessors"] as JsonObject[])[0]!["digest"]) as JsonObject)["value"] = "f".repeat(64);
  const early = { ...response, issued_at: "2026-09-29T09:59:59.999999999Z" };
  const unexpired = { ...response, evaluated_at: "2026-09-29T10:00:00.099999999Z" };
  for (const [answer, code, fragment] of [
    [badDigest, "ecl.error.digest-mismatch.v1", "digest"],
    [early, requestError, "issued_at"],
    [response, requestError, "evaluated_at"],
    [unexpired, "ecl.error.audience-mismatch.v1", "audience"],
  ] as const) {
    assert.throws(() => checkResponseBinding(request, answer), (error: unknown) => error instanceof BindingError && error.code === code && error.message.includes(fragment));
  }
});
