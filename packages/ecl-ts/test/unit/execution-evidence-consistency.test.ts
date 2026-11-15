// Signed execution and report-scope regressions. Robert F. Tilley Jr.; G-14, Inc.
import assert from "node:assert/strict";
import { test } from "node:test";
import { TrustPolicy, verifyBundle } from "../../src/index.js";
import { BindingError, checkEventBinding } from "../../src/binding/binding.js";
import { reportScope, reportToJson } from "../../src/evidence/verify.js";
import type { JsonObject } from "../../src/json/value.js";
import { bytes, json } from "./helpers.js";

interface Case { id: string; bundle: string; policy: string; verdict: string; primary: string | null; direct: Record<string, string | null>; }
interface ScopeCase { id: string; remove: string[] | "all"; }
const root = "tests/fixtures/execution-evidence-consistency/";
const manifest = json(root + "manifest.json") as unknown as { now: string; cases: Case[]; reconstructed_scopes: ScopeCase[] };
for (const item of manifest.cases) test("signed execution evidence: " + item.id, () => {
  const bundle = json(root + item.bundle);
  const report = verifyBundle(bundle, TrustPolicy.load(bytes(root + item.policy)), { now: manifest.now });
  assert.equal(report.verdict, item.verdict, JSON.stringify(report.findings));
  assert.equal(reportToJson(report)["primary"], item.primary);
  if (item.verdict === "invalid") assert.deepEqual(report.scope.established, []);
  else {
    assert.ok(report.scope.established.includes("bindings"));
    assert.equal(report.scope.established.includes("causal-completeness"), item.verdict === "verified");
  }
  const payloads = (bundle["envelopes"] as JsonObject[]).map((envelope) => JSON.parse(Buffer.from(envelope["payload"] as string, "base64").toString()) as JsonObject);
  const request = payloads[0] as JsonObject;
  const response = payloads.find((p) => p["message_type"] === "decision_response");
  for (const event of payloads) {
    const kind = event["event_type"] as string;
    if (!(kind in item.direct)) continue;
    let code: string | null = null;
    try { checkEventBinding(event, request, response); }
    catch (error) { if (!(error instanceof BindingError)) throw error; code = error.code; }
    assert.equal(code, item.direct[kind]);
  }
});

for (const item of manifest.reconstructed_scopes) test("reconstructed report consistency: " + item.id, () => {
  const suite = "conformance/suites/evidence-bundle/";
  const base = verifyBundle(json(suite + "bundle-valid-trusted-time.json"), TrustPolicy.load(bytes(suite + "trust-policy-time-authority.json")), { now: manifest.now });
  assert.equal(base.verdict, "verified");
  const report = { ...base, envelopeChecks: base.envelopeChecks.map((c) => ({ ...c })), trustDependencies: base.trustDependencies.map((d) => ({ ...d })) };
  const mode = item.id;
  if (["signer-historical-invalid", "time-authority-historical-invalid", "current-signer-invalid"].includes(mode)) {
    const role = mode.startsWith("time-authority") ? "time-authority" : "signer";
    const dependency = report.trustDependencies.find((d) => d.role === role);
    assert.ok(dependency);
    if (mode === "current-signer-invalid") dependency.current = "ecl.error.integrity-invalid.v1";
    else dependency.historical = "ecl.error.integrity-invalid.v1";
  } else if (mode === "missing-trusted-time") {
    const check = report.envelopeChecks[0]; assert.ok(check); check.trustedTime = null;
  } else if (mode === "envelope-historical-invalid") {
    const check = report.envelopeChecks[0]; assert.ok(check); check.historical = "ecl.error.integrity-invalid.v1";
  } else if (mode === "missing-signer-dependency") {
    report.trustDependencies = report.trustDependencies.filter((d) => !(d.index === 0 && d.role === "signer"));
  } else if (mode === "invalid-verdict") report.verdict = "invalid";
  const expected = item.remove === "all" ? [] : base.scope.established.filter((name) => !item.remove.includes(name));
  assert.deepEqual(reportScope(report).established, expected);
});
