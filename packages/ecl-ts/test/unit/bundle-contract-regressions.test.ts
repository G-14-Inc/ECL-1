import assert from "node:assert/strict";
import test from "node:test";
import { TrustPolicy, verifyBundle } from "../../src/index.js";
import type { JsonValue } from "../../src/index.js";
import { analyzeBundle } from "../../src/bundle/causal.js";
import { bytes, json } from "./helpers.js";

const root = "tests/fixtures/bundle-contract-regressions/";
interface Case { id: string; bundle: string; policy: string; verdict: string; primary: string | null; invalid_extra_signature: boolean; continuation_empty_key_guard: boolean; }
const manifest = json(root + "manifest.json") as unknown as { now: string; cases: Case[] };
for (const item of manifest.cases) test("Bundle contract signed contract: " + item.id, () => {
  const report = verifyBundle(json(root + item.bundle), TrustPolicy.load(bytes(root + item.policy)), { now: manifest.now });
  assert.equal(report.verdict, item.verdict, JSON.stringify(report.findings));
  assert.equal(report.findings[0]?.code ?? null, item.primary);
  if (item.invalid_extra_signature) {
    assert(!report.scope.established.includes("envelope-signatures"));
    assert(report.trustDependencies.some((d) => d.keyId === "urn:example:key:probe-extra-approval-key" && d.historical === "ecl.error.integrity-invalid.v1"));
  }
  if (item.continuation_empty_key_guard) assert(report.findings.some((f) => f.code === "ecl.error.decision-binding-invalid.v1"));
});

interface Graph { id: string; records: JsonValue[]; options: { max_records?: number; max_predecessors_per_record?: number }; status: string; unresolved: string[]; }
const graphs = (json(root + "causal.json") as unknown as { cases: Graph[] }).cases;
for (const item of graphs) test("Bundle contract causal contract: " + item.id, () => {
  const report = analyzeBundle(item.records, [], item.options.max_records, item.options.max_predecessors_per_record);
  assert.equal(report.status, item.status, JSON.stringify(report.findings));
  assert.deepEqual(report.unresolvedPredecessorIds, item.unresolved);
  if (item.id.includes("duplicate")) assert(report.findings.some((f) => f.ruleId === "ecl.rule.bundle-object-identifiers-unique.v1"));
});
test("Bundle contract duplicate graph report is permutation invariant", () => {
  const reports = graphs.filter((item) => item.id.includes("duplicate")).map((item) => analyzeBundle(item.records));
  for (const report of reports) assert.deepEqual(report, reports[0]);
});

const suite = "conformance/suites/evidence-bundle/";
for (const option of ["false", 0, 1, null, [], {}]) test("Bundle contract current-trust waiver type: " + JSON.stringify(option), () => {
  assert.throws(() => verifyBundle(json(suite + "bundle-current-trust-failed-revoked-after-use.json"),
    TrustPolicy.load(bytes(suite + "trust-policy-revoked-after-use.json")), {
      now: manifest.now, history: [TrustPolicy.load(bytes(suite + "trust-policy.json"))],
      acceptCurrentTrustFailure: option as boolean,
    }), /acceptCurrentTrustFailure/);
});
for (const option of [false, true]) test("Bundle contract boolean waiver control: " + option, () => {
  const report = verifyBundle(json(suite + "bundle-current-trust-failed-revoked-after-use.json"),
    TrustPolicy.load(bytes(suite + "trust-policy-revoked-after-use.json")), {
      now: manifest.now, history: [TrustPolicy.load(bytes(suite + "trust-policy.json"))], acceptCurrentTrustFailure: option,
    });
  assert.equal(report.verdict, option ? "verified" : "current-trust-failed");
  assert.equal(report.acceptedCurrentTrustFailure, option);
});
