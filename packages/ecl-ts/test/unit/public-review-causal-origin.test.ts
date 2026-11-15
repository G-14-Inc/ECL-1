import assert from "node:assert/strict";
import test from "node:test";
import { analyzeBundle } from "../../src/bundle/causal.js";
import { TrustPolicy, parseStrictJson, verifyBundle, objectDigest } from "../../src/index.js";
import { primaryFinding } from "../../src/evidence/verify.js";
import type { JsonObject, JsonValue } from "../../src/json/value.js";
import { bytes } from "./helpers.js";

interface OriginCase {
  name: string; records: JsonValue[]; status: string; expected_rules: string[];
  expected_unresolved: string[]; allowed_external_predecessors: string[];
  bundle_path: string; expected_verdict: string; expected_primary: string | null;
}
const cases = parseStrictJson(bytes("tests/fixtures/repair-causal-origin.json")) as unknown as OriginCase[];
const policy = TrustPolicy.load(bytes("conformance/suites/evidence-bundle/trust-policy.json"));
for (const c of cases) test(c.name, () => {
  const graph = analyzeBundle(c.records, c.allowed_external_predecessors, 1000, 128, { causalContext: true });
  assert.equal(graph.status, c.status);
  assert.deepEqual([...new Set(graph.findings.map(f => f.ruleId))].sort(), c.expected_rules);
  assert.deepEqual(graph.unresolvedPredecessorIds, c.expected_unresolved);
  const report = verifyBundle(parseStrictJson(bytes(c.bundle_path)), policy, { now: "2026-10-01T00:00:00Z" });
  assert.equal(report.verdict, c.expected_verdict);
  assert.equal(primaryFinding(report), c.expected_primary);
  assert.equal(report.scope.established.includes("causal-completeness"), c.expected_verdict === "verified");
  assert.ok(report.envelopeChecks.every(e => e.historical === "valid" && e.current === "valid"));
});
function minimal(id: string, workflow: string, sequence: number, prior?: JsonObject, parent?: string): JsonObject {
  const w: JsonObject = { workflow_id: workflow, root_trace_id: "urn:trace", attempt: 1, sequence, causal_predecessors: [] };
  if (parent !== undefined) w["parent_workflow_id"] = parent;
  if (prior !== undefined) w["causal_predecessors"] = [{ id: prior["object_id"]!, digest: { algorithm: "ecl.digest.sha-256.v1", value: objectDigest(prior) } }];
  return { object_id: id, workflow: w };
}
test("deep child progression and many joins are iterative", () => {
  const start = minimal("urn:parent:0", "urn:parent", 0), records: JsonValue[] = [start];
  let prior = start;
  for (let n = 0; n < 2048; n += 1) {
    const child = minimal(`urn:child:${String(n).padStart(4, "0")}`, "urn:child", n, prior, "urn:parent");
    records.push(child, minimal(`urn:join:${String(n).padStart(4, "0")}`, "urn:parent", n + 1, child)); prior = child;
  }
  const result = analyzeBundle(records.reverse(), [], 5000, 128, { causalContext: true });
  assert.equal(result.status, "complete"); assert.deepEqual(result.findings, []);
});
for (const length of [3, 2048]) test(`cycle normalization preserves diagnostic at length ${length}`, () => {
  const names = Array.from({ length }, (_, n) => `urn:cycle:${String(n).padStart(4, "0")}`);
  const records = names.map((name, n) => minimal(name, "urn:cycle", n));
  records.forEach((r, n) => { (r["workflow"] as JsonObject)["causal_predecessors"] = [{ id: names[(n + 1) % length]!, digest: { algorithm: "ecl.digest.sha-256.v1", value: "0".repeat(64) } }]; });
  for (const ordered of [records, [...records].reverse()]) {
    const result = analyzeBundle(ordered, [], 3000), cycles = result.findings.filter(f => f.ruleId === "ecl.rule.bundle-causal-graph-acyclic.v1");
    assert.equal(cycles.length, 1);
    let display = [...names, names[0]!];
    if (display.length > 18) display = [...display.slice(0, 8), "...", ...display.slice(-8)];
    assert.equal(cycles[0]?.message, "causal cycle: " + display.join(" -> "));
  }
});
