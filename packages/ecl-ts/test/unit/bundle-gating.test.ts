import assert from "node:assert/strict";
import test from "node:test";
import { TrustPolicy, parseStrictJson, verifyBundle } from "../../src/index.js";
import { bytes } from "./helpers.js";

interface Case { id: string; path: string; rationale: string; expected_verdict: string; expected_findings: string[]; }
const manifest = JSON.parse(new TextDecoder().decode(bytes("tests/fixtures/bundle-gating/expected.json"))) as {
  trust_policy: string; evaluated_at: string; cases: Case[];
};
for (const item of manifest.cases) {
  test(`complete bundle findings: ${item.id}`, () => {
    const report = verifyBundle(parseStrictJson(bytes(item.path)), TrustPolicy.load(bytes(manifest.trust_policy)), { now: manifest.evaluated_at });
    assert.equal(report.verdict, item.expected_verdict);
    assert.deepEqual(report.findings.map(f => `${f.code}: ${f.message}`), item.expected_findings, item.rationale);
  });
}


interface TrustCase {
  id: string; path: string; wrap_envelope: boolean; expected_verdict: string;
  expected_dependencies: { key_id: string; historical: string; current: string }[];
}
const trustCases = JSON.parse(new TextDecoder().decode(bytes("tests/fixtures/bundle-gating/trust-dependencies.json"))) as {
  trust_policy: string; evaluated_at: string; cases: TrustCase[];
};
for (const item of trustCases.cases) {
  test(`signer trust dependencies: ${item.id}`, () => {
    const value = parseStrictJson(bytes(item.path));
    const bundle = item.wrap_envelope ? { schema_version: "ecl_evidence_bundle_v1", envelopes: [value] } : value;
    const report = verifyBundle(bundle, TrustPolicy.load(bytes(trustCases.trust_policy)), { now: trustCases.evaluated_at });
    assert.equal(report.verdict, item.expected_verdict);
    const signers = report.trustDependencies.filter(d => d.role === "signer").map(d => ({
      key_id: d.keyId, historical: d.historical, current: d.current,
    }));
    assert.deepEqual(signers, item.expected_dependencies);
  });
}
