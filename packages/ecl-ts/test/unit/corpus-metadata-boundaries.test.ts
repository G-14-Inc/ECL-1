import assert from "node:assert/strict";
import { test } from "node:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CAPABILITIES, runCorpus } from "../../src/conformance/corpus.js";
import { repoRoot } from "./helpers.js";

const required = ["strict-json", "canonical-digest", "semantic-rules", "safe-state-profile-rules"];
function miniature(root: string, mode: string): void {
  mkdirSync(join(root, "conformance/suites"), { recursive: true });
  mkdirSync(join(root, "registries")); mkdirSync(join(root, "source"));
  const put = (path: string, value: unknown): void => writeFileSync(join(root, path), JSON.stringify(value));
  writeFileSync(join(root, "source/control.txt"), "bounded source fixture\n");
  for (const name of ["semantic-rules", "error-codes"]) copyFileSync(join(repoRoot(), "registries", name + ".json"), join(root, "registries", name + ".json"));
  const vectors = ["a", "b"].map((id) => ({ id, path: `conformance/${id}.json`, stage: "semantic", schema: "https://externalcontrollayer.ai/ns/schema/common/1", expected: "pass", expected_secondary_ids: [] }));
  put("conformance/a.json", {});
  put("conformance/b.json", ["failing-vector", "duplicate-corpus-id"].includes(mode) ? { protocol: "DCMP-2", message_type: "decision_response", outcome: "deny", authorization: {} } : {});
  const corpus = { schema_version: "ecl_shared_corpus_v1", version: 1, candidate_version: "1.0", required_capabilities: [...required], optional_capabilities: CAPABILITIES.filter((name) => !required.includes(name)) as string[], vectors: vectors.map((v) => ({ suite: "bounded-fixture", id: v.id, capability: "semantic-rules" })) };
  if (mode === "duplicate-corpus-id") corpus.vectors[1] = { ...corpus.vectors[0]! };
  if (mode === "wrong-candidate") corpus.candidate_version = "different-candidate";
  if (mode === "duplicate-required") corpus.required_capabilities.push("semantic-rules");
  if (mode === "duplicate-optional") corpus.optional_capabilities.push("schema-validation");
  if (mode === "overlapping-capabilities") corpus.optional_capabilities.push("semantic-rules");
  if (mode === "missing-required") corpus.required_capabilities.pop();
  if (mode === "extra-required") corpus.required_capabilities.push("schema-validation");
  if (mode === "unknown-required") corpus.required_capabilities[0] = "not-registered";
  if (mode === "unknown-optional") { corpus.optional_capabilities.push("not-registered"); corpus.vectors[0]!.capability = "not-registered"; }
  if (mode === "missing-bundle-implication") corpus.optional_capabilities = corpus.optional_capabilities.filter((name) => name !== "evidence-bundle-verification");
  if (mode === "missing-basis-implication") corpus.optional_capabilities = corpus.optional_capabilities.filter((name) => name !== "decision-basis-rule");
  if (mode === "undeclared-vector-capability") corpus.vectors[0]!.capability = "not-registered";
  if (mode === "wrong-suite") corpus.vectors[0]!.suite = "missing-suite";
  if (mode === "unlisted-vector") corpus.vectors[0]!.id = "missing-vector";
  if (mode === "foundation-only") corpus.optional_capabilities = [];
  const malformed = corpus as unknown as Record<string, unknown>;
  if (mode === "null-required") malformed["required_capabilities"] = null;
  if (mode === "nonstring-optional") malformed["optional_capabilities"] = [1];
  if (mode === "null-vector") malformed["vectors"] = [null, corpus.vectors[1]];
  if (mode === "null-vectors") malformed["vectors"] = null;
  put("conformance/manifest.json", { schema_version: "ecl_conformance_vector_manifest_v3", suite: "bounded-fixture", vectors });
  put("conformance/shared-corpus.json", corpus);
}

for (const mode of ["duplicate-corpus-id", "wrong-candidate", "duplicate-required", "duplicate-optional", "overlapping-capabilities", "missing-required", "extra-required", "unknown-required", "unknown-optional", "missing-bundle-implication", "missing-basis-implication", "undeclared-vector-capability", "wrong-suite", "unlisted-vector", "null-required", "nonstring-optional", "null-vector", "null-vectors"]) {
  test(`corpus metadata refuses ${mode} before emitting replay evidence`, () => {
    const root = mkdtempSync(join(tmpdir(), "ecl-corpus-metadata-"));
    try {
      miniature(root, mode); const report = join(root, "report.json");
      assert.throws(() => runCorpus(root, "bounded-fixture-revision", report, join(root, "source"), process.version));
      assert.equal(existsSync(report), false);
      assert.equal(existsSync(join(root, "report-evidence")), false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
}
for (const mode of ["valid", "foundation-only", "failing-vector"]) {
  test(`bounded corpus ${mode} control evaluates both distinct vectors`, () => {
    const root = mkdtempSync(join(tmpdir(), "ecl-corpus-metadata-"));
    try {
      miniature(root, mode); const path = join(root, "report.json");
      const result = runCorpus(root, "bounded-fixture-revision", path, join(root, "source"), process.version);
      assert.equal(result.decision, mode === "failing-vector" ? "fail" : "pass");
      const report = JSON.parse(readFileSync(path, "utf8"));
      assert.deepEqual(report.vector_results.map((row: { id: string }) => row.id), ["a", "b"]);
      if (mode === "valid") assert.deepEqual(new Set(report.implementation.capabilities), new Set(CAPABILITIES));
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
}
test("implemented capabilities agree with the fixed v3 schema and prose list", () => {
  const root = repoRoot();
  const schema = JSON.parse(readFileSync(join(root, "schemas/ecl-cross-implementation-report-v3.schema.json"), "utf8"));
  assert.deepEqual(new Set(CAPABILITIES), new Set(schema.properties.implementation.properties.capabilities.items.enum));
  const prose = readFileSync(join(root, "conformance/EXTERNAL_IMPLEMENTATION_PROFILE.md"), "utf8");
  const list = prose.split("The optional capabilities are")[1]!.split("The capability of a vector")[0]!;
  for (const name of CAPABILITIES.filter((capability) => !required.includes(capability))) assert.ok(list.includes("`" + name + "`"), name);
});
