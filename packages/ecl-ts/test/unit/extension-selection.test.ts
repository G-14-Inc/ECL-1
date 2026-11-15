import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { evaluateBindingRecord } from "../../src/bindings/index.js";
import { loadExportKeys } from "../../src/bindings/otel.js";
import { verifyBundle, primaryFinding } from "../../src/evidence/verify.js";
import { TrustPolicy } from "../../src/trust/policy.js";
import { parseStrictJson } from "../../src/json/strict.js";
import type { JsonObject } from "../../src/json/value.js";
import { interpretedExtension } from "../../src/registry/registries.js";
import { repoRoot } from "./helpers.js";

const root = join(repoRoot(), "tests/fixtures/extension-selection-cases");
const read = (file: string): JsonObject => parseStrictJson(readFileSync(join(root, file))) as JsonObject;
const manifest = read("manifest.json");
const policy = TrustPolicy.load(readFileSync(join(root, "bundle-trust.json")));
const keys = loadExportKeys(readFileSync(join(root, "export-keys.json")));
for (const item of manifest["cases"] as JsonObject[]) {
  test("extension selection: " + item["id"], () => {
    const value = read(item["file"] as string);
    const before = JSON.stringify(value);
    if (item["kind"] === "binding") {
      const found = evaluateBindingRecord(item["schema"] as string, value, undefined, keys);
      assert.equal(found.length === 0, item["accepted"], JSON.stringify(found));
      if (!item["accepted"]) assert.ok(found.some((finding) => finding.ruleId === item["required_code"]), JSON.stringify(found));
    } else {
      const report = verifyBundle(value, policy, { now: manifest["evaluated_at"] as string });
      assert.equal(report.verdict === "verified", item["accepted"], JSON.stringify(report));
      if (!item["accepted"]) assert.equal(primaryFinding(report), item["required_code"]);
    }
    assert.equal(JSON.stringify(value), before);
  });
}
test("default extension interpretation respects object type and exact supported version", () => {
  const entry = { id: "ecl.ext.outcome-reason.v1", version: 1, critical: false, value: { code: "ecl.error.expired.v1" } };
  assert.equal(interpretedExtension({ protocol: "EBMP-2" }, entry), true);
  assert.equal(interpretedExtension({ protocol: "DCMP-2" }, entry), false);
  assert.equal(interpretedExtension({ protocol: "EBMP-2" }, { ...entry, version: 2 }), false);
  assert.equal(interpretedExtension({ protocol: "EBMP-2" }, { ...entry, version: true }), false);
});
