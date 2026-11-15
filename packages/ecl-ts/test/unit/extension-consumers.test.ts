import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { SemanticValidator } from "../../src/semantic/rules.js";
import { TrustPolicy } from "../../src/trust/policy.js";
import { IntegrityError, verifyEnvelope } from "../../src/integrity/envelope.js";
import { verifyBundle } from "../../src/evidence/verify.js";
import { parseStrictJson } from "../../src/json/strict.js";
import type { JsonObject } from "../../src/json/value.js";
import { repoRoot } from "./helpers.js";

const root = process.env["ECL_EXTENSION_FIXTURES"] ?? join(repoRoot(), "tests/fixtures/extension-consumer-cases");
const read = (name: string): JsonObject => parseStrictJson(readFileSync(join(root, name))) as JsonObject;
const manifest = read("manifest.json");
const policy = TrustPolicy.load(readFileSync(join(root, "envelope-trust.json")));
const bundlePolicy = TrustPolicy.load(readFileSync(join(root, "bundle-trust.json")));
const context = policy.verificationContext(manifest["evaluated_at"] as string, "ecl.time.issued-at.v1");
const tag = manifest["custom_identifier"] as string;
const custom = new SemanticValidator([tag], new Map([[tag, manifest["custom_value_schema"] as string]]), undefined,
  new Map([[tag, new Set([1])]]), [], new Map([[tag, new Set([1])]]),
  new Map([[tag, new Map([[1, new Set(["DCMP-2", "EBMP-2", "ECL-IE-1", "ECL-WI-1"])]])]]));
const regular = new SemanticValidator();
for (const row of manifest["cases"] as JsonObject[]) {
  test("extension consumer: " + row["id"], () => {
    const value = read(row["file"] as string);
    const before = JSON.stringify(value);
    if (row["kind"] === "envelope") {
      let actual: string | null = null;
      try { verifyEnvelope(value, policy.keyring(), context); }
      catch (error) { if (!(error instanceof IntegrityError)) throw error; actual = error.code; }
      assert.equal(actual, row["expected"]);
    } else if (row["kind"] === "bundle") {
      assert.equal(verifyBundle(value, bundlePolicy, { now: "2026-10-01T00:00:00Z" }).verdict, row["expected"]);
    } else {
      const consumer = row["kind"] === "custom" ? custom : regular;
      assert.deepEqual([...new Set(consumer.validate(value).map((finding) => finding.ruleId))].sort(), row["expected"]);
      if (row["kind"] === "custom") assert.deepEqual([...new Set(consumer.extensionFindings(value).map((finding) => finding.ruleId))].sort(), row["expected"]);
    }
    assert.equal(JSON.stringify(value), before);
  });
}
