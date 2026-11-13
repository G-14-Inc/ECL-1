import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { evaluateBindingRecord } from "../../src/bindings/index.js";
import { parseStrictJson } from "../../src/json/strict.js";
import type { JsonObject } from "../../src/json/value.js";
import { bytes, json } from "./helpers.js";

const manifest = json("tests/fixtures/mcp-recovery-reason-priority/manifest.json") as unknown as {
  schema: string;
  cases: Array<{ id: string; path: string; sha256: string; accepted: boolean;
    schema_valid: boolean; expected_rules: string[]; expected_state: string; required_finding_paths: string[] }>;
};
for (const item of manifest.cases) {
  test("MCP recovered terminal reason priority: " + item.id, () => {
    const data = bytes(item.path);
    assert.equal(createHash("sha256").update(data).digest("hex"), item.sha256);
    const record = parseStrictJson(data) as JsonObject;
    const before = JSON.stringify(record);
    assert.equal(((record["terminal"] as JsonObject)["event"] as JsonObject)["state"], item.expected_state);
    const found = evaluateBindingRecord(manifest.schema, record);
    const rules = [...new Set(found.map(finding => finding.ruleId))].sort();
    assert.equal(!rules.includes("ecl.error.schema-invalid.v1"), item.schema_valid, JSON.stringify(found));
    assert.deepEqual(rules, item.expected_rules, JSON.stringify(found));
    assert.equal(found.length === 0, item.accepted, JSON.stringify(found));
    for (const path of item.required_finding_paths) assert.ok(found.some(finding => finding.path === path), JSON.stringify(found));
    assert.equal(JSON.stringify(record), before);
  });
}
