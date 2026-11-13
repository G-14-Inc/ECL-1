import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { evaluateBindingRecord } from "../../src/bindings/index.js";
import { parseStrictJson } from "../../src/json/strict.js";
import type { JsonObject } from "../../src/json/value.js";
import { repoRoot } from "./helpers.js";

const root = repoRoot();
const manifest = JSON.parse(readFileSync(join(root, "tests/fixtures/mcp-terminal-reasons/manifest.json"), "utf8")) as {
  schema: string;
  cases: Array<{ id: string; path: string; accepted: boolean; schema_valid: boolean; expected_rules: string[] }>;
};
for (const item of manifest.cases) {
  test("MCP terminal reason: " + item.id, () => {
    const record = parseStrictJson(readFileSync(join(root, item.path))) as JsonObject;
    const before = JSON.stringify(record);
    const found = evaluateBindingRecord(manifest.schema, record);
    const rules = new Set(found.map(finding => finding.ruleId));
    assert.equal(!rules.has("ecl.error.schema-invalid.v1"), item.schema_valid, JSON.stringify(found));
    assert.equal(found.length === 0, item.accepted, JSON.stringify(found));
    assert.deepEqual([...rules].sort(), [...item.expected_rules].sort(), JSON.stringify(found));
    assert.equal(JSON.stringify(record), before);
  });
}
