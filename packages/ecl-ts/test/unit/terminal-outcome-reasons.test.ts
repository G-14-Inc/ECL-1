import { terminalReasonFindings } from "../../src/bindings/terminal-reason.js";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { evaluateBindingRecord } from "../../src/bindings/index.js";
import { parseStrictJson } from "../../src/json/strict.js";
import type { JsonObject } from "../../src/json/value.js";
import { repoRoot } from "./helpers.js";

const root = repoRoot();
const manifest = JSON.parse(readFileSync(join(root, "tests/fixtures/terminal-outcome-reasons/manifest.json"), "utf8")) as {
  helper_cases: Array<{ id: string; path: string; response_outcome: string | null; paired: boolean; expected_rules: string[] }>;
  schema: string;
  cases: Array<{ id: string; path: string; accepted: boolean; schema_valid: boolean; expected_rules: string[] }>;
};
for (const item of manifest.cases) {
  test("AARM terminal outcome reasons: " + item.id, () => {
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

for (const item of manifest.helper_cases) {
  test("paired terminal outcome reason: " + item.id, () => {
    const record = parseStrictJson(readFileSync(join(root, item.path))) as JsonObject;
    const terminal = record["terminal"] as JsonObject;
    const before = JSON.stringify(terminal);
    const found = terminalReasonFindings(terminal, item.response_outcome, item.paired);
    assert.deepEqual([...new Set(found.map(finding => finding.ruleId))].sort(), [...item.expected_rules].sort());
    assert.ok(found.every(finding => finding.path === "/extensions"));
    assert.equal(JSON.stringify(terminal), before);
  });
}
