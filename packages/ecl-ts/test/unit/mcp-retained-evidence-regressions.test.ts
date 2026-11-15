import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { evaluateBindingRecord } from "../../src/bindings/index.js";
import { check, refusalCause } from "../../src/bindings/mcp.js";
import { parseStrictJson } from "../../src/json/strict.js";
import type { JsonObject } from "../../src/json/value.js";
import { repoRoot } from "./helpers.js";

const root = repoRoot();
const manifest = JSON.parse(readFileSync(join(root, "tests/fixtures/mcp-retained-evidence-regressions/manifest.json"), "utf8")) as {
  schema: string;
  cases: Array<{ id: string; path: string; accepted: boolean; schema_valid: boolean; expected_rules: string[] }>;
};
for (const item of manifest.cases) {
  test("MCP retained evidence: " + item.id, () => {
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

test("MCP malformed discharge keeps obligation refusal precedence", () => {
  const record = parseStrictJson(readFileSync(join(root, "tests/fixtures/mcp-record-consistency/clock-intrinsic-proof-failure-control.json"))) as JsonObject;
  assert.deepEqual(refusalCause(record), ["obligation-unproven", "ecl.error.obligation-unproven.v1", (record["decision_request"] as JsonObject)["message_id"]]);
  assert.deepEqual([...new Set(check(record).map(item => item.ruleId))], ["ecl.rule.mcp-obligations-discharged.v1"]);
});
