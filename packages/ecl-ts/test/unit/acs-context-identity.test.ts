// Robert F. Tilley Jr.; G-14, Inc.
import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluateBindingRecord } from "../../src/bindings/index.js";
import { json } from "./helpers.js";
import type { JsonValue } from "../../src/json/value.js";
const manifest = json("tests/fixtures/acs-context-identity.json") as unknown as {
  schema: string; cases: Array<{id: string; record: JsonValue; expected_rules: string[]}>;
};
for (const row of manifest.cases) test("ACS context identity: " + row.id, () => {
  const before = JSON.stringify(row.record);
  const found = evaluateBindingRecord(manifest.schema, row.record);
  assert.deepEqual([...new Set(found.map(x => x.ruleId))].sort(), row.expected_rules, JSON.stringify(found));
  assert.equal(JSON.stringify(row.record), before);
});
