// Authentication record regressions. Robert F. Tilley Jr.; G-14, Inc.
import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluateBindingRecord, acs } from "../../src/bindings/index.js";
import { json } from "./helpers.js";

interface Case { case: string; path: string; schema: string; expected_rules: string[]; message?: string; required_paths?: string[]; }
const root = "tests/fixtures/authentication-boundaries/";
const cases = json(root + "manifest.json")["cases"] as unknown as Case[];
for (const item of cases) {
  test("authentication record: " + item.case, () => {
    const found = evaluateBindingRecord(item.schema, json(root + item.path));
    assert.deepEqual([...new Set(found.map((f) => f.ruleId))].sort(), item.expected_rules, JSON.stringify(found));
    if (item.message !== undefined) assert.ok(found.some((f) => f.message === item.message));
    for (const path of item.required_paths ?? []) assert.ok(found.some((f) => f.path === path));
  });
}
test("native DEFER zero is a valid immediate deadline", () => {
  assert.equal(acs.deadline(json(root + "acs-defer-zero-denied-control.json"), "defer"), 1790758800080000000n);
});
