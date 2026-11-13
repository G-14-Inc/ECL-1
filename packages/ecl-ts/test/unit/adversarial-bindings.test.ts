import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluateBindingRecord } from "../../src/bindings/index.js";
import { json } from "./helpers.js";

interface Case { id: string; file: string; schema: string; expected_rules: string[]; }
const fixtureRoot = "tests/fixtures/adversarial-bindings/";
const cases = json(fixtureRoot + "manifest.json")["cases"] as unknown as Case[];
for (const item of cases) {
  test("adversarial binding record: " + item.id, () => {
    const findings = evaluateBindingRecord(item.schema, json(fixtureRoot + item.file));
    assert.deepEqual([...new Set(findings.map((finding) => finding.ruleId))].sort(), item.expected_rules, JSON.stringify(findings));
  });
}
