// ACS record completeness regressions. Robert F. Tilley Jr.; G-14, Inc.
import assert from "node:assert/strict";
import { test } from "node:test";
import { bindingFindings, evaluateBindingRecord } from "../../src/bindings/index.js";
import type { JsonObject } from "../../src/json/value.js";
import { json } from "./helpers.js";

interface Case {
  case: string;
  record: JsonObject;
  expected_public_rules: string[];
  expected_direct_rules: string[];
  required_direct_paths: string[];
}
const manifest = json("tests/fixtures/acs-record-completeness/cases.json");
for (const item of manifest["cases"] as unknown as Case[]) {
  test("ACS record completeness: " + item.case, () => {
    const direct = bindingFindings(item.record);
    assert.deepEqual([...new Set(direct.map((finding) => finding.ruleId))].sort(), item.expected_direct_rules, JSON.stringify(direct));
    for (const path of item.required_direct_paths) assert.ok(direct.some((finding) => finding.path === path), path);
    const found = evaluateBindingRecord(manifest["schema"] as string, item.record);
    assert.deepEqual([...new Set(found.map((finding) => finding.ruleId))].sort(), item.expected_public_rules, JSON.stringify(found));
  });
}
