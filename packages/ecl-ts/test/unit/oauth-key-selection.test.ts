/** Ambiguous configured key identifiers fail before selection, including exact repeats. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { bindingFindings, evaluateBindingRecord } from "../../src/index.js";
import type { JsonObject } from "../../src/index.js";
import { json } from "./helpers.js";
const cases = json("tests/fixtures/oauth-key-selection/cases.json") as unknown as JsonObject[];
for (const row of cases) {
  test(`OAuth key selection: ${String(row["name"])}`, () => {
    const record = row["record"] as JsonObject;
    for (const findings of [bindingFindings(record), evaluateBindingRecord(
      "https://externalcontrollayer.ai/ns/schema/binding/oauth-presentation/1", record)]) {
      assert.deepEqual([...new Set(findings.map((finding) => finding.ruleId))].sort(), row["expected_rules"]);
    }
  });
}
