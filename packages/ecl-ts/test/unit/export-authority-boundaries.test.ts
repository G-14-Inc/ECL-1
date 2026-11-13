// Telemetry and sender-constraint boundaries. Robert F. Tilley Jr.; G-14, Inc.
import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluateBindingRecord, otel } from "../../src/bindings/index.js";
import { bytes, json } from "./helpers.js";

interface Case { id: string; file: string; schema: string; expected_rules: string[]; }
const root = "tests/fixtures/export-authority-boundaries/";
const cases = json(root + "manifest.json")["cases"] as unknown as Case[];
const keys = otel.loadExportKeys(bytes(root + "export-keys.json"));
for (const item of cases) {
  test("export and authority boundary: " + item.id, () => {
    const value = json(root + item.file), original = structuredClone(value);
    const findings = evaluateBindingRecord(item.schema, value, undefined, keys);
    assert.deepEqual([...new Set(findings.map(row => row.ruleId))].sort(), item.expected_rules, JSON.stringify(findings));
    assert.deepEqual(value, original);
  });
}
