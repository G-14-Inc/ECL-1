/** MCP progress and completion controls exercise schema and profile validation. */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";
import { evaluateBindingRecord } from "../packages/ecl-ts/dist/bindings/index.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "tests/fixtures/mcp-release-progress-regressions/manifest.json"), "utf8"));
for (const c of manifest.cases) test(c.id, () => {
  const value = JSON.parse(fs.readFileSync(path.join(root, c.path), "utf8"));
  const findings = evaluateBindingRecord(manifest.schema, value);
  assert.equal(findings.length === 0, c.valid, JSON.stringify(findings));
  for (const rule of c.expected_rules) assert.ok(findings.some(f => f.ruleId === rule), JSON.stringify(findings));
});
