/** Retained counters and declared limits have mathematical integer semantics.
 * Robert F. Tilley Jr.; G-14, Inc.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { evaluateBindingRecord } from "../../src/bindings/index.js";
import type { JsonObject, JsonValue } from "../../src/json/value.js";
import { recordSchemas } from "../../src/schema/validator.js";
import { repoRoot } from "./helpers.js";

interface Case {
  id: string;
  fixture: string;
  schema: string;
  prepare: { path: string[]; value: JsonValue }[];
  field_path: string[];
  host_value: JsonValue;
  schema_valid: boolean;
  required: string[];
  clean: boolean;
}

const root = repoRoot();
const schemas = recordSchemas();
const read = (name: string): unknown => JSON.parse(readFileSync(join(root, name), "utf8"));

function replace(value: JsonObject, path: string[], replacement: JsonValue): void {
  let at = value;
  for (const key of path.slice(0, -1)) at = at[key] as JsonObject;
  at[path.at(-1)!] = replacement;
}

for (const row of read("tests/fixtures/binding-host-integers/cases.json") as Case[]) {
  test(row.id, () => {
    const value = read(row.fixture) as JsonObject;
    for (const change of row.prepare) replace(value, change.path, change.value);
    replace(value, row.field_path, row.host_value);
    const before = structuredClone(value);
    assert.equal(schemas.isValid(row.schema, value), row.schema_valid);
    const findings = evaluateBindingRecord(row.schema, value).map(item => item.ruleId);
    for (const rule of row.required) {
      assert.ok(findings.includes(rule), JSON.stringify(findings));
    }
    if (row.clean) assert.deepEqual(findings, []);
    assert.deepEqual(value, before);
  });
}
