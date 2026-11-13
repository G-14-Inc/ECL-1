/** Typed dispatch and namespace tests. Robert F. Tilley Jr.; G-14, Inc. */
import assert from "node:assert/strict";
import { test } from "node:test";
import type { JsonObject } from "../../src/json/value.js";
import { SemanticValidator } from "../../src/semantic/rules.js";
import { recordSchemas } from "../../src/schema/validator.js";
import { json } from "./helpers.js";

type Case = { name: string; value: JsonObject; schema: string | null; expected_schema?: boolean; expected_rules: string[] };
for (const c of json("tests/fixtures/schema-boundaries.json") as unknown as Case[]) {
  test(`schema boundary: ${c.name}`, () => {
    if (c.schema !== null) assert.equal(recordSchemas().isValid(c.schema, c.value), c.expected_schema);
    assert.deepEqual([...new Set(new SemanticValidator().validate(c.value).map(f => f.ruleId))].sort(), c.expected_rules);
  });
}
