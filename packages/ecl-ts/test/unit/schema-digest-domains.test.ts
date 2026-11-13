import assert from "node:assert/strict";
import { test } from "node:test";
import { recordSchemas } from "../../src/schema/validator.js";
import type { JsonValue } from "../../src/json/value.js";
import { json } from "./helpers.js";
type Case = { id: string; schema: string; value: JsonValue; valid: boolean };
for (const c of json("tests/fixtures/schema-digest-domains.json") as unknown as Case[]) {
  test(`digest schema: ${c.id}`, () => assert.equal(recordSchemas().isValid(c.schema, c.value), c.valid));
}
