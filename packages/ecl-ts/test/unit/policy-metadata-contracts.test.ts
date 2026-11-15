import assert from "node:assert/strict";
import { test } from "node:test";
import { recordSchemas, SchemaSet } from "../../src/schema/validator.js";
import type { JsonValue } from "../../src/json/value.js";
import { json } from "./helpers.js";
type Case = { id: string; schema: string; value: JsonValue; valid: boolean };
const registry = new SchemaSet([["https://externalcontrollayer.ai/ns/schema/registry/2", json("schemas/ecl-registry-v2.schema.json")]]);
for (const c of json("tests/fixtures/policy-metadata-contracts.json") as unknown as Case[]) {
  test(`policy metadata: ${c.id}`, () => assert.equal((c.schema.endsWith("/registry/2") ? registry : recordSchemas()).isValid(c.schema, c.value), c.valid));
}
