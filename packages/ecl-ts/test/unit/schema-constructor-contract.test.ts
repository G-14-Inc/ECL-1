import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { SchemaSet } from "../../src/schema/validator.js";
import type { JsonValue } from "../../src/json/value.js";
import { repoRoot } from "./helpers.js";
const cases = JSON.parse(readFileSync(join(repoRoot(), "tests/fixtures/schema-constructor-cases.json"), "utf8")) as {id:string;schema:JsonValue;build:boolean;instance?:JsonValue;valid?:boolean}[];
for (const c of cases) test(`schema constructor: ${c.id}`, () => {
 if (!c.build) {assert.throws(() => new SchemaSet([["urn:case", c.schema]]));return;}
 const set = new SchemaSet([["urn:case", c.schema]]);
 if (c.valid !== undefined) assert.equal(set.isValid("urn:case", c.instance as JsonValue), c.valid);
});
