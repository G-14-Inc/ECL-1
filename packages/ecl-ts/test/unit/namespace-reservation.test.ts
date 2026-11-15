import assert from "node:assert/strict";
import { test } from "node:test";
import type { JsonObject } from "../../src/json/value.js";
import { reservedExtensionNamespace } from "../../src/schema/formats.js";
import { eclSchemas } from "../../src/schema/validator.js";
import { objectFindings } from "../../src/semantic/object.js";
import { json } from "./helpers.js";

type Case = { name: string; identifier: string; reserved: boolean };
const request = json("tests/fixtures/extension-consumer-cases/request-control.json");
for (const row of json("tests/fixtures/namespace-reservation-cases.json") as unknown as Case[]) {
  for (const critical of [false, true]) {
    test(`namespace reservation: ${row.name}, critical=${critical}`, () => {
      const value: JsonObject = structuredClone(request);
      value["extensions"] = [{ id: row.identifier, version: 1, critical, value: { grant_authority: true } }];
      const before = structuredClone(value);
      assert.equal(reservedExtensionNamespace(row.identifier), row.reserved);
      assert.equal(eclSchemas().isValid("https://externalcontrollayer.ai/ns/schema/dcmp/2", value), !row.reserved);
      const expected: string[] = [];
      if (row.reserved) expected.push("ecl.error.schema-invalid.v1", "ecl.rule.extension-namespace-allocated.v1");
      if (critical) expected.push("ecl.rule.unknown-critical-extension-rejected.v1");
      assert.deepEqual([...new Set(objectFindings(value).map(f => f.ruleId))].sort(), expected.sort());
      assert.deepEqual(value, before);
    });
  }
}
