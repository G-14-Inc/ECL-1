/** Schema helper domains and malformed-input findings. Robert F. Tilley Jr.; G-14, Inc. */
import assert from "node:assert/strict";
import test from "node:test";
import { SchemaSet } from "../../src/schema/validator.js";
import { objectFindings } from "../../src/semantic/object.js";
import { evaluateDocument } from "../../src/documents/documents.js";
import type { JsonValue } from "../../src/json/value.js";

const json = (value: unknown): JsonValue => value as JsonValue;
for (const [name, value] of [["NaN", NaN], ["positive infinity", Infinity], ["negative infinity", -Infinity]] as const) {
 test(`number schema refuses ${name}`, () => {
  const set = new SchemaSet([["urn:case", {type: "number"}]]);
  assert.equal(set.isValid("urn:case", value), false);
  assert.ok(set.errors("urn:case", value).length > 0);
 });
}
for (const [name, value] of [["Map", new Map([["undeclared", 1]])], ["Set", new Set([1])], ["Date", new Date(0)], ["typed array", new Uint8Array()]] as const) {
 test(`object schema does not erase ${name} members`, () => {
  const set = new SchemaSet([["urn:case", {type: "object", additionalProperties: false}]]);
  assert.equal(set.isValid("urn:case", json(value)), false);
  assert.ok(set.errors("urn:case", json(value)).length > 0);
  assert.ok(evaluateDocument("urn:case", json(value), set).some(x => x.ruleId === "ecl.error.schema-invalid.v1"));
 });
}
for (const [name, value] of [["BigInt", 1n], ["undefined", undefined], ["symbol", Symbol("x")], ["function", () => 1]] as const) {
 test(`invalid ${name} yields bounded type diagnostics`, () => {
  const set = new SchemaSet([["urn:case", {type: "string"}]]);
  assert.equal(set.isValid("urn:case", json(value)), false);
  assert.ok(set.errors("urn:case", json(value))[0]?.message.length);
  for (const key of ["message_type", "extensions"]) {
   const findings = objectFindings(json({protocol: "DCMP-2", [key]: value}));
   assert.ok(findings.some(x => x.ruleId === "ecl.error.schema-invalid.v1"));
  }
 });
}
test("valid finite/plain values retain their schema meaning", () => {
 const numbers = new SchemaSet([["urn:n", {type: "number"}]]);
 for (const value of [0, -1, 1.5, 1e100]) assert.equal(numbers.isValid("urn:n", value), true);
 assert.equal(numbers.isValid("urn:n", true), false);
 const objects = new SchemaSet([["urn:o", {type: "object", additionalProperties: false}]]);
 for (const value of [{}, Object.create(null)]) assert.equal(objects.isValid("urn:o", value), true);
});
test("ordinary cycles receive object resource refusal before recursive schema work", () => {
 const value: Record<string, unknown> = {protocol: "DCMP-2"}; value["cycle"] = value;
 assert.equal(objectFindings(json(value))[0]?.ruleId, "ecl.error.resource-limit-exceeded.v1");
});

test("caller schema configuration errors propagate rather than looking like a completed check", () => {
 assert.throws(() => objectFindings({protocol: "DCMP-2"}, new SchemaSet([])), /unresolvable schema/);
});
