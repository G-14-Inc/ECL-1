import assert from "node:assert/strict";
import { test } from "node:test";
import { DOCUMENT_SCHEMAS, SchemaSet, eclSchemas, evaluateDocument, recordSchemas, isDcmpMessage, isEbmpObject, isEvidenceBundle, isIntegrityEnvelope, isTrustPolicyDocument, parseStrictJson, validateSchema } from "../../src/index.js";
import { isAbsoluteUri, isDateTime } from "../../src/schema/formats.js";
import { bytes, json, suite } from "./helpers.js";
import type { JsonValue } from "../../src/index.js";

test("the uri format follows the reference: printable ASCII, escapes, scheme, and authority or path", () => {
  const valid = ["urn:example:key:a", "https://externalcontrollayer.ai/ns/schema/dcmp/2", "https://[::1]/x", "https://[fe80::1%25eth0]:8443/", "https://[v1.x]/", "mailto:a@b", "a:b%20c"];
  const invalid = ["", "a:", "https://", "x:?y", "mailto:#x", "1a:b", "https://h/%2", "https://h/%zz", "https://[1.2.3.4]/", "https://us[er]@host/", "https://[::1/x", "has space:x", "café:x", "a\\b:c", 5];
  for (const value of valid) {
    assert.equal(isAbsoluteUri(value), true, value);
  }
  for (const value of invalid) {
    assert.equal(isAbsoluteUri(value), false, String(value));
  }
});

test("the date-time format is an ECL instant on a day that exists", () => {
  for (const value of ["2026-10-01T00:00:00Z", "2024-02-29T23:59:59.123456789Z", "0001-01-01T00:00:00Z"]) {
    assert.equal(isDateTime(value), true, value);
  }
  for (const value of ["2026-02-29T00:00:00Z", "0000-01-01T00:00:00Z", "2026-04-31T00:00:00Z", "2026-10-01T24:00:00Z", "2026-10-01T00:00:60Z", "2026-10-01T00:00:00+00:00", "2026-10-01T00:00:00.1234567890Z", "2026-10-01 00:00:00Z", 1]) {
    assert.equal(isDateTime(value), false, String(value));
  }
});

test("patterns are ECMA-262: $ is the end of the string and . excludes line terminators", () => {
  const set = new SchemaSet([
    ["urn:test:anchors", { type: "string", pattern: "^[a-z]+$" }],
    ["urn:test:dot", { type: "string", pattern: "^a.b$" }],
  ]);
  assert.equal(set.isValid("urn:test:anchors", "abc"), true);
  assert.equal(set.isValid("urn:test:anchors", "abc\n"), false);
  assert.equal(set.isValid("urn:test:dot", "a b"), false);
  assert.equal(set.isValid("urn:test:dot", "a-b"), true);
});

test("lengths count code points and enums keep booleans apart from numbers", () => {
  const set = new SchemaSet([
    ["urn:test:length", { type: "string", maxLength: 1 }],
    ["urn:test:enum", { enum: [1, "a"] }],
    ["urn:test:unique", { type: "array", uniqueItems: true }],
  ]);
  assert.equal(set.isValid("urn:test:length", "😀"), true);
  assert.equal(set.isValid("urn:test:enum", true), false);
  assert.equal(set.isValid("urn:test:enum", 1), true);
  assert.equal(set.isValid("urn:test:unique", [1, true]), true);
  assert.equal(set.isValid("urn:test:unique", [{ a: 1, b: 2 }, { b: 2, a: 1 }]), false);
});

test("unevaluatedProperties sees the members of satisfied branches only", () => {
  const set = new SchemaSet([
    [
      "urn:test:unevaluated",
      {
        allOf: [{ properties: { a: { type: "string" } } }],
        if: { required: ["kind"], properties: { kind: { const: "x" } } },
        then: { properties: { x: true } },
        else: { properties: { y: true } },
        properties: { kind: true },
        unevaluatedProperties: false,
      },
    ],
  ]);
  assert.equal(set.isValid("urn:test:unevaluated", { kind: "x", a: "s", x: 1 }), true);
  assert.equal(set.isValid("urn:test:unevaluated", { kind: "x", a: "s", y: 1 }), false);
  assert.equal(set.isValid("urn:test:unevaluated", { kind: "z", y: 1 }), true);
});

test("a keyword the validator does not implement is refused when the set is built", () => {
  assert.throws(() => new SchemaSet([["urn:test:unknown", { type: "array", contains: true, minContains: 2 }]]), /unsupported schema keyword minContains/);
  assert.throws(() => new SchemaSet([["urn:test:format", { type: "string", format: "email" }]]), /unsupported format/);
  assert.throws(() => new SchemaSet([["urn:test:nested", { type: "array", contains: { format: "email" } }]]), /unsupported format/);
});

test("contains needs one item that its schema accepts, and ignores anything but an array", () => {
  const set = new SchemaSet([["urn:test:contains", { contains: { const: "Decision" } }]]);
  assert.equal(set.isValid("urn:test:contains", ["Authority", "Decision"]), true);
  assert.equal(set.isValid("urn:test:contains", ["Authority"]), false);
  assert.equal(set.isValid("urn:test:contains", []), false);
  assert.equal(set.isValid("urn:test:contains", "Decision"), true);
  assert.deepEqual(
    set.errors("urn:test:contains", ["x"]).map((error) => error.keyword),
    ["contains"],
  );
});

test("the record schemas: every binding record and claim or assessment document schema is embedded", () => {
  const set = recordSchemas();
  for (const name of ["binding/aarm-exchange/1", "binding/acs-exchange/1", "binding/mcp-gateway-exchange/1", "binding/otel-export/1", "binding/oauth-presentation/1", ...DOCUMENT_SCHEMAS.map((item) => item.replace("https://externalcontrollayer.ai/ns/schema/", ""))]) {
    assert.ok(set.identifiers().includes("https://externalcontrollayer.ai/ns/schema/" + name), name);
  }
  assert.ok(!eclSchemas().identifiers().includes("https://externalcontrollayer.ai/ns/schema/binding/otel-export/1"));
  // A lookahead in a document pattern (the offline verification package's relative paths).
  const document = suite("document-coverage").find((item) => item.id === "offline-package-valid");
  assert.ok(document !== undefined);
  assert.deepEqual(evaluateDocument(document.schema as string, json(document.path)), []);
});

test("schema-coverage suite: the schema decision of every vector", () => {
  for (const vector of suite("schema-coverage")) {
    if (vector.schema === undefined) {
      continue;
    }
    const errors = validateSchema(vector.schema, parseStrictJson(bytes(vector.path)));
    const schemaInvalid = vector.expected === "fail" && vector.expected_primary_id === "ecl.error.schema-invalid.v1";
    if (vector.expected === "pass") {
      assert.deepEqual(errors, [], vector.id);
    } else if (schemaInvalid) {
      assert.notEqual(errors.length, 0, vector.id);
    }
  }
});

test("type guards check the schemas", () => {
  const request = json("conformance/vectors/dcmp-2/valid-decision-request.json") as JsonValue;
  assert.equal(isDcmpMessage(request), true);
  assert.equal(isEbmpObject(request), false);
  assert.equal(isTrustPolicyDocument(json("conformance/suites/trust-policy/trust-policy-valid.json")), true);
  const bundle = json("conformance/suites/evidence-bundle/bundle-valid-succeeded.json");
  assert.equal(isEvidenceBundle(bundle), true);
  assert.equal(isIntegrityEnvelope((bundle["envelopes"] as JsonValue[])[0] as JsonValue), true);
  assert.ok(eclSchemas().identifiers().includes("https://externalcontrollayer.ai/ns/schema/common/1"));
});
