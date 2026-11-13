import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluateBindingRecord, jcsCanonicalize, JcsError, jcsDigest, otel } from "../../src/bindings/index.js";
import { basisProblems } from "../../src/bindings/common.js";
import { parseStrictJson } from "../../src/json/strict.js";
import type { JsonObject, JsonValue } from "../../src/json/value.js";
import { bytes } from "./helpers.js";

const fixtureRoot = "tests/fixtures/binding-input-consistency/";
// Deliberately schema-invalid parsed records are included in this entrypoint test.
const load = (file: string): JsonObject => JSON.parse(new TextDecoder().decode(bytes(fixtureRoot + file))) as JsonObject;
const keys = otel.loadExportKeys(bytes(fixtureRoot + "export-keys.json"));
interface Case { id: string; file: string; schema: string; expected_rules: string[]; }
for (const item of load("manifest.json")["cases"] as unknown as Case[]) {
  test("binding input consistency: " + item.id, () => {
    const value = load(item.file), original = structuredClone(value);
    const findings = evaluateBindingRecord(item.schema, value, undefined, keys);
    assert.deepEqual([...new Set(findings.map((finding) => finding.ruleId))].sort(), item.expected_rules, JSON.stringify(findings));
    assert.deepEqual(value, original);
  });
}
interface Segment { id: string; base64: string; expected: string; }
for (const item of load("strict-segments.json")["cases"] as unknown as Segment[]) {
  test("strict JWS segment: " + item.id, () => {
    let result = "accept";
    try { parseStrictJson(Buffer.from(item.base64, "base64")); }
    catch (error) { result = /duplicate|repeat/i.test((error as Error).message) ? "duplicate" : "strict"; }
    assert.equal(result, item.expected);
  });
}
const noncharacters = [...Array.from({ length: 32 }, (_, i) => 0xfdd0 + i), ...Array.from({ length: 17 }, (_, p) => [p * 65536 + 65534, p * 65536 + 65535]).flat()];
for (const cp of noncharacters) {
  for (const slot of ["key", "value"]) {
    test(`JCS I-JSON ${slot} noncharacter U+${cp.toString(16)}`, () => {
      const value: JsonValue = slot === "key" ? { [String.fromCodePoint(cp)]: 1 } : { a: String.fromCodePoint(cp) };
      assert.throws(() => jcsCanonicalize(value), JcsError);
    });
  }
}
test("JCS retains valid supplementary scalars, fractions and UTF-16 key order", () => {
  const value = { "\ue000": 1, "\u{10000}": 2, scalar: "🔑", values: [1.5, -0, 1e21, 1e-7] };
  assert.equal(new TextDecoder().decode(jcsCanonicalize(value)), '{"scalar":"🔑","values":[1.5,0,1e+21,1e-7],"𐀀":2,"":1}');
});
test("export key identifiers use the supported codepoint range", () => {
  const key = new Uint8Array(32);
  for (const id of ["k", "k".repeat(256), "🔑".repeat(129), "🔑".repeat(256)]) assert.equal(otel.exportKey(id, key).keyId, id);
  for (const id of ["", "k".repeat(257), "🔑".repeat(257)]) assert.throws(() => otel.exportKey(id, key), otel.ExportKeyError);
});
test("missing after snapshot has a controlled direct finding", () => {
  const value = load("missing-after-otel-valid-failed-export-evidence-unchanged.json");
  assert(otel.check(value, keys).some((finding) => finding.ruleId === "ecl.rule.otel-export-after-evidence.v1"));
});
test("direct decision basis diagnostics sort differing names by codepoint", () => {
  // This helper ordering contract is broader than the registered profile's member names.
  const record: JsonObject = { response: { protocol: "DCMP-2", message_type: "decision_response", extensions: [{ id: "ecl.ext.decision-basis.v1", version: 1, critical: false, value: { inputs: [{ input: "urn:example:input", "\ue000": 1, "\u{10000}": 1 }] } }] }, inputs: [{ input: "urn:example:input", "\ue000": 2, "\u{10000}": 2 }] };
  assert.deepEqual(basisProblems(record, "retained").map(([path]) => path), ["/inputs/0/\ue000", "/inputs/0/\u{10000}"]);
});


test("OTEL handles a large valid parameter array without argument spreading", () => {
  const record = load("control-otel-valid-request-exported.json");
  const object = record["object"] as JsonObject, action = object["action"] as JsonObject;
  action["parameters"] = { samples: Array<number>(150000).fill(0) };
  action["parameters_digest"] = jcsDigest(action["parameters"] as JsonValue);
  record["evidence_after"] = structuredClone(object);
  const attrs = (record["log_record"] as JsonObject)["attributes"] as JsonObject[];
  const keyId = (attrs.find((item) => item["key"] === otel.KEY_ID)?.["value"] as JsonObject)["stringValue"] as string;
  const key = keys.get(keyId);
  assert(key);
  for (const [name, value] of [[otel.OBJECT_DIGEST, object], [otel.PARAMETERS_DIGEST, action["parameters_digest"]]] as const) {
    const attribute = attrs.find((item) => item["key"] === name);
    assert(attribute);
    attribute["value"] = { stringValue: otel.keyedDigest(key, value as JsonObject) };
  }
  // Both copies together remain within default strict byte/depth/node limits.
  const parsed = parseStrictJson(JSON.stringify(record));
  assert.deepEqual(evaluateBindingRecord(otel.EXPORT_SCHEMA, parsed, undefined, keys), []);
});
