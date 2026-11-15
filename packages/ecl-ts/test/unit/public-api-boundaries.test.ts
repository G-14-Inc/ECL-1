import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { objectFindings } from "../../src/semantic/object.js";
import { SemanticValidator } from "../../src/semantic/rules.js";
import { canonicalText, objectDigest } from "../../src/json/canonical.js";
import { SchemaSet } from "../../src/schema/validator.js";
import { TrustPolicyError } from "../../src/trust/policy.js";
import { registerSchemaProblems } from "../../src/evidence/decision-basis.js";
import { describeCode, describeVerdict } from "../../src/evidence/explain.js";
import type { Verdict } from "../../src/evidence/verify.js";
import { evaluateBindingRecord } from "../../src/bindings/index.js";
import type { JsonObject, JsonValue } from "../../src/json/value.js";
import { json, repoRoot, suite } from "./helpers.js";

for (const count of [136, 137, 138, 139, 140]) {
  test(`object diagnostics preserve Unicode at boundary ${count}`, () => {
    const findings = objectFindings({ protocol: "DCMP-2", ["a".repeat(count) + "😀bc"]: 1 });
    assert.ok(findings.length > 0);
    assert.doesNotThrow(() => canonicalText(findings as unknown as JsonValue));
    for (const finding of findings.filter((item) => item.ruleId === "ecl.error.schema-invalid.v1")) {
      assert.ok(Array.from(finding.path).length <= 200);
      assert.ok(Array.from(finding.message).length <= 200);
    }
  });
}
for (const count of [56, 57, 58]) {
  test(`schema descriptions preserve Unicode at boundary ${count}`, () => {
    const id = "urn:example:integer";
    const schemas = new SchemaSet(new Map([[id, { $id: id, type: "integer" }]]));
    const errors = schemas.errors(id, "a".repeat(count) + "😀tail");
    assert.equal(errors.length, 1);
    assert.doesNotThrow(() => canonicalText(errors as unknown as JsonValue));
  });
}
for (const count of [197, 198, 199, 200]) {
  test(`trust-policy errors preserve Unicode at boundary ${count}`, () => {
    const error = new TrustPolicyError("a".repeat(count) + "😀tail", "ecl.error.schema-invalid.v1");
    assert.doesNotThrow(() => canonicalText({ message: error.message }));
    assert.ok(Array.from(error.message).length <= 200);
  });
}
for (const count of [158, 159, 160]) {
  test(`register diagnostics preserve Unicode at boundary ${count}`, () => {
    const errors = registerSchemaProblems({ ["a".repeat(count) + "😀tail"]: 1 });
    assert.ok(errors.length > 0);
    assert.doesNotThrow(() => canonicalText(errors));
    assert.ok(errors.every((message) => Array.from(message).length <= 200));
  });
}
test("diagnostic truncation counts Unicode scalar values", () => {
  const message = "😀".repeat(200);
  assert.equal(new TrustPolicyError(message, "error").message, message);
  assert.equal(new TrustPolicyError(message + "x", "error").message, "😀".repeat(199) + "…");
});

for (const [name, payload] of [
  ["member-name", { protocol: "DCMP-2", ["a".repeat(137) + "😀bc"]: 1 }],
  ["enum-value", { protocol: "DCMP-2", message_type: "a".repeat(57) + "😀tail" }],
] as const) {
  test(`CLI emits a structured refusal for the Unicode ${name} boundary`, () => {
    const root = repoRoot();
    const bundle = structuredClone(json("conformance/suites/evidence-bundle/bundle-valid-succeeded.json"));
    const envelope = (bundle["envelopes"] as JsonObject[])[0]!;
    bundle["envelopes"] = [envelope]; bundle["observations"] = [];
    envelope["payload"] = Buffer.from(canonicalText(payload)).toString("base64");
    (envelope["payload_digest"] as JsonObject)["value"] = objectDigest(payload);
    const dir = mkdtempSync(join(tmpdir(), "ecl-unicode-diagnostics-"));
    try {
      const path = join(dir, "bundle.json"); writeFileSync(path, JSON.stringify(bundle));
      const result = spawnSync(process.execPath, [join(root, "packages/ecl-ts/dist/cli/ecl-verify.js"), path,
        "--trust-policy", join(root, "conformance/suites/evidence-bundle/trust-policy.json"),
        "--now", "2026-10-01T00:00:00Z", "--json"], { encoding: "utf8" });
      assert.equal(result.status, 1, result.stderr);
      const report = JSON.parse(result.stdout) as JsonObject;
      assert.equal(report["verdict"], "invalid");
      assert.equal(report["primary"], "ecl.error.schema-invalid.v1");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}

for (const name of ["constructor", "toString", "__proto__", "valueOf", "unregistered-code"]) {
  test(`explanation lookups do not inherit ${name}`, () => {
    for (const value of [describeCode(name), describeVerdict(name as Verdict)]) {
      assert.equal(typeof value, "object"); assert.equal(value.title, name);
      assert.match(value.text, /unrecognized/i);
    }
  });
}
test("registered explanation controls remain descriptive", () => {
  assert.doesNotMatch(describeCode("ecl.error.schema-invalid.v1").text, /unrecognized/i);
  assert.doesNotMatch(describeCode("ecl.rule.json-no-duplicate-members.v1").text, /unrecognized/i);
  assert.doesNotMatch(describeVerdict("verified").text, /unrecognized/i);
});

for (const family of ["aarm-binding", "acs-binding", "mcp-gateway", "otel-export", "oauth-authority"]) {
  test(`binding evaluator requires a supported schema for ${family}`, () => {
    const vector = suite(family).find((item) => item.expected === "pass" && item.stage === "binding")!;
    const value = json(vector.path); const empty = { schema_version: value["schema_version"]! };
    assert.deepEqual(evaluateBindingRecord(vector.schema!, value), []);
    assert.ok(evaluateBindingRecord(vector.schema!, empty).length > 0);
    for (const schema of ["https://externalcontrollayer.ai/ns/schema/common/1", "urn:example:unknown"]) {
      assert.throws(() => evaluateBindingRecord(schema, empty), /unsupported binding record schema/);
      assert.throws(() => evaluateBindingRecord(schema, null), /unsupported binding record schema/);
    }
  });
}

for (const [name, amount] of [["float", 1.5], ["unsafe-integer", 1e20], ["negative-zero", -0], ["noncharacter", "\ufdd0"]] as const) {
  test(`direct semantic ${name} refusal retains an unrelated budget finding`, () => {
    const value = { protocol: "DCMP-2", message_type: "decision_request", action: { parameters: { amount }, budget_debit: { amount: "-5" } } };
    for (const findings of [new SemanticValidator().validate(value), objectFindings(value)]) {
      assert.ok(findings.some((item) => item.ruleId === "ecl.rule.parameters-digest-matches.v1"));
      assert.ok(findings.some((item) => item.ruleId === "ecl.rule.budget-debit-non-negative.v1"));
    }
  });
}
test("valid parameter digest control retains only the independent budget refusal", () => {
  const parameters = { amount: 1 };
  const value = { protocol: "DCMP-2", message_type: "decision_request", action: {
    parameters, parameters_digest: { algorithm: "ecl.digest.sha-256.v1", value: objectDigest(parameters) }, budget_debit: { amount: "-5" },
  } };
  const findings = new SemanticValidator().validate(value);
  assert.ok(!findings.some((item) => item.ruleId === "ecl.rule.parameters-digest-matches.v1"));
  assert.ok(findings.some((item) => item.ruleId === "ecl.rule.budget-debit-non-negative.v1"));
});
