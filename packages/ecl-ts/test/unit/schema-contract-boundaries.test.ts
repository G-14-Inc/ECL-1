import assert from "node:assert/strict";
import { test } from "node:test";
import { eclSchemas, recordSchemas } from "../../src/schema/validator.js";
import { SemanticValidator } from "../../src/semantic/rules.js";
import { evaluateBindingRecord } from "../../src/bindings/index.js";
import { verifyBundle } from "../../src/evidence/verify.js";
import { TrustPolicy } from "../../src/trust/policy.js";
import type { EbmpStateEvent } from "../../src/generated/types.js";
import type { JsonValue } from "../../src/json/value.js";
import { bytes, json } from "./helpers.js";

interface Case { id: string; lane: string; value: JsonValue; schema: string; valid: boolean;
  rules: string[]; verdict: string; primary: string | null; }
const policy = TrustPolicy.load(bytes("conformance/fixtures/evidence/trust-policy.json"));
for (const item of json("tests/fixtures/schema-contract-boundaries.json") as unknown as Case[]) {
  test(`schema contract: ${item.id}`, () => {
    if (item.lane === "bundle") {
      const report = verifyBundle(item.value, policy, { now: "2026-10-01T00:00:00Z" });
      assert.equal(report.verdict, item.verdict);
      assert.equal(report.findings[0]?.code ?? null, item.primary);
      return;
    }
    const schemas = ["binding", "primitive"].includes(item.lane) ? recordSchemas() : eclSchemas();
    assert.equal(schemas.isValid(item.schema, item.value), item.valid);
    if (item.lane === "adapter") {
      assert.deepEqual([...new Set(new SemanticValidator().validate(item.value).map(f => f.ruleId))].sort(), item.rules);
    } else if (item.lane === "binding" && item.valid) {
      assert.deepEqual(evaluateBindingRecord(item.schema, item.value), []);
    }
  });
}

test("generated frontier map retains its integer member type", () => {
  const valid: NonNullable<EbmpStateEvent["frontiers"]> = { policy_epochs: 0 };
  // @ts-expect-error A frontier member is numeric, not arbitrary JSON.
  const invalid: NonNullable<EbmpStateEvent["frontiers"]> = { policy_epochs: "zero" };
  assert.equal(typeof valid.policy_epochs, "number");
  assert.equal(typeof invalid.policy_epochs, "string");
});
