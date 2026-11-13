/** IE1-034 per-entry time binding and TP1-006 current attestation policy checks. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseStrictJson, reportToJson, TrustPolicy, verifyBundle } from "../../src/index.js";
import type { JsonObject } from "../../src/index.js";
import { bytes } from "./helpers.js";

const cases = parseStrictJson(bytes("tests/fixtures/trust-signature-entry.json")) as JsonObject[];
for (const c of cases) {
  test(`signature entry time / attestation eligibility: ${String(c["id"])}`, () => {
    const report = reportToJson(verifyBundle(c["bundle"] as JsonObject,
      TrustPolicy.load(JSON.stringify(c["policy"])), { now: c["now"] as string }));
    const expected = c["expected"] as JsonObject;
    assert.equal(report["verdict"], expected["verdict"]);
    assert.equal(report["primary"], expected["primary"]);
    for (const dependency of expected["dependencies"] as JsonObject[]) {
      const matches = (report["trust_dependencies"] as JsonObject[])
        .filter(d => d["index"] === dependency["index"] && d["role"] === dependency["role"]);
      const actual = matches[dependency["occurrence"] as number];
      assert.ok(actual !== undefined);
      for (const [key, value] of Object.entries(dependency)) {
        if (key !== "occurrence") assert.deepEqual(actual[key], value, key);
      }
    }
  });
}
