/** Typed identities at the direct causal and envelope verifier boundaries. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeBundle, IntegrityError, TrustPolicy, verifyEnvelope } from "../../src/index.js";
import { get, has } from "../../src/json/value.js";
import type { JsonObject } from "../../src/index.js";
import { bytes, json } from "./helpers.js";

const cases = json("tests/fixtures/identity-boundaries/cases.json");
for (const row of cases["causal"] as JsonObject[]) {
  test(`causal identity: ${String(row["name"])}`, () => {
    const members = (row["identifier_members"] ?? ["object_id"]) as string[];
    const result = analyzeBundle(row["records"] as JsonObject[], [], undefined, undefined, {
      identify: (record) => {
        const key = members.find((member) => has(record, member));
        return key === undefined ? null : get(record, key);
      },
    });
    assert.deepEqual({
      status: result.status,
      terminal: result.terminalActionIds,
      open: result.openActionIds,
      rules: [...new Set(result.findings.map((finding) => finding.ruleId))].sort(),
    }, row["expected"]);
  });
}

for (const row of cases["envelopes"] as JsonObject[]) {
  test(`signature identity: ${String(row["name"])}`, () => {
    const envelope = json("conformance/suites/envelope/envelope-valid-ed25519-signed.json");
    const entries = envelope["signatures"] as JsonObject[];
    const entry = entries[0]!;
    if (row["operation"] === "duplicate") entries.push(structuredClone(entry));
    else if (row["operation"] === "remove") delete entry[row["member"] as string];
    else if (row["operation"] === "replace") entry[row["member"] as string] = row["value"]!;
    else if (row["operation"] === "object-pair") {
      entry["key_id"] = { b: 1, "1": 1 };
      entries.push({ ...entry, key_id: { "1": 1, b: 1 } });
    }
    const policy = TrustPolicy.load(bytes("conformance/suites/envelope/trust-policy.json"));
    let actual = "";
    try {
      verifyEnvelope(envelope, policy.keyring(),
        policy.verificationContext("2026-11-10T12:00:00Z", "ecl.time.issued-at.v1"));
    } catch (error) {
      assert.ok(error instanceof IntegrityError);
      actual = error.code;
    }
    assert.equal(actual, row["expected"]);
  });
}
