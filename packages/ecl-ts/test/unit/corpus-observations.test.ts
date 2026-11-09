import assert from "node:assert/strict";
import test from "node:test";
import { recordObservations, type CorpusVector, type ResultRow } from "../../src/conformance/corpus.js";

const names = ["observed_verdict", "observed_scope", "observed_effects", "observed_unresolved_predecessor_ids", "observed_canonical_sha256"] as const;
const base: CorpusVector = { id: "fixture", path: "fixture.json", stage: "evidence-bundle", expected: "pass", expected_secondary_ids: [] };
const expected: CorpusVector = { ...base, expected_verdict: "verified", expected_canonical_sha256: "a".repeat(64),
  expected_scope: { established: [], not_established: [], reasons: {} },
  expected_effects: [{ action_id: "urn:test:action", level: "none" }], expected_unresolved_predecessor_ids: [] };
function row(status: ResultRow["status"] = "not-met"): ResultRow {
  return { id: "fixture", suite: "fixture", artifact_sha256: "a".repeat(64), expected: "pass", status, observed_secondary_ids: [] };
}

test("unavailable declared observations are explicit nulls", () => {
  const result = row();
  assert.equal(recordObservations(result, expected, undefined, undefined, undefined), false);
  for (const name of names) { assert.ok(Object.hasOwn(result, name)); assert.equal(result[name], null); }
});

test("undeclared observations remain absent", () => {
  const result = row("met");
  assert.equal(recordObservations(result, base, "verified", undefined, "digest"), true);
  for (const name of names) assert.equal(Object.hasOwn(result, name), false);
});

test("unsupported rows carry no observations", () => {
  const result = row("unsupported");
  assert.equal(recordObservations(result, expected, "verified", undefined, "digest"), false);
  for (const name of names) assert.equal(Object.hasOwn(result, name), false);
});

test("actual empty collections remain arrays and objects", () => {
  const result = row();
  const observed = { scope: { established: [], not_established: [], reasons: {} }, effects: [], unresolved_predecessor_ids: [] };
  assert.equal(recordObservations(result, expected, "invalid", observed, undefined), false);
  assert.equal(result.observed_verdict, "invalid");
  assert.deepEqual(result.observed_scope, observed.scope);
  assert.deepEqual(result.observed_effects, []);
  assert.deepEqual(result.observed_unresolved_predecessor_ids, []);
});
