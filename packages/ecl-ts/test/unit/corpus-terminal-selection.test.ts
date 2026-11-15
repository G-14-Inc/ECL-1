import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { SemanticValidator } from "../../src/index.js";
import type { JsonObject } from "../../src/index.js";
import { observedForVector, selectFindings } from "../../src/conformance/corpus.js";
import { bytes, json, repoRoot } from "./helpers.js";

interface SelectionCase {
  id: string;
  observed: string[];
  primary: string | null;
  secondary: string[];
  error_contains?: string;
}
interface RecordCase extends SelectionCase { path: string; sha256: string; schema: string }
const manifest = json("tests/fixtures/corpus-terminal-selection/manifest.json");
const precedence = new Map((json("registries/semantic-rules.json")["entries"] as JsonObject[])
  .filter((entry) => entry["status"] === "active")
  .map((entry) => [entry["id"] as string, (entry["attributes"] as JsonObject)["precedence"] as number]));
const errors = new Set((json("registries/error-codes.json")["entries"] as JsonObject[])
  .filter((entry) => entry["status"] === "active").map((entry) => entry["id"] as string));

for (const item of manifest["record_cases"] as unknown as RecordCase[]) {
  test(`terminal corpus evaluator and selector: ${item.id}`, () => {
    const data = bytes(item.path);
    assert.equal(createHash("sha256").update(data).digest("hex"), item.sha256);
    const observed = observedForVector({ id: item.id, path: item.path, stage: "binding", schema: item.schema,
      expected: "pass", expected_secondary_ids: [] },
    { root: repoRoot(), semantics: new SemanticValidator(), verdicts: new Map() });
    assert.deepEqual([...new Set(observed)].sort(), item.observed);
    assert.deepEqual(selectFindings(observed, precedence, errors), [item.primary, item.secondary]);
    assert.deepEqual(bytes(item.path), data);
  });
}

for (const item of manifest["selection_cases"] as unknown as SelectionCase[]) {
  test(`generic fallback preserves selector boundary: ${item.id}`, () => {
    for (const observed of [item.observed, [...item.observed].reverse(), [...item.observed, ...item.observed]]) {
      if (item.error_contains !== undefined) {
        assert.throws(() => selectFindings(observed, precedence, errors), new RegExp(item.error_contains));
      } else {
        assert.deepEqual(selectFindings(observed, precedence, errors), [item.primary, item.secondary]);
      }
    }
  });
}
