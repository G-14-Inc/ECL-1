import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { evaluateDocument } from "../../src/documents/documents.js";
import { parseStrictJson } from "../../src/json/strict.js";
import { repoRoot } from "./helpers.js";

interface Row {
  id: string; path: string; schema: string; expected: string;
  expected_primary_id?: string; expected_secondary_ids: string[];
}
const root = repoRoot();
const manifest = JSON.parse(readFileSync(join(root, "conformance/suites/lifecycle-policy-contract/manifest.json"), "utf8")) as { vectors: Row[] };
for (const row of manifest.vectors) test(row.id, () => {
  const value = parseStrictJson(readFileSync(join(root, row.path)));
  const original = JSON.stringify(value);
  const found = evaluateDocument(row.schema, value);
  assert.deepEqual(found.map(f => f.ruleId), row.expected === "fail" ? [row.expected_primary_id!, ...row.expected_secondary_ids] : []);
  assert.equal(JSON.stringify(value), original);
});
