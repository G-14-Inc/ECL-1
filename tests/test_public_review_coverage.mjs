/** Exact stage results for the new structural coverage witnesses. */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";
import { observedForVector } from "../packages/ecl-ts/dist/conformance/corpus.js";
import { SemanticValidator } from "../packages/ecl-ts/dist/semantic/rules.js";
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const manifest = JSON.parse(fs.readFileSync(path.join(root, "conformance/suites/repair-coverage/manifest.json")));
for (const row of manifest.vectors) {
  test(row.id, () => {
    const found = [...new Set(observedForVector(row, { root, semantics: new SemanticValidator(), verdicts: new Map() }))].sort();
    assert.deepEqual(found, row.expected === "pass" ? [] : [row.expected_primary_id, ...row.expected_secondary_ids].sort());
  });
}
