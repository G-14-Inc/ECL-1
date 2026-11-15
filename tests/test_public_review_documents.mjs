/** Document placeholder corrections preserve their intended verifier outcomes. */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";
import { evaluateDocument } from "../packages/ecl-ts/dist/documents/documents.js";
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const read = relative => JSON.parse(fs.readFileSync(path.join(root, relative), "utf8"));
const corrected = new Set(read("tests/fixtures/document-digest-repairs/corrections.json").corrections.map(row => row.path));
for (const row of read("conformance/suites/document-coverage/manifest.json").vectors.filter(row => corrected.has(row.path))) {
  test(row.id, () => {
    const found = [...new Set(evaluateDocument(row.schema, read(row.path)).map(item => item.ruleId))].sort();
    const expected = row.expected === "pass" ? [] : [row.expected_primary_id, ...row.expected_secondary_ids].sort();
    assert.deepEqual(found, expected);
  });
}
