import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { evaluateBindingRecord } from "../../src/bindings/index.js";
import * as mcp from "../../src/bindings/mcp.js";
import { parseStrictJson } from "../../src/json/strict.js";
import type { JsonObject } from "../../src/json/value.js";
import { repoRoot } from "./helpers.js";
const root = join(repoRoot(), "tests/fixtures/mcp-record-consistency");
const read = (file: string): JsonObject => parseStrictJson(readFileSync(join(root, file))) as JsonObject;
const manifest = read("manifest.json");
for (const item of manifest["cases"] as JsonObject[]) {
  test("MCP record consistency: " + item["id"], () => {
    const value = read(item["file"] as string), before = JSON.stringify(value);
    const found = evaluateBindingRecord(mcp.EXCHANGE_SCHEMA, value);
    const direct = mcp.check(value);
    assert.equal(found.length === 0, item["accepted"], JSON.stringify(found));
    assert.equal(direct.length === 0, item["direct_accepted"], JSON.stringify(direct));
    assert.equal(found.some((finding) => finding.ruleId === "ecl.error.schema-invalid.v1"), !item["schema_valid"], JSON.stringify(found));
    if (!item["direct_accepted"]) assert.ok(direct.some((finding) => finding.ruleId === item["required_direct_rule"]), JSON.stringify(direct));
    assert.equal(JSON.stringify(value), before);
  });
}
