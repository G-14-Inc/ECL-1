import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { BindingError, checkResponseBinding, checkEventBinding, checkAuthorityEventBinding } from "../../src/binding/binding.js";
import * as oauth from "../../src/bindings/oauth.js";
import * as mcp from "../../src/bindings/mcp.js";
import { parseStrictJson } from "../../src/json/strict.js";
import type { JsonObject } from "../../src/json/value.js";
import { json } from "./helpers.js";

interface Case { id: string; file: string; kind: string; expected: string | null; refusal_expected?: string; authority_expected?: string | null; }
function fixture(name: string): JsonObject {
  const external = process.env["ECL_CAPABILITY_FIXTURES"];
  return external === undefined ? json("tests/fixtures/single-use-capability/" + name) : parseStrictJson(readFileSync(join(external, name))) as JsonObject;
}
function code(call: () => void): string | null {
  try { call(); } catch(error) { if(error instanceof BindingError) return error.code; throw error; }
  return null;
}
for(const item of fixture("manifest.json")["cases"] as unknown as Case[]) {
  test("single-use capability: " + item.id, () => {
    const r=fixture(item.file);
    if(item.kind === "pair") assert.equal(code(() => checkResponseBinding(r["request"]!,r["response"]!)),item.expected);
    else if(item.kind === "event") {
      assert.equal(code(() => checkEventBinding(r["released"]!,r["request"]!,r["response"]!)),item.expected);
      assert.equal(code(() => checkAuthorityEventBinding(r["consumed"]!,r["response"]!)),item.authority_expected);
    } else if(item.kind === "oauth") {
      assert.equal(oauth.presentationChecks(r)[0]?.[2] ?? null,item.expected);
      assert.equal(oauth.refusalProblems(r)[0]?.[2] ?? null,item.refusal_expected ?? item.expected);
    } else if(item.kind === "mcp") {
      const findings=mcp.check(r);
      if(item.expected === null) { assert.deepEqual(findings,[]); assert.equal(mcp.refusalCause(r),null); }
      else { assert.ok(findings.some((finding) => finding.ruleId===item.expected),JSON.stringify(findings)); assert.equal(mcp.refusalCause(r)?.[0],"decision-invalid"); }
    } else assert.fail(item.kind);
  });
}
