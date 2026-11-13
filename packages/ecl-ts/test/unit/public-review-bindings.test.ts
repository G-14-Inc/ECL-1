import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { evaluateBindingRecord } from "../../src/index.js";
import type { JsonObject } from "../../src/index.js";
import { validateSafeStateProfile, CLASSIFICATION_RULE } from "../../src/semantic/safe-state.js";
import { validateSchema } from "../../src/schema/validator.js";
import { repoRoot } from "./helpers.js";
const root=repoRoot();
const manifest=JSON.parse(readFileSync(resolve(root,"conformance/suites/repair-bindings/manifest.json"),"utf8")) as {vectors:Array<{id:string,path:string,schema:string,stage:string,expected:string,expected_primary_id?:string,expected_secondary_ids:string[]}>};
for(const vector of manifest.vectors){
  test(vector.id,()=>{
    const value=JSON.parse(readFileSync(resolve(root,vector.path),"utf8")) as JsonObject;
    const findings=vector.stage==="binding"?evaluateBindingRecord(vector.schema,value):
      [...(validateSchema(vector.schema,value).length>0?[{ruleId:"ecl.error.schema-invalid.v1"}]:[]),...validateSafeStateProfile(value)];
    const actual=[...new Set(findings.map(f=>f.ruleId))].sort();
    const expected=vector.expected==="fail"?[vector.expected_primary_id as string,...vector.expected_secondary_ids].sort():[];
    assert.deepEqual(actual,expected);
  });
}
test("direct safe-state API rejects an advisory required-proof dependency",()=>{
 const value=JSON.parse(readFileSync(resolve(root,"conformance/suites/repair-bindings/repair-safe-state-advisory-required-proof.json"),"utf8")) as JsonObject;
 assert.ok(validateSafeStateProfile(value).some(f=>f.ruleId===CLASSIFICATION_RULE));
});
