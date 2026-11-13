import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { evaluateDocument } from "../../src/documents/documents.js";
import { parseStrictJson } from "../../src/json/strict.js";
import type { JsonObject } from "../../src/json/value.js";
import { repoRoot } from "./helpers.js";
interface Row { id:string; path:string; schema:string; expected:string; expected_primary_id?:string; expected_secondary_ids:string[]; }
const root=repoRoot(), rule="ecl.rule.deployment-timing-case-consistent.v1";
for(const suite of ["claim-deployment-contract","deployment-timing-case"]){
 const manifest=JSON.parse(readFileSync(join(root,"conformance/suites",suite,"manifest.json"),"utf8")) as {vectors:Row[]};
 for(const row of manifest.vectors)test(row.id,()=>{
  const value=parseStrictJson(readFileSync(join(root,row.path)));
  const actual=[...new Set(evaluateDocument(row.schema,value).map(f=>f.ruleId))].sort();
  assert.deepEqual(actual,row.expected==="fail"?[row.expected_primary_id!,...row.expected_secondary_ids].sort():[]);
 });
}
for(const invalid of [true,"1",null,1.5,NaN,Infinity])test("parsed timing type: "+String(invalid),()=>{
 const value=parseStrictJson(readFileSync(join(root,"conformance/suites/document-coverage/deployment-valid-federated-example.json"))) as JsonObject;
 (value["timing_case"] as JsonObject)["federated_exchange_seconds"]=invalid;
 const findings=evaluateDocument("https://externalcontrollayer.ai/ns/schema/deployment-profile/1",value);
 assert.ok(findings.some(f=>f.ruleId==="ecl.error.schema-invalid.v1"));
 assert.ok(!findings.some(f=>f.ruleId===rule));
});
