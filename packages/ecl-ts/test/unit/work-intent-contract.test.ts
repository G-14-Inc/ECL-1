import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { evaluateDocument } from "../../src/documents/documents.js";
import { parseStrictJson } from "../../src/json/strict.js";
import { recordSchemas } from "../../src/schema/validator.js";
import { validateSafeStateProfile } from "../../src/semantic/safe-state.js";
import { repoRoot } from "./helpers.js";
interface Row { id:string; path:string; schema:string; stage:string; expected:string; expected_primary_id?:string; expected_secondary_ids:string[]; }
const root=repoRoot();
for(const suite of ["safe-state-declaration-contract","work-intent-contract"]){
 const manifest=JSON.parse(readFileSync(join(root,"conformance/suites",suite,"manifest.json"),"utf8")) as {vectors:Row[]};
 for(const row of manifest.vectors)test(row.id,()=>{
  const value=parseStrictJson(readFileSync(join(root,row.path))), original=JSON.stringify(value);
  const found=row.stage==="document"?evaluateDocument(row.schema,value):[
   ...(recordSchemas().errors(row.schema,value,1).length?[{ruleId:"ecl.error.schema-invalid.v1"}]:[]),
   ...validateSafeStateProfile(value)
  ];
  const actual=[...new Set(found.map(f=>f.ruleId))].sort();
  assert.deepEqual(actual,row.expected==="fail"?[row.expected_primary_id!,...row.expected_secondary_ids].sort():[]);
  assert.equal(JSON.stringify(value),original);
 });
}
