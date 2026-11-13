import assert from "node:assert/strict";
import {test} from "node:test";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";
import {analyzeBundle} from "../../src/bundle/causal.js";
import {evaluateDocument} from "../../src/documents/documents.js";
import type {JsonValue} from "../../src/json/value.js";
import type {DeploymentProfileFallback} from "../../src/generated/types.js";
import {repoRoot} from "./helpers.js";
const root=repoRoot();
const load=(p:string):unknown=>JSON.parse(readFileSync(resolve(root,p),"utf8"));
const vectors=load("conformance/suites/repair-contracts/manifest.json") as {vectors:Array<{id:string,path:string,schema:string,expected:string}>};
for(const v of vectors.vectors)test(v.id,()=>assert.equal(evaluateDocument(v.schema,load(v.path) as JsonValue).length>0,v.expected==="fail"));
const graphs=load("tests/fixtures/repair-causal-context.json") as Array<{name:string,records:JsonValue[],status:string,required_findings:string[]}>;
for(const c of graphs)test("causal "+c.name,()=>{
 const r=analyzeBundle(c.records,[],1000,128,{causalContext:true});
 assert.equal(r.status,c.status);
 for(const code of c.required_findings)assert.ok(r.findings.some(f=>f.ruleId===code));
 if(c.status!=="indeterminate")assert.deepEqual(r.findings,[]);
});
// Compilation must accept the schema's four-element tuple and reject omissions/reordering.
const valid:DeploymentProfileFallback["precedence"]=["emergency_halt","restricted","degraded","ordinary"];
// @ts-expect-error empty precedence cannot satisfy prefixItems/minItems
const empty:DeploymentProfileFallback["precedence"]=[];
// @ts-expect-error fallback order is fixed by the schema
const reversed:DeploymentProfileFallback["precedence"]=["ordinary","degraded","restricted","emergency_halt"];
test("fallback precedence preserves exact generated tuple",()=>assert.equal(valid.length,4));
void empty;void reversed;
