import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { verifyBundle } from "../../src/evidence/verify.js";
import { verifyBundleBytes, VerifierInputError } from "../../src/evidence/bytes.js";
import { TrustPolicy } from "../../src/trust/policy.js";
import { parseStrictJson, MAX_JSON_DEPTH, MAX_JSON_NODES } from "../../src/json/strict.js";
import type { JsonObject,JsonValue } from "../../src/json/value.js";
import { repoRoot } from "./helpers.js";
const root=join(repoRoot(),"tests/fixtures/bundle-contract-regressions");
const policyBytes=readFileSync(join(root,"f001-prepared-control.policy.json"));
const policy=TrustPolicy.load(policyBytes), now="2026-10-01T00:00:00Z", RESOURCE="ecl.error.resource-limit-exceeded.v1";
function bundle(value:JsonValue):JsonObject{
 const b=parseStrictJson(readFileSync(join(root,"f001-prepared-control.bundle.json"))) as JsonObject;
 (b["envelopes"] as JsonObject[])[0]!["extensions"]=[{id:"com.example.annotation.v1",version:1,critical:false,value}];return b;
}
function nodes(value:JsonValue):number{const todo=[value];let n=0;while(todo.length){const v=todo.pop()!;n++;if(Array.isArray(v))todo.push(...v);else if(v!==null&&typeof v==="object")todo.push(...Object.values(v));}return n;}
for(const [name,excess] of [["depth-at",false],["depth-over",true],["nodes-at",false],["nodes-over",true],["cycle",true],["shared",false],["shared-over",true],["large-string",false]] as const)test("mapping limit: "+name,()=>{
 let v:JsonValue=null;
 if(name.startsWith("depth")){for(let i=0;i<MAX_JSON_DEPTH-5+Number(name==="depth-over");i++)v=[v];}
 else if(name.startsWith("nodes"))v=Array(MAX_JSON_NODES-nodes(bundle([]))+Number(name==="nodes-over")).fill(0) as number[];
 else if(name==="cycle"){const a:JsonValue[]=[];a.push(a);v=a;}
 else if(name==="shared"){const shared={values:[1,2]};v=[shared,shared];}
 else if(name==="shared-over"){for(let i=0;i<20;i++)v=[v,v];}
 else v="a".repeat(1024*1024+1);
 const report=verifyBundle(bundle(v),policy,{now});
 assert.equal(report.verdict,excess?"invalid":"verified",JSON.stringify(report.findings));
 if(excess){assert.equal(report.findings[0]?.code,RESOURCE);assert.deepEqual(report.envelopeChecks,[]);}
});
test("byte interface retains its separate byte limit",()=>{
 const bytes=new TextEncoder().encode(JSON.stringify(bundle("a".repeat(1024*1024+1))));
 assert.throws(()=>verifyBundleBytes(bytes,policyBytes,{now}),(e:unknown)=>e instanceof VerifierInputError&&e.code===RESOURCE);
});
