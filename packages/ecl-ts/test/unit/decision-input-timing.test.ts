import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { verifyBundle } from "../../src/evidence/verify.js";
import { timingCoverage } from "../../src/evidence/decision-basis.js";
import { TrustPolicy } from "../../src/trust/policy.js";
import { parseStrictJson } from "../../src/json/strict.js";
import type { JsonObject } from "../../src/json/value.js";
import { repoRoot } from "./helpers.js";
const root=join(repoRoot(),"tests/fixtures/decision-input-timing");
const read=(name:string)=>parseStrictJson(readFileSync(join(root,name))) as JsonObject;
const manifest=read("manifest.json"), policy=TrustPolicy.load(readFileSync(join(root,"policy.json"))), SCOPE="decision-input-timing";
for(const row of manifest["cases"] as JsonObject[]) test("input timing scope: "+row["id"],()=>{
 const report=verifyBundle(read(row["bundle"] as string),policy,{now:manifest["now"] as string,...(typeof row["register"]==="string"?{register:read(row["register"])}:{})});
 assert.equal(report.verdict,row["verdict"],JSON.stringify(report.findings));
 assert.equal(report.scope.established.includes(SCOPE),row["scope"]==="established");
 assert.equal(report.scope.notEstablished.includes(SCOPE),row["scope"]==="missing"||row["scope"]==="not-established");
 assert.equal(report.scope.reasons[SCOPE],row["scope"]==="missing"?"input-times-not-recorded":undefined);
 assert(!report.scope.established.includes("recorded-times-true"));
 if(row["scope"]==="established") assert.deepEqual(report.scope.checks[SCOPE]?.objects,[1]);
});
const helpers=parseStrictJson(readFileSync(join(root,"helper-cases.json"))) as JsonObject[];
for(const row of helpers) test("input timing applicability: "+row["id"],()=>{
 assert.deepEqual(timingCoverage(row["basis"] as JsonObject,row["register"] as JsonObject,"ecl.action.ai-proposed-operation.v1","2026-09-29T10:00:00Z"),row["expected"]);
});
