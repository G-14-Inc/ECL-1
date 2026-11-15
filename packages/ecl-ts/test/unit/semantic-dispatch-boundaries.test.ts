import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {test} from "node:test";
import {SemanticValidator} from "../../src/semantic/rules.js";
import {objectFindings} from "../../src/semantic/object.js";
import {eclSchemas} from "../../src/schema/validator.js";
import {TrustPolicy} from "../../src/trust/policy.js";
import {verifyBundle,withScope} from "../../src/evidence/verify.js";
import type {JsonValue} from "../../src/json/value.js";
import {interpretedExtension} from "../../src/registry/registries.js";
import {repoRoot} from "./helpers.js";
interface Case {id:string;value:JsonValue;required:string[];absent:string[];required_paths?:Record<string,string[]>;max_rule_counts?:Record<string,number>;clean:boolean;api?:string;options?:string;kind?:string;go_only?:boolean}
const ROOT=repoRoot();const json=(path:string):JsonValue=>JSON.parse(readFileSync(join(ROOT,path),"utf8")) as JsonValue;
const cases=JSON.parse(readFileSync(join(ROOT,"tests/fixtures/semantic-dispatch-boundaries/cases.json"),"utf8")) as Case[];
const policy=TrustPolicy.load(readFileSync(join(ROOT,"conformance/suites/evidence-bundle/trust-policy.json")));
for(const c of cases.filter(c=>!c.go_only))test(`semantic dispatch boundary: ${c.id}`,()=>{
 const before=JSON.stringify(c.value);
 if(c.api==="bundle"){
  // Changed nested payloads test diagnostic ordering, not valid signatures or acceptance.
  const report=verifyBundle(c.value,policy,{now:"2026-10-01T00:00:00Z"});assert.equal(report.verdict,"invalid");
  for(const rule of c.required)assert.ok(report.findings.some(f=>f.code===rule));assert.equal(JSON.stringify(c.value),before);return;
 }
 let validator=new SemanticValidator();
 if(c.options){const id="urn:example:review-extension";validator=new SemanticValidator([id],new Map(),eclSchemas(),new Map([[id,new Set([1])]]),[],new Map(c.options==="custom"?[[id,new Set([1])]]:[]),new Map([[id,new Map([[1,new Set([c.kind!])]])]]));}
 const findings=c.api==="object"?objectFindings(c.value):validator.validate(c.value);const ids=new Set(findings.map(f=>f.ruleId));assert.equal(JSON.stringify(c.value),before);
 if(c.id==="adapter-generic-operand-complete-semantic")assert.equal(new Set(findings.map(f=>f.ruleId+"@"+f.path)).size,findings.length);
 for(const rule of c.required)assert.ok(ids.has(rule),JSON.stringify(findings));for(const rule of c.absent)assert.ok(!ids.has(rule),JSON.stringify(findings));
 for(const[rule,maximum]of Object.entries(c.max_rule_counts??{}))assert.ok(findings.filter(f=>f.ruleId===rule).length<=maximum);
 if(c.clean)assert.deepEqual(findings,[]);
 for(const[rule,paths]of Object.entries(c.required_paths??{}))for(const path of paths)assert.ok(findings.some(f=>f.ruleId===rule&&f.path===path));
 if(["dcmp-adapter-discriminator","ebmp-adapter-discriminator"].includes(c.id))assert.ok(objectFindings(c.value).some(f=>f.ruleId==="ecl.error.schema-invalid.v1"));
});
for(const mode of["valid","all-time-authority","one-time-authority","none","signer-and-time-authority"])test(`scope signer dependency: ${mode}`,()=>{
 const base=verifyBundle(json("conformance/suites/evidence-bundle/bundle-valid-observation-corroborates.json"),policy,{now:"2026-10-01T00:00:00Z"});
 assert.equal(base.verdict,"verified");assert.equal(base.effects[0]?.level,"corroborated");let dependencies=base.trustDependencies;
 if(mode==="none")dependencies=[];
 else if(mode==="all-time-authority")dependencies=dependencies.map(d=>({...d,role:"time-authority" as const}));
 else if(mode==="one-time-authority")dependencies=dependencies.map(d=>d.index===0?{...d,role:"time-authority" as const}:d);
 else if(mode==="signer-and-time-authority")dependencies=[...dependencies,...dependencies.map(d=>({...d,role:"time-authority" as const}))];
 const result=withScope({...base,trustDependencies:dependencies});const supported=["valid","signer-and-time-authority"].includes(mode);
 assert.equal(result.scope.established.includes("envelope-signatures"),supported);assert.equal(result.effects[0]?.level,supported?"corroborated":"issuer-asserted");
});

for(const envelope of[undefined,"","ECL-IE-1"])test(`outcome reason protocol selection: ${String(envelope)}`,()=>{
 const value=json("conformance/suites/control-extensions/outcome-reason-valid-expired-before-release.json") as Record<string,JsonValue>;
 if(envelope!==undefined)value.envelope_version=envelope;
 const before=JSON.stringify(value);const extensions=value.extensions as JsonValue[];
 assert.equal(interpretedExtension(value,extensions[0]),true);
 assert.equal(JSON.stringify(value),before);
});
test("adapter noncanonical host value gives a structured finding",()=>{
 const value=json("conformance/vectors/adapters/valid-native-binding.json") as Record<string,JsonValue>;
 value.noncanonical=1.5;const before=JSON.stringify(value);
 const findings=new SemanticValidator().validate(value);
 assert.ok(findings.some(f=>f.ruleId==="ecl.rule.adapter-source-binding-valid.v1"&&f.path==="/binding_digest"));
 assert.equal(JSON.stringify(value),before);
});
