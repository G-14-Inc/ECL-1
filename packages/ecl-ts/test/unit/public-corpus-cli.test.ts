// Complete report CLI on a miniature local corpus. Robert F. Tilley Jr.; G-14, Inc.
// These controls exercise the producer/report boundary, not full qualification.
import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { CAPABILITIES } from "../../src/conformance/corpus.js";
import { repoRoot } from "./helpers.js";
const CLI = fileURLToPath(new URL("../../../scripts/run-corpus.mjs", import.meta.url));
function fixture(body: (root: string, args: string[]) => void): void {
 const root = fs.mkdtempSync(join(tmpdir(), "ecl-public-corpus-"));
 try {
  for (const name of ["conformance/suites", "registries", "source"]) fs.mkdirSync(join(root,name), { recursive:true });
  for (const name of ["semantic-rules", "error-codes"]) fs.copyFileSync(join(repoRoot(), "registries", name+".json"), join(root,"registries",name+".json"));
  fs.writeFileSync(join(root,"source/control.txt"),"miniature report binding fixture\n");
  fs.writeFileSync(join(root,"conformance/input.json"),"{}");
  const foundation = ["strict-json", "canonical-digest", "semantic-rules", "safe-state-profile-rules"];
  fs.writeFileSync(join(root,"conformance/shared-corpus.json"), JSON.stringify({ schema_version:"ecl_shared_corpus_v1", version:1, candidate_version:"1.0", required_capabilities:foundation, optional_capabilities:CAPABILITIES.filter(x=>!foundation.includes(x)), vectors:[{ id:"control", suite:"miniature", capability:"strict-json" }] }));
  fs.writeFileSync(join(root,"conformance/manifest.json"), JSON.stringify({ schema_version:"ecl_conformance_vector_manifest_v3", suite:"miniature", vectors:[{ id:"control", path:"conformance/input.json", stage:"strict-json", expected:"pass", expected_secondary_ids:[] }] }));
  body(root,[CLI,"--repo-root",root,"--source-root",join(root,"source"),"--report",join(root,"report.json"),"--revision","a".repeat(40)]);
 } finally { fs.rmSync(root,{recursive:true,force:true}); }
}
test("public corpus CLI emits complete raw-bound control and refuses output reuse", () => fixture((root,args)=>{
 const result=spawnSync(process.execPath,args,{encoding:"utf8"}); assert.equal(result.status,0,result.stderr);
 const summary=JSON.parse(result.stdout); assert.equal(summary.vector_count,1); assert.equal(summary.counts.met,1);
 const bytes=fs.readFileSync(join(root,"report.json")); const report=JSON.parse(bytes.toString());
 assert.equal(report.vector_results.length,1); assert.equal(report.evidence.length,1);
 const raw=JSON.parse(fs.readFileSync(join(root,report.evidence[0].path),"utf8"));
 assert.equal(raw.result.id,"control"); assert.equal(raw.result.status,"met");
 const repeat=spawnSync(process.execPath,args,{encoding:"utf8"}); assert.equal(repeat.status,2);
 assert.deepEqual(fs.readFileSync(join(root,"report.json")),bytes);
}));
test("public corpus CLI retains an actual failed replay and exits one", () => fixture((root,args)=>{
 fs.writeFileSync(join(root,"conformance/input.json"),"{");
 const result=spawnSync(process.execPath,args,{encoding:"utf8"}); assert.equal(result.status,1,result.stderr);
 const report=JSON.parse(fs.readFileSync(join(root,"report.json"),"utf8"));
 assert.equal(report.decision,"fail"); assert.equal(report.vector_results[0].status,"not-met");
 assert.equal(report.vector_results[0].observed_primary_id,"ecl.rule.json-strict-syntax.v1");
}));
test("public corpus CLI refuses an undeclared revision before output", () => fixture((root,args)=>{
 args[args.length-1]="0".repeat(40);
 const result=spawnSync(process.execPath,args,{encoding:"utf8"}); assert.equal(result.status,2);
 assert.equal(fs.existsSync(join(root,"report.json")),false);
}));

for (const name of ["report with spaces.json", "résultat.json", "CON.json", "a".repeat(250)+".json"]) test("public report name uses portable evidence: " + name, () => fixture((root,args)=>{
 const path=join(root,name); args[args.indexOf("--report")+1]=path;
 const result=spawnSync(process.execPath,args,{encoding:"utf8"}); assert.equal(result.status,0,result.stderr);
 const report=JSON.parse(fs.readFileSync(path,"utf8"));
 for (const entry of report.evidence) {
  assert.match(entry.path,/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/);
  assert.ok(fs.statSync(join(root,entry.path)).isFile());
 }
}));
test("existing report fails before creating any evidence", () => fixture((root,args)=>{
 fs.writeFileSync(join(root,"report.json"),"preserve original");
 const before=fs.readdirSync(root).sort();
 const result=spawnSync(process.execPath,args,{encoding:"utf8"}); assert.equal(result.status,2);
 assert.deepEqual(fs.readdirSync(root).sort(),before);
 assert.equal(fs.readFileSync(join(root,"report.json"),"utf8"),"preserve original");
}));
