import assert from "node:assert/strict";
import { test } from "node:test";
import { observedForVector, scopeMatches, scopeExpectationMatches } from "../../src/conformance/corpus.js";
import type { CorpusVector, ObservedScope } from "../../src/conformance/corpus.js";
import { SemanticValidator } from "../../src/semantic/rules.js";
import { TrustPolicy } from "../../src/trust/policy.js";
import { decodeCanonicalJsonPayload, IntegrityError, verifyEnvelope } from "../../src/integrity/envelope.js";
import { oversizedPackageReport } from "../../web/package-limit.js";
import { bytes, json, repoRoot } from "./helpers.js";
import type { JsonObject } from "../../src/json/value.js";

const manifest=json("conformance/suites/repair-harness/manifest.json");
const vectors=manifest["vectors"] as unknown as CorpusVector[];
const policy=TrustPolicy.load(bytes(manifest["trust_policy_path"] as string));
for (const vector of vectors) {
  test(vector.id,()=>{
    const scopes=new Map<string,ObservedScope>();const verdicts=new Map<string,string>();
    const actual=observedForVector(vector,{root:repoRoot(),semantics:new SemanticValidator(),trustPolicy:policy,scopes,verdicts});
    if (vector.expected==="pass") assert.deepEqual(actual,[]);
    else assert.equal(actual[0],vector.expected_primary_id);
    if(vector.expected_verdict!==undefined)assert.equal(verdicts.get(vector.id),vector.expected_verdict);
    assert.ok(scopeMatches(vector,scopes.get(vector.id)),JSON.stringify(scopes.get(vector.id)));
  });
}

test("supporting scope checks and exact object sets cannot disappear behind correct claim labels",()=>{
  const vector=vectors.find(v=>v.id==="repair-harness-scope-valid-succeeded-with-register")!;
  for (const change of ["missing-map","missing-check","extra-check","missing-object","wrong-object","extra-object","duplicate-object"]) {
    const got=JSON.parse(JSON.stringify(vector.expected_scope));const entry=got.checks["release-within-authority"];
    if(change==="missing-map")delete got.checks;
    else if(change==="missing-check")entry.checks=[];
    else if(change==="extra-check")entry.checks.push("current-status");
    else if(change==="missing-object")entry.objects.pop();
    else if(change==="wrong-object")entry.objects[0]=99;
    else if(change==="extra-object")entry.objects.push(2);
    else entry.objects.push(entry.objects[0]);
    assert.equal(scopeExpectationMatches(got,vector.expected_scope!),false,change);
  }
  const reordered=JSON.parse(JSON.stringify(vector.expected_scope));
  for (const entry of Object.values(reordered.checks) as {checks:string[];objects:number[]}[]) {entry.checks.reverse();entry.objects.reverse();}
  assert.ok(scopeExpectationMatches(reordered,vector.expected_scope!));
});

test("envelope preflight precedes a lazy context; direct context remains compatible",()=>{
  for(const name of ["array","media-before-time","budget-before-payload","missing-policy-and-time"]){
    let calls=0;
    assert.throws(()=>verifyEnvelope(json(`conformance/suites/repair-harness/repair-harness-envelope-${name}.json`),policy.keyring(),()=>{calls++;throw new Error("must not run");}),IntegrityError);
    assert.equal(calls,0,name);
  }
  const envelope=json("conformance/suites/repair-harness/repair-harness-envelope-valid-control.json");
  const payload=decodeCanonicalJsonPayload(envelope) as JsonObject;
  const context=policy.verificationContext(payload["issued_at"] as string,"ecl.time.issued-at.v1");
  assert.deepEqual(verifyEnvelope(envelope,policy.keyring(),context),verifyEnvelope(envelope,policy.keyring(),()=>context));
  assert.throws(()=>verifyEnvelope(envelope,policy.keyring(),()=>{throw new Error("context unavailable");}),error=>error instanceof IntegrityError && error.code==="ecl.error.signature-policy-invalid.v1");
});

test("unread oversized package has an invalid report with empty supporting scope",()=>{
  const {report}=oversizedPackageReport(bytes("conformance/suites/offline-package/trust-policy.json"),{now:"2026-10-01T00:00:00Z"},16777217,16777216);
  assert.equal(report.verdict,"invalid");assert.equal(report.findings[0]?.code,"ecl.error.resource-limit-exceeded.v1");
  assert.deepEqual(report.scope.established,[]);assert.deepEqual(report.scope.checks,{});
  assert.deepEqual(report.envelopeChecks,[]);assert.deepEqual(report.bindingChecks,[]);assert.deepEqual(report.effects,[]);
  assert.throws(()=>oversizedPackageReport(bytes("conformance/suites/offline-package/trust-policy.json"),{now:"invalid"},16777217,16777216));
});
