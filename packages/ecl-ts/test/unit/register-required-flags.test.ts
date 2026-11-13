import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { registerProblems, registerReference } from "../../src/evidence/decision-basis.js";
import type { JsonObject } from "../../src/json/value.js";
import { repoRoot } from "./helpers.js";
interface Case {id:string; basis:JsonObject; register:JsonObject; action_class:string; required_problem:boolean}
const cases=JSON.parse(readFileSync(join(repoRoot(),"tests/fixtures/register-required-flags/cases.json"),"utf8")) as Case[];
for(const item of cases) test(`register required flag: ${item.id}`,()=>{
  const value={...item.basis,register:registerReference(item.register)};
  const problems=registerProblems(value,item.register,item.action_class);
  assert.equal(problems.some(([path])=>path==="/inputs/0/required"),item.required_problem);
  assert.ok(problems.every(([path])=>path==="/inputs/0/required"));
});
