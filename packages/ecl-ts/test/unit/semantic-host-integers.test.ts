import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {test} from "node:test";
import {objectFindings} from "../../src/semantic/object.js";
import {evaluateDocument} from "../../src/documents/documents.js";
import type {JsonValue} from "../../src/json/value.js";
import {repoRoot} from "./helpers.js";

interface Case {id:string; value:JsonValue; required:string[]; api:string; clean:boolean}
const cases=JSON.parse(readFileSync(join(repoRoot(),"tests/fixtures/semantic-host-integers/cases.json"),"utf8")) as Case[];
for(const c of cases)test(`schema integer semantic control: ${c.id}`,()=>{
    const before=JSON.stringify(c.value);
    // JavaScript uses one Number representation for these integer-valued operands.
    const findings=c.api==="deployment"?evaluateDocument("https://externalcontrollayer.ai/ns/schema/deployment-profile/1",c.value):objectFindings(c.value);
    const ids=new Set(findings.map(f=>f.ruleId));
    for(const rule of c.required)assert.ok(ids.has(rule),JSON.stringify(findings));
    if(c.clean)assert.deepEqual(findings,[]);
    assert.equal(JSON.stringify(c.value),before);
});
