/** Complete synthetic MCP records, checked by the TypeScript implementation. */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateBindingRecord } from '../packages/ecl-ts/dist/bindings/index.js';
import { selectFindings } from '../packages/ecl-ts/dist/conformance/corpus.js';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const manifest=JSON.parse(fs.readFileSync(path.join(root,'tests/fixtures/mcp-public-review-repairs/manifest.json'),'utf8'));
for (const c of manifest.cases) test(c.id,()=>{
  const record=JSON.parse(fs.readFileSync(path.join(root,c.path),'utf8'));
  const findings=evaluateBindingRecord(manifest.schema,record);
  assert.equal(findings.length===0,c.valid,JSON.stringify(findings));
  if(c.expected_rule) assert.ok(findings.some(f=>f.ruleId===c.expected_rule),JSON.stringify(findings));
});

const active=JSON.parse(fs.readFileSync(path.join(root,'conformance/suites/mcp-gateway/manifest.json'),'utf8'));
const registry=(name)=>JSON.parse(fs.readFileSync(path.join(root,'registries',name+'.json'),'utf8')).entries.filter(e=>e.status==='active');
const precedence=new Map(registry('semantic-rules').map(e=>[e.id,e.attributes.precedence]));
const errorCodes=new Set(registry('error-codes').map(e=>e.id));
for (const c of active.vectors.filter(c=>c.stage==='binding')) test('active corpus: '+c.id,()=>{
  const findings=evaluateBindingRecord(c.schema,JSON.parse(fs.readFileSync(path.join(root,c.path),'utf8')));
  assert.equal(findings.length===0,c.expected==='pass',JSON.stringify(findings));
  assert.deepEqual(selectFindings(findings.map(f=>f.ruleId),precedence,errorCodes),[c.expected_primary_id??null,c.expected_secondary_ids??[]],JSON.stringify(findings));
});
