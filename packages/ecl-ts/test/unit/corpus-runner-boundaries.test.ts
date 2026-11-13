// Bounded replay inputs and report provenance. Robert F. Tilley Jr.; G-14, Inc.
import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { test } from "node:test";
import { observedForVector, pythonCompactJson, runCorpus, sourceTreeDigest } from "../../src/conformance/corpus.js";
import type { CorpusVector, EvaluationContext, ObservedScope } from "../../src/conformance/corpus.js";
import { SemanticValidator } from "../../src/semantic/rules.js";
import { repoRoot } from "./helpers.js";

const digest = (data: string | Uint8Array): string => createHash("sha256").update(data).digest("hex");
function fixture(vector: Partial<CorpusVector> = {}): { root: string; vector: CorpusVector; context: EvaluationContext } {
  const root = fs.mkdtempSync(join(tmpdir(), "ecl-replay-boundary-"));
  for (const path of ["conformance/suites", "registries", "source"]) fs.mkdirSync(join(root, path), { recursive: true });
  fs.writeFileSync(join(root, "source/control.txt"), "bounded source\n");
  for (const name of ["semantic-rules", "error-codes"]) fs.copyFileSync(join(repoRoot(), "registries", name + ".json"), join(root, "registries", name + ".json"));
  const item: CorpusVector = { id: "control", path: "conformance/input.json", stage: "semantic", schema: "https://externalcontrollayer.ai/ns/schema/common/1", expected: "pass", expected_secondary_ids: [], ...vector };
  fs.writeFileSync(join(root, item.path), "{}");
  fs.writeFileSync(join(root, "conformance/manifest.json"), JSON.stringify({ schema_version: "ecl_conformance_vector_manifest_v3", suite: "bounded", vectors: [item] }));
  fs.writeFileSync(join(root, "conformance/shared-corpus.json"), JSON.stringify({ schema_version: "ecl_shared_corpus_v1", version: 1, candidate_version: "1.0", required_capabilities: ["strict-json", "canonical-digest", "semantic-rules", "safe-state-profile-rules"], optional_capabilities: [], vectors: [{ id: item.id, suite: "bounded", capability: "semantic-rules" }] }));
  const context: EvaluationContext = { root, semantics: new SemanticValidator(), verdicts: new Map(), scopes: new Map<string, ObservedScope>() };
  return { root, vector: item, context };
}
function replay(root: string, report = join(root, "report.json")): ReturnType<typeof runCorpus> {
  return runCorpus(root, "bounded-local-fixture", report, join(root, "source"), process.version);
}
function withFixture(body: (f: ReturnType<typeof fixture>) => void, vector: Partial<CorpusVector> = {}): void {
  const f = fixture(vector); try { body(f); } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
}

test("vector reads honor parser default and custom byte budgets above 16 MiB", () => withFixture(({ root, vector, context }) => {
  const data = Buffer.concat([Buffer.alloc(16 * 1024 * 1024, 0x20), Buffer.from("{}")]);
  fs.writeFileSync(join(root, vector.path), data);
  const limits = { max_bytes: 17 * 1024 * 1024, max_depth: 256, max_nodes: 1000000 };
  assert.deepEqual(observedForVector({ ...vector, stage: "strict-json" }, context), []);
  assert.deepEqual(observedForVector({ ...vector, stage: "strict-json", strict_json_limits: limits }, context), []);
  assert.deepEqual(observedForVector({ ...vector, stage: "strict-json", strict_json_limits: { ...limits, max_bytes: 16 * 1024 * 1024 } }, context), ["ecl.error.resource-limit-exceeded.v1"]);
  fs.copyFileSync(join(repoRoot(), "conformance/fixtures/evidence/trust-policy.json"), join(root, "policy.json"));
  assert.deepEqual(observedForVector({ ...vector, stage: "package", trust_policy_path: "policy.json", evaluated_at: "2026-10-01T00:00:00Z" }, context), ["ecl.error.semantic-invalid.v1"]);
}));

test("bounded replay binds all artifact bytes beyond its retained Parse prefix", () => withFixture(({ root, vector }) => {
  const data = Buffer.concat([Buffer.alloc(16 * 1024 * 1024, 0x20), Buffer.from("{}")]);
  fs.writeFileSync(join(root, vector.path), data);
  assert.equal(replay(root).decision, "pass");
  const report = JSON.parse(fs.readFileSync(join(root, "report.json"), "utf8"));
  assert.equal(report.vector_results[0].artifact_sha256, digest(data));
  assert.notEqual(report.vector_results[0].artifact_sha256, digest(data.subarray(0, 16 * 1024 * 1024 + 1)));
}, { stage: "strict-json", expected: "fail", expected_primary_id: "ecl.error.resource-limit-exceeded.v1", strict_json_limits: { max_bytes: 16 * 1024 * 1024, max_depth: 256, max_nodes: 1000000 } }));

test("report hashing has its own explicit 512 MiB artifact ceiling", () => withFixture(({ root, vector }) => {
  const descriptor = fs.openSync(join(root, vector.path), "w"); fs.ftruncateSync(descriptor, 512 * 1024 * 1024 + 1); fs.closeSync(descriptor);
  assert.throws(() => replay(root), /report artifact exceeds 512 MiB/);
  assert.equal(fs.existsSync(join(root, "report.json")), false);
}, { stage: "strict-json" }));

for (const stage of ["unknown-stage", "safe-state", "evidence_bundle"]) test(`unknown stage ${stage} cannot produce a passing result`, () => withFixture(({ root, vector, context }) => {
  assert.throws(() => observedForVector(vector, context), /unsupported evaluation stage/);
  assert.throws(() => observedForVector({ ...vector, path: "absent.json" }, context), /unsupported evaluation stage/);
  assert.throws(() => replay(root), /unsupported evaluation stage/);
  assert.equal(fs.existsSync(join(root, "report.json")), false);
  assert.equal(fs.existsSync(join(root, "report-evidence")), false);
}, { stage }));

test("malformed expected-result metadata is refused before evidence output", () => withFixture(({ root }) => {
  assert.throws(() => replay(root), /malformed manifest vector/);
  assert.equal(fs.existsSync(join(root, "report-evidence")), false);
}, { expected: "neither" as "pass" }));

test("empty source exports cannot be bound by a replay report", () => withFixture(({ root }) => {
  fs.unlinkSync(join(root, "source/control.txt"));
  assert.throws(() => sourceTreeDigest(join(root, "source")), /source tree is empty/);
  assert.throws(() => replay(root), /source tree is empty/);
  assert.equal(fs.existsSync(join(root, "report-evidence")), false);
}));

test("clean source exports reject a worktree .git file as well as a directory", () => withFixture(({ root }) => {
  fs.writeFileSync(join(root, "source/.git"), "gitdir: local-metadata\n");
  assert.throws(() => sourceTreeDigest(join(root, "source")), /clean export/);
  fs.unlinkSync(join(root, "source/.git")); fs.mkdirSync(join(root, "source/.git"));
  assert.throws(() => sourceTreeDigest(join(root, "source")), /clean export/);
}));

test("source and compact JSON ordering use Unicode code points", () => withFixture(({ root }) => {
  assert.equal(pythonCompactJson({ "\u{10000}": 2, "\uE000": 1 }), '{"\uE000":1,"\u{10000}":2}');
  assert.equal(pythonCompactJson({ a: "\u2028\u2029" }), '{"a":"\u2028\u2029"}');
  const source = join(root, "unicode-source"); fs.mkdirSync(source);
  fs.writeFileSync(join(source, "\u{10000}.txt"), "b"); fs.writeFileSync(join(source, "\uE000.txt"), "a");
  const entries = [{ path: "\uE000.txt", sha256: digest("a"), size_bytes: 1 }, { path: "\u{10000}.txt", sha256: digest("b"), size_bytes: 1 }];
  assert.deepEqual(sourceTreeDigest(source), { files: 2, digest: digest(JSON.stringify(entries)) });
}));

test("ordinary files under suites do not become phantom suite directories", () => withFixture(({ root }) => {
  fs.writeFileSync(join(root, "conformance/suites/README.txt"), "local notes\n");
  assert.equal(replay(root).decision, "pass");
}));

test("filtering ordinary suite entries does not permit a symlink", () => withFixture(({ root }) => {
  fs.symlinkSync(join(root, "source"), join(root, "conformance/suites/linked"), "dir");
  assert.throws(() => replay(root), /symlink/);
  assert.equal(fs.existsSync(join(root, "report-evidence")), false);
}));

test("native dotted directories and extensionless reports retain adjacent evidence paths", () => withFixture(({ root }) => {
  const parent = join(root, "a.b"); fs.mkdirSync(parent);
  assert.equal(replay(root, join(parent, "report")).decision, "pass");
  const report = JSON.parse(fs.readFileSync(join(parent, "report"), "utf8"));
  assert.equal(report.evidence[0].path, "report-evidence/0000.json");
  assert.ok(fs.existsSync(join(parent, "report-evidence/0000.json")));
}));

test("a POSIX backslash filename cannot become a nonportable evidence reference", { skip: sep !== "/" }, () => withFixture(({ root }) => {
  const name = "odd\\report.json", path = join(root, name);
  assert.equal(replay(root, path).decision, "pass");
  const report = JSON.parse(fs.readFileSync(path, "utf8"));
  const evidenceName = "report-" + digest(name) + "-evidence/0000.json";
  assert.equal(report.evidence[0].path, evidenceName);
  assert.ok(!report.evidence[0].path.includes("\\"));
  assert.ok(fs.statSync(join(root, evidenceName)).isFile());
}));

function atRead(path: string, action: () => void, body: () => void): void {
  const read = fs.readFileSync, open = fs.openSync; let triggered = false;
  const trigger = (value: unknown): void => { if (String(value) === path && !triggered) { triggered = true; action(); } };
  fs.readFileSync = ((...args: Parameters<typeof fs.readFileSync>) => { trigger(args[0]); return read(...args); }) as typeof fs.readFileSync;
  fs.openSync = ((...args: Parameters<typeof fs.openSync>) => { trigger(args[0]); return open(...args); }) as typeof fs.openSync;
  syncBuiltinESMExports();
  try { body(); assert.equal(triggered, true); }
  finally { fs.readFileSync = read; fs.openSync = open; syncBuiltinESMExports(); }
}

test("report corpus digest binds the bytes parsed at the beginning", () => withFixture(({ root, vector }) => {
  const path = join(root, "conformance/shared-corpus.json"), original = fs.readFileSync(path);
  atRead(join(root, vector.path), () => fs.appendFileSync(path, " "), () => {
    assert.equal(replay(root).decision, "pass");
    const report = JSON.parse(fs.readFileSync(join(root, "report.json"), "utf8"));
    assert.equal(report.suite.manifest_sha256, digest(original));
    assert.notEqual(report.suite.manifest_sha256, digest(fs.readFileSync(path)));
  });
}));

test("an earlier vector artifact changed during replay prevents report success", () => withFixture(({ root, vector }) => {
  const other = { ...vector, id: "other", path: "conformance/other.json" };
  fs.writeFileSync(join(root, other.path), "{}");
  const manifest = join(root, "conformance/manifest.json"), corpus = join(root, "conformance/shared-corpus.json");
  const m = JSON.parse(fs.readFileSync(manifest, "utf8")), c = JSON.parse(fs.readFileSync(corpus, "utf8"));
  m.vectors.push(other); c.vectors.push({ suite: "bounded", id: "other", capability: "semantic-rules" });
  fs.writeFileSync(manifest, JSON.stringify(m)); fs.writeFileSync(corpus, JSON.stringify(c));
  atRead(join(root, other.path), () => fs.appendFileSync(join(root, vector.path), " "), () => {
    assert.throws(() => replay(root), /artifact changed during replay/);
    assert.equal(fs.existsSync(join(root, "report.json")), false);
  });
}));

for (const [name, data, primary, limit] of [
  ["syntax", "{", "ecl.rule.json-strict-syntax.v1", undefined],
  ["duplicate", '{"a":1,"a":2}', "ecl.rule.json-no-duplicate-members.v1", undefined],
  ["number", '{"a":1.5}', "ecl.rule.json-restricted-numbers.v1", undefined],
  ["resource", "{}", "ecl.error.resource-limit-exceeded.v1", 1],
] as const) test(`evidence-bundle Parse refusal ${name} has an invalid verdict without invented scope`, () => withFixture(({ root, vector, context }) => {
  fs.writeFileSync(join(root, vector.path), data);
  assert.deepEqual(observedForVector(vector, context), [primary]);
  assert.equal(context.verdicts.get(vector.id), "invalid");
  assert.equal(context.scopes!.has(vector.id), false);
}, { stage: "evidence-bundle", trust_policy_path: "must-not-read.json", ...(limit === undefined ? {} : { strict_json_limits: { max_bytes: limit, max_depth: 256, max_nodes: 1000000 } }) }));

test("parse-valid invalid bundle shape still reaches ordinary bundle verification", () => withFixture(({ root, vector, context }) => {
  fs.copyFileSync(join(repoRoot(), "conformance/fixtures/evidence/trust-policy.json"), join(root, "policy.json"));
  assert.deepEqual(observedForVector(vector, context), ["ecl.error.schema-invalid.v1"]);
  assert.equal(context.verdicts.get(vector.id), "invalid");
  assert.equal(context.scopes!.has(vector.id), true);
}, { stage: "evidence-bundle", trust_policy_path: "policy.json", evaluated_at: "2026-10-01T00:00:00Z" }));
