// Explicit formats and confined corpus inputs. Robert F. Tilley Jr.; G-14, Inc.
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { copyFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { repoRoot } from "./helpers.js";

const cli = join(repoRoot(), "packages/ecl-ts/dist/cli/ecl-verify.js");
const harness = join(repoRoot(), "packages/ecl-ts/scripts/check-corpus.mjs");
function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), "ecl-cli-format-"));
  mkdirSync(join(root, "conformance/suites"), { recursive: true });
  cpSync(join(repoRoot(), "conformance/fixtures/evidence"), join(root, "conformance/fixtures/evidence"), { recursive: true });
  copyFileSync(join(root, "conformance/fixtures/evidence/trust-policy.json"), join(root, "policy.json"));
  writeFileSync(join(root, "bad-magic.zip"), Buffer.from([0xde, 0xad, 0xbe, 0xef]));
  writeFileSync(join(root, "pk-json.json"), "PKxx"); writeFileSync(join(root, "shape.json"), "{}");
  const vectors = [
    { id: "bad-magic", stage: "package", path: "bad-magic.zip", expected_primary_id: "ecl.error.semantic-invalid.v1" },
    { id: "shape", stage: "evidence-bundle", path: "shape.json", expected_primary_id: "ecl.error.schema-invalid.v1" },
  ].map((v) => ({ ...v, expected: "fail", expected_secondary_ids: [], expected_verdict: "invalid", trust_policy_path: "policy.json", evaluated_at: "2026-10-01T00:00:00Z" }));
  writeFileSync(join(root, "conformance/manifest.json"), JSON.stringify({ schema_version: "ecl_conformance_vector_manifest_v3", suite: "formats", vectors }));
  writeFileSync(join(root, "conformance/shared-corpus.json"), JSON.stringify({ vectors: vectors.map((v) => ({ id: v.id, suite: "formats", capability: v.stage === "package" ? "offline-package-verification" : "evidence-bundle-verification" })) }));
  return root;
}
function invoke(root: string, name: string, format?: string): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [cli, join(root, name), "--trust-policy", join(root, "policy.json"), "--now", "2026-10-01T00:00:00Z", "--json", ...(format === undefined ? [] : ["--input-format", format])], { encoding: "utf8" });
}
test("explicit package accepts malformed archive bytes as package input, preserving automatic mode", () => {
  const root = fixture(); try {
    const explicit = invoke(root, "bad-magic.zip", "package"); assert.equal(explicit.status, 1, String(explicit.stderr));
    assert.equal(JSON.parse(String(explicit.stdout)).primary, "ecl.error.semantic-invalid.v1");
    const automatic = invoke(root, "bad-magic.zip"); assert.equal(automatic.status, 2); assert.match(String(automatic.stderr), /ecl.rule.json-strict-syntax.v1/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test("explicit bundle bypasses PK sniffing while retaining malformed-JSON usage exit", () => {
  const root = fixture(); try {
    const explicit = invoke(root, "pk-json.json", "bundle"); assert.equal(explicit.status, 2); assert.match(String(explicit.stderr), /ecl.rule.json-strict-syntax.v1/); assert.equal(explicit.stdout, "");
    const automatic = invoke(root, "pk-json.json"); assert.equal(automatic.status, 1); assert.equal(JSON.parse(String(automatic.stdout)).primary, "ecl.error.semantic-invalid.v1");
    const shape = invoke(root, "shape.json", "bundle"); assert.equal(shape.status, 1); assert.equal(JSON.parse(String(shape.stdout)).primary, "ecl.error.schema-invalid.v1");
    assert.equal(invoke(root, "shape.json", "unknown").status, 2);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
for (const mode of ["valid", "duplicate-metadata", "traversal", "symlink", "leading-dash"]) test(`CLI corpus inputs ${mode}`, () => {
  const root = fixture(); try {
    const path = join(root, "conformance/manifest.json"), manifest = JSON.parse(readFileSync(path, "utf8"));
    if (mode === "duplicate-metadata") writeFileSync(path, '{"vectors":[],"vectors":' + JSON.stringify(manifest.vectors) + "}");
    if (mode === "traversal") { manifest.vectors[0].path = "../outside.zip"; writeFileSync(path, JSON.stringify(manifest)); }
    if (mode === "symlink") { symlinkSync(join(root, "bad-magic.zip"), join(root, "alias.zip")); manifest.vectors[0].path = "alias.zip"; writeFileSync(path, JSON.stringify(manifest)); }
    if (mode === "leading-dash") { copyFileSync(join(root, "bad-magic.zip"), join(root, "--not-an-option")); manifest.vectors[0].path = "--not-an-option"; writeFileSync(path, JSON.stringify(manifest)); }
    const result = spawnSync(process.execPath, [harness, "--repo-root", root], { encoding: "utf8" });
    if (mode === "valid" || mode === "leading-dash") {
      assert.equal(result.status, 0, result.stderr + result.stdout); assert.equal(JSON.parse(result.stdout).failures.length, 0);
    } else assert.equal(result.status, 2, result.stderr + result.stdout);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
