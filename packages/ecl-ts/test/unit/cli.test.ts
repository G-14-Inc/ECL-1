import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { canonicalText, loadRegister, reportToJson, VerifierInputError, verifyPackageBytes } from "../../src/index.js";
import { bytes, repoRoot, suite } from "./helpers.js";
import type { Vector } from "./helpers.js";

// The command as the test build compiles it (build/src/cli/ecl-verify.js).
const COMMAND = fileURLToPath(new URL("../../src/cli/ecl-verify.js", import.meta.url));
const EXIT: Record<string, number> = { verified: 0, invalid: 1, incomplete: 3, "current-trust-failed": 4 };

function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [COMMAND, ...args], { encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function args(vector: Vector, file?: string): string[] {
  const found = [file ?? join(repoRoot(), vector.path), "--trust-policy", join(repoRoot(), vector.trust_policy_path as string), "--now", vector.evaluated_at as string];
  for (const path of vector.trust_policy_history_paths ?? []) {
    found.push("--trust-policy-history", join(repoRoot(), path));
  }
  return found;
}

const PACKAGES = suite("offline-package");

function vector(id: string): Vector {
  return PACKAGES.find((item) => item.id === id) as Vector;
}

test("a schema-invalid register retains its registered refusal code in the library and CLI", () => {
  const policy = "conformance/fixtures/evidence/trust-policy.json";
  assert.throws(
    () => loadRegister(bytes(policy)),
    (error: unknown) => error instanceof VerifierInputError && error.code === "ecl.error.schema-invalid.v1",
  );
  const result = run([
    join(repoRoot(), "conformance/fixtures/evidence/succeeded.json"),
    "--trust-policy", join(repoRoot(), policy),
    "--register", join(repoRoot(), policy),
    "--now", "2026-10-01T00:00:00Z", "--json",
  ]);
  assert.equal(result.status, 2);
  assert.equal(result.stdout, "");
  assert.ok(result.stderr.startsWith("error: ecl.error.schema-invalid.v1: malformed register:"), result.stderr);
});

test("ecl-verify-ts verifies every offline-package vector as verifyPackageBytes does, with its exit status", () => {
  for (const item of PACKAGES) {
    const { status, stdout, stderr } = run([...args(item), "--json"]);
    assert.equal(stderr, "", item.id);
    const { report } = verifyPackageBytes(bytes(item.path), bytes(item.trust_policy_path as string), {
      now: item.evaluated_at as string,
      history: (item.trust_policy_history_paths ?? []).map((path) => bytes(path)),
    });
    assert.equal(stdout, canonicalText(reportToJson(report)) + "\n", item.id);
    assert.equal(report.verdict, item.expected_verdict, item.id);
    assert.equal(status, EXIT[item.expected_verdict as string], item.id);
    const primary = item.expected_primary_id ?? null;
    assert.equal(JSON.parse(stdout).primary, primary, item.id);
    const text = run(args(item));
    assert.equal(text.status, status, item.id);
    assert.equal(text.stdout.includes(`primary: ${primary}\n`), primary !== null, item.id);
  }
});

test("JSON exposes the decided primary finding for each bundle verdict, including an accepted current trust failure", () => {
  const ids = new Set([
    "bundle-incomplete-no-terminal", "bundle-current-trust-failed-revoked-after-use",
    "bundle-current-trust-failed-order", "bundle-invalid-missing-decision-basis", "bundle-valid-succeeded",
  ]);
  for (const item of suite("evidence-bundle").filter((item) => ids.has(item.id))) {
    const json = run([...args(item), "--json"]);
    const value = JSON.parse(json.stdout);
    assert.equal(json.status, EXIT[item.expected_verdict as string], item.id);
    assert.equal(value.primary, item.expected_primary_id ?? null, item.id);
    const text = run(args(item));
    assert.equal(text.stdout.includes(`primary: ${value.primary}\n`), value.primary !== null, item.id);
    if (item.id === "bundle-current-trust-failed-revoked-after-use") {
      const accepted = run([...args(item), "--accept-current-trust-failure", "--json"]);
      assert.equal(accepted.status, 0);
      assert.equal(JSON.parse(accepted.stdout).accepted_current_trust_failure, true);
      assert.equal(JSON.parse(accepted.stdout).primary, null);
    }
  }
});

test("ecl-verify-ts reports a package in the bundle's form, requires each decision basis and passes the register to its bundle", () => {
  const valid = vector("package-valid-corroborated");
  let result = run(args(valid));
  assert.equal(result.status, 0);
  assert.ok(result.stdout.startsWith("verdict: verified\n"));
  assert.ok(result.stdout.includes("established: decision-basis-recorded: "));
  // The option that once waived the decision basis is no option: a usage error.
  result = run([...args(valid), "--no-require-decision-basis"]);
  assert.equal(result.status, 2);
  assert.equal(result.stdout, "");
  assert.ok(result.stderr.startsWith("usage:"));
  result = run([...args(valid), "--register", join(repoRoot(), "conformance/suites/evidence-bundle/register-version-2.json")]);
  assert.equal(result.status, 1);
  assert.ok(result.stdout.includes("finding: ecl.rule.decision-basis-matches-register.v1: "));
  const overLimit = vector("package-invalid-entry-name-over-limit");
  result = run(args(overLimit));
  assert.equal(result.status, 1);
  assert.ok(result.stdout.includes("finding: ecl.error.resource-limit-exceeded.v1: "));
});

test("ecl-verify-ts still reads a file that does not begin with PK as a JSON bundle", () => {
  const folder = mkdtempSync(join(tmpdir(), "ecl-cli-"));
  try {
    const path = join(folder, "not-json.zip");
    writeFileSync(path, "P not an archive");
    const result = run(args(vector("package-valid-verified"), path));
    assert.equal(result.status, 2);
    assert.equal(result.stdout, "");
    assert.ok(result.stderr.startsWith("error: ecl.rule.json-strict-syntax.v1: malformed bundle JSON"));
    const bundle = run([
      join(repoRoot(), "conformance/fixtures/evidence/succeeded.json"),
      "--trust-policy",
      join(repoRoot(), "conformance/fixtures/evidence/trust-policy.json"),
      "--now",
      "2026-09-29T10:00:02.000000Z",
    ]);
    assert.equal(bundle.status, 0, bundle.stderr);
    assert.ok(bundle.stdout.startsWith("verdict: verified\n"));
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
});
