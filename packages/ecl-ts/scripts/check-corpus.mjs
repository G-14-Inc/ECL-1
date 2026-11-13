#!/usr/bin/env node
/**
 * Run ecl-verify-ts, the command-line verifier of this package, on every evidence-bundle and
 * offline-package vector of the conformance corpus and on the sample evidence, and compare each
 * verdict, primary finding and exit status with the expected ones.
 *
 *   node scripts/check-corpus.mjs [--repo-root DIR]
 *
 * Run it from this package after `npm run build`. DIR is the root that holds `conformance/`; it
 * defaults to the directory two levels above this package. The vectors are the entries of
 * conformance/manifest.json and conformance/suites/<suite>/manifest.json that name an expected
 * verdict. Each runs under the trust policy, trust-policy history, evaluation time, trusted-time
 * requirement, register and acceptance of a current trust failure that its entry gives, and must
 * give the expected verdict with its exit status (0 verified, 1 invalid, 3 incomplete, 4 current
 * trust failed) and, when the entry names them, its expected scope (the two lists of EBMP2-076 and
 * their reasons), the expected evidence level of each listed action (EBMP2-061) and the
 * unresolved predecessor identifiers it expects, as a set. Their identifiers must be exactly the vectors of conformance/shared-corpus.json whose
 * capability is evidence-bundle or offline-package verification, so no vector is left out. The
 * sample bundles in conformance/fixtures/evidence run under the trust policy beside them at
 * 2026-10-01T00:00:00Z, and each must give its verdict and the evidence level of its effect.
 *
 * The script prints a JSON summary and exits 0 when every result met its expectation, 1 when one
 * did not, and 2 on a usage error. It reads only the files named above and makes no network request.
 */

import { artifactPath, readArtifact, scopeExpectationMatches } from "../dist/conformance/corpus.js";
import { parseStrictJson } from "../dist/json/strict.js";
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(PACKAGE, "dist", "cli", "ecl-verify.js");
const EXIT = { verified: 0, invalid: 1, incomplete: 3, "current-trust-failed": 4 };
const CAPABILITIES = new Set(["evidence-bundle-verification", "offline-package-verification"]);
const FIXTURES = "conformance/fixtures/evidence";
const FIXTURE_TIME = "2026-10-01T00:00:00Z";
// The verdict and the evidence level of the first effect of each sample bundle.
const SAMPLES = {
  succeeded: ["verified", "issuer-asserted"],
  denied: ["verified", "issuer-asserted"],
  corroborated: ["verified", "corroborated"],
  tampered: ["invalid", "none"],
};

function options(argv) {
  let root = resolve(PACKAGE, "../..");
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--repo-root" && index + 1 < argv.length) {
      index += 1;
      root = resolve(argv[index]);
    } else {
      throw new Error(`usage: check-corpus.mjs [--repo-root DIR] (unexpected ${argv[index]})`);
    }
  }
  return root;
}

function readJson(root, path) {
  const value = parseStrictJson(readArtifact(root, path));
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new Error(`${path}: root must be an object`);
  return value;
}

/** Exact equality of two JSON values, as the reference runner compares a scope. */
function same(left, right) {
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((item, index) => same(item, right[index]));
  }
  if (left !== null && right !== null && typeof left === "object" && typeof right === "object") {
    const keys = Object.keys(left).sort();
    return same(keys, Object.keys(right).sort()) && keys.every((key) => same(left[key], right[key]));
  }
  return left === right;
}

/**
 * Whether a report's scope and evidence levels are those the vector names, when it names them:
 * the scope's lists and reasons exactly, and every reported level of each listed action's effects.
 */
function scopeMatches(vector, report) {
  if (vector.expected_scope !== undefined) {
    const scope = report?.scope;
    if (scope === undefined || !scopeExpectationMatches(scope, vector.expected_scope)) {
      return false;
    }
  }
  if (vector.expected_unresolved_predecessor_ids !== undefined) {
    const reported = new Set(report?.unresolved_predecessor_ids ?? []);
    const expected = new Set(vector.expected_unresolved_predecessor_ids);
    if (!Array.isArray(report?.unresolved_predecessor_ids) || reported.size !== report.unresolved_predecessor_ids.length || reported.size !== expected.size || [...expected].some((identifier) => !reported.has(identifier))) {
      return false;
    }
  }
  for (const expected of vector.expected_effects ?? []) {
    const levels = new Set((report?.effects ?? []).filter((item) => item.action_id === expected.action_id).map((item) => item.level));
    if (levels.size !== 1 || !levels.has(expected.level)) {
      return false;
    }
  }
  return true;
}

/** Run the verifier with `--json`; return its exit status and parsed report. */
function verify(root, args) {
  const result = spawnSync(process.execPath, [CLI, ...args, "--json"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  let report = null;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    report = null;
  }
  return { status: result.status, report, stderr: (result.stderr ?? "").trim().slice(-400) };
}

function vectorArguments(root, vector) {
  const args = [artifactPath(root, vector.path), "--trust-policy", artifactPath(root, vector.trust_policy_path), "--input-format", vector.stage === "package" ? "package" : "bundle"];
  for (const path of vector.trust_policy_history_paths ?? []) {
    args.push("--trust-policy-history", artifactPath(root, path));
  }
  args.push("--now", vector.evaluated_at);
  if (vector.require_trusted_time === true) {
    args.push("--require-trusted-time");
  }
  if (vector.accept_current_trust_failure === true) {
    args.push("--accept-current-trust-failure");
  }
  if (typeof vector.register_path === "string") {
    args.push("--register", artifactPath(root, vector.register_path));
  }
  return args;
}

function main() {
  const root = options(process.argv.slice(2));
  if (!existsSync(CLI)) {
    throw new Error("dist/cli/ecl-verify.js is missing: run npm run build first");
  }
  const suiteEntries = readdirSync(join(root, "conformance/suites"), { withFileTypes: true });
  if (suiteEntries.some((entry) => entry.isSymbolicLink())) throw new Error("suite directory contains a symlink");
  const manifests = [
    "conformance/manifest.json",
    ...suiteEntries.filter((entry) => entry.isDirectory()).map((entry) => entry.name)
      .sort()
      .map((suite) => `conformance/suites/${suite}/manifest.json`)
      .filter((path) => existsSync(join(root, path))),
  ];
  const vectors = manifests.flatMap((path) => readJson(root, path).vectors.filter((vector) => {
    const signed = vector.stage === "evidence-bundle" || vector.stage === "package";
    if (signed !== (typeof vector.expected_verdict === "string")) throw new Error(`${vector.id}: bundle/package stage must have its verdict`);
    return signed;
  }));
  const corpus = readJson(root, "conformance/shared-corpus.json").vectors.filter((row) => CAPABILITIES.has(row.capability));
  const listed = new Set(vectors.map((vector) => vector.id));
  const expected = new Set(corpus.map((row) => row.id));
  if (listed.size !== vectors.length || expected.size !== corpus.length) {
    throw new Error("duplicate manifest or corpus vector ID");
  }
  const unmatched = [...expected].filter((id) => !listed.has(id)).concat([...listed].filter((id) => !expected.has(id)));
  const failures = [];
  const verdicts = {};
  for (const vector of vectors) {
    const { status, report, stderr } = verify(root, vectorArguments(root, vector));
    const verdict = report?.verdict ?? null;
    verdicts[vector.expected_verdict] = (verdicts[vector.expected_verdict] ?? 0) + 1;
    const expectedPrimary = vector.expected === "pass" ? null : vector.expected_primary_id;
    if (verdict !== vector.expected_verdict || status !== EXIT[vector.expected_verdict] || report?.primary !== expectedPrimary || !scopeMatches(vector, report)) {
      failures.push({ id: vector.id, expected: vector.expected_verdict, verdict, status, stderr });
    }
  }
  const samples = [];
  for (const [name, [verdict, level]] of Object.entries(SAMPLES)) {
    const { status, report, stderr } = verify(root, [artifactPath(root, `${FIXTURES}/${name}.json`), "--trust-policy", artifactPath(root, `${FIXTURES}/trust-policy.json`), "--now", FIXTURE_TIME, "--input-format", "bundle"]);
    const met = report?.verdict === verdict && status === EXIT[verdict] && report?.effects?.[0]?.level === level;
    samples.push({ name, verdict: report?.verdict ?? null, level: report?.effects?.[0]?.level ?? null, met });
    if (!met) {
      failures.push({ id: `${FIXTURES}/${name}.json`, expected: `${verdict}, ${level}`, verdict: report?.verdict ?? null, status, stderr });
    }
  }
  const summary = {
    verifier: "ecl-verify-ts",
    vectors: vectors.length,
    corpus_vectors: corpus.length,
    unmatched_vectors: unmatched,
    expected_verdicts: verdicts,
    samples,
    failures,
  };
  process.stdout.write(`${JSON.stringify(summary)}\n`);
  return failures.length === 0 && unmatched.length === 0 && vectors.length > 0 ? 0 : 1;
}

try {
  process.exitCode = main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
}
