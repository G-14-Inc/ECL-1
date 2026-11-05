/**
 * Declared limits of strict JSON and of the archive reader (IE1-028, IE1-029, IE1-037): the parser
 * compares its value and nesting budgets while it builds a value, and refuses NaN and Infinity as
 * budgets, in the library and in the browser bundle.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { closeSync, ftruncateSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";
import { GRAMMAR_NESTING_BOUND, MAX_JSON_BYTES_CEILING, MAX_JSON_DEPTH, MAX_JSON_DEPTH_CEILING, MAX_JSON_NODES, MAX_JSON_NODES_CEILING, parseStrictJson, StrictJsonError } from "../../src/index.js";
import type { StrictJsonLimits } from "../../src/index.js";
import { checkLimits } from "../../src/json/strict.js";
import { MAX_BUNDLE_BYTES, MAX_REGISTER_BYTES, VerifierInputError, verifyBundleBytes } from "../../src/evidence/bytes.js";
import { verifyPackageBytes } from "../../src/offline/package.js";
import { MAX_TRUST_POLICY_BYTES } from "../../src/trust/policy.js";
import { ArchiveRefusal, DEFAULT_OFFLINE_RESOURCE_LIMITS, readStoredZip } from "../../src/offline/zip.js";
import { repoRoot } from "./helpers.js";

const RESOURCE_LIMIT = "ecl.error.resource-limit-exceeded.v1";
const CONFIGURATION_INVALID = "ecl.error.configuration-invalid.v1";
const STRICT_SYNTAX = "ecl.rule.json-strict-syntax.v1";
const DUPLICATE_MEMBERS = "ecl.rule.json-no-duplicate-members.v1";
const RESTRICTED_NUMBERS = "ecl.rule.json-restricted-numbers.v1";
const encoder = new TextEncoder();

type Parse = (input: Uint8Array | string, limits?: StrictJsonLimits) => unknown;

function finding(input: Uint8Array | string, limits: StrictJsonLimits = {}, parse: Parse = parseStrictJson): string {
  try {
    parse(input, limits);
  } catch (error) {
    // The shipped bundle runs in a context of its own, whose errors are not this context's Error.
    if (typeof error === "object" && error !== null && "ruleId" in error) {
      return (error as StrictJsonError).ruleId;
    }
    throw error;
  }
  return "accepted";
}

const INVALID: Array<[string, unknown]> = [
  ["NaN", Number.NaN],
  ["Infinity", Number.POSITIVE_INFINITY],
  ["-Infinity", Number.NEGATIVE_INFINITY],
  ["a fraction", 8.5],
  ["zero", 0],
  ["a negative number", -1],
  ["an unsafe integer", 2 ** 53],
  ["an integer above every ceiling", 2 ** 53 - 1],
  ["text", "8"],
  ["a boolean", true],
  ["null", null],
  ["an object", {}],
];

test("IE1-028: a budget that is not an exact integer from 1 to its ceiling is a configuration error, refused before the input is read", () => {
  for (const name of ["maxBytes", "maxDepth", "maxNodes"] as const) {
    for (const [label, value] of INVALID) {
      for (const input of ["[0,1,2]", encoder.encode("[0,1,2]"), "[[[[", encoder.encode('["\xff"')]) {
        assert.throws(
          () => parseStrictJson(input, { [name]: value } as StrictJsonLimits),
          (error: unknown) => error instanceof StrictJsonError && error.ruleId === CONFIGURATION_INVALID && error.kind === "configuration" && error.message.includes(name),
          `${name} = ${label}`,
        );
      }
    }
  }
  for (const [label, value] of INVALID) {
    assert.throws(() => checkLimits([1], value as number), (error: unknown) => error instanceof StrictJsonError && error.ruleId === CONFIGURATION_INVALID, `canonical maxDepth = ${label}`);
    assert.throws(() => checkLimits([1], 256, value as number), (error: unknown) => error instanceof StrictJsonError && error.ruleId === CONFIGURATION_INVALID, `canonical maxNodes = ${label}`);
  }
  // An absent budget is the default; null is not absent. The ceilings are admissible budgets
  // (2,147,483,647 bytes, 4,096 levels, 100,000,000 values) and one above each is refused.
  assert.deepEqual(parseStrictJson("[0,1,2]", { maxNodes: undefined } as unknown as StrictJsonLimits), [0, 1, 2]);
  assert.deepEqual([MAX_JSON_BYTES_CEILING, MAX_JSON_DEPTH_CEILING, MAX_JSON_NODES_CEILING], [2_147_483_647, 4_096, 100_000_000]);
  assert.deepEqual(parseStrictJson("[0,1,2]", { maxBytes: MAX_JSON_BYTES_CEILING, maxDepth: MAX_JSON_DEPTH_CEILING, maxNodes: MAX_JSON_NODES_CEILING }), [0, 1, 2]);
  for (const [name, ceiling] of [["maxBytes", MAX_JSON_BYTES_CEILING], ["maxDepth", MAX_JSON_DEPTH_CEILING], ["maxNodes", MAX_JSON_NODES_CEILING]] as const) {
    assert.throws(() => parseStrictJson("[0,1,2]", { [name]: ceiling + 1 } as StrictJsonLimits), (error: unknown) => error instanceof StrictJsonError && error.ruleId === CONFIGURATION_INVALID, name);
  }
  assert.deepEqual([MAX_JSON_DEPTH, MAX_JSON_NODES], [256, 1_000_000]);
});

function flatArray(count: number, tail = ""): string {
  return "[" + "0,".repeat(count - 1) + "0" + tail + "]";
}

function nested(depth: number, tail = ""): string {
  return "[".repeat(depth) + "]".repeat(depth) + tail;
}

/** Each case: the input, the budgets, and the finding of IE1-037 (or "accepted"). */
const ORDER: Array<[string, StrictJsonLimits, string]> = [
  [flatArray(20), { maxNodes: 8 }, RESOURCE_LIMIT],
  [flatArray(20, ","), { maxNodes: 8 }, STRICT_SYNTAX],
  ["[0,0,0,0,0,0,0,0,0,0] x", { maxNodes: 8 }, STRICT_SYNTAX],
  ["[[[[[[]]]]]]", { maxDepth: 4 }, RESOURCE_LIMIT],
  ["[[[[[[]]]]]]]", { maxDepth: 4 }, STRICT_SYNTAX],
  ["[[[[[[", { maxDepth: 4 }, STRICT_SYNTAX],
  ['[1.5,"\\uffff",{"a":1,"a":2},0,0,0,0,0,0,0]', { maxNodes: 8 }, RESOURCE_LIMIT],
  ["[0,0,0,0,0,0,0,0,0,NaN]", { maxNodes: 8 }, STRICT_SYNTAX],
  [flatArray(8), { maxNodes: 9 }, "accepted"],
  ["[[[[[]]]]]", { maxDepth: 4 }, "accepted"],
  [nested(40, "x"), { maxBytes: 16 }, RESOURCE_LIMIT],
  ['{"a":1.5,"a":"\\ud800"}', {}, STRICT_SYNTAX],
  ['{"a":1.5,"a":2}', {}, DUPLICATE_MEMBERS],
  ['[1.5,-0,{"b":1}]', {}, RESTRICTED_NUMBERS],
];

test("IE1-037: the grammar comes before the budgets wherever each defect lies, in text and in bytes", () => {
  for (const [input, limits, expected] of ORDER) {
    assert.equal(finding(input, limits), expected, `${input.slice(0, 40)} ${JSON.stringify(limits)}`);
    assert.equal(finding(encoder.encode(input), limits), expected, `bytes: ${input.slice(0, 40)}`);
  }
  // Bytes that are not UTF-8 after the budget is exceeded: check 2.
  const bad = encoder.encode('[0,0,0,0,0,0,0,0,0,"?"]');
  bad[bad.length - 3] = 0xff;
  assert.equal(finding(bad, { maxNodes: 8 }), STRICT_SYNTAX);
});

test("IE1-037 check 2: the grammar is read to the parser's own nesting bound, 10,000 levels or the nesting budget", () => {
  assert.equal(GRAMMAR_NESTING_BOUND, 10_000);
  assert.equal(finding(nested(GRAMMAR_NESTING_BOUND + 1, "x")), STRICT_SYNTAX);
  assert.equal(finding(nested(GRAMMAR_NESTING_BOUND + 2, "x")), RESOURCE_LIMIT);
  assert.equal(finding(nested(GRAMMAR_NESTING_BOUND + 2)), RESOURCE_LIMIT);
  // The nesting ceiling of 4,096 is below the bound, so the bound is always 10,000 levels: an
  // input nested to the ceiling is built, one level deeper is refused at check 3, and a grammar
  // error below the bound still decides.
  assert.equal(finding(nested(4_097), { maxDepth: 4_096, maxNodes: 5_000 }), "accepted");
  assert.equal(finding(nested(4_098), { maxDepth: 4_096, maxNodes: 5_000 }), RESOURCE_LIMIT);
  assert.equal(finding(nested(4_098, "x"), { maxDepth: 4_096, maxNodes: 5_000 }), STRICT_SYNTAX);
});

/** The garbage collector, without the --expose-gc flag. */
function collector(): () => void {
  setFlagsFromString("--expose-gc");
  return runInNewContext("gc") as () => void;
}

test("IE1-029: a refusal under a small value budget does not build the input", () => {
  const gc = collector();
  // Inputs of 500,000 values under a budget of 8: the refusal comes before the value is built, so
  // the heap grows by far less than the input would take.
  for (const input of [encoder.encode(flatArray(500_000)), encoder.encode(flatArray(500_000, ",")), encoder.encode("{" + Array.from({ length: 100_000 }, (_, index) => `"m${index}":0`).join(",") + "}")]) {
    gc();
    const before = process.memoryUsage().heapUsed;
    const result = finding(input, { maxNodes: 8 });
    const growth = process.memoryUsage().heapUsed - before;
    assert.ok(result === RESOURCE_LIMIT || result === STRICT_SYNTAX, result);
    assert.ok(growth < 2 * 1024 * 1024, `heap grew by ${growth} bytes`);
  }
});

/** The shipped browser bundle, run in a context of its own with its parser exposed. */
function shippedParser(): Parse {
  let source = readFileSync(join(repoRoot(), "web/verifier/verifier.js"), "utf8").trimEnd();
  assert.ok(source.endsWith("})();"), "the bundle is one immediately invoked function");
  source = source.slice(0, -5) + "globalThis.ECL_TEST = { parseStrictJson };})();";
  const sandbox: Record<string, unknown> = {
    document: { readyState: "loading", addEventListener() {} },
    TextEncoder,
    TextDecoder,
    console,
  };
  sandbox["globalThis"] = sandbox;
  runInNewContext(source, sandbox, { filename: "web/verifier/verifier.js" });
  return (sandbox["ECL_TEST"] as { parseStrictJson: Parse }).parseStrictJson;
}

test("the shipped browser bundle refuses NaN and Infinity budgets and keeps the order of IE1-037", () => {
  const parse = shippedParser();
  for (const value of [Number.NaN, Number.POSITIVE_INFINITY, null, "8", 2 ** 53]) {
    assert.equal(finding("[0,1,2]", { maxNodes: value, maxDepth: value, maxBytes: value } as unknown as StrictJsonLimits, parse), CONFIGURATION_INVALID);
  }
  // The parsed value comes from the bundle's own context, so it is compared by its text.
  assert.equal(JSON.stringify(parse("[0,1,2]", { maxBytes: MAX_JSON_BYTES_CEILING, maxDepth: MAX_JSON_DEPTH_CEILING, maxNodes: MAX_JSON_NODES_CEILING })), "[0,1,2]");
  assert.equal(finding(flatArray(20), { maxNodes: 8 }, parse), RESOURCE_LIMIT);
  assert.equal(finding(flatArray(20, ","), { maxNodes: 8 }, parse), STRICT_SYNTAX);
});

/** An archive of `count` central directory entries named "a"; with `corruptAfter`, that entry's signature is wrong. */
function centralDirectory(count: number, corruptAfter?: number): Uint8Array {
  const data = new Uint8Array(47 * count + 22);
  const view = new DataView(data.buffer);
  for (let index = 0; index < count; index += 1) {
    const at = 47 * index;
    view.setUint32(at, index === corruptAfter ? 0x58585858 : 0x02014b50, true);
    view.setUint16(at + 4, (3 << 8) | 20, true);
    view.setUint16(at + 6, 20, true);
    view.setUint16(at + 14, 33, true);
    view.setUint16(at + 28, 1, true);
    view.setUint32(at + 38, 0o100644 * 0x10000, true);
    data[at + 46] = 0x61;
  }
  const end = 47 * count;
  view.setUint32(end, 0x06054b50, true);
  view.setUint16(end + 8, count & 0xffff, true);
  view.setUint16(end + 10, count & 0xffff, true);
  view.setUint32(end + 12, 47 * count, true);
  return data;
}

test("IE1-029: the archive reader keeps no more directory entries than its member limit", () => {
  const gc = collector();
  const limits = { ...DEFAULT_OFFLINE_RESOURCE_LIMITS, maxMemberCount: 10 };
  const data = centralDirectory(300_000);
  gc();
  const before = process.memoryUsage().heapUsed;
  assert.throws(
    () => readStoredZip(data, limits),
    (error: unknown) => error instanceof ArchiveRefusal && error.limit && error.message.includes("member count"),
  );
  const growth = process.memoryUsage().heapUsed - before;
  assert.ok(growth < 4 * 1024 * 1024, `heap grew by ${growth} bytes; 90 MB before`);
  // The whole directory is still read first: a structure it cannot read is refused as such.
  assert.throws(
    () => readStoredZip(centralDirectory(30, 25), limits),
    (error: unknown) => error instanceof ArchiveRefusal && !error.limit,
  );
});

// The command as the test build compiles it (build/src/cli/ecl-verify.js).
const COMMAND = fileURLToPath(new URL("../../src/cli/ecl-verify.js", import.meta.url));

test("IE1-029: ecl-verify-ts reads at most one byte more of a file than its limit", () => {
  const directory = mkdtempSync(join(tmpdir(), "ecl-limits-"));
  try {
    // A sparse file of 3 GiB, which takes no disk space. Read whole, as the command read its inputs
    // before, it fails as a file too large to read; read up to the limit, it is over the limit.
    const big = join(directory, "big");
    const descriptor = openSync(big, "w");
    try {
      ftruncateSync(descriptor, 3 * 2 ** 30);
    } finally {
      closeSync(descriptor);
    }
    const small = join(directory, "small.json");
    writeFileSync(small, "{}");
    const cases: Array<[string[], string]> = [
      [[big, "--trust-policy", small], "bundle file exceeds the 1 MiB limit"],
      [[small, "--trust-policy", big], "trust policy file exceeds the 256 KiB limit"],
      [[small, "--trust-policy", small, "--trust-policy-history", big], "trust policy history file exceeds the 256 KiB limit"],
      [[small, "--trust-policy", small, "--register", big], "register file exceeds the 1 MiB limit"],
    ];
    for (const [args, message] of cases) {
      // TP1-007: the one line of the refusal names the registered code first, with or without --json.
      for (const extra of [[], ["--json"]]) {
        const result = spawnSync(process.execPath, [COMMAND, ...args, ...extra], { encoding: "utf8" });
        assert.equal(result.stderr, `error: ${RESOURCE_LIMIT}: ${message}\n`, args.join(" "));
        assert.equal(result.stdout, "", args.join(" "));
        assert.equal(result.status, 2);
      }
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

/** The registered code of a usage error, or "accepted" when the call returns. */
function inputCode(call: () => unknown): string {
  try {
    call();
  } catch (error) {
    assert.ok(error instanceof VerifierInputError, String(error));
    return error.code ?? "no code";
  }
  return "accepted";
}

/** `data` followed by spaces up to `size` bytes: the same JSON value, at an exact length. */
function padded(data: Uint8Array, size: number): Uint8Array {
  const out = new Uint8Array(size).fill(0x20);
  out.set(data);
  return out;
}

test("TP1-007: each byte limit refuses one byte over with the registered code and admits the limit itself, for bundles and packages", () => {
  const fixtures = join(repoRoot(), "conformance/fixtures/evidence");
  const bundle = new Uint8Array(readFileSync(join(fixtures, "succeeded.json")));
  const policy = new Uint8Array(readFileSync(join(fixtures, "trust-policy.json")));
  const register = new Uint8Array(readFileSync(join(repoRoot(), "conformance/suites/evidence-bundle/register-version-2.json")));
  const now = "2026-10-01T00:00:00Z";
  const cases: Array<[string, (size: number) => () => unknown, number]> = [
    ["bundle", (size) => () => verifyBundleBytes(padded(bundle, size), policy, { now }), MAX_BUNDLE_BYTES],
    ["trust policy", (size) => () => verifyBundleBytes(bundle, padded(policy, size), { now }), MAX_TRUST_POLICY_BYTES],
    ["trust policy history", (size) => () => verifyBundleBytes(bundle, policy, { now, history: [padded(policy, size)] }), MAX_TRUST_POLICY_BYTES],
    ["register", (size) => () => verifyBundleBytes(bundle, policy, { now, register: padded(register, size) }), MAX_REGISTER_BYTES],
    ["package trust policy", (size) => () => verifyPackageBytes(new Uint8Array(0), padded(policy, size), { now }), MAX_TRUST_POLICY_BYTES],
    ["package register", (size) => () => verifyPackageBytes(new Uint8Array(0), policy, { now, register: padded(register, size) }), MAX_REGISTER_BYTES],
  ];
  for (const [name, call, limit] of cases) {
    assert.equal(inputCode(call(limit + 1)), RESOURCE_LIMIT, `${name}: one byte over`);
    // At the limit the file is read: whatever else it gives, it is not refused for its size. (A
    // history equal to the current policy is refused as history, not for its size.)
    assert.notEqual(inputCode(call(limit)), RESOURCE_LIMIT, `${name}: at the limit`);
  }
  // A bundle at exactly its limit verifies.
  assert.equal(verifyBundleBytes(padded(bundle, MAX_BUNDLE_BYTES), policy, { now }).report.verdict, "verified");
  // A strict-JSON refusal of an input file keeps its registered rule.
  assert.equal(inputCode(() => verifyBundleBytes(encoder.encode("[1,]"), policy, { now })), STRICT_SYNTAX);
  assert.equal(inputCode(() => verifyBundleBytes(bundle, policy, { now, register: encoder.encode("{") })), STRICT_SYNTAX);
  assert.equal(inputCode(() => verifyBundleBytes(encoder.encode("[".repeat(300) + "]".repeat(300)), policy, { now })), RESOURCE_LIMIT);
});
