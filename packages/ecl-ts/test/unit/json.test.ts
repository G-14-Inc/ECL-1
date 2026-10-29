import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalText, canonicalize, CanonicalizationError, digestObject, objectDigest, parseStrictJson, sha256Hex, StrictJsonError } from "../../src/index.js";
import type { JsonValue } from "../../src/index.js";
import { bytes, hex, suite } from "./helpers.js";

const encoder = new TextEncoder();

function refusal(input: Uint8Array | string): StrictJsonError {
  try {
    parseStrictJson(input);
  } catch (error) {
    assert.ok(error instanceof StrictJsonError);
    return error;
  }
  assert.fail("input was accepted");
}

test("canonical suite: every known answer and refusal", () => {
  for (const vector of suite("canonical")) {
    const data = bytes(vector.path);
    if (vector.expected === "fail") {
      const error = refusal(data);
      assert.equal(error.ruleId, vector.expected_primary_id, vector.id);
    } else {
      assert.equal(sha256Hex(canonicalize(parseStrictJson(data))), vector.expected_canonical_sha256, vector.id);
    }
  }
});

test("RFC 8785 member order is by UTF-16 code units", () => {
  const value = parseStrictJson(
    '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}',
  );
  assert.equal(
    canonicalText(value),
    '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
  );
});

test("canonical escapes are the shortest RFC 8785 forms", () => {
  const text = String.fromCharCode(...Array.from({ length: 32 }, (_, index) => index)) + '"\\é€\u007f ';
  assert.equal(
    canonicalText({ text }),
    '{"text":"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r\\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f\\"\\\\é€\u007f "}',
  );
});

test("integers in the exact range only; no fractions, exponents, -0 or constants", () => {
  assert.deepEqual(parseStrictJson("[-9007199254740991,0,9007199254740991]"), [-9007199254740991, 0, 9007199254740991]);
  for (const text of ["9007199254740992", "-9007199254740992", "1.0", "1e3", "1E-2", "-0", "123456789012345678901234567890"]) {
    const error = refusal(text);
    assert.equal(error.kind, "number", text);
    assert.equal(error.ruleId, "ecl.rule.json-restricted-numbers.v1", text);
  }
  // The constants are outside the grammar of RFC 8259 (IE1-037, check 2).
  for (const text of ["NaN", "Infinity", "-Infinity"]) {
    const error = refusal(text);
    assert.equal(error.kind, "constant", text);
    assert.equal(error.ruleId, "ecl.rule.json-strict-syntax.v1", text);
  }
  assert.throws(() => canonicalize(1.5), CanonicalizationError);
  assert.throws(() => canonicalize(2 ** 53), CanonicalizationError);
});

test("non-UTF-8 input and byte-order marks are refused", () => {
  const cases: Array<[string, number[]]> = [
    ["UTF-8 byte-order mark", [0xef, 0xbb, 0xbf, 0x7b, 0x7d]],
    ["UTF-16 LE with mark", [0xff, 0xfe, 0x7b, 0x00, 0x7d, 0x00]],
    ["UTF-16 BE with mark", [0xfe, 0xff, 0x00, 0x7b, 0x00, 0x7d]],
    ["UTF-16 LE without mark", [0x7b, 0x00, 0x7d, 0x00]],
    ["UTF-32 LE with mark", [0xff, 0xfe, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x7d, 0x00, 0x00, 0x00]],
    ["UTF-32 BE without mark", [0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x7d]],
    ["invalid byte", [0x22, 0xff, 0x22]],
    ["overlong encoding", [0x22, 0xc0, 0xaf, 0x22]],
    ["encoded surrogate", [0x22, 0xed, 0xa0, 0x80, 0x22]],
    ["truncated sequence", [0x22, 0xe2, 0x82, 0x22]],
  ];
  for (const [name, data] of cases) {
    const error = refusal(new Uint8Array(data));
    assert.equal(error.ruleId, "ecl.rule.json-strict-syntax.v1", name);
  }
});

test("the checks of IE1-037 run in order, whatever the position of each defect", () => {
  assert.equal(refusal('"\\ud800"').kind, "surrogate");
  assert.equal(refusal('"\\udc00x"').kind, "surrogate");
  assert.equal(refusal('"\\uffff"').kind, "noncharacter");
  assert.equal(refusal('"\\ufdd0"').kind, "noncharacter");
  assert.equal(refusal('"\\ud83f\\udffe"').kind, "noncharacter");
  assert.equal(refusal(new Uint8Array([0x22, 0xef, 0xbf, 0xbf, 0x22])).kind, "noncharacter");
  assert.equal(parseStrictJson('"\\ud83d\\ude00"'), "😀");
  assert.equal(parseStrictJson('"\\ue000"'), "\ue000");
  // Unicode scalar values (check 4) before repeated names (check 5) before numbers (check 6).
  assert.equal(refusal('{"a":"\\ud800","a":1}').kind, "surrogate");
  assert.equal(refusal('{"a":1,"a":"\\ufffe"}').kind, "noncharacter");
  assert.equal(refusal('{"a":1.5,"a":2}').kind, "duplicate-member");
  assert.equal(refusal('{"a":1,"a":2,"b":1.5}').kind, "duplicate-member");
  assert.equal(refusal('{"x":{"a":1,"a":2},"b":1.5}').kind, "duplicate-member");
  // A grammar error stops the parse: it decides even after a repeated name.
  assert.equal(refusal('{"a":1,"a":2').ruleId, "ecl.rule.json-strict-syntax.v1");
  // The nesting limit (check 3) before every later check.
  assert.equal(refusal("[".repeat(300) + '"\\ud800"' + "]".repeat(300)).ruleId, "ecl.error.resource-limit-exceeded.v1");
});

test("member names never reach a prototype", () => {
  const value = parseStrictJson('{"__proto__":{"polluted":true},"constructor":1}') as Record<string, JsonValue>;
  assert.deepEqual(Object.keys(value), ["__proto__", "constructor"]);
  assert.equal(({} as Record<string, unknown>)["polluted"], undefined);
  assert.equal(Object.getPrototypeOf(value), Object.prototype);
});

test("syntax and budgets", () => {
  for (const text of ["", " ", "{", "[1,]", '{"a":1,}', "{'a':1}", "01", "1 2", '"\\x"', '"\u0001"', "nul", "[1]x"]) {
    assert.equal(refusal(text).ruleId, "ecl.rule.json-strict-syntax.v1", JSON.stringify(text));
  }
  assert.deepEqual(parseStrictJson(" \t\r\n[1] \n"), [1]);
  // The outermost value is at depth 0, so 257 nested arrays reach the limit of 256 and 258 exceed it.
  assert.ok(Array.isArray(parseStrictJson("[".repeat(257) + "]".repeat(257))));
  assert.equal(refusal("[".repeat(258) + "]".repeat(258)).kind, "budget");
  assert.equal(refusal("[".repeat(258) + "]".repeat(258)).ruleId, "ecl.error.resource-limit-exceeded.v1");
  assert.throws(() => parseStrictJson(encoder.encode("[1, 2]"), { maxBytes: 5 }), (error: unknown) => error instanceof StrictJsonError && error.kind === "budget");
  assert.throws(() => parseStrictJson("[[1]]", { maxDepth: 1 }), (error: unknown) => error instanceof StrictJsonError && error.kind === "budget");
  assert.throws(() => parseStrictJson("[1,2,3]", { maxNodes: 3 }), (error: unknown) => error instanceof StrictJsonError && error.kind === "budget");
});

test("objectDigest is the SHA-256 of the canonical bytes", () => {
  assert.equal(objectDigest({ b: [1, 2], a: "x" }), sha256Hex(encoder.encode('{"a":"x","b":[1,2]}')));
  assert.equal(objectDigest({}), sha256Hex(hex("7b7d")));
});

test("IE1-002: canonicalize refuses a noncharacter in a string or a member name, as the reference does", () => {
  for (const code of [0xfdd0, 0xfdef, 0xfffe, 0xffff, 0x1fffe, 0x1ffff, 0x10fffe, 0x10ffff]) {
    const text = "x" + String.fromCodePoint(code);
    for (const value of [{ id: text }, { [text]: 1 }, { a: [{ b: text }] }]) {
      assert.throws(() => canonicalize(value), CanonicalizationError, code.toString(16));
    }
  }
  for (const code of [0xfdcf, 0xfdf0, 0xfffd, 0x10000, 0x1fffd, 0x10fffd]) {
    const text = "x" + String.fromCodePoint(code);
    assert.doesNotThrow(() => canonicalize({ [text]: text }), code.toString(16));
  }
});

/** The value that a canonical text must strict-parse back to: -0 is 0 (RFC 8785, section 3.2.2.3). */
function admitted(value: JsonValue): JsonValue {
  if (typeof value === "number") {
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) {
    return value.map(admitted);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([name, member]) => [name, admitted(member as JsonValue)]));
  }
  return value;
}

test("canonicalization refuses array holes and undefined, at every entry point that canonicalizes", () => {
  const sparse: unknown[] = [Array(1), [, 1], [1, ,], [1, , 2], [[, 1]], { a: [, 1] }, [undefined], [1, undefined], { a: undefined }, { a: [{ b: undefined }] }];
  for (const value of sparse) {
    for (const entry of [canonicalize, canonicalText, objectDigest, digestObject]) {
      assert.throws(
        () => entry(value as JsonValue),
        (error: unknown) => error instanceof CanonicalizationError && error.ruleId === "ecl.rule.json-strict-syntax.v1",
        `${entry.name}: ${String(value)}`,
      );
    }
  }
  // Values of the host language that are not JSON values.
  class Point {
    x = 1;
  }
  for (const value of [new Date(0), new Map([["a", 1]]), new Set([1]), new Uint8Array([1]), new Point(), () => 1, Symbol("s"), 1n, undefined]) {
    assert.throws(() => canonicalText(value as unknown as JsonValue), CanonicalizationError, String(typeof value));
  }
  for (const value of [NaN, Infinity, -Infinity, 0.5, 2 ** 53]) {
    assert.throws(() => canonicalText(value), (error: unknown) => error instanceof CanonicalizationError && error.ruleId === "ecl.rule.json-restricted-numbers.v1", String(value));
  }
  // A null-prototype object used as a prototype, whose member would be dropped, and an array with
  // a named member, which would be dropped too, are not JSON values.
  const base = Object.create(null) as Record<string, JsonValue>;
  base["inherited"] = 1;
  const derived = Object.create(base) as Record<string, JsonValue>;
  derived["own"] = 2;
  assert.throws(() => canonicalText(derived), CanonicalizationError);
  const named = [1, 2] as unknown as JsonValue[] & { extra?: number };
  named.extra = 3;
  assert.throws(() => canonicalText(named), CanonicalizationError);
  // A sparse array of any length is refused by the node budget before any position is read
  // (IE1-029), with the resource-limit code.
  for (const length of [2_000_000, 20_000_000, 2 ** 32 - 1]) {
    const started = Date.now();
    assert.throws(() => canonicalize(new Array(length) as JsonValue), (error: unknown) => error instanceof CanonicalizationError && error.ruleId === "ecl.error.resource-limit-exceeded.v1", String(length));
    assert.ok(Date.now() - started < 1000, `${length}: refused in ${Date.now() - started} ms`);
  }
  // A plain object without a prototype is a JSON object.
  const bare = Object.create(null) as Record<string, JsonValue>;
  bare["b"] = 1;
  bare["a"] = [true, null];
  assert.equal(canonicalText(bare), '{"a":[true,null],"b":1}');
  // A value beyond a declared budget is the resource-limit refusal.
  let deep: JsonValue = 1;
  for (let depth = 0; depth < 300; depth += 1) {
    deep = [deep];
  }
  assert.throws(() => canonicalize(deep), (error: unknown) => error instanceof CanonicalizationError && error.ruleId === "ecl.error.resource-limit-exceeded.v1");
});

/** Whether a value holds an array hole or `undefined` anywhere: a value that is not JSON. */
function holdsNonJson(value: unknown): boolean {
  if (value === undefined) {
    return true;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value) || holdsNonJson(value[index])) {
        return true;
      }
    }
    return false;
  }
  if (value !== null && typeof value === "object") {
    return Object.values(value).some(holdsNonJson);
  }
  return false;
}

test("every successful canonicalization strict-parses to the admitted value, and a value with a hole or undefined is refused", () => {
  // A deterministic generator (a linear congruential sequence), so a failure is reproducible.
  let state = 0x2545f491;
  const next = (limit: number): number => {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    return state % limit;
  };
  const strings = ["", "a", "\u0000", '"', "\\", "\u001f", "\u007f", "é", "€", "😀", "𝄞", "x y", "__proto__", "constructor"];
  const generate = (depth: number): JsonValue => {
    const choice = next(depth > 4 ? 6 : 8);
    switch (choice) {
      case 0:
        return null;
      case 1:
        return next(2) === 0;
      case 2:
        return [0, -0, 1, -1, 9007199254740991, -9007199254740991, next(1_000_000) - 500_000][next(7)] as number;
      case 3:
      case 4:
      case 5:
        return strings[next(strings.length)] as string;
      case 6: {
        const length = next(5);
        const items: JsonValue[] = [];
        for (let index = 0; index < length; index += 1) {
          // Now and then a hole or `undefined`, which canonicalization must refuse.
          const odd = next(40);
          if (odd === 0) {
            items.length += 1;
          } else if (odd === 1) {
            items.push(undefined as unknown as JsonValue);
          } else {
            items.push(generate(depth + 1));
          }
        }
        return items;
      }
      default: {
        const value: Record<string, JsonValue> = {};
        const count = next(5);
        for (let index = 0; index < count; index += 1) {
          const member = next(60) === 0 ? (undefined as unknown as JsonValue) : generate(depth + 1);
          Object.defineProperty(value, strings[next(strings.length)] as string, { value: member, enumerable: true, writable: true, configurable: true });
        }
        return value;
      }
    }
  };
  let refused = 0;
  for (let round = 0; round < 2000; round += 1) {
    const value = generate(0);
    if (holdsNonJson(value)) {
      assert.throws(() => canonicalText(value), (error: unknown) => error instanceof CanonicalizationError && error.ruleId === "ecl.rule.json-strict-syntax.v1");
      refused += 1;
      continue;
    }
    const text = canonicalText(value);
    const parsed = parseStrictJson(text);
    assert.deepEqual(parsed, admitted(value), text);
    assert.equal(canonicalText(parsed), text, text);
  }
  // The generator made values of both kinds.
  assert.ok(refused > 50 && refused < 1950, String(refused));
});
