import assert from "node:assert/strict";
import { test } from "node:test";
import { parseStrictJson, StrictJsonError } from "../../src/index.js";

for (const [name, input, maxBytes, expected] of [
  ["lone high followed by three-byte scalar", '"\ud800\u1000"', 6, "ecl.error.resource-limit-exceeded.v1"],
  ["lone high at exact byte limit", '"\ud800', 4, "ecl.rule.json-strict-syntax.v1"],
  ["lone low at exact byte limit", '"\udc00"', 5, "ecl.rule.json-strict-syntax.v1"],
  ["lone high plus ASCII at exact limit", '"\ud800x"', 6, "ecl.rule.json-strict-syntax.v1"],
  ["two high surrogates exceed limit", '"\ud800\ud801"', 7, "ecl.error.resource-limit-exceeded.v1"],
  ["paired surrogate exceeds limit", '"\ud83d\ude00"', 5, "ecl.error.resource-limit-exceeded.v1"],
] as const) {
  test(name, () => assert.throws(() => parseStrictJson(input, {maxBytes}),
    (error: unknown) => error instanceof StrictJsonError && error.ruleId === expected));
}
test("valid pair and BMP retain their exact UTF-8 limits", () => {
  assert.equal(parseStrictJson('"\ud83d\ude00"', {maxBytes: 6}), "\ud83d\ude00");
  assert.equal(parseStrictJson('"\u1000"', {maxBytes: 5}), "\u1000");
});
