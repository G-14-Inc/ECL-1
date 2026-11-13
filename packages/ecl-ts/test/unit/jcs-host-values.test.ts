import assert from "node:assert/strict";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import { JcsError, jcsCanonicalize, jcsDigest } from "../../src/bindings/jcs.js";
import type { JsonValue } from "../../src/json/value.js";

test("full JCS refuses array holes and named members without dropping content", () => {
  const named = Object.assign([1.5], { extra: "deny" });
  const numeric = Object.assign([], { "4294967295": "deny" });
  for (const value of [Array(1), [, 1.5], [1.5, ,], [1.5, , 2.5], [undefined], named, numeric, { nested: numeric }, { nested: [, 1] }]) {
    for (const entry of [jcsCanonicalize, jcsDigest]) {
      assert.throws(() => entry(value as JsonValue), JcsError);
    }
  }
  const hugeSparse: JsonValue[] = [];
  hugeSparse[4294967294] = 1.5;
  assert.throws(() => jcsCanonicalize(hugeSparse), JcsError);
});

test("full JCS refuses non-plain host objects and retains JSON object shapes", () => {
  class RecordLike { allowed = false; }
  const inherited = Object.create({ inherited: true }) as JsonValue;
  for (const value of [new Date(0), new Map([["allowed", false]]), new Set([1]), new Uint8Array([1]), new RecordLike(), inherited, undefined]) {
    assert.throws(() => jcsCanonicalize(value as JsonValue), JcsError);
  }
  const bare = Object.create(null) as Record<string, JsonValue>;
  bare["allowed"] = false;
  assert.equal(new TextDecoder().decode(jcsCanonicalize(bare)), '{"allowed":false}');
  const otherRealm = runInNewContext('({ allowed: false, values: [1.5] })') as JsonValue;
  assert.equal(new TextDecoder().decode(jcsCanonicalize(otherRealm)), '{"allowed":false,"values":[1.5]}');
});

test("full JCS retains finite fractions, negative zero and full string serialization", () => {
  const value: JsonValue = { values: [1.5, -0, 1e21, 1e-7], text: "é😀\n" };
  const canonical = new TextDecoder().decode(jcsCanonicalize(value));
  assert.equal(canonical, '{"text":"é😀\\n","values":[1.5,0,1e+21,1e-7]}');
  assert.deepEqual(JSON.parse(canonical), { text: "é😀\n", values: [1.5, 0, 1e21, 1e-7] });
  assert.equal(new TextDecoder().decode(jcsCanonicalize([])), "[]");
});
