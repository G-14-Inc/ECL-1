// Report identities are preserved, never trimmed into a different action. Robert F. Tilley Jr.; G-14, Inc.
import assert from "node:assert/strict";
import { test } from "node:test";
import { scopeMatches } from "../../src/conformance/corpus.js";
import type { CorpusVector, ObservedScope } from "../../src/conformance/corpus.js";
const effects = [{ action_id: "control", level: "none" }];
const vector: CorpusVector = { id: "effect-domain", path: "fixture.json", stage: "bundle", expected: "pass", expected_secondary_ids: [], expected_effects: effects };
for (const [name, text, met] of [
 ["empty", "", false], ["space", " ", false], ["ascii", "\t\n\r\v\f", false],
 ["next-line", "\x85", false], ["nbsp", "\u00a0", false], ["ogham", "\u1680", false],
 ["spaces", "\u2000\u200a", false], ["separators", "\u2028\u2029", false],
 ["narrow-medium-ideographic", "\u202f\u205f\u3000", false],
 ["token", "custom-token", true], ["preserved-spacing", " token ", true],
 ["bom-is-not-white-space", "\ufeff", true], ["separator-control-is-not-white-space", "\x1c", true],
] as const) test(`effect ID comparison ${name}`, () => {
 const actual: ObservedScope = { scope: { established: [], not_established: [], reasons: {} }, unresolved_predecessor_ids: [], effects: [...effects, { action_id: text, level: "none" }] };
 assert.equal(scopeMatches(vector, actual), met);
 assert.equal(actual.effects[1]!.action_id, text);
});
test("no effect expectation stays absent", () => assert.equal(scopeMatches({ id: "none", path: "fixture.json", stage: "semantic", expected: "pass", expected_secondary_ids: [] }, undefined), true));

test("empty effect expectation still checks retained action names", () => {
 const empty = { ...vector, expected_effects: [] };
 const actual: ObservedScope = { scope: { established: [], not_established: [], reasons: {} }, unresolved_predecessor_ids: [], effects: [{ action_id: "   ", level: "none" }] };
 assert.equal(scopeMatches(empty, actual), false);
 assert.equal(scopeMatches(empty, { ...actual, effects: [] }), true);
});
