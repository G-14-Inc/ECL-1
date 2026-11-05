import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { SemanticValidator, TrustPolicy, otel } from "../../src/index.js";
import { CAPABILITIES, observedForVector, scopeMatches, selectBundleFinding, selectFindings } from "../../src/conformance/corpus.js";
import type { CorpusVector, EvaluationContext, ObservedScope } from "../../src/conformance/corpus.js";
import { bytes, json, repoRoot } from "./helpers.js";
import type { JsonObject } from "../../src/index.js";

function registries(): { precedence: Map<string, number>; errors: Set<string> } {
  const precedence = new Map<string, number>();
  for (const entry of json("registries/semantic-rules.json")["entries"] as JsonObject[]) {
    if (entry["status"] === "active") {
      precedence.set(entry["id"] as string, (entry["attributes"] as JsonObject)["precedence"] as number);
    }
  }
  const errors = new Set((json("registries/error-codes.json")["entries"] as JsonObject[]).filter((entry) => entry["status"] === "active").map((entry) => entry["id"] as string));
  return { precedence, errors };
}

test("every shared vector of a supported capability meets its expected primary, secondaries and verdict", () => {
  const root = repoRoot();
  const { precedence, errors } = registries();
  const semantics = new SemanticValidator();
  const corpus = json("conformance/shared-corpus.json");
  const optional = corpus["optional_capabilities"] as string[];
  const capabilityOf = new Map((corpus["vectors"] as JsonObject[]).map((row) => [row["id"] as string, row["capability"] as string]));
  const manifests = ["conformance/manifest.json", ...readdirSync(join(root, "conformance/suites")).sort().map((name) => `conformance/suites/${name}/manifest.json`)];
  let count = 0;
  let unsupported = 0;
  let verdicts = 0;
  let expectedVerdicts = 0;
  for (const path of manifests) {
    const manifest = json(path);
    const trustPath = manifest["trust_policy_path"];
    const trustPolicy = typeof trustPath === "string" ? TrustPolicy.load(bytes(trustPath)) : undefined;
    const keysPath = manifest["export_keys_path"];
    const exportKeys = typeof keysPath === "string" ? otel.loadExportKeys(bytes(keysPath)) : undefined;
    for (const vector of manifest["vectors"] as unknown as CorpusVector[]) {
      const capability = capabilityOf.get(vector.id) as string;
      if (!(CAPABILITIES as readonly string[]).includes(capability)) {
        // A capability this library does not implement: it must be an optional one, and the
        // corpus runner reports the vector as unsupported, never as met.
        assert.ok(optional.includes(capability), `${vector.id}: ${capability}`);
        unsupported += 1;
        count += 1;
        continue;
      }
      const scopes = new Map<string, ObservedScope>();
      const context: EvaluationContext = {
        root,
        semantics,
        verdicts: new Map(),
        scopes,
        ...(trustPolicy === undefined ? {} : { trustPolicy }),
        ...(exportKeys === undefined ? {} : { exportKeys }),
      };
      // A signed bundle reports its findings in the order of EBMP2-068 and has no required
      // secondary findings; every other stage is ordered by precedence.
      const select = vector.stage === "evidence-bundle" ? selectBundleFinding : selectFindings;
      const [primary, secondary] = select(observedForVector(vector, context), precedence, errors);
      if (vector.expected === "pass") {
        assert.equal(primary, null, vector.id);
      } else {
        assert.equal(primary, vector.expected_primary_id, vector.id);
        assert.deepEqual(secondary, [...vector.expected_secondary_ids].sort(), vector.id);
      }
      // EBMP2-076 and EBMP2-061: the scope and evidence levels a vector names.
      assert.ok(scopeMatches(vector, scopes.get(vector.id)), `${vector.id}: ${JSON.stringify(scopes.get(vector.id))}`);
      if (vector.expected_verdict !== undefined) {
        expectedVerdicts += 1;
        assert.equal(context.verdicts.get(vector.id), vector.expected_verdict, vector.id);
        verdicts += 1;
      }
      count += 1;
    }
  }
  assert.equal(count, (corpus["vectors"] as unknown[]).length);
  // Every capability of the corpus is implemented, offline package verification included, so no
  // vector is reported unsupported and none is pending.
  assert.equal(unsupported, 0);
  for (const capability of [...(corpus["required_capabilities"] as string[]), ...optional]) {
    assert.ok((CAPABILITIES as readonly string[]).includes(capability), capability);
  }
  assert.ok(verdicts > 0);
  assert.equal(verdicts, expectedVerdicts);
});
