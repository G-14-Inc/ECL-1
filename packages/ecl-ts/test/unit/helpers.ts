import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseStrictJson } from "../../src/index.js";
import type { JsonObject } from "../../src/index.js";

/** The repository root: ECL_REPO_ROOT, or the checkout this package sits in. */
export function repoRoot(): string {
  return process.env["ECL_REPO_ROOT"] ?? fileURLToPath(new URL("../../../../../", import.meta.url));
}

export function bytes(path: string): Uint8Array {
  return new Uint8Array(readFileSync(join(repoRoot(), path)));
}

export function json(path: string): JsonObject {
  return parseStrictJson(bytes(path)) as JsonObject;
}

export interface Vector {
  id: string;
  path: string;
  stage: string;
  expected: "pass" | "fail";
  expected_primary_id?: string;
  expected_secondary_ids: string[];
  expected_verdict?: string;
  expected_canonical_sha256?: string;
  schema?: string;
  trust_policy_path?: string;
  trust_policy_history_paths?: string[];
  evaluated_at?: string;
  require_trusted_time?: boolean;
  register_path?: string;
  strict_json_limits?: { max_bytes: number; max_depth: number; max_nodes: number };
}

export function suite(name: string): Vector[] {
  return (json(`conformance/suites/${name}/manifest.json`)["vectors"] as unknown) as Vector[];
}

export function hex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}
