/**
 * Schema and semantic findings for one DCMP-2, EBMP-2 or ECL-IE-1 object, as the bundle verifier
 * applies them to each signed payload. The declared strict-parser profile comes first: root
 * depth zero, every scalar leaf included, 256 levels and 1 000 000 values by default. Exceeding
 * a declared limit is a resource-limit finding before schema or semantic checks.
 */

import { get, isArray, isObject } from "../json/value.js";
import type { JsonValue } from "../json/value.js";
import { eclSchemas } from "../schema/validator.js";
import type { SchemaSet } from "../schema/validator.js";
import { isMalformedInputError } from "./python.js";
import { SCHEMA_INVALID, SemanticValidator, sortFindings } from "./rules.js";
import type { Finding } from "./rules.js";
import { MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_JSON_DEPTH_CEILING, MAX_JSON_NODES_CEILING, RESOURCE_LIMIT, CONFIGURATION_INVALID } from "../json/strict.js";
import type { StrictJsonLimits } from "../json/strict.js";

export const MAX_OBJECT_DEPTH = MAX_JSON_DEPTH;
export const MAX_OBJECT_NODES = MAX_JSON_NODES;
const MAX_FINDINGS_PER_RULE = 100;
const MAX_TEXT = 200;
const PROTOCOL_SCHEMAS: Record<string, string> = {
  "DCMP-2": "https://externalcontrollayer.ai/ns/schema/dcmp/2",
  "EBMP-2": "https://externalcontrollayer.ai/ns/schema/ebmp/2",
};
const ENVELOPE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/integrity-envelope/1";

function cut(text: string): string {
  const characters = Array.from(text);
  return characters.length <= MAX_TEXT ? text : characters.slice(0, MAX_TEXT - 1).join("") + "…";
}

function invalid(path: string, message: string): Finding {
  return { ruleId: SCHEMA_INVALID, path: cut(path), message: cut(message) };
}

export function objectLimitExceeded(value: JsonValue, maxDepth = MAX_JSON_DEPTH, maxNodes = MAX_JSON_NODES): string | undefined {
  let nodes = 1;
  const pending: Array<[JsonValue, number]> = [[value, 0]];
  while (pending.length > 0) {
    const [container, depth] = pending.pop() as [JsonValue, number];
    if (depth > maxDepth) {
      return `nesting depth exceeds ${maxDepth}`;
    }
    const children = isArray(container) ? container : isObject(container) ? Object.values(container) : [];
    nodes += children.length;
    if (nodes > maxNodes) {
      return `node count exceeds ${maxNodes}`;
    }
    if (children.length > 0 && depth + 1 > maxDepth) {
      return `nesting depth exceeds ${maxDepth}`;
    }
    for (const child of children) {
      if (isArray(child) || isObject(child)) {
        pending.push([child, depth + 1]);
      }
    }
  }
  return undefined;
}

function schemaFor(value: JsonValue): string | undefined {
  const protocol = get(value, "protocol");
  if (typeof protocol === "string" && Object.prototype.hasOwnProperty.call(PROTOCOL_SCHEMAS, protocol)) {
    return PROTOCOL_SCHEMAS[protocol];
  }
  if (get(value, "envelope_version") === "ECL-IE-1") {
    return ENVELOPE_SCHEMA;
  }
  return undefined;
}

function capped(findings: Finding[]): Finding[] {
  const kept: Finding[] = [];
  const counts = new Map<string, number>();
  for (const entry of findings) {
    const count = (counts.get(entry.ruleId) ?? 0) + 1;
    counts.set(entry.ruleId, count);
    if (count <= MAX_FINDINGS_PER_RULE) {
      kept.push({ ruleId: entry.ruleId, path: cut(entry.path), message: cut(entry.message) });
    }
  }
  for (const [ruleId, count] of counts) {
    if (count > MAX_FINDINGS_PER_RULE) {
      kept.push({ ruleId, path: "/", message: `${count - MAX_FINDINGS_PER_RULE} more follow, and are not listed` });
    }
  }
  return kept;
}

let defaultSemantics: SemanticValidator | undefined;

/**
 * Schema and semantic findings for a JSON value under a valid validator configuration.
 * Values outside the DCMP-2, EBMP-2 and ECL-IE-1 object families yield a schema finding.
 * Recognized malformed-input errors from schema or semantic validation become schema findings;
 * unexpected faults, including errors from caller-supplied validator configuration, propagate.
 */
export function objectFindings(value: JsonValue, schemas: SchemaSet = eclSchemas(), semantics?: SemanticValidator, limits: Pick<StrictJsonLimits, "maxDepth" | "maxNodes"> = {}): Finding[] {
  const maxDepth = limits.maxDepth === undefined ? MAX_OBJECT_DEPTH : limits.maxDepth;
  const maxNodes = limits.maxNodes === undefined ? MAX_OBJECT_NODES : limits.maxNodes;
  for (const [name, limit, ceiling] of [["maxDepth", maxDepth, MAX_JSON_DEPTH_CEILING], ["maxNodes", maxNodes, MAX_JSON_NODES_CEILING]] as const) {
    if (typeof limit !== "number" || !Number.isSafeInteger(limit) || limit < 1 || limit > ceiling) {
      return [{ ruleId: CONFIGURATION_INVALID, path: "/", message: `${name} must be an integer from 1 to ${ceiling}` }];
    }
  }
  if (!isObject(value)) {
    return [invalid("/", "an ECL object must be a JSON object")];
  }
  const excess = objectLimitExceeded(value, maxDepth, maxNodes);
  if (excess !== undefined) {
    return [{ ruleId: RESOURCE_LIMIT, path: "/", message: excess }];
  }
  const schema = schemaFor(value);
  if (schema === undefined) {
    return [invalid("/", "not a DCMP-2 or EBMP-2 object, and not an ECL-IE-1 envelope")];
  }
  let errors: ReturnType<SchemaSet["errors"]>;
  try {
    errors = schemas.errors(schema, value, MAX_FINDINGS_PER_RULE + 1);
  } catch (error) {
    if (!isMalformedInputError(error)) {
      throw error;
    }
    return [invalid("/", `schema validation could not be completed: ${(error as Error).name}`)];
  }
  const findings = errors.slice(0, MAX_FINDINGS_PER_RULE).map((error) => invalid(error.path, `${error.keyword}: ${error.message}`));
  if (errors.length > MAX_FINDINGS_PER_RULE) {
    findings.push(invalid("/", "more schema errors follow, and are not listed"));
  }
  const validator = semantics ?? (defaultSemantics ??= new SemanticValidator());
  try {
    findings.push(...capped(validator.validate(value)));
  } catch (error) {
    if (!isMalformedInputError(error)) {
      throw error;
    }
    findings.push(invalid("/", `semantic validation could not be completed: ${(error as Error).name}`));
  }
  return sortFindings(findings);
}
