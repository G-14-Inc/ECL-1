/**
 * Schema and semantic findings for one DCMP-2, EBMP-2 or ECL-IE-1 object, as the bundle verifier
 * applies them to each signed payload. The parser limits of the reference come first: an object
 * nested deeper than 32 levels or holding more than 10 000 values gets one finding and nothing
 * else is checked.
 */

import { get, isArray, isObject } from "../json/value.js";
import type { JsonValue } from "../json/value.js";
import { eclSchemas } from "../schema/validator.js";
import type { SchemaSet } from "../schema/validator.js";
import { isMalformedInputError } from "./python.js";
import { SCHEMA_INVALID, SemanticValidator, sortFindings } from "./rules.js";
import type { Finding } from "./rules.js";

export const MAX_OBJECT_DEPTH = 32;
export const MAX_OBJECT_NODES = 10_000;
const MAX_FINDINGS_PER_RULE = 100;
const MAX_TEXT = 200;
const PROTOCOL_SCHEMAS: Record<string, string> = {
  "DCMP-2": "https://externalcontrollayer.ai/ns/schema/dcmp/2",
  "EBMP-2": "https://externalcontrollayer.ai/ns/schema/ebmp/2",
};
const ENVELOPE_SCHEMA = "https://externalcontrollayer.ai/ns/schema/integrity-envelope/1";

function cut(text: string): string {
  return text.length <= MAX_TEXT ? text : text.slice(0, MAX_TEXT - 1) + "…";
}

function invalid(path: string, message: string): Finding {
  return { ruleId: SCHEMA_INVALID, path: cut(path), message: cut(message) };
}

function limitExceeded(value: JsonValue): string | undefined {
  let nodes = 1;
  const pending: Array<[JsonValue, number]> = [[value, 1]];
  while (pending.length > 0) {
    const [container, depth] = pending.pop() as [JsonValue, number];
    if (depth > MAX_OBJECT_DEPTH) {
      return `nesting depth exceeds ${MAX_OBJECT_DEPTH}`;
    }
    const children = isArray(container) ? container : isObject(container) ? Object.values(container) : [];
    nodes += children.length;
    if (nodes > MAX_OBJECT_NODES) {
      return `node count exceeds ${MAX_OBJECT_NODES}`;
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
 * The schema and semantic findings for a DCMP-2, EBMP-2 or ECL-IE-1 value. It never throws:
 * anything that is not one of those objects yields one `ecl.error.schema-invalid.v1` finding.
 */
export function objectFindings(value: JsonValue, schemas: SchemaSet = eclSchemas(), semantics?: SemanticValidator): Finding[] {
  if (!isObject(value)) {
    return [invalid("/", "an ECL object must be a JSON object")];
  }
  const excess = limitExceeded(value);
  if (excess !== undefined) {
    return [invalid("/", excess)];
  }
  const schema = schemaFor(value);
  if (schema === undefined) {
    return [invalid("/", "not a DCMP-2 or EBMP-2 object, and not an ECL-IE-1 envelope")];
  }
  const errors = schemas.errors(schema, value, MAX_FINDINGS_PER_RULE + 1);
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
