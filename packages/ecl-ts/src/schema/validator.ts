/**
 * A JSON Schema Draft 2020-12 validator for the keywords the ECL schemas use, written to reach
 * the same decisions as the reference (python-jsonschema 4.25 with the ECL format checker).
 *
 * - `pattern` is an ECMA-262 regular expression, so it is matched natively, searching anywhere
 *   in the string, with Unicode semantics.
 * - Lengths count Unicode code points; `const`, `enum` and `uniqueItems` never equate a boolean
 *   with a number.
 * - `unevaluatedProperties` treats as evaluated the members that the reference's annotation
 *   collection finds: declared `properties`, members valid under `additionalProperties`, and
 *   those of every `allOf`, `anyOf` and `oneOf` branch, `if`/`then`/`else` arm and `$ref` that
 *   the instance satisfies.
 * - `date-time` and `uri` are asserted, and are false for anything that is not a string.
 * - `contains` needs at least one item that its schema accepts (the default `minContains` of 1;
 *   `minContains` and `maxContains` are not used by the ECL schemas and are refused).
 *
 * Any other keyword is refused when the schema set is built, so a schema that needs more than
 * this validator implements fails loudly instead of being half-checked.
 */

import { RECORD_SCHEMA_DOCUMENTS } from "../generated/record-schemas.js";
import { SCHEMA_DOCUMENTS } from "../generated/schemas.js";
import { isArray, isObject, schemaEquals, codePointLength, has } from "../json/value.js";
import type { JsonObject, JsonValue } from "../json/value.js";
import { isAbsoluteUri, isDateTime } from "./formats.js";

/** One way an instance fails a schema. Messages are informative; the keyword is not. */
export interface SchemaError {
  /** JSON Pointer to the failing member of the instance. */
  readonly path: string;
  /** The keyword that failed. */
  readonly keyword: string;
  readonly message: string;
}

const VALIDATION_KEYWORDS = new Set([
  "$ref",
  "type",
  "required",
  "properties",
  "patternProperties",
  "additionalProperties",
  "unevaluatedProperties",
  "propertyNames",
  "dependentRequired",
  "dependentSchemas",
  "minProperties",
  "maxProperties",
  "items",
  "prefixItems",
  "contains",
  "minItems",
  "maxItems",
  "uniqueItems",
  "const",
  "enum",
  "minLength",
  "maxLength",
  "pattern",
  "format",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "allOf",
  "anyOf",
  "oneOf",
  "not",
  "if",
  "then",
  "else",
]);
const ANNOTATION_KEYWORDS = new Set([
  "$schema",
  "$id",
  "$defs",
  "$comment",
  "title",
  "description",
  "default",
  "examples",
  "deprecated",
  "readOnly",
  "writeOnly",
  "contentEncoding",
  "contentMediaType",
]);
const FORMATS: Record<string, (value: unknown) => boolean> = {
  "date-time": isDateTime,
  uri: isAbsoluteUri,
};

type Schema = JsonObject | boolean;

interface Resolved {
  schema: Schema;
  base: string;
}

/** A schema set: documents by `$id`, with every reference resolvable within the set. */
export class SchemaSet {
  private readonly documents = new Map<string, JsonObject>();
  private readonly patterns = new Map<string, RegExp>();
  private readonly cache = new Map<string, Resolved>();

  constructor(documents: Iterable<readonly [string, JsonValue]>) {
    for (const [identifier, document] of documents) {
      if (!isObject(document)) {
        throw new Error(`schema ${identifier} is not an object`);
      }
      this.documents.set(identifier, document);
    }
    for (const [identifier, document] of this.documents) {
      this.prepare(document, identifier, identifier);
    }
  }

  /** The schema `$id`s of the set. */
  identifiers(): string[] {
    return [...this.documents.keys()];
  }

  private prepare(node: JsonValue, base: string, where: string): void {
    if (typeof node === "boolean") {
      return;
    }
    if (!isObject(node)) {
      throw new Error(`${where}: a schema is an object or a boolean`);
    }
    for (const keyword of Object.keys(node)) {
      if (!VALIDATION_KEYWORDS.has(keyword) && !ANNOTATION_KEYWORDS.has(keyword)) {
        throw new Error(`${where}: unsupported schema keyword ${keyword}`);
      }
    }
    const format = node["format"];
    if (format !== undefined && (typeof format !== "string" || !(format in FORMATS))) {
      throw new Error(`${where}: unsupported format ${String(format)}`);
    }
    const pattern = node["pattern"];
    if (typeof pattern === "string") {
      this.regex(pattern);
    }
    const reference = node["$ref"];
    if (typeof reference === "string") {
      this.resolve(reference, base);
    }
    for (const keyword of ["properties", "patternProperties", "dependentSchemas", "$defs"]) {
      const map = node[keyword];
      if (isObject(map)) {
        for (const key of Object.keys(map)) {
          if (keyword === "patternProperties") {
            this.regex(key);
          }
          this.prepare(map[key] as JsonValue, base, where);
        }
      }
    }
    for (const keyword of ["additionalProperties", "unevaluatedProperties", "propertyNames", "items", "contains", "not", "if", "then", "else"]) {
      if (has(node, keyword)) {
        this.prepare(node[keyword] as JsonValue, base, where);
      }
    }
    for (const keyword of ["allOf", "anyOf", "oneOf", "prefixItems"]) {
      const list = node[keyword];
      if (isArray(list)) {
        for (const item of list) {
          this.prepare(item, base, where);
        }
      }
    }
  }

  private regex(pattern: string): RegExp {
    let compiled = this.patterns.get(pattern);
    if (compiled === undefined) {
      compiled = new RegExp(pattern, "u");
      this.patterns.set(pattern, compiled);
    }
    return compiled;
  }

  /** Resolve a reference (absolute, or a fragment of the base document) to its schema. */
  resolve(reference: string, base: string): Resolved {
    const key = base + " " + reference;
    const cached = this.cache.get(key);
    if (cached !== undefined) {
      return cached;
    }
    const hash = reference.indexOf("#");
    const target = hash < 0 ? reference : reference.slice(0, hash);
    const fragment = hash < 0 ? "" : reference.slice(hash + 1);
    const identifier = target === "" ? base : target;
    const document = this.documents.get(identifier);
    if (document === undefined) {
      throw new Error(`unresolvable schema reference ${reference}`);
    }
    let node: JsonValue = document;
    if (fragment !== "") {
      if (!fragment.startsWith("/")) {
        throw new Error(`unsupported schema reference ${reference}`);
      }
      for (const raw of fragment.slice(1).split("/")) {
        const step = decodeURIComponent(raw).replace(/~1/g, "/").replace(/~0/g, "~");
        if (isObject(node) && has(node, step)) {
          node = node[step] as JsonValue;
        } else if (isArray(node) && /^(0|[1-9][0-9]*)$/.test(step) && Number(step) < node.length) {
          node = node[Number(step)] as JsonValue;
        } else {
          throw new Error(`unresolvable schema reference ${reference}`);
        }
      }
    }
    if (typeof node !== "boolean" && !isObject(node)) {
      throw new Error(`schema reference ${reference} does not name a schema`);
    }
    const resolved = { schema: node, base: identifier };
    this.cache.set(key, resolved);
    return resolved;
  }

  /** Every way `instance` fails the schema named by `reference` (an `$id`, optionally with a fragment). */
  errors(reference: string, instance: JsonValue, limit = 1000): SchemaError[] {
    const { schema, base } = this.resolve(reference, reference.split("#", 1)[0] as string);
    const out: SchemaError[] = [];
    this.evaluate(schema, base, instance, "", out, limit);
    return out;
  }

  /** Whether `instance` satisfies the schema named by `reference`. */
  isValid(reference: string, instance: JsonValue): boolean {
    const { schema, base } = this.resolve(reference, reference.split("#", 1)[0] as string);
    return this.evaluate(schema, base, instance, "", null, 0);
  }

  private valid(schema: Schema, base: string, instance: JsonValue): boolean {
    return this.evaluate(schema, base, instance, "", null, 0);
  }

  /**
   * Evaluate one schema node. With `out` null it stops at the first failure and only answers
   * validity; otherwise it records up to `limit` errors.
   */
  private evaluate(schema: Schema, base: string, instance: JsonValue, path: string, out: SchemaError[] | null, limit: number): boolean {
    if (schema === true) {
      return true;
    }
    if (schema === false) {
      if (out !== null) {
        push(out, limit, path, "false", "no value is valid here");
      }
      return false;
    }
    let ok = true;
    const fail = (keyword: string, message: string, at: string = path): boolean => {
      ok = false;
      if (out !== null) {
        push(out, limit, at, keyword, message);
      }
      return out === null;
    };
    const descend = (child: Schema, childBase: string, value: JsonValue, childPath: string): boolean => {
      if (!this.evaluate(child, childBase, value, childPath, out, limit)) {
        ok = false;
        return out === null;
      }
      return false;
    };

    if (typeof schema["$ref"] === "string") {
      const target = this.resolve(schema["$ref"], base);
      if (descend(target.schema, target.base, instance, path)) {
        return false;
      }
    }
    const type = schema["type"];
    if (type !== undefined) {
      const types = isArray(type) ? type : [type];
      if (!types.some((item) => typeof item === "string" && hasType(instance, item))) {
        if (fail("type", `${describe(instance)} is not of type ${types.map((item) => JSON.stringify(item)).join(", ")}`)) {
          return false;
        }
      }
    }
    if (has(schema, "const") && !schemaEquals(instance, schema["const"] as JsonValue)) {
      if (fail("const", `${describe(instance)} is not the required constant`)) {
        return false;
      }
    }
    const enumeration = schema["enum"];
    if (isArray(enumeration) && !enumeration.some((item) => schemaEquals(item, instance))) {
      if (fail("enum", `${describe(instance)} is not one of the permitted values`)) {
        return false;
      }
    }
    if (typeof instance === "string") {
      const length = typeof schema["minLength"] === "number" || typeof schema["maxLength"] === "number" ? codePointLength(instance) : 0;
      if (typeof schema["minLength"] === "number" && length < schema["minLength"]) {
        if (fail("minLength", `string is shorter than ${schema["minLength"]} characters`)) {
          return false;
        }
      }
      if (typeof schema["maxLength"] === "number" && length > schema["maxLength"]) {
        if (fail("maxLength", `string is longer than ${schema["maxLength"]} characters`)) {
          return false;
        }
      }
      if (typeof schema["pattern"] === "string" && !this.regex(schema["pattern"]).test(instance)) {
        if (fail("pattern", `string does not match ${schema["pattern"]}`)) {
          return false;
        }
      }
    }
    if (typeof schema["format"] === "string") {
      const check = FORMATS[schema["format"]];
      if (check !== undefined && !check(instance)) {
        if (fail("format", `${describe(instance)} is not a ${schema["format"]}`)) {
          return false;
        }
      }
    }
    if (typeof instance === "number") {
      if (typeof schema["minimum"] === "number" && instance < schema["minimum"]) {
        if (fail("minimum", `${instance} is less than the minimum of ${schema["minimum"]}`)) {
          return false;
        }
      }
      if (typeof schema["maximum"] === "number" && instance > schema["maximum"]) {
        if (fail("maximum", `${instance} is greater than the maximum of ${schema["maximum"]}`)) {
          return false;
        }
      }
      if (typeof schema["exclusiveMinimum"] === "number" && instance <= schema["exclusiveMinimum"]) {
        if (fail("exclusiveMinimum", `${instance} is not greater than ${schema["exclusiveMinimum"]}`)) {
          return false;
        }
      }
      if (typeof schema["exclusiveMaximum"] === "number" && instance >= schema["exclusiveMaximum"]) {
        if (fail("exclusiveMaximum", `${instance} is not less than ${schema["exclusiveMaximum"]}`)) {
          return false;
        }
      }
    }
    if (isArray(instance)) {
      if (typeof schema["minItems"] === "number" && instance.length < schema["minItems"]) {
        if (fail("minItems", `array has fewer than ${schema["minItems"]} items`)) {
          return false;
        }
      }
      if (typeof schema["maxItems"] === "number" && instance.length > schema["maxItems"]) {
        if (fail("maxItems", `array has more than ${schema["maxItems"]} items`)) {
          return false;
        }
      }
      if (schema["uniqueItems"] === true && !unique(instance)) {
        if (fail("uniqueItems", "array has repeated items")) {
          return false;
        }
      }
      const prefix = isArray(schema["prefixItems"]) ? schema["prefixItems"] : [];
      for (let index = 0; index < Math.min(prefix.length, instance.length); index += 1) {
        if (descend(prefix[index] as Schema, base, instance[index] as JsonValue, `${path}/${index}`)) {
          return false;
        }
      }
      if (has(schema, "contains") && !instance.some((entry) => this.valid(schema["contains"] as Schema, base, entry))) {
        if (fail("contains", "array does not contain an item that the given schema accepts")) {
          return false;
        }
      }
      if (has(schema, "items") && instance.length > prefix.length) {
        const items = schema["items"] as Schema;
        if (items === false) {
          if (fail("items", `array has more than ${prefix.length} items`)) {
            return false;
          }
        } else {
          for (let index = prefix.length; index < instance.length; index += 1) {
            if (descend(items, base, instance[index] as JsonValue, `${path}/${index}`)) {
              return false;
            }
          }
        }
      }
    }
    if (isObject(instance)) {
      const names = Object.keys(instance);
      if (typeof schema["minProperties"] === "number" && names.length < schema["minProperties"]) {
        if (fail("minProperties", `object has fewer than ${schema["minProperties"]} members`)) {
          return false;
        }
      }
      if (typeof schema["maxProperties"] === "number" && names.length > schema["maxProperties"]) {
        if (fail("maxProperties", `object has more than ${schema["maxProperties"]} members`)) {
          return false;
        }
      }
      const required = schema["required"];
      if (isArray(required)) {
        for (const name of required) {
          if (typeof name === "string" && !has(instance, name)) {
            if (fail("required", `${JSON.stringify(name)} is a required member`)) {
              return false;
            }
          }
        }
      }
      const dependentRequired = schema["dependentRequired"];
      if (isObject(dependentRequired)) {
        for (const name of Object.keys(dependentRequired)) {
          const needed = dependentRequired[name];
          if (has(instance, name) && isArray(needed)) {
            for (const other of needed) {
              if (typeof other === "string" && !has(instance, other)) {
                if (fail("dependentRequired", `${JSON.stringify(other)} is required when ${JSON.stringify(name)} is present`)) {
                  return false;
                }
              }
            }
          }
        }
      }
      const properties = isObject(schema["properties"]) ? schema["properties"] : undefined;
      if (properties !== undefined) {
        for (const name of Object.keys(properties)) {
          if (has(instance, name)) {
            if (descend(properties[name] as Schema, base, instance[name] as JsonValue, `${path}/${escapePointer(name)}`)) {
              return false;
            }
          }
        }
      }
      const patternProperties = isObject(schema["patternProperties"]) ? schema["patternProperties"] : undefined;
      if (patternProperties !== undefined) {
        for (const pattern of Object.keys(patternProperties)) {
          const regex = this.regex(pattern);
          for (const name of names) {
            if (regex.test(name)) {
              if (descend(patternProperties[pattern] as Schema, base, instance[name] as JsonValue, `${path}/${escapePointer(name)}`)) {
                return false;
              }
            }
          }
        }
      }
      if (has(schema, "additionalProperties")) {
        const additional = schema["additionalProperties"] as Schema;
        const patterns = patternProperties === undefined ? [] : Object.keys(patternProperties).map((item) => this.regex(item));
        const extras = names.filter(
          (name) => (properties === undefined || !has(properties, name)) && !patterns.some((regex) => regex.test(name)),
        );
        if (additional === false) {
          if (extras.length > 0) {
            if (fail("additionalProperties", `additional members are not allowed (${extras.map((name) => JSON.stringify(name)).join(", ")})`)) {
              return false;
            }
          }
        } else {
          for (const name of extras) {
            if (descend(additional, base, instance[name] as JsonValue, `${path}/${escapePointer(name)}`)) {
              return false;
            }
          }
        }
      }
      if (has(schema, "propertyNames")) {
        for (const name of names) {
          if (descend(schema["propertyNames"] as Schema, base, name, path)) {
            return false;
          }
        }
      }
      const dependentSchemas = schema["dependentSchemas"];
      if (isObject(dependentSchemas)) {
        for (const name of Object.keys(dependentSchemas)) {
          if (has(instance, name) && descend(dependentSchemas[name] as Schema, base, instance, path)) {
            return false;
          }
        }
      }
    }
    const allOf = schema["allOf"];
    if (isArray(allOf)) {
      for (const item of allOf) {
        if (descend(item as Schema, base, instance, path)) {
          return false;
        }
      }
    }
    const anyOf = schema["anyOf"];
    if (isArray(anyOf)) {
      if (!anyOf.some((item) => this.valid(item as Schema, base, instance))) {
        this.branchErrors(anyOf as Schema[], base, instance, path, out, limit);
        if (fail("anyOf", `${describe(instance)} is not valid under any of the given schemas`)) {
          return false;
        }
      }
    }
    const oneOf = schema["oneOf"];
    if (isArray(oneOf)) {
      const matching = oneOf.filter((item) => this.valid(item as Schema, base, instance)).length;
      if (matching === 0) {
        this.branchErrors(oneOf as Schema[], base, instance, path, out, limit);
        if (fail("oneOf", `${describe(instance)} is not valid under any of the given schemas`)) {
          return false;
        }
      } else if (matching > 1) {
        if (fail("oneOf", `${describe(instance)} is valid under more than one of the given schemas`)) {
          return false;
        }
      }
    }
    if (has(schema, "not") && this.valid(schema["not"] as Schema, base, instance)) {
      if (fail("not", `${describe(instance)} matches a schema it must not match`)) {
        return false;
      }
    }
    if (has(schema, "if")) {
      if (this.valid(schema["if"] as Schema, base, instance)) {
        if (has(schema, "then") && descend(schema["then"] as Schema, base, instance, path)) {
          return false;
        }
      } else if (has(schema, "else") && descend(schema["else"] as Schema, base, instance, path)) {
        return false;
      }
    }
    if (has(schema, "unevaluatedProperties") && isObject(instance)) {
      const evaluated = new Set(this.evaluatedKeys(schema, base, instance));
      const unevaluated = schema["unevaluatedProperties"] as Schema;
      const refused = Object.keys(instance).filter(
        (name) => !evaluated.has(name) && !this.valid(unevaluated, base, instance[name] as JsonValue),
      );
      if (refused.length > 0) {
        if (fail("unevaluatedProperties", `unevaluated members are not allowed (${refused.map((name) => JSON.stringify(name)).join(", ")})`)) {
          return false;
        }
      }
    }
    return ok;
  }

  /** For a failed anyOf or oneOf, report the errors of the branch with the fewest errors. */
  private branchErrors(branches: Schema[], base: string, instance: JsonValue, path: string, out: SchemaError[] | null, limit: number): void {
    if (out === null) {
      return;
    }
    let best: SchemaError[] | undefined;
    for (const branch of branches) {
      const errors: SchemaError[] = [];
      this.evaluate(branch, base, instance, path, errors, limit);
      if (best === undefined || errors.length < best.length) {
        best = errors;
      }
    }
    for (const error of best ?? []) {
      push(out, limit, error.path, error.keyword, error.message);
    }
  }

  /** The members that the reference's unevaluatedProperties counts as evaluated. */
  private evaluatedKeys(schema: Schema, base: string, instance: JsonObject): string[] {
    if (typeof schema === "boolean") {
      return [];
    }
    const found: string[] = [];
    if (typeof schema["$ref"] === "string") {
      const target = this.resolve(schema["$ref"], base);
      found.push(...this.evaluatedKeys(target.schema, target.base, instance));
    }
    const properties = schema["properties"];
    if (isObject(properties)) {
      found.push(...Object.keys(properties).filter((name) => has(instance, name)));
    }
    for (const keyword of ["additionalProperties", "unevaluatedProperties"]) {
      if (has(schema, keyword) && schema[keyword] !== null) {
        const child = schema[keyword] as Schema;
        found.push(...Object.keys(instance).filter((name) => this.valid(child, base, instance[name] as JsonValue)));
      }
    }
    const patternProperties = schema["patternProperties"];
    if (isObject(patternProperties)) {
      for (const name of Object.keys(instance)) {
        for (const pattern of Object.keys(patternProperties)) {
          if (this.regex(pattern).test(name)) {
            found.push(name);
          }
        }
      }
    }
    const dependentSchemas = schema["dependentSchemas"];
    if (isObject(dependentSchemas)) {
      for (const name of Object.keys(dependentSchemas)) {
        if (has(instance, name)) {
          found.push(...this.evaluatedKeys(dependentSchemas[name] as Schema, base, instance));
        }
      }
    }
    for (const keyword of ["allOf", "oneOf", "anyOf"]) {
      const list = schema[keyword];
      if (isArray(list)) {
        for (const item of list) {
          if (this.valid(item as Schema, base, instance)) {
            found.push(...this.evaluatedKeys(item as Schema, base, instance));
          }
        }
      }
    }
    if (has(schema, "if")) {
      if (this.valid(schema["if"] as Schema, base, instance)) {
        found.push(...this.evaluatedKeys(schema["if"] as Schema, base, instance));
        if (has(schema, "then")) {
          found.push(...this.evaluatedKeys(schema["then"] as Schema, base, instance));
        }
      } else if (has(schema, "else")) {
        found.push(...this.evaluatedKeys(schema["else"] as Schema, base, instance));
      }
    }
    return found;
  }
}

function push(out: SchemaError[], limit: number, path: string, keyword: string, message: string): void {
  if (out.length < limit) {
    out.push({ path: path === "" ? "/" : path, keyword, message });
  }
}

function hasType(instance: JsonValue, type: string): boolean {
  switch (type) {
    case "object":
      return isObject(instance);
    case "array":
      return isArray(instance);
    case "string":
      return typeof instance === "string";
    case "integer":
      return typeof instance === "number" && Number.isInteger(instance);
    case "number":
      return typeof instance === "number";
    case "boolean":
      return typeof instance === "boolean";
    case "null":
      return instance === null;
    default:
      return false;
  }
}

/** Items are repeated when their canonical texts repeat, which keeps booleans and numbers apart. */
function unique(items: JsonValue[]): boolean {
  const seen = new Set<string>();
  for (const item of items) {
    const key = stableText(item);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
  }
  return true;
}

function stableText(value: JsonValue): string {
  if (isArray(value)) {
    return "[" + value.map(stableText).join(",") + "]";
  }
  if (isObject(value)) {
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map((name) => JSON.stringify(name) + ":" + stableText(value[name] as JsonValue))
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

function escapePointer(name: string): string {
  return name.replace(/~/g, "~0").replace(/\//g, "~1");
}

function describe(value: JsonValue): string {
  if (isObject(value)) {
    return "object";
  }
  if (isArray(value)) {
    return "array";
  }
  const text = JSON.stringify(value);
  return text.length > 60 ? text.slice(0, 59) + "…" : text;
}

let defaultSet: SchemaSet | undefined;
let recordSet: SchemaSet | undefined;

/** The schema set embedded in this library: the ECL wire schemas and what they reference. */
export function eclSchemas(): SchemaSet {
  defaultSet ??= new SchemaSet(SCHEMA_DOCUMENTS);
  return defaultSet;
}

/**
 * The wire schemas together with the records of the binding profiles and the claim and assessment
 * documents (the conformance runner's `binding` and `document` stages), which reference them.
 */
export function recordSchemas(): SchemaSet {
  recordSet ??= new SchemaSet([...SCHEMA_DOCUMENTS, ...RECORD_SCHEMA_DOCUMENTS]);
  return recordSet;
}

/** Validate `instance` against an embedded ECL schema (by `$id`, optionally with a fragment). */
export function validateSchema(reference: string, instance: JsonValue): SchemaError[] {
  return eclSchemas().errors(reference, instance);
}
