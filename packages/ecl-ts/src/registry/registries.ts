/**
 * The registry snapshot embedded in this library (generated from registries/*.json), read the way
 * the reference reads it.
 */

import { ALGORITHM_SUITES, ERROR_CODES, EXTENSIONS, SEMANTIC_RULES, VOCABULARY } from "../generated/registries.js";
import type { RegistryEntry } from "../generated/registries.js";

const REGISTRIES: Record<string, readonly RegistryEntry[]> = {
  "algorithm-suites": ALGORITHM_SUITES,
  "error-codes": ERROR_CODES,
  extensions: EXTENSIONS,
  "semantic-rules": SEMANTIC_RULES,
  vocabulary: VOCABULARY,
};

/** The entries of an embedded registry. */
export function registry(name: string): readonly RegistryEntry[] {
  const entries = REGISTRIES[name];
  if (entries === undefined) {
    throw new Error(`no embedded registry is named ${name}`);
  }
  return entries;
}

/** The active entries of a registry whose attribute has this value. */
export function activeIds(name: string, attribute: "category" | "kind", value: string): ReadonlySet<string> {
  return new Set(
    registry(name)
      .filter((entry) => entry.status === "active" && entry[attribute] === value)
      .map((entry) => entry.id),
  );
}

let errorCodes: ReadonlySet<string> | undefined;

/** The active registered error codes (`ecl.error.*`). */
export function activeErrorCodes(): ReadonlySet<string> {
  errorCodes ??= new Set(
    ERROR_CODES.filter((entry) => entry.status === "active" && entry.id.startsWith("ecl.error.")).map((entry) => entry.id),
  );
  return errorCodes;
}

/** Every allocated extension identifier, whatever its status (the semantic validator's snapshot). */
export function knownExtensions(): ReadonlySet<string> {
  return new Set(EXTENSIONS.map((entry) => entry.id));
}

/**
 * The versions that the extension registry allocates for each identifier (XR1-003). An extension
 * is the pair of its identifier and version (XR1-009), so a consumer can interpret only the
 * versions allocated for an identifier it knows.
 */
export function allocatedExtensionVersions(): ReadonlyMap<string, ReadonlySet<number>> {
  return extensionVersions(EXTENSIONS);
}

/**
 * The versions of the active entries of the extension registry (XR1-006): an occurrence is known
 * to a consumer only through an active entry of its identifier and version that the consumer
 * implements, and this library implements every active entry. A deprecated, prohibited,
 * superseded or reserved entry stays allocated for XR1-017 but makes no occurrence known.
 */
export function activeExtensionVersions(): ReadonlyMap<string, ReadonlySet<number>> {
  return extensionVersions(EXTENSIONS.filter((entry) => entry.status === "active"));
}

function extensionVersions(entries: readonly RegistryEntry[]): ReadonlyMap<string, ReadonlySet<number>> {
  const map = new Map<string, Set<number>>();
  for (const entry of entries) {
    if (typeof entry.version === "number" && Number.isInteger(entry.version)) {
      let versions = map.get(entry.id);
      if (versions === undefined) {
        versions = new Set<number>();
        map.set(entry.id, versions);
      }
      versions.add(entry.version);
    }
  }
  return map;
}

/**
 * The extension identifiers whose registry entry declares their versions composable (XR1-010):
 * only `composable_versions` set to `true` does; anything else, an absent attribute included,
 * leaves two versions of the identifier in one object a conflict.
 */
export function composableExtensions(): ReadonlySet<string> {
  return new Set(EXTENSIONS.filter((entry) => entry.composable_versions === true).map((entry) => entry.id));
}

/**
 * The active semantic rules whose `applies_to` names the object type `kind`, such as `ECL-WI-1`
 * for a work intent: the rules that the conformance runner's `document` stage applies to a document
 * whose `protocol` is `kind`. A `kind` that is not a string names no rule.
 */
export function rulesApplyingTo(kind: unknown): ReadonlySet<string> {
  if (typeof kind !== "string") {
    return new Set();
  }
  return new Set(SEMANTIC_RULES.filter((entry) => entry.status === "active" && (entry.applies_to ?? []).includes(kind)).map((entry) => entry.id));
}

/** Each registered extension that names a value schema (XR1-023), with that schema's `$id`. */
export function extensionValueSchemas(): ReadonlyMap<string, string> {
  const map = new Map<string, string>();
  for (const entry of EXTENSIONS) {
    if (typeof entry.value_schema === "string") {
      map.set(entry.id, entry.value_schema);
    }
  }
  return map;
}

/** The stage of EBMP2-068 that each active bundle rule names in its registry `stage` attribute. */
export function ruleStage(): ReadonlyMap<string, number> {
  const map = new Map<string, number>();
  for (const entry of SEMANTIC_RULES) {
    if (entry.status === "active" && typeof entry.stage === "number" && Number.isInteger(entry.stage)) {
      map.set(entry.id, entry.stage);
    }
  }
  return map;
}

/** The precedence of each active semantic rule; a lower number is reported first. */
export function rulePrecedence(): ReadonlyMap<string, number> {
  const map = new Map<string, number>();
  for (const entry of SEMANTIC_RULES) {
    if (entry.status !== "active") {
      continue;
    }
    if (typeof entry.precedence !== "number" || map.has(entry.id) || [...map.values()].includes(entry.precedence)) {
      throw new Error("semantic precedence is missing, duplicate or invalid");
    }
    map.set(entry.id, entry.precedence);
  }
  return map;
}
