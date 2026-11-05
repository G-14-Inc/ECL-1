/**
 * The claim and assessment documents: the Consequential Action Register, the conformance claim,
 * the assessment package, the mapping packet, the deployment profile, the lifecycle policy, the
 * offline verification package and the work intent. The conformance runner's `document` stage
 * reads each by strict parsing, validates it against the schema the vector names, and applies the
 * registered semantic rules whose `applies_to` names the document's type: its `protocol`, or the
 * `$id` of the schema the vector names. The work intent (ECL-WI-1) carries extensions, and the
 * extension rules apply to it (XR1-006, XR1-009, XR1-010 and XR1-017): EXTENSION-REGISTRY-1
 * section 2; the register declarations rule applies to an action register (ECL1N-0178).
 *
 * A rule registered for a document type later needs no code here: the registry's `applies_to`
 * names the type, and the semantic validator holds the rule.
 */

import { get, isObject } from "../json/value.js";
import type { JsonValue } from "../json/value.js";
import { rulesApplyingTo } from "../registry/registries.js";
import { SCHEMA_INVALID, SemanticValidator, sortFindings } from "../semantic/rules.js";
import type { Finding } from "../semantic/rules.js";
import { recordSchemas } from "../schema/validator.js";
import type { SchemaSet } from "../schema/validator.js";

const NS = "https://externalcontrollayer.ai/ns/schema/";

/** The schemas of the documents that the `document` stage evaluates. */
export const DOCUMENT_SCHEMAS: readonly string[] = [
  NS + "action-register/1",
  NS + "assessment-package/1",
  NS + "conformance-claim/1",
  NS + "deployment-profile/1",
  NS + "lifecycle-policy/1",
  NS + "mapping-packet/1",
  NS + "offline-verification-package/1",
  NS + "work-intent/1",
];

let defaultSemantics: SemanticValidator | undefined;

/**
 * The findings of the registered rules whose `applies_to` names the document's type, its
 * `protocol` or the `$id` of its schema: the semantic findings of the document, kept only for those
 * rules.
 */
export function documentRuleFindings(value: JsonValue, semantics?: SemanticValidator, schema?: string): Finding[] {
  if (!isObject(value)) {
    return [];
  }
  const scoped = new Set([...rulesApplyingTo(get(value, "protocol")), ...(schema === undefined ? [] : rulesApplyingTo(schema))]);
  if (scoped.size === 0) {
    return [];
  }
  const validator = semantics ?? (defaultSemantics ??= new SemanticValidator());
  return validator.validate(value).filter((item) => scoped.has(item.ruleId));
}

/**
 * The `document` stage for a parsed document and the schema it names: one schema finding when the
 * value is not an object; else one schema finding when it fails that schema, together with the
 * findings of the rules that apply to its type, which the stage applies whether or not the schema
 * accepts the document, as the reference runner does.
 */
export function evaluateDocument(schema: string, value: JsonValue, schemas: SchemaSet = recordSchemas(), semantics?: SemanticValidator): Finding[] {
  if (!isObject(value)) {
    return [{ ruleId: SCHEMA_INVALID, path: "/", message: "a document is a JSON object" }];
  }
  const found: Finding[] = [];
  const errors = schemas.errors(schema, value, 1);
  if (errors.length > 0) {
    const error = errors[0] as { path: string; keyword: string; message: string };
    found.push({ ruleId: SCHEMA_INVALID, path: error.path, message: `${error.keyword}: ${error.message}` });
  }
  return sortFindings([...found, ...documentRuleFindings(value, semantics, schema)]);
}
