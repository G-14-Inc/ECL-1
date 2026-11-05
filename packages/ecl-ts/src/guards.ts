/**
 * Run-time type guards: a value is of a generated type exactly when it satisfies the schema the
 * type was generated from. They check the schema only; a schema-valid object can still break a
 * semantic rule (use SemanticValidator or objectFindings for those).
 */

import type { JsonValue } from "./json/value.js";
import { eclSchemas } from "./schema/validator.js";
import type { DcmpMessage, EbmpObject, EvidenceBundle, IntegrityEnvelope, TrustPolicyDocument } from "./generated/types.js";

const NS = "https://externalcontrollayer.ai/ns/schema/";

/** Whether `value` is a schema-valid DCMP-2 message. */
export function isDcmpMessage(value: JsonValue): value is DcmpMessage & JsonValue {
  return eclSchemas().isValid(NS + "dcmp/2", value);
}

/** Whether `value` is a schema-valid EBMP-2 event record or bundle manifest. */
export function isEbmpObject(value: JsonValue): value is EbmpObject & JsonValue {
  return eclSchemas().isValid(NS + "ebmp/2", value);
}

/** Whether `value` is a schema-valid ECL-IE-1 integrity envelope. */
export function isIntegrityEnvelope(value: JsonValue): value is IntegrityEnvelope & JsonValue {
  return eclSchemas().isValid(NS + "integrity-envelope/1", value);
}

/** Whether `value` is a schema-valid signed evidence bundle. */
export function isEvidenceBundle(value: JsonValue): value is EvidenceBundle & JsonValue {
  return eclSchemas().isValid(NS + "evidence-bundle/1", value);
}

/** Whether `value` is a schema-valid trust-policy document (the semantic checks are TrustPolicy.load's). */
export function isTrustPolicyDocument(value: JsonValue): value is TrustPolicyDocument & JsonValue {
  return eclSchemas().isValid(NS + "trust-policy/1", value);
}
