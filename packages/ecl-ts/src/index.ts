/**
 * ECL-1 for TypeScript and JavaScript: strict JSON and canonicalization, schema and semantic
 * validation of DCMP-2 and EBMP-2 objects, ECL-IE-1 integrity envelopes, trust policies, the
 * offline verification of signed evidence bundles and of the offline packages that carry them, the
 * rules of the five binding profiles and the claim and assessment document stage. It runs the same in Node.js and in a browser, makes no
 * network request, and reaches the same verdicts and finding identifiers as the Python reference
 * on the shared conformance corpus.
 */

export type { JsonArray, JsonObject, JsonPrimitive, JsonValue } from "./json/value.js";
export { PythonTypeError } from "./json/value.js";
export { PythonValueError } from "./semantic/python.js";
export {
  parseStrictJson,
  StrictJsonError,
  MAX_SAFE_INTEGER,
  MAX_JSON_BYTES,
  MAX_JSON_DEPTH,
  MAX_JSON_NODES,
  MAX_JSON_BYTES_CEILING,
  MAX_JSON_DEPTH_CEILING,
  MAX_JSON_NODES_CEILING,
  GRAMMAR_NESTING_BOUND,
  CONFIGURATION_INVALID,
} from "./json/strict.js";
export type { StrictJsonErrorKind, StrictJsonLimits } from "./json/strict.js";
export { canonicalize, canonicalText, objectDigest, digestObject, CanonicalizationError } from "./json/canonical.js";
export { instantNanoseconds, isInstant, InstantError } from "./time.js";
export { sha256Hex, toBase64, fromCanonicalBase64 } from "./crypto/bytes.js";
export {
  ED25519_SUITE,
  P256_SUITE,
  MLDSA65_SUITE,
  verifyEd25519,
  verifyP256,
  verifySignature,
  publicKeyProblem,
  SignatureEncodingError,
  UnsupportedSuiteError,
} from "./crypto/signatures.js";
export { SchemaSet, eclSchemas, recordSchemas, validateSchema } from "./schema/validator.js";
export type { SchemaError } from "./schema/validator.js";
export { SemanticValidator, adapterBindingFindings, DECISION_BASIS, DECISION_BASIS_RULE } from "./semantic/rules.js";
export type { Finding } from "./semantic/rules.js";
export { validateSafeStateProfile } from "./semantic/safe-state.js";
export { objectFindings } from "./semantic/object.js";
export { analyzeBundle } from "./bundle/causal.js";
export type { BundleAnalysis } from "./bundle/causal.js";
export {
  signingInput,
  decodePayload,
  decodeCanonicalJsonPayload,
  verifyEnvelope,
  IntegrityError,
  INTEGRITY_INVALID,
  SIGNATURE_POLICY_INVALID,
  TRUSTED_TIME_CLAIM,
  TIME_ATTESTATION_TYPE,
} from "./integrity/envelope.js";
export type { KeyRevocation, VerificationContext, VerificationKey, VerificationResult } from "./integrity/envelope.js";
export { TrustPolicy, TrustPolicyError, MAX_TRUST_POLICY_BYTES, ROLE_PURPOSES, PURPOSE_APPROVAL, QUALIFYING_PURPOSES, roleConflict } from "./trust/policy.js";
export type { TrustedKey, TrustPolicyReference } from "./trust/policy.js";
export {
  checkResponseBinding,
  checkEventBinding,
  checkAuthorityEventBinding,
  BindingError,
  TERMINAL_STATE_OUTCOMES,
} from "./binding/binding.js";
export {
  verifyBundle,
  findingCodes,
  reportedIdentifiers,
  reportToJson,
  REFERENCE_PROFILE,
  TRUSTED_TIME_PROFILE,
  CURRENT_TRUST_FAILED,
  CAUSAL_CLOSURE_INCOMPLETE,
  OBLIGATION_UNPROVEN,
  SCOPE_RELEASE,
  SCOPE_PROOFS,
  REASON_NO_RELEASE,
  REASON_PROOF_NOT_ECL_OBJECT,
  REASON_ISSUER_NOT_NAMED,
} from "./evidence/verify.js";
export type {
  BindingCheck,
  BundleFinding,
  BundleReport,
  EffectEvidence,
  EnvelopeCheck,
  ReportScope,
  Verdict,
  VerifyBundleOptions,
} from "./evidence/verify.js";
export { verifyBundleBytes, loadRegister, MAX_BUNDLE_BYTES, MAX_REGISTER_BYTES, VerifierInputError } from "./evidence/bytes.js";
export {
  REGISTER_RULE as DECISION_BASIS_REGISTER_RULE,
  REQUIRED_RULE as DECISION_BASIS_REQUIRED_RULE,
  declaredInputs,
  registerDigest,
  registerProblems,
  registerReference,
  registerSchemaProblems,
} from "./evidence/decision-basis.js";
export {
  BINDING_PROFILES,
  BINDING_RULES,
  bindingFindings,
  evaluateBindingRecord,
  aarm,
  acs,
  mcp,
  oauth,
  otel,
  JcsError,
  jcsCanonicalize,
  jcsDigest,
  jcsNumber,
  JoseError,
  b64url,
  b64urlDecode,
  decodeJws,
  verifyJws,
  verifyDpop,
  thumbprint,
  tokenHash,
  parsePyJson,
  PyJsonError,
  pyEquals,
  toPy,
} from "./bindings/index.js";
export type { PyObject, PyValue } from "./bindings/index.js";
export { DOCUMENT_SCHEMAS, documentRuleFindings, evaluateDocument } from "./documents/documents.js";
export { describeCode, describeVerdict } from "./evidence/explain.js";
export * from "./generated/types.js";
export { isDcmpMessage, isEbmpObject, isIntegrityEnvelope, isEvidenceBundle, isTrustPolicyDocument } from "./guards.js";
export {
  verifyOfflinePackage,
  verifyPackageBytes,
  packageIdentifiers,
  MANIFEST_NAME,
  MANIFEST_SCHEMA,
  PACKAGE_MEDIA_TYPE,
} from "./offline/package.js";
export type { PackageBytesOptions, VerifyOfflinePackageOptions } from "./offline/package.js";
export {
  readStoredZip,
  isEntryName,
  foldAscii,
  checkLimits,
  crc32,
  ArchiveRefusal,
  DEFAULT_OFFLINE_RESOURCE_LIMITS,
  PORTABLE_NAME_CHARACTERS,
} from "./offline/zip.js";
export type { OfflineResourceLimits, ZipMember } from "./offline/zip.js";
