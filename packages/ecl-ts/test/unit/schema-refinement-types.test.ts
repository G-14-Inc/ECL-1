import type { RuntimeConfigurationExtensionValue, DecisionBasisExtensionRegisterReference } from "../../src/generated/types.js";
// These schema refinements are already required at runtime and must also be required by the SDK.
// @ts-expect-error configuration requires both version and digest
const missingConfiguration: RuntimeConfigurationExtensionValue = { configuration: { uri: "urn:example:config" } };
// @ts-expect-error register references require the digest
const missingRegister: DecisionBasisExtensionRegisterReference = { uri: "urn:example:register" };
const configuration: RuntimeConfigurationExtensionValue = { configuration: { uri: "urn:example:config", version: "1", digest: {algorithm: "ecl.digest.sha-256.v1", value: "ab".repeat(32)} } };
const register: DecisionBasisExtensionRegisterReference = { uri: "urn:example:register", digest: {algorithm: "ecl.digest.sha-256.v1", value: "ab".repeat(32)} };
void [missingConfiguration, missingRegister, configuration, register];
