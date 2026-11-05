# Minimum path to an L1 claim

ECL-1 `1.0`. This document is generated from the compiled requirement registry (`registries/requirements-compiled.json`) and the checklist in Section 11.3 of the standard, and is not edited by hand.

An `L1` claim answers 380 requirements across 8 documents and 29 checklist items. Of the requirements, 355 are obligations (MUST), 11 are recommendations (SHOULD only) and 14 are permissions (MAY only). 36 are conditional: they open with a condition, either a choice that only some deployments make, such as federation or an AI bill of materials, or an event that every deployment handles when it happens, such as a key compromise. The list sizes the first implementation and the first assessment. It is not a conformance claim.

## How the path is derived

- Every requirement of the core standard whose minimum level is `L1` is on the path. The minimum level is the `Min Level` cell of an FR row, or the level qualifier that opens a requirement ("For `L2` and above", "`L2`:" and similar); a requirement without one applies at every level (standard, Section 6.1).
- An obligation on the path, a requirement with a MUST-class keyword, that names a companion protocol or profile brings in every requirement of that document that applies at `L1`. An obligation on the path that cites another requirement by its ID brings in that requirement. A recommendation or permission on the path brings nothing in, because it binds no claim. This repeats until nothing new is named.
- A companion that no obligation on the path names is not on the path. A claim that declares a profile, or uses a function that a protocol governs, adds those requirements.
- A requirement is conditional when its text opens with the condition under which it binds, such as "When", "If" or "This model".

## Size by document

| Document | On the path because | Requirements | Obligations | Recommendations | Permissions | Conditional |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| ECL-1 core standard | it is the core standard | 186 | 163 | 11 | 12 | 31 |
| DCMP-2 | named by ECL1N-0022, ECL1N-0057, ECL1N-0118, EBMP2-006, EBMP2-057, EBMP2-059, EBMP2-069, EBMP2-078, IE1-034, TP1-004, TP1-010 | 57 | 57 | 0 | 0 | 1 |
| EBMP-2 | named by ECL1N-0022, ECL1N-0057, ECL1N-0118, ECL1N-0199, DCMP2-043, DCMP2-056, IE1-021, IE1-034, TP1-006 | 78 | 76 | 0 | 2 | 3 |
| INTEGRITY-ENVELOPE-1 | named by ECL1N-0022, ECL1N-0117, DCMP2-002, DCMP2-043, EBMP2-057, EBMP2-068, TP1-002, TP1-006, TP1-007, TP1-010 | 39 | 39 | 0 | 0 | 0 |
| TIMING-SAFE-STATE-1 | requirements on the path cite TS1-014, TS1-018, TS1-027, TS1-031, TS1-032, TS1-034 | 6 | 6 | 0 | 0 | 0 |
| EVIDENCE-LIFECYCLE-1 | requirements on the path cite EL1-014 | 1 | 1 | 0 | 0 | 0 |
| EXTENSION-REGISTRY-1 | requirements on the path cite XR1-005, XR1-006, XR1-023 | 3 | 3 | 0 | 0 | 1 |
| TRUST-POLICY-1 | named by EBMP2-057, EBMP2-060, EBMP2-068, IE1-034, IE1-037 | 10 | 10 | 0 | 0 | 0 |
| Total | | 380 | 355 | 11 | 14 | 36 |

Not on the path: DISTRIBUTED-WORKFLOW-1, DCMP2-HTTP-1, TRANSACTIONAL-EFFECT-1, AUTHZEN-BINDING-1, STRICT-FAILURE-1, AARM-BINDING-1, ACS-BINDING-1, MCP-GATEWAY-1, OTEL-EVIDENCE-EXPORT-1, OAUTH-AUTHORITY-1.

## Checklist items for an L1 claim

| Domain | Items |
| --- | ---: |
| `BC` | 3 |
| `IA` | 1 |
| `EA` | 16 |
| `PA` | 2 |
| `VF` | 5 |
| `PR` | 2 |

| Item | Related | Applicability | Control question |
| --- | --- | --- | --- |
| BC-01 | FR-006 | Always | Is there a maintained Consequential Action Register with classification rationale and enforcement class for every in-scope action class, and has it been reconciled against the reachable capability… |
| BC-02 | FR-007 | Always | Is the claim boundary class declared and accompanied by a Negative Boundary Annex? |
| BC-03 | Section 2.9 | Conversational output sent in the organization's name that recipients may rely on | Is sending such a statement treated as a consequential action and checked against approved content, or approved by a person, before release (ECL1N-0163)? |
| IA-01 | FR-001 | Always | Does the SoI satisfy the required independence class and avoid single-credential or single-trust-root control collapse? |
| EA-01 | FR-003 | Always | Does enforcement deny by default on missing proof or invalid inputs, including missing, stale, or contradictory witness state, broken capability-freeze conditions, exhausted budgets, or failed quorum… |
| EA-02 | FR-004 | Always | Is the emergency control plane separate, authenticated, constrained to pre-declared containment actions, and tested? |
| EA-03 | FR-008 | Always | Are degraded mode and restricted mode defined and tested? |
| EA-13 | Section 5.10 | Always | Does the register state, for each in-scope action class, the largest aggregate effect in one hour and in one day if every action were admitted (ECL1N-0172)? |
| EA-15 | Section 5.2 | Always | Do the register and supporting claim distinguish actor-controlled assertions from authoritative inputs and identify source authority and independent transition validation (ECL1N-0164, ECL1N-0178)? |
| EA-17 | Section 5.11 | Human approval used | Does each approval show human-readable consequential fields and bind the presentation to the exact released action, with a fresh approval after a consequential change (ECL1N-0174)? |
| EA-20 | Section 5.11 | The register declares a human-approval threshold | Are actions at or above the threshold kept from release until the approvals that the threshold requires are recorded (ECL1N-0177)? |
| EA-21 | Section 5.2 | Always | Does the register declare, for each decision input of each in-scope class, its class (`verifiable`, `actor_supplied`, or `judgment`), whether the class requires it, its source, its maximum age, any… |
| EA-22 | Section 5.2 | Always | Is every outcome at least as strict as its verifiable-only outcome, so that `actor_supplied` and `judgment` inputs only make outcomes stricter and every `admit` rests on policy over `verifiable`… |
| EA-23 | Section 5.2 | Always | Does the evidence of each decision name the register version it was made under and record every input that the Decision Layer consulted and every input that the register declares, each once, with its… |
| EA-24 | Section 5.2 | Always | Does an unavailable, late, or malformed input have the declared effect: no `admit` when the class requires it, and no effect other than a stricter outcome when it is optional (ECL1N-0182)? |
| EA-25 | Section 5.1 | Claim includes mediated action classes | Does every in-scope action cross the Enforcement Boundary before its effect, with no undisclosed path, and can the governed AI system neither rewrite, disable nor bypass enforcement (ECL1N-0028… |
| EA-26 | Section 9.7 | Always | Do decision requests, decision responses and evidence pass strict parsing, schema validation, semantic rules, critical-extension processing and payload-bound integrity policy (ECL1N-0057, ECL1N-0117… |
| EA-27 | Section 5.4 | Claim includes mediated action classes | Do the claim and each enforcement profile it relies on name the release boundary and any later effect boundary of each in-scope action class, and does the enforcement point release an action only… |
| EA-28 | Section 5.4 | Claim includes mediated action classes | Before it releases an action, does the enforcement point durably keep the recovery information that its declared failure model requires; after each failure that the claim declares covered, does… |
| EA-29 | Section 8.8 | Always | Does a loss of required proof bring the scope and state that ECL1N-0191 gives it under the declared dependency model, and is each restriction lifted only after fresh proof returns and the declared… |
| PA-08 | Section 9.8 | Signed evidence produced | Is every evidence-signing key inventoried, held out of the governed AI system's reach, and bound to one component role (ECL1N-0155 to ECL1N-0157)? |
| PA-09 | Section 9.8 | Signed evidence produced | Are evidence-signing keys rotated within their declared lifetime with overlap, and is key compromise handled by an exercised revocation procedure (ECL1N-0158, ECL1N-0159)? |
| VF-01 | FR-005 | Always | Is there requirement-to-evidence traceability for all applicable controls? |
| VF-06 | Section 5.6 | Always | Are the detections that indicate wrong behavior declared, each with its response (ECL1N-0167)? |
| VF-08 | Section 5.4 | Always | Is a change that disables, bypasses, or sets a control to automatic approval approved by another person, time-limited, and recorded (ECL1N-0166, EBMP2-064)? |
| VF-10 | Section 5.7 | Always | Is every change to the policy, the register, the tool or capability manifest, an enforcement configuration, the trust policy, or a detection response reviewed by another person before it takes effect… |
| VF-12 | Section 5.6 | Evidence verified for the claim | Does each verifier that the claim relies on report a check that it did not make, or could not make for lack of information, as unchecked rather than passed, and keep verification of a producer's… |
| PR-05 | Section 7.7 | Public or procurement claim made | Does the public claim statement include the minimum fields required by Section 7.7, including SoI, level, status, boundary class, independence class, assessment date, version set, and material… |
| PR-06 | Section 10 | External framework support asserted | Does the mapping-backed claim name the framework, packet identifier, bounded obligation slice, residual-gap disclosure, and mapping validation state? |

## Requirements by document

### ECL-1 core standard (`standard/ECL-1_Standard.md`)

| ID | Section | Kind | Summary |
| --- | --- | --- | --- |
| ECL1N-0001 | 2.2 | obligation | A system MUST be treated as in scope for ECL-1 when all conditions below are true: 1. The AI system can initiate or materially advance actions without… |
| ECL1N-0002 | 2.2 | obligation, conditional | If scope classification is uncertain, the deployment MUST be classified as in scope until a documented review concludes otherwise. |
| ECL1N-0003 | 2.3 | obligation | Out-of-scope classification MUST NOT be used as a substitute for legal, regulatory, or contractual obligations. |
| ECL1N-0004 | 2.4 | obligation | An action MUST be classified as consequential if any of the following is true: 1. It mutates external state. 2. It discloses, routes, exports, or transforms… |
| ECL1N-0005 | 2.4 | permission | An action MAY be classified as non-consequential only when all of the following are true: 1. It remains fully confined to an isolated execution context. 2. It… |
| ECL1N-0006 | 2.4 | permission | A local draft rewrite that remains fully confined to an isolated execution context, discloses no non-public data, mutates no external state, and expands no… |
| ECL1N-0007 | 2.4 | obligation | Each claim MUST publish a Consequential Action Register containing: - action class identifier; - classification decision (`consequential` or… |
| ECL1N-0008 | 2.4 | obligation | For `full-system-mediation` and `bounded-action-class-mediation` claims, the Consequential Action Register MUST be validated against the actual runtime… |
| ECL1N-0009 | 2.5 | obligation | A conformance claim MUST define a System of Interest (SoI) boundary that includes: - the claim class; - the Consequential Action Register; - all interfaces and… |
| ECL1N-0010 | 2.5 | obligation | Every claim MUST include a Negative Boundary Annex listing: - excluded effect channels; - excluded tools, agents, or resources; - shared runtime or admin… |
| ECL1N-0011 | 2.5 | obligation, conditional | If an external-effect path is not explicitly included in the SoI or disclosed in the Negative Boundary Annex, the claim is incomplete and MUST be treated as… |
| ECL1N-0012 | 2.7 | obligation | Conformance to ECL-1 MUST NOT be represented as proof that all liveness, performance, or business-continuity objectives are guaranteed. |
| ECL1N-0013 | 2.8 | obligation | A Consequential Action Trace MUST use one root trace identifier for the approval-to-effect chain. |
| ECL1N-0014 | 2.8 | obligation | Each external effect MUST have a unique action identifier. |
| ECL1N-0015 | 2.8 | obligation, conditional | Model-routing, multi-model, or model-switching architectures MUST treat each model that can originate, transform, or approve consequential actions for the SoI… |
| ECL1N-0016 | 2.9 | permission | Conversational systems are not automatically out of scope. |
| ECL1N-0017 | 2.9 | obligation | A conversational or language-mediated system MUST be treated as in scope when its output can: 1. disclose non-public data; 2. trigger, queue, parameterize, or… |
| ECL1N-0018 | 2.9 | obligation | Prompt injection, jailbreaks, hostile retrieved content, and hostile tool responses are language-origin threats, but ECL-1 does not attempt to standardize… |
| ECL1N-0019 | 2.9 | permission | A public FAQ bot with no tools, no protected-data access, and no downstream workflow or execution path MAY be out of scope. |
| ECL1N-0020 | 2.9 | permission | A draft-only assistant whose human separately reviews and authorizes every consequential send or execution step MAY remain out of scope for direct ECL-1… |
| ECL1N-0021 | 3.3 | obligation | Living-specification references in this subsection MUST NOT be invoked normatively in a claim, profile, or checklist package unless the claimant or profile… |
| ECL1N-0022 | 3.4 | obligation | The companion artifacts listed in this subsection are part of the normative assessment package at every level. |
| ECL1N-0023 | 3.6 | obligation, conditional | When a deployment profile claims ECL-1 conformance in a sector governed by IEC 62443 or ISO 26262, the applicable sector standard controls MUST be treated as… |
| ECL1N-0024 | 3.7 | obligation | An implementation claim MUST cite the reference identifier used by each control assertion in Sections 6, 7, 10, and 11. |
| ECL1N-0025 | 3.7 | obligation | Any living-specification reference used normatively in a claim or profile MUST be frozen by version, date, or immutable hash in the relevant package. |
| ECL1N-0026 | 3.7 | obligation | A mapping claim to an external framework MUST distinguish direct runtime support, supporting evidence only, and residual obligations. |
| ECL1N-0027 | 3.7 | obligation | Conformance to ECL-1 MUST NOT be represented as automatic certification or legal compliance with any external framework that this document cites. |
| ECL1N-0028 | 5.1 | obligation | All in-scope consequential actions MUST cross the Enforcement Boundary before execution. |
| ECL1N-0029 | 8.8 | obligation, conditional | When the degraded-mode window expires or a critical integrity failure occurs, a system in Degraded Mode MUST transition to Restricted Mode or Emergency Halt. |
| ECL1N-0030 | 11.6 | obligation | An AI bill of materials used as part of an ECL-1 conformance claim (AIBOM-MIN-1) MUST include at minimum: artifact identifier, supplier or owner, component… |
| ECL1N-0031 | 5.3 | obligation | Across heterogeneous token or credential systems, each delegation hop MUST preserve or narrow the parent authority on operation scope, resource scope, data… |
| ECL1N-0032 | 5 | obligation | ECL-1 defines a logical control architecture. |
| ECL1N-0033 | 5.1 | obligation | Every consequential action listed as in scope in the Consequential Action Register MUST traverse the Enforcement Layer before external effect. |
| ECL1N-0034 | 5.1 | obligation | The Decision Layer MUST supply the applicable policy outcome or policy evaluation context. |
| ECL1N-0035 | 5.1 | obligation | The Authority Layer MUST supply or validate bounded right-to-act. |
| ECL1N-0036 | 5.1 | obligation | The Enforcement Layer MUST apply the resulting control outcome before execution. |
| ECL1N-0037 | 5.1 | obligation | The Provenance Layer MUST record action evidence and control context. |
| ECL1N-0038 | 5.1 | obligation, conditional | If an effect path exists but is excluded from the claim, it MUST appear in the Negative Boundary Annex. |
| ECL1N-0039 | 5.1 | obligation | Evidence of complete mediation is always bounded by the declared path- enumeration method, exercised negative tests, and the reachable capability inventory… |
| ECL1N-0040 | 5.2 | obligation | The Decision Layer MUST: - evaluate machine-readable, versioned policy; - produce reproducible outcomes from the logged request state, policy version, trust… |
| ECL1N-0041 | 5.2 | obligation | Model self-report is an `actor_supplied` input: it MAY be one context input, but MUST NOT be the basis for authorizing any action (ECL1N-0179). |
| ECL1N-0042 | 5.3 | obligation | The Authority Layer MUST: - distinguish actor and subject context in delegated actions; - issue or validate transaction-bound typed authority; - enforce… |
| ECL1N-0043 | 5.4 | obligation | The Enforcement Layer MUST: - intercept all in-scope consequential actions before execution; - apply Decision and Authority outcomes without silent fallback; -… |
| ECL1N-0044 | 5.4 | obligation | Action classes with `L4` consequence, irreversible physical effect, or a sector-mandated independent actuation boundary MUST use Hard Enforcement. |
| ECL1N-0046 | 5.4 | obligation | A system where the governed AI system can rewrite, disable, or bypass enforcement logic MUST NOT be treated as conformant. |
| ECL1N-0047 | 5.5 | obligation | The Provenance Layer MUST create tamper-evident evidence bundles containing at minimum: - actor and subject context; - policy and authority context used for the… |
| ECL1N-0048 | 5.5 | obligation | The Provenance Layer MUST support evidence granularity tiers: - summary evidence for low-consequence routine actions when reconstructability is preserved; -… |
| ECL1N-0049 | 5.5 | permission | Hashes or digest references MAY be used for bulky supporting artifacts, but not when doing so would prevent a competent assessor from determining whether the… |
| ECL1N-0050 | 5.5 | obligation | Evidence bundles MUST be retained for at least the longer of: - the active assessment cycle for the claimed level; - any applicable regulatory, contractual, or… |
| ECL1N-0051 | 5.5 | obligation, conditional | Sector profiles MAY extend but MUST NOT shorten this minimum except under the documented legal-conflict procedure of ECL1N-0195 to ECL1N-0199. |
| ECL1N-0052 | 5.6 | obligation | The Verification Layer MUST: - monitor enforcement and policy integrity; - detect drift between approved and active control state; - export reviewable evidence… |
| ECL1N-0053 | 5.7 | obligation | The Fleet Layer MUST: - distribute policy state with version control; - propagate urgent revocations within the declared timing case; - support quarantine or… |
| ECL1N-0054 | 5.7 | recommendation | The Fleet Layer SHOULD support rollback on verification failure. |
| ECL1N-0055 | 5.8 | obligation | Layers MAY be co-located in one runtime product, but implementations MUST demonstrate analyzable separation of: - decision versus enforcement responsibility; -… |
| ECL1N-0056 | 5.8 | obligation | The minimum independence class for a claim is defined in Section 7. `Class A` is same-operator separation only. |
| ECL1N-0057 | 5.9 | obligation | The Decision Layer MUST implement at least `DCMP-2` and the Provenance Layer MUST implement at least `EBMP-2`. |
| ECL1N-0059 | 5.9 | obligation | Canonical JSON is the mandatory Version 1 interchange floor. |
| ECL1N-0060 | 5.10 | permission | The six-responsibility architecture remains the ECL core. |
| ECL1N-0061 | 6.1 | permission | Alternative technical implementations MAY be used. |
| ECL1N-0062 | 6.1 | obligation | Conformance evidence for an alternative technical implementation MUST demonstrate equivalent security and governance effect. |
| ECL1N-0063 | 6.1 | obligation | The assessor MUST document the replaced requirement, proposed alternative, preserved security or governance property, residual difference, and the conditions… |
| ECL1N-0064 | 6.1 | obligation | An equivalence claim MUST NOT weaken the deny-by-default, anti-bypass, independence, or evidence-integrity intent of the replaced requirement. |
| ECL1N-0066 | 6.3 | obligation | Conformance claims MUST NOT represent compliance with this section as proof of liveness guarantees, business-outcome guarantees, or universal model correctness. |
| ECL1N-0067 | 6.4 | obligation, conditional | When RFC 8693 token exchange is used across trust domains, the exchanged authority context MUST preserve at minimum: actor and subject separation, audience or… |
| ECL1N-0068 | 6.4 | obligation, conditional | When a supplier relies on an AIBOM as conformance evidence, the AIBOM MUST satisfy `AIBOM-MIN-1`. |
| ECL1N-0070 | 6.4 | obligation, conditional | When a profile or SoI invokes consequence-coupling controls, the required identifiers, inputs, and outcomes for those controls MUST be carried in the decision… |
| ECL1N-0071 | 7.2 | obligation | The required minimum level for a System of Interest MUST be determined by high-water-mark scoring across: - autonomy - data sensitivity - action consequence |
| ECL1N-0072 | 7.2 | obligation, conditional | If any dimension cannot be defensibly scored due to missing information, the scorer MUST assign the next higher provisional level until evidence is provided. |
| ECL1N-0073 | 7.4 | obligation | Every claim MUST declare one of the following boundary classes: - `full-system-mediation` - `bounded-action-class-mediation` -… |
| ECL1N-0074 | 7.4 | obligation | Boundary class MUST be stated alongside the claimed level. |
| ECL1N-0075 | 7.5 | obligation, conditional | Sector profiles MAY require a higher class. |
| ECL1N-0076 | 7.5 | obligation | Public claims satisfied only at `Class A` MUST disclose that the control plane uses same-operator separated controls and that no separately administered or… |
| ECL1N-0077 | 7.6 | obligation | Conditional conformance is not permitted for `L4`. |
| ECL1N-0078 | 7.7 | obligation | Any public, procurement-facing, or regulator-facing ECL-1 claim MUST state at least all of the following: - the System of Interest identifier or bounded SoI… |
| ECL1N-0079 | 7.7 | obligation, conditional | When external framework support is asserted, the claim surface MUST also name the framework, the packet identifier, and the bounded obligation slice being… |
| ECL1N-0080 | 7.8 | obligation | Assessment records MUST include artifact hashes or equivalent immutable references for reproducibility. |
| ECL1N-0081 | 7.9 | obligation | This hierarchy MUST be preserved in conformance reports so checklist results, finding severity, claim status, and procurement decisions are not conflated. |
| ECL1N-0082 | 7.10 | obligation | MUST describe ECL runtime-control maturity only; |
| ECL1N-0083 | 7.10 | obligation | MUST cite both claimed level and claim boundary class; |
| ECL1N-0084 | 7.10 | obligation | MUST NOT be represented as automatic legal compliance or sector certification; |
| ECL1N-0085 | 7.10 | obligation | MUST distinguish direct control evidence from interpretive mappings. |
| ECL1N-0087 | 7.12 | obligation | Every claim MUST declare: - the ECL-1 core version; - the companion interoperability artifact version set; - any sector profile version invoked. |
| ECL1N-0088 | 7.12 | obligation | Breaking changes to the core standard or companion interop profiles MUST provide at least a 12-month deprecation window unless an emergency security fix… |
| ECL1N-0089 | 8.1 | obligation | Regardless of topology, a conformant deployment MUST: - preserve Decision, Authority, Enforcement, Provenance, Verification, and Fleet responsibilities; -… |
| ECL1N-0090 | 8.1 | obligation | A deployment that only observes behavior after execution, without a pre-action enforcement boundary, MUST NOT claim mediation conformance. |
| ECL1N-0091 | 8.2 | recommendation, conditional | This model SHOULD be used where: - low-latency policy updates are required across many instances; - central audit operations and rapid revocation are… |
| ECL1N-0092 | 8.3 | obligation, conditional | This model MUST define: - domain trust-bundle exchange and update procedures; - delegation semantics across domain boundaries; - cross-domain evidence… |
| ECL1N-0093 | 8.4 | recommendation, conditional | This model SHOULD be used where data residency, regulatory, or mission constraints require local control of policy, keys, and evidence stores. |
| ECL1N-0094 | 8.5 | obligation, conditional | This model MUST define: - maximum policy and trust-cache staleness thresholds; - transition behavior when stale-state thresholds are exceeded; - post-reconnect… |
| ECL1N-0095 | 8.5 | obligation | The claim MUST state which actions stop and which continue when cached state goes stale. |
| ECL1N-0096 | 8.6 | obligation, conditional | This model MUST include: - integrity verification for update media and evidence export packages; - dual-control or equivalent safeguards for emergency policy… |
| ECL1N-0097 | 8.7 | obligation | Each conformance claim MUST publish a declared timing case covering the following control intervals. |
| ECL1N-0098 | 8.7 | obligation | The table below is the default baseline. |
| ECL1N-0099 | 8.7 | obligation, conditional | For federated deployments, trust-bundle updates and revocation exchange across domains MUST satisfy the same connected revocation timing case. |
| ECL1N-0101 | 8.8 | obligation | Every claim MUST define: - **Degraded Mode** entry conditions; - **Restricted Mode** entry conditions and allowed actions; - **Emergency Halt** or equivalent… |
| ECL1N-0102 | 8.8 | permission | Degraded Mode MAY continue only bounded actions under signed cached state; |
| ECL1N-0103 | 8.8 | obligation | Restricted Mode MUST deny all new consequential actions except explicit safe-state or containment actions; |
| ECL1N-0104 | 8.8 | obligation | Emergency Halt MUST take precedence when integrity failure or operator safety requires cessation of consequential action execution. |
| ECL1N-0105 | 8.8 | obligation | An implementation MAY transition to a stricter state earlier than this table requires. |
| ECL1N-0106 | 8.10 | permission, conditional | Sector profiles MAY tighten the default timing baselines or the required enforcement class for a named action class. |
| ECL1N-0107 | 8.10 | permission, conditional | Sector profiles MAY require a State Witness Register, Capability Freeze, Consequence Budget Ledger, Irreversibility Class with declared Commit Mode, or… |
| ECL1N-0108 | 8.10 | obligation, conditional | Federated cross-vendor deployments MUST exchange at minimum: trust-domain identifier, issuer or trust-bundle reference, decision-contract version, root trace… |
| ECL1N-0109 | 9.2 | obligation | Conforming implementations MUST assume at least: - malicious or compromised agent principals; - compromised plugins, tools, or upstream dependencies; - external… |
| ECL1N-0110 | 9.4 | obligation | ECL implementations MUST: - enforce fail-closed behavior for policy ambiguity, missing proof, and integrity failure; - preserve architectural independence… |
| ECL1N-0111 | 9.4 | obligation | Human oversight MAY supplement these controls but MUST NOT be the sole mechanism for governing consequential actions. |
| ECL1N-0112 | 9.5 | recommendation | Security controls SHOULD minimize sensitive-data exposure: - secrets SHOULD be passed via reference-based mechanisms where possible; |
| ECL1N-0113 | 9.5 | recommendation | Evidence bundles SHOULD support redaction or partitioning while preserving auditability; |
| ECL1N-0114 | 9.5 | recommendation | Provenance exports SHOULD preserve required accountability with least necessary disclosure; |
| ECL1N-0115 | 9.5 | obligation, conditional | If redaction hides materially relevant context, a sealed-review or escrow path MUST exist for the assessor or regulator authorized to inspect it. |
| ECL1N-0116 | 9.6 | recommendation | Deployments SHOULD implement: - regular red-team exercises targeting layer bypass, delegation abuse, and boundary misclassification; - incident workflows that… |
| ECL1N-0117 | 9.7 | obligation | Evidence-signing interoperability MUST use ECL Integrity Envelope 1 or a separately profiled, loss-audited envelope that preserves its typed-payload… |
| ECL1N-0118 | 9.7 | obligation | `DCMP-2` and `EBMP-2` artifacts MUST pass strict parsing, companion schema validation, applicable semantic rules, critical-extension processing, and… |
| ECL1N-0119 | 9.7 | obligation | Redacted provenance exports MUST preserve verifier-critical fields: root trace identifier, action identifier, actor and subject identifier or stable… |
| ECL1N-0120 | 9.7 | obligation | Redaction MUST create a new derivative and authenticated redaction manifest. |
| ECL1N-0121 | 10.1 | obligation | ECL-1 conformance MUST be represented as a runtime-control conformance statement, not as framework certification by proxy. |
| ECL1N-0122 | 10.1 | obligation | ECL-1 mappings to external standards, laws, or guidance MUST identify both supported obligations and uncovered obligations. |
| ECL1N-0123 | 10.1 | obligation | Marketing or procurement materials MUST NOT state that ECL-1 alone guarantees legal compliance with any law or regulation. |
| ECL1N-0124 | 10.2 | obligation | Any ECL-to-framework mapping MUST classify each mapped obligation as one of: - **Direct runtime support**: ECL control semantics directly address the named… |
| ECL1N-0125 | 10.3 | obligation | Any public or procurement-facing mapping claim MUST include: - clause or article references for the mapped external surface; - explicit statement of the ECL… |
| ECL1N-0126 | 10.3 | recommendation | Mappings SHOULD be versioned and updated when source framework editions change. |
| ECL1N-0127 | 10.4 | recommendation, conditional | When a public claim cites external framework support, the claim SHOULD use a single structured statement or an inseparable adjacent pair of statements that… |
| ECL1N-0128 | 10.7 | obligation | Framework mappings, crosswalks, and claim packets MAY support adoption. |
| ECL1N-0129 | 11.1 | obligation | A supplier claiming ECL-1 conformance MUST submit this checklist with evidence links for all applicable items. |
| ECL1N-0130 | 11.1 | obligation | Each checklist item MUST be marked `Pass`, `Fail`, or `Not Applicable`. |
| ECL1N-0131 | 11.1 | obligation | `Not Applicable` classifications for delegation, emergency-control, boundary-challenge, or public-claim items MUST be supported by evidence that the… |
| ECL1N-0132 | 11.1 | recommendation | Runtime evidence SHOULD be current within 12 months for `L1-L2` claims and within 6 months for `L3-L4` claims unless the item is tied to a static certification… |
| ECL1N-0133 | 11.1 | obligation | Checklist submission MUST include the SoI boundary, claim boundary class, and Negative Boundary Annex defined in Section 2. |
| ECL1N-0134 | 11.1 | obligation | A separate FR-to-checklist coverage matrix MUST accompany the checklist. |
| ECL1N-0136 | 11.5 | recommendation | A complete supplier package SHOULD include: - explicit public claim statement required by Section 7.7; - populated checklist table; - requirement-to-evidence… |
| ECL1N-0137 | 11.6 | obligation, conditional | When an AIBOM is included in a supplier package, it MUST satisfy `AIBOM-MIN-1`. |
| ECL1N-0138 | 11.6 | permission | Provenance exports submitted for checklist evaluation MAY be redacted. |
| ECL1N-0139 | 11.6 | obligation | Provenance exports submitted for checklist evaluation MUST preserve verifier-critical fields as defined in Section 9.7. |
| ECL1N-0141 | 5.1 | obligation | A conformant implementation MUST NOT provide an undisclosed bypass path around the Enforcement Layer for in-scope actions, and MUST NOT suppress the required… |
| ECL1N-0142 | 7.5 | obligation | A claim MUST achieve at least the control-independence class that the following table gives for its claimed level. |
| ECL1N-0143 | 7.5 | obligation | A `Class B` or `Class C` claim MUST identify the separately administered trust domain in which control approval and evidence verification both occur, the… |
| ECL1N-0144 | 7.5 | obligation | A `Class C` claim MUST also identify the externally independent authority that holds control approval and evidence verification and state why it is independent… |
| ECL1N-0145 | 5.5 | obligation | A producer MUST NOT use summary evidence unless reconstructability is preserved, and MUST use expanded evidence for overrides, incidents, critical actions… |
| ECL1N-0146 | 8.8 | obligation | Fallback states MUST take precedence in the order `Emergency Halt` > `Restricted Mode` > `Degraded Mode` > ordinary operation, and each trigger condition in the… |
| ECL1N-0147 | 7.11 | obligation | An assessor MUST classify each failed checklist item with one of these severities: - `critical`: bypassable enforcement, undisclosed effect path, fail-open… |
| ECL1N-0148 | 7.11 | obligation | The assessment MUST be signed by a reviewer who is not the primary implementer for the assessed SoI; at `L1` it MAY be internal. |
| ECL1N-0152 | 7.12 | obligation | A claim MUST be reassessed after any of the following: - any `critical` finding in a claimed deployment; - material change to enforcement placement, trust… |
| ECL1N-0153 | 11.1 | obligation | An item MUST NOT be marked `Not Applicable` unless its applicability predicate is false for the SoI or the claimed level is below the item's minimum level. |
| ECL1N-0154 | 11.2 | obligation | An assessor MUST record each of the following as a `critical` finding: - bypassable enforcement for in-scope consequential actions; - fail-open behavior on… |
| ECL1N-0155 | 9.8 | obligation | A claim MUST maintain an inventory of every evidence-signing key that its trust policy accepts, giving for each key: its key identifier, its registered… |
| ECL1N-0156 | 9.8 | obligation | The governed AI system MUST NOT be able to read or export a private key that signs decision responses, evidence events, observations, or time attestations, or… |
| ECL1N-0157 | 9.8 | obligation | A private key MUST NOT sign for more than one of the decision point, the enforcement point, an observer, and a time authority. |
| ECL1N-0158 | 9.8 | obligation | Each evidence-signing key MUST have a declared maximum active lifetime of no more than 24 months for `L1` and `L2` claims and no more than 12 months for `L3`… |
| ECL1N-0159 | 9.8 | obligation, conditional | When an evidence-signing key is known or suspected to be compromised, the claimant MUST publish a trust-policy version that revokes the key with an effective… |
| ECL1N-0163 | 2.9 | obligation, conditional | When output that a conversational system sends in the organization's name can state a price, term, policy, eligibility, legal, or health matter on which a… |
| ECL1N-0164 | 5.2 | obligation | For each in-scope action class, the Consequential Action Register MUST state each decision input's source and class, distinguishing actor-controlled assertions… |
| ECL1N-0166 | 5.4 | obligation | A change that disables, bypasses, or sets to automatic approval an in-scope control, including a policy rule, an enforcement point, a human-approval step, a… |
| ECL1N-0167 | 5.6 | obligation | A claim MUST declare the detections that indicate that the SoI may be acting wrongly, including verification findings, monitoring alerts, anomaly signals, and… |
| ECL1N-0170 | 5.7 | obligation | A change to the policy, the Consequential Action Register, the tool or capability manifest reachable by the SoI, an enforcement point's configuration, the trust… |
| ECL1N-0172 | 5.10 | obligation | For each in-scope action class, the Consequential Action Register MUST state the largest aggregate effect that the SoI could cause through that class in one… |
| ECL1N-0174 | 5.11 | obligation, conditional | When a person approves or rejects a consequential action, the approval MUST be made on a human-readable presentation of its operation, target, every parameter… |
| ECL1N-0177 | 5.11 | obligation, conditional | When the Consequential Action Register declares a human-approval threshold for an action class (ECL1N-0007), the Decision Layer MUST NOT return `admit` for an… |
| ECL1N-0178 | 5.2 | obligation | For each in-scope action class, the Consequential Action Register MUST declare, for each decision input that ECL1N-0164 requires it to state, its class as… |
| ECL1N-0179 | 5.2 | obligation | An `actor_supplied` or `judgment` input MUST NOT be the basis of an `admit`. |
| ECL1N-0180 | 5.2 | obligation | An `admit` MUST be justified by policy evaluated over `verifiable` inputs alone: its verifiable-only outcome is `admit`, and its authorization is that outcome's… |
| ECL1N-0181 | 5.2 | obligation | The evidence of each decision MUST identify, by reference and digest, the version of the Consequential Action Register under which the decision was made, and… |
| ECL1N-0182 | 5.2 | obligation | A declared decision input is late when the Decision Layer obtains it after its declared deadline, or when its value is older than its declared maximum age at… |
| ECL1N-0183 | 6.1 | obligation | Equivalence MUST be determined by the assessor, not the claimant. |
| ECL1N-0184 | 8.10 | obligation, conditional | Where a federated cross-vendor deployment exchanges an equivalent representation of an item that ECL1N-0108 lists, the representation MUST be semantically… |
| ECL1N-0185 | 5.4.1 | obligation | Each enforcement profile MUST identify the release boundary at which an enforcement point under the profile releases an action, and each claim MUST identify the… |
| ECL1N-0186 | 5.4.1 | obligation | Before an action crosses its release boundary, the enforcement point MUST have established, for that action and at that boundary: 1. that what it releases is… |
| ECL1N-0187 | 5.4.1 | obligation | Required proof for a release that is missing, of a kind that the enforcement point does not support, stale, failed, or bound to another action, request… |
| ECL1N-0188 | 5.4.1 | obligation | A timestamp used to show that an action was released while its authority was valid MUST describe the release boundary under the observation mechanism and clock… |
| ECL1N-0189 | 5.4.2 | obligation | Before it releases an action, an enforcement point MUST durably preserve the recovery information that its declared failure model requires, which includes at… |
| ECL1N-0190 | 5.4.2 | obligation | Each claim MUST declare, for each enforcement point, which of these failures its recovery information and its evidence survive: the exit of the enforcement… |
| ECL1N-0191 | 8.8 | obligation | The state that ECL1N-0146 requires for missing proof, for a critical integrity failure and for an emergency control activation MUST cover at least the scope… |
| ECL1N-0192 | 8.8 | obligation | Each claim MUST declare its dependency model with its mode definitions (ECL1N-0101): for each in-scope action class, every dependency whose loss can remove its… |
| ECL1N-0193 | 8.8 | obligation | The claim's mode definitions MUST state, for each trigger of ECL1N-0146, which authorization, if any, is needed to lift the restriction that the trigger brings. |
| ECL1N-0194 | 5.6 | obligation | A verifier MUST NOT imply that it performed a check that it did not perform or that lay outside its declared scope, MUST report a condition that it could not… |
| ECL1N-0195 | 5.5 | obligation, conditional | Where a qualified legal reviewer determines that applicable law requires earlier removal, minimization or restriction, the operator MUST follow that recorded… |
| ECL1N-0196 | 5.5 | obligation | Before changing retention the operator MUST record, to the extent lawful, the legal basis and scope, responsible legal reviewer, approving authority, affected… |
| ECL1N-0197 | 5.5 | obligation | The operator MUST minimize source content and identifiers separately from operational metadata, commitments and destruction records, retain only lawful… |
| ECL1N-0198 | 5.5 | obligation | An unresolved conflict MUST be escalated for an authorized legal determination within the applicable deadline; an administrative hold MUST NOT be used to extend… |
| ECL1N-0199 | 5.5 | obligation | The claim MUST disclose unavailable evidence; a verifier MUST NOT treat its destruction record as the missing evidence or claim the original bundle is complete. |
| FR-001 | 6.2 | obligation | The ECL control plane MUST be architecturally independent of the governed AI system. |
| FR-002 | 6.2 | obligation | The decision interface MUST be model-agnostic and vendor-neutral. |
| FR-003 | 6.2 | obligation | Enforcement MUST fail closed when policy, identity proof, contract validation, integrity checks, or evidence preconditions are missing or invalid. |
| FR-004 | 6.2 | obligation | The system MUST provide a separately authenticated and separately audited emergency control plane capable of halt, quarantine, or equivalent pre-declared… |
| FR-005 | 6.2 | obligation | A conformance claim MUST provide requirement-to-evidence traceability for all applicable `FR-*` controls. |
| FR-006 | 6.2 | obligation | The deployment MUST maintain a Consequential Action Register with classification rationale, affected resources, data classes, and enforcement class for every… |
| FR-007 | 6.2 | obligation | Every claim MUST declare a claim class, explicit SoI boundary, and Negative Boundary Annex listing excluded effect channels and shared surfaces. |
| FR-008 | 6.2 | obligation | The deployment MUST define restricted-mode and degraded-mode behavior, including the conditions under which degraded mode expires into restricted mode or… |

### DCMP-2 (`protocols/DCMP-2.md`)

| ID | Section | Kind | Summary |
| --- | --- | --- | --- |
| DCMP2-001 | 2 | obligation | A DCMP-2 producer MUST emit an object that satisfies the published JSON Schema and all applicable semantic rules. |
| DCMP2-002 | 2 | obligation | A DCMP-2 consumer MUST perform strict JSON parsing before schema validation. |
| DCMP2-003 | 2 | obligation | Schema validation alone MUST NOT be represented as complete DCMP-2 validation. |
| DCMP2-004 | 2 | obligation | Every message MUST carry `protocol`, `schema_version`, `message_type`, `message_id`, `workflow`, `issuer`, `issued_at`, `extensions`, and `integrity_policy`. |
| DCMP2-005 | 2 | obligation | The pair of a logical `message_id` and the digest of the canonical message payload identifies an immutable message version. |
| DCMP2-006 | 3.1 | obligation | A decision request MUST identify the actor, any distinct subject, the action, target, operation, parameter digest, constraints, risk class, required evidence… |
| DCMP2-007 | 3.1 | obligation, conditional | If parameters are carried in-band in `action.parameters`, `action.parameters_digest` MUST be the `ecl.digest.sha-256.v1` digest of the restricted canonical JSON… |
| DCMP2-008 | 3.1 | obligation | A mutable resource reference used in a consequential decision MUST include a digest, version, immutable snapshot reference, or a profile- defined witness that… |
| DCMP2-009 | 3.1 | obligation | Actor and subject MUST remain distinct through delegation. |
| DCMP2-010 | 3.1 | obligation | Each delegation hop MUST be independently referencable, integrity-verifiable, audience-bound, expiry-bounded, and scope-attenuating. |
| DCMP2-011 | 3.1 | obligation | An idempotency key MAY identify an intended effect boundary, but MUST NOT replace the unique message, action, attempt, decision, authority, or receipt… |
| DCMP2-012 | 3.2 | obligation | A response whose outcome is not `admit` MUST NOT carry an `authorization` object. |
| DCMP2-013 | 3.2 | obligation | An `admit` response MUST carry an authorization object whose audience, scope digest, validity interval, and use policy bind the exact release authority. |
| DCMP2-014 | 3.2 | obligation | A deny, hold, challenge, expired, revoked, cancelled, or superseded message MUST NOT be interpreted as release authority. |
| DCMP2-015 | 3.2 | obligation | An authorization validity interval MUST be non-empty, MUST be contained within any governing decision and delegation validity interval, and MUST NOT exceed the… |
| DCMP2-016 | 3.2 | obligation | Every response MUST bind the policy identifier, version, digest, and applicable policy epoch. |
| DCMP2-017 | 3.2 | obligation | Obligations with `before_release` satisfaction MUST be proven at Enforcement before the action is released. |
| DCMP2-018 | 3.2 | obligation | `hold` and `challenge` MUST carry or causally reference the condition for progress, a deadline where time-bounded, and the timeout disposition. |
| DCMP2-019 | 3.3 | obligation | A challenge MUST identify the original request, a unique challenge, required evidence or actions, a deadline, and `on_timeout`. |
| DCMP2-020 | 3.3 | obligation | A challenge response MUST reference both challenge and request and MUST carry immutable evidence references. |
| DCMP2-021 | 3.3 | obligation | Challenge satisfaction MUST cause a new evaluation and a new decision response. |
| DCMP2-022 | 3.4 | obligation | A control message MUST identify the controlled object (`target_id`), effective time, issuer, authority context, reason, and any required safe state. |
| DCMP2-023 | 3.4 | obligation | `supersede` MUST identify the replacement object. |
| DCMP2-024 | 3.4 | obligation | A cancellation or revocation received after release MUST be recorded and applied according to the action's interruptibility and compensation profile. |
| DCMP2-025 | 3.4 | obligation | A `halt` or `quarantine` control message MUST be issued on the separately authenticated emergency control plane that FR-004 requires at every level, and MUST… |
| DCMP2-026 | 4 | obligation | Retries MUST create a new message identifier and attempt number. |
| DCMP2-027 | 4 | obligation | A message MUST NOT list itself as a causal predecessor. |
| DCMP2-028 | 4 | obligation | A causal reference MUST bind both the predecessor's logical identifier and canonical digest. |
| DCMP2-029 | 4 | obligation | Within one workflow sequence domain, a predecessor sequence MUST be lower than its successor sequence. |
| DCMP2-030 | 4 | obligation | Forks, joins, delegated sub-workflows, and human interventions MUST be represented through explicit workflow and causal references rather than inferred from… |
| DCMP2-031 | 5 | obligation | `issued_at`, `expires_at`, `evaluated_at`, validity intervals, and deadlines MUST be UTC RFC 3339 values in the restricted ECL timestamp profile. |
| DCMP2-032 | 5 | obligation | An expiry MUST be later than issue. |
| DCMP2-033 | 5 | obligation | Wall-clock timestamps alone MUST NOT override a causal relationship or trusted sequence observation. |
| DCMP2-034 | 5 | obligation | A verifier MUST apply the declared verification-time and clock- skew policy. |
| DCMP2-035 | 6 | obligation | A message used to release an in-scope action MUST satisfy its payload-bound integrity policy. |
| DCMP2-036 | 6 | obligation | A consumer MUST reject signature-suite substitution, key substitution, an unmet signature threshold, a missing required signer, unacceptable trust material, or… |
| DCMP2-037 | 6 | obligation | Extension identifiers and versions MUST be unique within a message. |
| DCMP2-038 | 6 | obligation | An unknown critical extension, in the sense of XR1-006, MUST cause rejection before admission or release. |
| DCMP2-039 | 7 | obligation | Failure output MUST identify one stable primary error code and MAY carry registered subcodes and bounded detail. |
| DCMP2-040 | 7 | obligation | A parse, schema, semantic, integrity, trust, expiry, replay, revocation, or unknown-critical-extension failure MUST NOT produce an effective admit. |
| DCMP2-041 | 7 | obligation | A timeout or unavailable remote dependency MUST apply the profile's declared action-class safe-state rule. |
| DCMP2-042 | 7 | obligation | A consumer MAY support DCMP-1 during a declared transition window, but MUST NOT silently coerce a DCMP-1 object into DCMP-2 or claim DCMP-2 conformance for an… |
| DCMP2-043 | 7 | obligation | A conformant validator MUST report exactly one primary error per invalid artifact: a strict-input failure first, with the finding of the first check of… |
| DCMP2-044 | 8 | obligation | In an `admit`, `authorization.scope_digest` MUST be the `ecl.digest.sha-256.v1` digest of the restricted canonical JSON of an object with exactly two members… |
| DCMP2-045 | 8 | obligation | A response's `request_id` MUST equal its request's `message_id`, and its `workflow_id`, `root_trace_id` and `attempt` MUST equal the request's. |
| DCMP2-046 | 8 | obligation | A response MUST carry exactly one causal predecessor with the relation `ecl.relation.responds-to.v1`; that predecessor's `id` MUST be the request's `message_id`… |
| DCMP2-047 | 8 | obligation | A response's `issued_at` MUST NOT be earlier than its request's `issued_at` by more than the response clock-skew allowance that the verification profile… |
| DCMP2-048 | 8 | obligation | In an `admit`, `authorization.audience` MUST equal the request's `authority_request.audience`, reported as `ecl.error.audience-mismatch.v1` when it does not… |
| DCMP2-049 | 8 | obligation | In an `admit`, the authorization window MUST be non-empty and no longer than the request's `requested_validity_seconds`; `valid_from` MUST NOT be earlier than… |
| DCMP2-050 | 8 | obligation | In an `admit`, a `single_use` authorization MUST omit `max_uses` or set it to 1, and when the request carries `authority_request.max_uses` the authorization… |
| DCMP2-051 | 8 | obligation | A consumer MUST NOT release an action on a response that fails any of DCMP2-044 to DCMP2-050, and an evidence verifier MUST report such a response as not… |
| DCMP2-052 | 3.2 | obligation | An `admit` response MUST NOT carry, in `ecl.ext.consequence-coupling.v1`, a `budget_result` whose outcome is not `authorized`, a `witness_result` whose outcome… |
| DCMP2-053 | 3.2 | obligation | A response that carries `ecl.ext.decision-basis.v1` MUST NOT list one `input` more than once, MUST NOT record an `actor_supplied` or `judgment` input, or an… |
| DCMP2-054 | 3.1 | obligation | `action.risk_class`, `constraints`, `action.budget_debit`, and the `witness_reference` and `capability_manifest` of `ecl.ext.consequence-coupling.v1` in a… |
| DCMP2-055 | 3.1 | obligation | A request's `action.budget_debit.amount` MUST be written without a sign, so that no declared debit is negative. |
| DCMP2-056 | 3.3 | obligation | A request that continues a request answered with a decision response whose outcome is `challenge` MUST be a new decision request (DCMP2-021, DCMP2-026): a new… |
| DCMP2-057 | 3.3 | obligation | The Decision Layer MUST evaluate a continuation afresh under the policy in force at its evaluation and MUST NOT copy the outcome, authorization or obligations… |

### EBMP-2 (`protocols/EBMP-2.md`)

| ID | Section | Kind | Summary |
| --- | --- | --- | --- |
| EBMP2-001 | 2 | obligation | Every record MUST satisfy schema, semantic, canonicalization, extension, and integrity requirements applicable to its profile. |
| EBMP2-002 | 2 | obligation | Every record MUST identify its logical object, exact content through a canonical digest when referenced, workflow, root trace, attempt, sequence, producer… |
| EBMP2-003 | 2 | obligation | A record producer MUST be identified separately from the actor, subject, decision service, authority issuer, enforcement point, verifier, and evidence custodian… |
| EBMP2-004 | 2 | obligation | A verifier MUST treat a producer's event as a claim with a declared observation boundary, not as omniscient ground truth. |
| EBMP2-005 | 3 | permission | A profile MAY require additional registered critical events. |
| EBMP2-006 | 3.1 | obligation | A decision event MUST reference the exact DCMP-2 decision, record its outcome, and bind the evaluated policy. |
| EBMP2-007 | 3.1 | obligation | An authority event MUST identify the authority and its state: `issued`, `active`, `consumed`, `revoked`, `expired`, or `superseded`. |
| EBMP2-008 | 3.1 | obligation | Consumption MUST be separately recorded for a single-use authority. |
| EBMP2-009 | 3.1 | obligation | Revocation, expiry, and supersession MUST NOT delete an authority record and MUST NOT be treated as proof that a prior release did not occur. |
| EBMP2-010 | 3.2 | obligation | An execution attempt MUST have a unique attempt identifier. |
| EBMP2-011 | 3.2 | obligation | A terminal attempt MUST NOT return to a non-terminal state. |
| EBMP2-012 | 3.2 | obligation | `denied`, `held`, `challenged`, and `expired_before_release` MUST NOT be reported as execution failures because the governed action was not released. |
| EBMP2-013 | 3.2 | obligation | A terminal event in `partially_succeeded`, `timed_out`, `cancelled` or `unknown` MUST carry `side_effects`, listing every known side effect (an empty array when… |
| EBMP2-014 | 3.2 | obligation | Rollback and compensation are new effects. |
| EBMP2-015 | 3.2 | obligation | A successful tool or API return MUST NOT be equated with successful external effect unless the declared observation boundary supports that conclusion. |
| EBMP2-016 | 3.3 | obligation | A human intervention event MUST identify the human or approved organizational principal (`actor`), operation, target (`target_id`), authority (`authority`)… |
| EBMP2-017 | 3.3 | obligation | An approval MUST expire, be supersedable, and be transaction- bound. |
| EBMP2-018 | 3.3 | obligation | Dual-control profiles MUST preserve each independent approval and prove that the required threshold was met before release. |
| EBMP2-019 | 3.4 | obligation | A verification event MUST identify the verifier, subject, rules applied, decision, findings (`findings`, empty when there are none), registry versions… |
| EBMP2-020 | 3.4 | obligation | `indeterminate` MUST remain distinct from `pass` and `fail`. |
| EBMP2-021 | 3.4 | obligation | Fleet events MUST record relevant policy, trust-root, registry, verifier, revocation, and evidence-export frontiers. |
| EBMP2-022 | 4 | obligation | A causal predecessor reference MUST include the predecessor's logical identifier and canonical digest. |
| EBMP2-023 | 4 | obligation | A complete bundle MUST contain every required predecessor or declare it as an external immutable dependency available to the verifier. |
| EBMP2-024 | 4 | obligation | A causal graph MUST be acyclic. |
| EBMP2-025 | 4 | obligation | Within one workflow sequence domain, causal predecessors MUST have lower sequence values than successors. |
| EBMP2-026 | 4 | obligation | Timestamps MUST NOT be used to fabricate missing causal edges or override contradictory sequence and digest evidence. |
| EBMP2-027 | 4 | obligation | A bundle manifest MUST declare `complete`, `incomplete`, or `indeterminate`, and enumerate terminal actions, open actions, and unresolved predecessors. |
| EBMP2-028 | 4 | obligation | A manifest claiming `complete` MUST be rejected if closure recalculation yields any open action or unresolved required predecessor. |
| EBMP2-029 | 4 | obligation | Bundle order is not semantic order. |
| EBMP2-030 | 5 | obligation | A storage path, database primary key, display label, or tenant- local sequence MUST NOT substitute for canonical content identity. |
| EBMP2-031 | 5 | obligation | The exact immutable version of a record MUST be identified by the pair of its logical identifier and canonical digest. |
| EBMP2-032 | 5 | obligation | A conflicting digest for the same logical identifier MUST be reported as a collision, equivocation, or explicit superseding version according to authenticated… |
| EBMP2-033 | 5 | obligation | Evidence needed for offline verification MUST include or immutably reference the trust policy, verification material, registry snapshots, revocation state, and… |
| EBMP2-034 | 6 | obligation | Evidence collection MUST be limited to declared purpose and data classes. |
| EBMP2-035 | 6 | obligation | Secrets, raw credentials, unnecessary personal data, and unbounded reasoning transcripts MUST NOT be included merely to make a bundle look complete. |
| EBMP2-036 | 6 | obligation | A redacted artifact is a new derivative with a new identity. |
| EBMP2-037 | 6 | obligation | Redaction MUST NOT preserve a claim whose required verifier- critical evidence was removed. |
| EBMP2-038 | 7 | obligation | Seal, verify, retain, export, redact, supersede, revoke, legal hold, release hold, and destroy MUST be represented as append-only lifecycle events. |
| EBMP2-039 | 7 | obligation | A lifecycle event MUST reference the prior digest and active lifecycle policy. |
| EBMP2-040 | 7 | obligation | Redact and supersede MUST reference the derived artifact (`derived_artifact`), and redact MUST also reference its redaction manifest (`redaction_manifest`… |
| EBMP2-041 | 7 | obligation | Legal hold MUST take precedence over scheduled destruction until a separately authorized release-hold event. |
| EBMP2-042 | 7 | obligation | Lifecycle metadata MUST NOT falsely claim physical deletion beyond the observation and control boundary of its producer. |
| EBMP2-043 | 8 | obligation | Each invalid vector MUST map to one stable primary error and MAY map to registered subcodes. |
| EBMP2-044 | 8 | obligation | An EBMP-1 adapter MUST identify every lossless, derived, defaulted, omitted, and impossible field. |
| EBMP2-045 | 8 | permission | A richer implementation-native receipt MAY coexist with EBMP-2 only when a digest-bound causal relation and precedence rule identify which artifact supports… |
| EBMP2-046 | 9 | obligation | An event record's `event.kind` MUST be the kind its `event_type` requires, and an authority or execution event's `event.state` MUST be one its `event_type`… |
| EBMP2-047 | 10 | obligation | An `execution_released` or `execution_terminal` event MUST bind its request: `event.action_id` MUST equal the request's `action.action_id`; when the event… |
| EBMP2-048 | 10 | obligation, conditional | When a response to the request exists, an execution event MUST name it: `event.decision.uri` MUST equal the response's `message_id`, `event.decision.digest`… |
| EBMP2-049 | 10 | obligation | An execution event that carries `event.authority` MUST belong to an `admit` response; `event.authority.uri` MUST equal the authorization's `authorization_id`… |
| EBMP2-050 | 10 | obligation | An `execution_released` event MUST belong to an `admit` response, its `observed_at` MUST NOT be earlier than the authorization's `valid_from`, and its… |
| EBMP2-051 | 10 | obligation | The state of an `execution_terminal` event MUST agree with the outcome of its response under the state-outcome table of the verification profile. |
| EBMP2-052 | 10 | obligation | An `authority_issued` or `authority_consumed` event MUST belong to an `admit` response whose `authorization.authorization_id` equals the event's… |
| EBMP2-053 | 10 | obligation | For one action attempt, a non-execution terminal state (`denied`, `held`, `challenged`, `expired_before_release`) MUST NOT coexist with consumed authority, an… |
| EBMP2-054 | 10 | obligation | A `request` or `decision` reference in an event MUST resolve to a message in the bundle with the same `workflow_id`, `root_trace_id` and `attempt`, and a digest… |
| EBMP2-055 | 10 | obligation | A `succeeded` attempt MUST have an `authority_consumed` event in state `consumed` and an `execution_released` event for the same attempt. |
| EBMP2-056 | 10 | obligation | A terminal event MUST carry at most one `ecl.ext.outcome-reason.v1` extension, whose value is exactly `{"code": C}` with `C` an active registered error code. |
| EBMP2-057 | 11 | obligation | An observation MUST be an EBMP-2 `verification` event; a verifier MUST report one that is not with `ecl.error.semantic-invalid.v1`. |
| EBMP2-058 | 11 | obligation | A verifier MUST pair objects by identity and never by an event's claimed decision URI: a request by its `message_id` and by its (`action.action_id`… |
| EBMP2-059 | 11 | obligation | A verifier MUST apply DCMP2-044 to DCMP2-051 to every request and response pair, EBMP2-046 to EBMP2-056, EBMP2-070 and EBMP2-072 to EBMP2-075 to every event… |
| EBMP2-060 | 11 | obligation | A verifier MUST report exactly one verdict: `invalid` when an object of the bundle, in `envelopes` or `observations`, is not historically valid, a trust… |
| EBMP2-061 | 11 | obligation | A verifier MUST report the evidence level of each terminal effect: `none` when the terminal is not historically valid; `issuer-asserted` when it is; and… |
| EBMP2-062 | 11 | obligation | A verifier MUST declare finite limits on the number of envelopes and observations and on the decoded payload nodes of a bundle, MUST count the nodes of each… |
| EBMP2-063 | 3.3 | obligation | A human intervention event that approves or rejects and carries `ecl.ext.approval-record.v1` MUST have an `issued_at` no earlier than `presented_at` plus… |
| EBMP2-064 | 3.3 | obligation | An event that carries `ecl.ext.control-change.v1` MUST name at least one approver, none of whom is the requester, and a change of kind `disable`, `bypass` or… |
| EBMP2-065 | 3.2 | obligation | The execution events of one attempt, those with the same `event.action_id` and `event.attempt_id`, taken in ascending order of `workflow.sequence` and then of… |
| EBMP2-066 | 3.2 | obligation | Every execution event with the same `event.action_id`, `workflow.workflow_id` and `workflow.attempt` MUST carry the same `event.attempt_id`, and one… |
| EBMP2-067 | 11 | obligation | A verifier MUST apply the verification profile that its caller names, and the reference verification profile `ecl.verification-profile.reference.v1` when the… |
| EBMP2-068 | 11 | obligation | A verifier MAY stop at the first of the stages below that has a finding, and need not report a bundle's other findings as secondary findings, but MUST report as… |
| EBMP2-069 | 8 | obligation | A native adapter binding (`ecl_adapter_binding_v1`) binds one retained implementation-native object to the ECL objects derived from it. |
| EBMP2-070 | 3.2 | obligation, conditional | When the decision response that an `execution_released` event records carries an obligation whose `satisfaction` is `before_release`, or carries in… |
| EBMP2-071 | 3.2 | obligation | The `observed_at` of an `execution_released` event MUST be the enforcement point's observation of the release boundary that its profile declares, taken after… |
| EBMP2-072 | 10 | obligation | A verifier MUST report with `ecl.error.expired.v1`, as a finding of stage 7 of EBMP2-068, an `execution_terminal` event that binds its request and response and… |
| EBMP2-073 | 10 | obligation | An `authority_consumed` event in state `consumed` that binds its response under EBMP2-052 and carries `use_count` MUST give a value from 1 to the number of uses… |
| EBMP2-074 | 10 | obligation | An action attempt with an `execution_released` event that binds its request and response, and whose authorization's `use_policy` is `single_use`, MUST also have… |
| EBMP2-075 | 10 | obligation, conditional | When a request carries `ecl.ext.mcp-binding.v1`, an `execution_released` or `execution_terminal` event of its action that carries the extension MUST carry, in… |
| EBMP2-076 | 11 | obligation | With each verdict a verifier MUST report its scope, as the two lists of the table below: `established`, the checks that it made for the bundle and that held… |
| EBMP2-077 | 4 | obligation | A causal predecessor MUST have its successor's `workflow.root_trace_id`, and MUST be in its successor's workflow or in the workflow that its successor's… |
| EBMP2-078 | 11 | obligation | A bundle MAY hold a continued request and its continuation (DCMP-2 DCMP2-056), each with its own response and attempt, and then verifies as one history. |

### INTEGRITY-ENVELOPE-1 (`protocols/INTEGRITY-ENVELOPE-1.md`)

| ID | Section | Kind | Summary |
| --- | --- | --- | --- |
| IE1-001 | 1 | obligation | A signed ECL JSON payload MUST first satisfy the restricted ECL canonical JSON profile. |
| IE1-002 | 1 | obligation | The JSON profile MUST conform to I-JSON (RFC 7493) and RFC 8785 behavior, including I-JSON's prohibition of surrogate code points and noncharacters in strings… |
| IE1-003 | 1 | obligation | Decimal quantities, currency, durations, integers outside the exact range, and other precision-sensitive values MUST use registered string representations. |
| IE1-004 | 1 | obligation | A consumer MUST apply the verified RFC 8785 erratum relevant to negative zero (Errata ID 7920) and MUST reject rather than normalize ambiguous input. |
| IE1-005 | 2 | obligation | The envelope MUST carry the payload bytes as canonical base64, payload media type, and payload digest. |
| IE1-006 | 2 | obligation | The verifier MUST recompute the payload digest before signature policy evaluation. |
| IE1-007 | 2 | obligation | SHA-256 is the ECL v1 universal digest floor. |
| IE1-008 | 2 | obligation | A logical protocol identifier and canonical content digest together identify an immutable object version. |
| IE1-009 | 3 | obligation | Signers and verifiers MUST compute this domain-separated input over the exact payload type and decoded payload bytes. |
| IE1-010 | 3 | obligation | A signature valid for one payload type MUST NOT validate for another payload type. |
| IE1-011 | 3 | obligation | A verifier MUST NOT re-serialize a parsed payload before signature verification. |
| IE1-012 | 4 | obligation | Envelope fields MUST NOT weaken the payload-bound policy. |
| IE1-013 | 4 | obligation | The threshold MUST be an integer, MUST be at least one when integrity is required, MUST be zero when integrity is declared optional, and MUST NOT be lower than… |
| IE1-014 | 4 | obligation | Each valid signer MUST count at most once toward threshold, independent of duplicate signature entries. |
| IE1-015 | 4 | obligation | A key MUST be acceptable under the trust policy, eligible-key set, suite binding, validity interval, usage constraint, and revocation policy before its… |
| IE1-016 | 5 | obligation | Ed25519 encoding and verification MUST follow RFC 8032. |
| IE1-017 | 5 | obligation | ECDSA P-256 signatures MUST use minimally encoded ASN.1 DER and a low-S value. |
| IE1-018 | 5 | obligation | ML-DSA-65 use MUST follow FIPS 204, read with the potential updates (errata) that NIST lists for it, and MUST be explicitly enabled by profile and trust policy. |
| IE1-019 | 5 | obligation | A post-quantum signature MUST NOT silently replace a required classical signature during a transition. |
| IE1-020 | 5 | obligation | Recognition of an algorithm name is not trust. |
| IE1-021 | 6 | obligation | An offline package (OFFLINE-VERIFICATION-1) MUST carry one signed evidence bundle (EBMP-2 section 11) and every certificate, raw public key, trust root… |
| IE1-022 | 6 | obligation | Verification material that an envelope or an offline package carries MUST be treated as evidence and MUST NOT automatically be treated as a trust anchor. |
| IE1-023 | 6 | obligation | Verification at issue time, observation time, trusted timestamp time, current time, or another declared time are distinct policies. |
| IE1-024 | 6 | obligation | A signature MUST NOT count, even when its cryptographic check passes, if its key is not acceptable under the trust policy, suite, purpose or policy context, or… |
| IE1-025 | 7 | obligation | A countersignature, notarization, or timestamp MUST bind the digest and media type of the exact object it covers and identify its distinct claim. |
| IE1-026 | 7 | obligation | Adding verification material or a countersignature creates a new envelope version or bundle artifact; it MUST NOT change the signed payload. |
| IE1-027 | 7 | obligation | Algorithm deprecation and emergency prohibition MUST be registry-versioned, time-bounded, appealable, and reflected in offline trust bundles. |
| IE1-028 | 8 | obligation | Every conforming parser, verifier, and offline-package processor MUST operate under a declared profile of finite, positive resource limits covering, as… |
| IE1-029 | 8 | obligation | An implementation MUST enforce applicable resource limits before unbounded allocation, decompression, recursive traversal, or cryptographic work. |
| IE1-030 | 8 | obligation | Archive and package processing MUST reject absolute paths, platform drive paths, parent traversal, control characters, non-canonical Unicode path aliases… |
| IE1-031 | 8 | obligation | A package format that claims deterministic construction MUST define canonical entry names and order, timestamps, permissions, platform attributes, encoding… |
| IE1-032 | 9 | obligation | A trusted-time countersignature MUST be an entry of the envelope's `countersignatures` member with `counter_id`, `claim` set to `ecl.claim.trusted-time.v1`, and… |
| IE1-033 | 9 | obligation | A time attestation MUST bind in `covered` the covered envelope's payload type (`media_type`), its payload digest (`digest`) and the signatures that it attests… |
| IE1-034 | 9 | obligation | A verifier that evaluates a trusted-time countersignature MUST verify the attestation under the trust-policy version the attestation names, at its attested… |
| IE1-035 | 9 | obligation | A verification profile MAY require trusted time. |
| IE1-037 | 1 | obligation | A consumer MUST refuse a configured limit that IE1-028 does not allow before it reads any input, as a configuration error and never as the finding of a check… |
| IE1-038 | 1 | obligation | A validator MUST evaluate the `pattern` keyword of an ECL schema as an ECMA-262 regular expression that may match anywhere in the string unless the pattern… |
| IE1-039 | 11 | obligation | A verifier MUST count a signature only under a key whose trust-policy purposes include the purpose of the payload that this table gives: |
| IE1-040 | 11 | obligation | A verifier MUST check an envelope in this order, and MUST refuse an envelope at the first step it fails, with that step's error code: 1. the envelope satisfies… |

### TIMING-SAFE-STATE-1 (`protocols/TIMING-SAFE-STATE-1.md`)

| ID | Section | Kind | Summary |
| --- | --- | --- | --- |
| TS1-014 | 3 | obligation | Recovery after partition MUST reconcile policy epochs, revocations, consumed authorities, buffered evidence, unresolved effects, and clock discontinuities… |
| TS1-018 | 4 | obligation | Missing or invalid policy, identity, authority, integrity, critical extension, or pre-release evidence MUST fail closed. |
| TS1-027 | 6 | obligation | A lower-precedence decision MUST NOT revive an object placed in a higher-precedence safe state. |
| TS1-031 | 4 | obligation | A consumer MUST treat required proof as the set of inputs that TS1-018 names: policy, identity, authority, integrity, critical-extension handling, and… |
| TS1-032 | 4 | obligation | A failure whose consequence is that any required proof is absent, invalid, expired, or unavailable MUST be classified as missing required proof and MUST fail… |
| TS1-034 | 2 | obligation | Every declared timing bound MUST name its observation points (the events between which the interval is measured), its objective type (a maximum, or a stated… |

### EVIDENCE-LIFECYCLE-1 (`protocols/EVIDENCE-LIFECYCLE-1.md`)

| ID | Section | Kind | Summary |
| --- | --- | --- | --- |
| EL1-014 | 5 | obligation | Redaction MUST create a new derivative and redaction manifest. |

### EXTENSION-REGISTRY-1 (`protocols/EXTENSION-REGISTRY-1.md`)

| ID | Section | Kind | Summary |
| --- | --- | --- | --- |
| XR1-005 | 1 | obligation | A sender MUST mark an extension critical when ignoring it could change admission, authority, enforcement, evidence interpretation, safe state, or conformance… |
| XR1-006 | 2 | obligation | Unknown critical extensions MUST be rejected. |
| XR1-023 | 1 | obligation, conditional | When the registry entry of an extension that a consumer processes names a value schema, the consumer MUST validate the extension's `value` against that schema… |

### TRUST-POLICY-1 (`profiles/TRUST-POLICY-1.md`)

| ID | Section | Kind | Summary |
| --- | --- | --- | --- |
| TP1-001 | ECL Trust Policy Profile 1 | obligation | The verifier MUST use only its caller's current trust policy and explicitly supplied earlier versions of that same policy; a bundle MUST NOT carry, select, or… |
| TP1-002 | ECL Trust Policy Profile 1 | obligation | A trust-policy document MUST validate against `https://externalcontrollayer.ai/ns/schema/trust-policy/1` with no unknown members. |
| TP1-003 | ECL Trust Policy Profile 1 | obligation | A trust-policy document MUST have unique key identifiers and public keys, active supported signature suites, canonically decoded keys of the correct length, a… |
| TP1-004 | ECL Trust Policy Profile 1 | obligation | Bundle verification MUST accept a key only for an object's declared role within its payload media type, and MUST reject a decision-request key used for a… |
| TP1-005 | ECL Trust Policy Profile 1 | obligation | Bundle verification MUST reject a signing key whose bound principal differs from the object's issuer or producer identifier. |
| TP1-006 | ECL Trust Policy Profile 1 | obligation | Bundle verification MUST evaluate each trust dependency of a bundle: each signing key of each envelope and observation, and each signing key of each time… |
| TP1-007 | ECL Trust Policy Profile 1 | obligation | A verifier interface MUST enforce declared byte limits before parsing. |
| TP1-008 | ECL Trust Policy Profile 1 | obligation | Ed25519 verification MUST require canonical scalar `S < L` and check the cofactorless equation `[S]B = R + [k]A`, where `k` is the little-endian SHA-512… |
| TP1-009 | ECL Trust Policy Profile 1 | obligation | A trust-policy key MUST NOT carry more than one of the decision-request, decision-response, control, observation and trusted-time purposes; the evidence-event… |
| TP1-010 | ECL Trust Policy Profile 1 | obligation | Envelope verification under a trust policy, standalone or within a bundle, MUST count a signature over a DCMP-2 message only when its key carries the purpose… |
