# ECL external-framework crosswalks

These crosswalks map the ECL-1 Version 1 public-review source build
`1.0.2-review.1` to two outside frameworks: the
conformance requirements R1 to R9 of AARM (Autonomous Action Runtime
Management) and the ten ACS-Core conformance bullets of the OWASP Agent Control
Standard. Each packet in `../conformance/crosswalks/` pins the framework's
source by revision and digest, names the edition it maps, and gives for each
clause a support class, the ECL requirements that it cites and the work that
remains. The packets' validation state is `internally_reviewed`: the mapping was
reviewed within the project, and no packet claims review or endorsement by the
publisher of the framework it maps.

Each packet states its own boundary in its `non_endorsement` member. Both
statements open with the sentence "This crosswalk is a technical mapping." The
rest of each statement is quoted here:

| Packet | Rest of the statement |
|---|---|
| `aarm-r1-r9.json` | It claims no AARM conformance or program status, no CSA endorsement, and confers none; AARM conformance has its own prerequisites this project has not met. |
| `owasp-acs-core.json` | It claims no ACS conformance or program status, no OWASP endorsement, and confers none; the mapped clauses have not been independently assessed for this deployment. |

## Reading the mapping

A support class describes the cited ECL surface, not satisfaction of every field and behavior in an external obligation. Deployment evidence and the residual work in each row remain necessary. No packet asserts certification, owner endorsement or automatic legal compliance. The mapping boundary is the named public-review source build, identified by each packet's digest-bound source references. A row cites normative obligations, not the features of an implementation. Every requirement retains its level, applicability conditions and profile-declaration scope.

Packets use digest-bound resource URNs: remove `urn:example:ecl:artifact:` to obtain a repository-relative artifact path. Current packet evidence binds the reviewed bytes of those documents in this package: the standard, a companion protocol or a profile. It is source evidence, not a deployment assessment. Earlier packets remain in `conformance/crosswalks/history/` with their original digest-bound source identities.

## AARM (Autonomous Action Runtime Management)

Edition: `v1; conformance requirements last updated 2026-03-26`. Packet: [aarm-r1-r9.json](../conformance/crosswalks/aarm-r1-r9.json).

Source: [AARM (Autonomous Action Runtime Management) source](https://raw.githubusercontent.com/aarm-dev/docs/5bd02fdb5d5f6483a16a42539e38cfe8743c3a97/conformance/requirements.mdx). Exact captured-source revision, digest and clause extraction are recorded in the packet assumptions.

| Clause | Support class | ECL surfaces | Residual / gap |
|---|---|---|---|
| R1 | `direct_runtime_support` | `ECL1N-0034`, `ECL1N-0035`, `ECL1N-0036`, `ECL1N-0037`, `ECL1N-0141`, `DCMP2-040`, `TS1-018`, `SF1-001`, `SF1-002` | AARM deferral ordering, cascade bounds and follow-up receipts require deployment-specific work. ECL hold and timeout-to-safe-state are different mechanisms; TS1-009 does not supply a session deferral scheduler. |
| R2 | `supporting_evidence_only` | `DCMP2-026`, `DCMP2-028`, `DCMP2-030`, `EBMP2-022`, `EBMP2-023`, `EBMP2-024`, `ECL1N-0178`, `ECL1N-0181` | ECL supplies workflow and digest-bound causal linkage, not a session-context store, accumulated data classification, original-intent store or rolling context hash log; those stay with other tools by design. Their outputs connect as decision inputs that the register classifies (ECL1N-0178) and that the decision record identifies by reference and digest (ECL1N-0181); a classification made by a model is a judgment input. |
| R3 (policy evaluation) | `direct_runtime_support` | `ECL1N-0034`, `DCMP2-006`, `DCMP2-012`, `DCMP2-013`, `DCMP2-016`, `DCMP2-018`, `AZB1-001`, `AB1-006` | The deployment must implement the external action classifications, predicate conflict resolution and parameter policies. AuthZEN supplies a policy-engine interface, not those policies. Under AARM-BINDING-1, R3 outputs are judgment inputs; the ECL decision point must evaluate the policy over verifiable inputs itself before admitting (AB1-006). |
| R3 (intent alignment and deferral) | `out_of_scope` | `DCMP2-018`, `TS1-009`, `ECL1N-0179`, `ECL1N-0182`, `DCMP2-053` | ECL does not evaluate accumulated intent; intent alignment stays with other tools by design. An intent-alignment or confidence result connects as a judgment input that can hold, deny or challenge an action but never admit it (ECL1N-0179, DCMP2-053), and missing context maps to an unavailable required input, which prevents an admit (ECL1N-0182). Equal-priority conflict deferral remains deployment policy. |
| R4 | `supporting_evidence_only` | `DCMP2-012`, `DCMP2-013`, `DCMP2-014`, `DCMP2-017`, `DCMP2-018`, `TS1-009` | Admit/deny map directly; challenge and hold are approximate STEP_UP/DEFER analogues with different continuation and timeout semantics. ECL has no MODIFY parameter-transformation outcome, approval router or cascading-deferral scheduler; an AARM deployment's MODIFY and deferral connect to ECL decisions through the binding profile AARM-BINDING-1 in profiles/. |
| R5 | `direct_runtime_support` | `IE1-001`, `IE1-006`, `IE1-009`, `IE1-010`, `EBMP2-002`, `EBMP2-003`, `EBMP2-022`, `TP1-001`, `TP1-002`, `TP1-003`, `TP1-004`, `TP1-005`, `TP1-006`, `TP1-007`, `TP1-008` | Deployments must supply all AARM receipt context, approvals and deferral fields, among them an accumulated-context store and the AARM five-disposition receipts, which ECL-1 does not specify. Signature validity alone does not prove execution truth or assessment independence. |
| R6 | `direct_runtime_support` | `FR-104`, `FR-105`, `FR-106`, `FR-203`, `DCMP2-006`, `DCMP2-009`, `EBMP2-003` | Human, service, agent, session and role claims need a deployment identity source, freshness and revocation checks. FR-104, FR-105 and FR-106 apply at L2 and above; FR-203 applies at L3 and above. FR-106 governs plaintext secrets and opaque handles, not identity validation. Workload attestation and automatic rotation under FR-105 remain obligations of each deployment at the applicable level. |
| R7 | `out_of_scope` | `ECL1N-0167`, `ECL1N-0168`, `ECL1N-0179` | Embedding-based and cumulative semantic drift detection, calibration and alerts are not ECL surfaces; they stay with other tools by design. A drift detector connects as a judgment input that can only make a decision stricter (ECL1N-0179), or as a declared detection whose response holds or stops the affected actions (ECL1N-0167, ECL1N-0168). |
| R8 | `direct_runtime_support` | `OE1-001`, `OE1-003`, `OE1-005`, `OE1-007` | OTEL-EVIDENCE-EXPORT-1 specifies a structured log mapping and encoding with evidence-copy and data-export constraints. Seconds-level latency, SIEM delivery and transport, filtering by action, decision and identity, and historical batching remain deployment work. This is partial normative support, not an implemented-exporter claim or satisfaction of all R8 behavior. |
| R9 | `supporting_evidence_only` | `FR-104`, `FR-105`, `FR-203` | Bounded authority and delegation attenuation do not issue just-in-time credentials. Credential provisioning, scoping and usage logging remain deployment work. FR-104 and FR-105 apply at L2 and above; FR-203 applies at L3 and above. |

Each row cites the identically named `framework_clause` in the linked packet; the packet supplies digest-bound evidence and assumptions.

## OWASP Agent Control Standard (ACS)

Edition: `v0.1.0 (source tag v0.1.2; commit authored 2026-09-09)`. Packet: [owasp-acs-core.json](../conformance/crosswalks/owasp-acs-core.json).

Source: [OWASP Agent Control Standard (ACS) source](https://raw.githubusercontent.com/GenAI-Security-Project/agent-control-standard/7743826b2ec02e3daf47a08c82170fc7a43b0838/docs/spec/conformance.md). Exact captured-source revision, digest and clause extraction are recorded in the packet assumptions.

| Clause | Support class | ECL surfaces | Residual / gap |
|---|---|---|---|
| Handshake | `out_of_scope` |  | ECL profile declaration does not implement in-band ACS ClientHello/ServerHello negotiation. The ACS-Core wire protocol is outside ECL by design and connects through the binding profile ACS-BINDING-1 in profiles/. |
| Request/response envelope | `out_of_scope` | `DCMP2-001`, `DCMP2-002` | DCMP-2 is a different wire protocol; no JSON-RPC 2.0 ACS envelope compatibility is provided. ACS messages connect to DCMP-2 decisions through the binding profile ACS-BINDING-1 in profiles/. |
| Hook taxonomy | `out_of_scope` |  | ECL does not implement the ACS lifecycle hook names, payloads or negotiated optional hooks. Hook points connect as decision or enforcement points through the binding profile ACS-BINDING-1 in profiles/. |
| Dispositions | `supporting_evidence_only` | `DCMP2-012`, `DCMP2-013`, `DCMP2-014`, `DCMP2-018` | ALLOW/DENY have admit/deny analogues; ASK/DEFER have challenge/hold analogues with different semantics. MODIFY is absent and mandatory ACS disposition fields are not supplied; ACS dispositions connect to ECL decisions through the binding profile ACS-BINDING-1 in profiles/. |
| SessionContext and Intent | `supporting_evidence_only` | `DCMP2-028`, `DCMP2-030`, `EBMP2-022`, `EBMP2-024`, `ECL1N-0178`, `ECL1N-0179`, `AC1-004`, `AC1-008`, `AC1-009` | Digest-bound causal predecessors are not an append-only ACS ContextEntry store or published rolling chain head. Context accumulation and IBAC intent evaluation remain deployment work. ECL1N-0178 classifies each input by its source and derivation: actor-controlled context is actor_supplied; intent-alignment judgments are judgment. Either class may only make an outcome stricter (ECL1N-0179). Authenticated authoritative context can be verifiable only with the declared authority, independent validation, freshness, selection, completeness and derivation controls of ECL1N-0178. ACS-BINDING-1 retains and checks native chain heads (AC1-008, AC1-009); it does not implement the context store or IBAC evaluator. |
| Replay protection | `direct_runtime_support` | `DCMP2-005`, `DCMP2-011`, `DCMP2-026`, `DCMP2-031`, `DCMP2-032`, `DCMP2-040`, `FR-104` | ECL request identity, retry and expiry semantics support replay control; ACS UUID/timestamp wire fields and Guardian replay rules still need a dedicated adapter and deployment checks. |
| Baseline integrity | `supporting_evidence_only` | `IE1-001`, `IE1-006`, `IE1-009`, `IE1-010`, `TP1-001` | ECL asymmetric envelopes use a different mechanism from ACS-Core per-session HKDF/HMAC-SHA256. They do not implement that HMAC wire requirement; no blanket strength ranking is inferred. |
| Decision honoring | `out_of_scope` | `TS1-018`, `SF1-001`, `SF1-002`, `DCMP2-040`, `AC1-006` | ACS-Core's default-proceed posture on decision failure conflicts with ECL's requirement to fail closed when required proof is missing or invalid. ACS permits a different configured posture; a deployment claiming ACS-BINDING-1 must negotiate deny and configure startup refuse under AC1-006. This stricter binding does not provide the complete ACS decision-honoring implementation. This row is not a gap to implement by allowing fail-open. |
| Liveness | `out_of_scope` | `AC1-006` | No ACS system/ping method is specified or implemented, and ACS-BINDING-1 maps none: ECL-1 relies on the decision timeout, after which a Guardian that has not answered is a decision failure that releases nothing (AC1-006). |
| Wrapped MCP | `out_of_scope` |  | No protocols/MCP ACS wrapper is specified or implemented. An MCP tool gateway connects under the binding profile MCP-GATEWAY-1, and the ACS wrapper under ACS-BINDING-1, both in profiles/. |

Each row cites the identically named `framework_clause` in the linked packet; the packet supplies digest-bound evidence and assumptions.

## Outside ECL-1 by design, and how each connects

ECL-1 standardizes the decision, authority, enforcement and evidence around each consequential action. The mapped clauses that ask for other functions stay with other tools by design. Each item below says how such a tool connects to an ECL-1 deployment; Section 2.10 of the [core](../standard/ECL-1_Standard.md) lists the same functions.

- AARM R2, AARM R3 (intent alignment and deferral) and ACS SessionContext and Intent: session context, accumulated classification and intent evaluation connect as decision inputs that the register classifies (ECL1N-0178). A judgment can hold, deny or challenge an action and is never the basis of an admit (ECL1N-0179, DCMP2-053); missing context prevents an admit when the register declares it required (ECL1N-0182).
- AARM R7: semantic drift detection connects as a judgment input, or as a declared detection whose response holds or stops the affected actions (ECL1N-0167, ECL1N-0168).
- AARM R8 and telemetry: SIEM and observability tools consume exported ECL evidence through the profile `OTEL-EVIDENCE-EXPORT-1`.
- AARM R4 and the ACS dispositions, including MODIFY, connect through the binding profiles `AARM-BINDING-1` and `ACS-BINDING-1`. The ACS-Core wire protocol (handshake, JSON-RPC envelope and hook taxonomy) connects through `ACS-BINDING-1`; wrapped MCP connects through `ACS-BINDING-1`, and an MCP tool gateway through `MCP-GATEWAY-1`. No ACS liveness method is mapped: ECL-1 relies on the decision timeout of `ACS-BINDING-1` (AC1-006).
- The ACS-Core default of proceeding when its Guardian cannot answer conflicts with ECL's required-proof failure rule. ACS permits a stricter posture; ACS-BINDING-1 requires negotiated `deny` and startup `refuse` (AC1-006). This difference is not a gap to implement by allowing fail-open.

The binding profiles named here are defined in `profiles/`. Naming them says how a function connects; it does not claim AARM or ACS conformance or endorsement by their owners.

## ECL obligations outside these mapped clauses

Relative to the listed editions and Core clauses, ECL separately specifies halt and timing classes, assessment-independence classes, a fail-closed proof floor, offline black-box evidence checking and claim discipline. These are additional ECL obligations, not a claim that another framework or its optional profiles never address them. See [timing](../protocols/TIMING-SAFE-STATE-1.md), [evidence](../protocols/EBMP-2.md), [trust policy](../profiles/TRUST-POLICY-1.md) and the [core](../standard/ECL-1_Standard.md). Class B requires both control approval and evidence verification in a separately administered trust domain (ECL1N-0143).

## Source digest reproduction

Use the pinned raw-source URLs in each packet. Hash the raw UTF-8 LF bytes without trimming or rewrapping. AARM clause ranges start at `### Rn:` and end before the next heading of level 1–3; both R3 rows bind that same range. ACS ranges are the ten exact Core bullets, each including its terminating LF. This makes an upstream source change detectable without copying the upstream requirements into this repository. The public AARM page https://aarm.dev/conformance is a reader link that words the requirements differently; it carries no digest.
