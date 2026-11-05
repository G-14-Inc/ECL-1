# Control-gap coverage in ECL-1

This annex shows, for each of the 13 control gaps of the Control Gap Classification, which requirements of ECL-1 address it and at which conformance level, which requirements of the binding profiles address it for an implementation that claims them, how an assessor and a machine check test it, which entries of the Control Gap Record showed it, and what the text leaves open. It describes the text of ECL-1 `1.0`. It is not a conformance claim or an assessment.

Gap definitions are from the Control Gap Classification, version 0.2, © 2026 G-14, Inc., https://externalcontrollayer.ai/classification, licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). The definitions of G5, G6, G8, G10 and G12 are adapted: their two sentences are joined into one, or the first sentence is kept. Incident entries are from the Control Gap Record, version 0.2, © 2026 G-14, Inc., https://externalcontrollayer.ai, licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/); an entry is listed under a gap when the record codes that gap for it.

This file is generated from `registries/gap-coverage.json` and the compiled requirement registry, and is not edited by hand.

## Summary

| Gap | Requirements | Lowest level | Profile requirements | Checklist items | Machine checks | Record entries |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| [G1 Instruction-only limit](#g1-instruction-only-limit) | 6 | L1 | 2 | 4 | 2 | 5 |
| [G2 Direct access](#g2-direct-access) | 6 | L1 | 3 | 4 | 0 | 11 |
| [G3 Unchecked statement](#g3-unchecked-statement) | 2 | L1 | 0 | 1 | 0 | 5 |
| [G4 Boundary not enforced](#g4-boundary-not-enforced) | 9 | L1 | 6 | 4 | 0 | 7 |
| [G5 Blind to the total](#g5-blind-to-the-total) | 3 | L1 | 0 | 2 | 1 | 7 |
| [G6 No independent evidence](#g6-no-independent-evidence) | 9 | L1 | 5 | 6 | 2 | 7 |
| [G7 Review in name only](#g7-review-in-name-only) | 4 | L1 | 0 | 3 | 1 | 9 |
| [G8 No human decision](#g8-no-human-decision) | 3 | L1 | 2 | 2 | 0 | 5 |
| [G9 Warning with no authority](#g9-warning-with-no-authority) | 4 | L1 | 0 | 3 | 0 | 9 |
| [G10 No independent stop](#g10-no-independent-stop) | 4 | L1 | 0 | 2 | 1 | 3 |
| [G11 Safeguard off](#g11-safeguard-off) | 3 | L1 | 1 | 2 | 1 | 8 |
| [G12 Unreviewed change](#g12-unreviewed-change) | 4 | L1 | 2 | 2 | 2 | 8 |
| [G13 Self-reported record](#g13-self-reported-record) | 24 | L1 | 4 | 9 | 3 | 2 |

## G1 Instruction-only limit

Definition: The rule that should have stopped the action existed only as an instruction, prompt, or trained behavior of the AI system, so it held only as long as the system followed it.

| Requirement | Level | Summary |
| --- | --- | --- |
| ECL1N-0033 | L1 | Every consequential action listed as in scope in the Consequential Action Register MUST traverse the Enforcement Layer before external effect. |
| ECL1N-0036 | L1 | The Enforcement Layer MUST apply the resulting control outcome before execution. |
| ECL1N-0046 | L1 | A system where the governed AI system can rewrite, disable, or bypass enforcement logic MUST NOT be treated as conformant. |
| ECL1N-0179 | L1 | An `actor_supplied` or `judgment` input MUST NOT be the basis of an `admit`. |
| ECL1N-0180 | L1 | An `admit` MUST be justified by policy evaluated over `verifiable` inputs alone: its verifiable-only outcome is `admit`, and its authorization is that outcome's… |
| FR-001 | L1 | The ECL control plane MUST be architecturally independent of the governed AI system. |

Binding profiles. These requirements apply only to an implementation that claims the profile:

| Requirement | Profile | Summary |
| --- | --- | --- |
| AB1-010 | AARM-BINDING-1 | An AARM interception point (a protocol gateway, SDK instrumentation, a kernel eBPF hook or a vendor integration) MUST NOT be claimed as an ECL enforcement point… |
| AC1-002 | ACS-BINDING-1 | An ACS hook point MUST NOT be claimed as an ECL enforcement point unless the governed AI system can neither bypass it, disable it nor change the decision it… |

Checklist items: EA-22 (L1), EA-25 (L1), IA-01 (L1), EA-04 (L2).

Machine checks:

- `ecl.rule.decision-basis-one-way.v1`: a response that records its decision basis lists each input once, input names compared after the case normalization of RFC 3986 section 6.2.2.1 and RFC 8141 section 3.1; cites no actor_supplied or judgment input, and no input that was not available or was computed from one that was not, as supporting it; records no input computed from an input that is not verifiable as verifiable; and has no input computed from itself, directly or through other inputs. An admit cites at least one verifiable input as supporting it and no required input that was not available or was computed from one that was not. The outcome is no less strict than a recorded verifiable-only outcome; while that outcome is not admit, no input supports the outcome, and when it is admit, a verifiable input supports it and no required verifiable input was not available. No input obtained after the decision is recorded as available, and no value describes a time after the decision or after the input was obtained; a record that gives when an input was obtained gives when the request was received, no later than the decision, and a record that gives when the request was received gives both times of each available input. A verifier that holds the request refuses an input recorded as verifiable whose source is the request's actor, and a request received before it was issued. Each decision response that an AARM, ACS or MCP exchange record holds carries exactly one decision basis and is checked with the request the record holds.
- `ecl.rule.non-admit-prohibits-authority.v1`: deny, hold, and challenge outcomes do not issue executable authority.

Record entries that showed this gap (5): [Record 14: Chevrolet dealer, 2023](https://externalcontrollayer.ai/record-14), [Record 17: OpenAI Operator, 2025](https://externalcontrollayer.ai/record-17), [Record 22: Replit, 2025](https://externalcontrollayer.ai/record-22), [Record 25: OpenClaw, 2026](https://externalcontrollayer.ai/record-25), [Record 28: UK AISI cyber range, 2026](https://externalcontrollayer.ai/record-28).

Left open: Whether the enforcement point is in fact out of the AI system's reach is a property of the deployment. An assessor establishes it from the enumerated effect paths and interception tests (ECL1N-0039 with checklist item EA-25 at every level) and, from L2, the assessor's own negative tests (FR-101 with checklist item EA-04); no single artifact can show it.

## G2 Direct access

Definition: The system held the credentials or connection to carry out the action itself, so nothing outside it stood between its decision and the effect.

| Requirement | Level | Summary |
| --- | --- | --- |
| ECL1N-0008 | L1 | For `full-system-mediation` and `bounded-action-class-mediation` claims, the Consequential Action Register MUST be validated against the actual runtime… |
| ECL1N-0033 | L1 | Every consequential action listed as in scope in the Consequential Action Register MUST traverse the Enforcement Layer before external effect. |
| ECL1N-0039 | L1 | Evidence of complete mediation is always bounded by the declared path- enumeration method, exercised negative tests, and the reachable capability inventory… |
| ECL1N-0141 | L1 | A conformant implementation MUST NOT provide an undisclosed bypass path around the Enforcement Layer for in-scope actions, and MUST NOT suppress the required… |
| FR-101 | L2 | In addition to ECL1N-0033, ECL1N-0039, and ECL1N-0141, which apply at every level, a no-bypass claim MUST be supported by negative testing of the enforcement… |
| FR-106 | L2 | Plaintext secrets MUST NOT be exposed in agent reasoning context. |

Binding profiles. These requirements apply only to an implementation that claims the profile:

| Requirement | Profile | Summary |
| --- | --- | --- |
| AB1-012 | AARM-BINDING-1 | A credential that an AARM deployment issues for an admitted action under R9 MUST NOT carry more authority than the action's ECL authorization: no wider scope… |
| MG1-009 | MCP-GATEWAY-1 | The governed AI system MUST NOT hold a credential, token, key or connection that reaches an in-scope server or a system that one of its tools reaches; the… |
| OA1-004 | OAUTH-AUTHORITY-1 | The token MUST be sender-constrained, with `cnf.jkt` (RFC 9449) or the `cnf` member `x5t#S256` (RFC 8705), to a key held by the component that presents it and… |

Checklist items: BC-01 (L1), EA-25 (L1), EA-04 (L2), EA-07 (L2).

Machine checks: none for the core requirements. An assessor checks them, as described under what is left open.

Machine checks of the binding profiles, applied to the records they define:

- `ecl.rule.oauth-token-expresses-admit.v1`: an access token is issued only for a verified admit, and its ECL authorization_details entry, audience, validity, subject, actor and confirmation key express that admit.
- `ecl.rule.oauth-presentation-checked.v1`: a resource server accepts a presentation only for its own audience, within the token's validity with the declared clock-skew allowance and within its entry's window, with a valid proof of possession, for the entry's target, operation and parameter digest, and within its uses.

Record entries that showed this gap (11): [Record 1: Knight Capital, 2012](https://externalcontrollayer.ai/record-1), [Record 17: OpenAI Operator, 2025](https://externalcontrollayer.ai/record-17), [Record 21: Amazon Q Developer, 2025](https://externalcontrollayer.ai/record-21), [Record 22: Replit, 2025](https://externalcontrollayer.ai/record-22), [Record 23: postmark-mcp, 2025](https://externalcontrollayer.ai/record-23), [Record 24: Google Antigravity, 2025](https://externalcontrollayer.ai/record-24), [Record 25: OpenClaw, 2026](https://externalcontrollayer.ai/record-25), [Record 26: Irregular's test environments, 2026](https://externalcontrollayer.ai/record-26), [Record 27: OpenAI–Hugging Face, 2026](https://externalcontrollayer.ai/record-27), [Record 28: UK AISI cyber range, 2026](https://externalcontrollayer.ai/record-28), [Record 29: OpenAI DNS escape, 2026](https://externalcontrollayer.ai/record-29).

Left open: Whether the AI system holds a credential that reaches a target directly is a property of the deployment that no message shows. At L1 the register is reconciled with the reachable capability inventory (ECL1N-0008), and each point of effect is called directly with every credential the AI system holds or can obtain through its tools (checklist item EA-25); the assessor's own negative tests and keeping secrets out of the AI system's context start at L2 (FR-101, FR-106).

## G3 Unchecked statement

Definition: Words the system produced reached customers or the public in the organization's name, on matters people rely on such as prices, policy, law, or health, and nothing checked them first.

| Requirement | Level | Summary |
| --- | --- | --- |
| ECL1N-0017 | L1 | A conversational or language-mediated system MUST be treated as in scope when its output can: 1. disclose non-public data; 2. trigger, queue, parameterize, or… |
| ECL1N-0163 | L1 | When output that a conversational system sends in the organization's name can state a price, term, policy, eligibility, legal, or health matter on which a… |

Checklist items: BC-03 (L1).

Machine checks: none. An assessor checks this gap, as described under what is left open.

Record entries that showed this gap (5): [Record 10: Air Canada, 2022–2024](https://externalcontrollayer.ai/record-10), [Record 12: NEDA's Tessa, 2023](https://externalcontrollayer.ai/record-12), [Record 14: Chevrolet dealer, 2023](https://externalcontrollayer.ai/record-14), [Record 15: NYC MyCity, 2024–2026](https://externalcontrollayer.ai/record-15), [Record 18: Cursor, 2025](https://externalcontrollayer.ai/record-18).

Left open: ECL-1 requires that such a statement be compared with approved reference content, or approved by a person, before it is sent. The accuracy and coverage of the approved content remain the organization's responsibility, and no machine check of the comparison is defined.

## G4 Boundary not enforced

Definition: The action reached systems, data, or operating conditions outside those the system was built or approved for, and nothing enforced that boundary when it acted.

| Requirement | Level | Summary |
| --- | --- | --- |
| ECL1N-0007 | L1 | Each claim MUST publish a Consequential Action Register containing: - action class identifier; - classification decision (`consequential` or… |
| ECL1N-0008 | L1 | For `full-system-mediation` and `bounded-action-class-mediation` claims, the Consequential Action Register MUST be validated against the actual runtime… |
| ECL1N-0043 | L1 | The Enforcement Layer MUST: - intercept all in-scope consequential actions before execution; - apply Decision and Authority outcomes without silent fallback; -… |
| ECL1N-0186 | L1 | Before an action crosses its release boundary, the enforcement point MUST have established, for that action and at that boundary: 1. that what it releases is… |
| ECL1N-0187 | L1 | Required proof for a release that is missing, of a kind that the enforcement point does not support, stale, failed, or bound to another action, request… |
| ECL1N-0188 | L1 | A timestamp used to show that an action was released while its authority was valid MUST describe the release boundary under the observation mechanism and clock… |
| FR-003 | L1 | Enforcement MUST fail closed when policy, identity proof, contract validation, integrity checks, or evidence preconditions are missing or invalid. |
| FR-006 | L1 | The deployment MUST maintain a Consequential Action Register with classification rationale, affected resources, data classes, and enforcement class for every… |
| FR-007 | L1 | Every claim MUST declare a claim class, explicit SoI boundary, and Negative Boundary Annex listing excluded effect channels and shared surfaces. |

Binding profiles. These requirements apply only to an implementation that claims the profile:

| Requirement | Profile | Summary |
| --- | --- | --- |
| AC1-003 | ACS-BINDING-1 | A Guardian decision MUST reach an ECL enforcement point only through a DCMP-2 decision response that an ECL decision point issues and signs for the exact… |
| MG1-001 | MCP-GATEWAY-1 | A claim of this profile MUST identify the MCP revision its gateway implements by the revision and digests that this profile pins, every in-scope MCP server, and… |
| MG1-002 | MCP-GATEWAY-1 | The gateway MUST treat as side-effecting, and send to the Decision Layer before forwarding, every `tools/call` request (including a retry that carries… |
| MG1-005 | MCP-GATEWAY-1 | The gateway MUST forward a side-effecting request only after it has verified a DCMP-2 `admit` for exactly that request under DCMP2-HTTP-1 and the claim's trust… |
| MG1-007 | MCP-GATEWAY-1 | When the decision service cannot be reached, does not answer within the declared total timeout, or answers with anything other than a verified decision response… |
| OA1-005 | OAUTH-AUTHORITY-1 | A resource server or enforcement point MUST accept the token only for a request whose target, operation and parameter digest equal the `identifier`, the… |

Checklist items: BC-01 (L1), BC-02 (L1), EA-01 (L1), EA-27 (L1).

Machine checks: none for the core requirements. An assessor checks them, as described under what is left open.

Machine checks of the binding profiles, applied to the records they define:

- `ecl.rule.decision-basis-one-way.v1`: a response that records its decision basis lists each input once, input names compared after the case normalization of RFC 3986 section 6.2.2.1 and RFC 8141 section 3.1; cites no actor_supplied or judgment input, and no input that was not available or was computed from one that was not, as supporting it; records no input computed from an input that is not verifiable as verifiable; and has no input computed from itself, directly or through other inputs. An admit cites at least one verifiable input as supporting it and no required input that was not available or was computed from one that was not. The outcome is no less strict than a recorded verifiable-only outcome; while that outcome is not admit, no input supports the outcome, and when it is admit, a verifiable input supports it and no required verifiable input was not available. No input obtained after the decision is recorded as available, and no value describes a time after the decision or after the input was obtained; a record that gives when an input was obtained gives when the request was received, no later than the decision, and a record that gives when the request was received gives both times of each available input. A verifier that holds the request refuses an input recorded as verifiable whose source is the request's actor, and a request received before it was issued. Each decision response that an AARM, ACS or MCP exchange record holds carries exactly one decision basis and is checked with the request the record holds.
- `ecl.rule.acs-release-requires-admit.v1`: an action released at an ACS hook point has a DCMP-2 admit bound to the exact request, and is released within the authorization's window with the admitted parameters.
- `ecl.rule.mcp-decision-failure-not-forwarded.v1`: an MCP gateway that asked for a decision forwards nothing when the decision service is unavailable or answers with no verified decision.
- `ecl.rule.mcp-tool-mapped-and-reviewed.v1`: an MCP gateway forwards only a request whose method is mapped, a call only to a mapped tool, and only when the tool's definition and server identity are those the mapping reviewed.
- `ecl.rule.mcp-forward-requires-admit.v1`: an MCP gateway forwards a request only on a verified admit bound to its decision request, within the authorization's window and uses, at a final observation that the release guard places before the window's end and that the release event records, with a send that completed before the window's end, and forwards exactly the call that the admitted request binds: its method, tool, arguments, input responses and request state, a params object with the digest that the admitted request carries, and no member added or removed.
- `ecl.rule.oauth-presentation-checked.v1`: a resource server accepts a presentation only for its own audience, within the token's validity with the declared clock-skew allowance and within its entry's window, with a valid proof of possession, for the entry's target, operation and parameter digest, and within its uses.

Record entries that showed this gap (7): [Record 3: Tesla Autopilot, 2016](https://externalcontrollayer.ai/record-3), [Record 22: Replit, 2025](https://externalcontrollayer.ai/record-22), [Record 24: Google Antigravity, 2025](https://externalcontrollayer.ai/record-24), [Record 26: Irregular's test environments, 2026](https://externalcontrollayer.ai/record-26), [Record 27: OpenAI–Hugging Face, 2026](https://externalcontrollayer.ai/record-27), [Record 28: UK AISI cyber range, 2026](https://externalcontrollayer.ai/record-28), [Record 29: OpenAI DNS escape, 2026](https://externalcontrollayer.ai/record-29).

Left open: Inside the claim boundary, actions are mediated and fail closed. A path that the claim excludes is disclosed in the Negative Boundary Annex rather than blocked (ECL1N-0010, ECL1N-0038), so the boundary a reader relies on is the declared one. An enforcement point establishes the authority's validity and use, the control state and every before-release obligation at the release boundary itself (ECL1N-0186 to ECL1N-0188); where the effect takes place later and elsewhere, that check does not show that the authority was still valid when the effect occurred.

## G5 Blind to the total

Definition: Each action was allowed one at a time, and nothing tracked what the actions added up to in volume, rate, exposure, or repetition until the total did the harm.

| Requirement | Level | Summary |
| --- | --- | --- |
| DCMP2-052 | L1 | An `admit` response MUST NOT carry, in `ecl.ext.consequence-coupling.v1`, a `budget_result` whose outcome is not `authorized`, a `witness_result` whose outcome… |
| ECL1N-0172 | L1 | For each in-scope action class, the Consequential Action Register MUST state the largest aggregate effect that the SoI could cause through that class in one… |
| ECL1N-0173 | L2 | For `L2` and above, each in-scope action class with financial, legal, data-disclosure, communication, identity, infrastructure, or physical consequence MUST be… |

Checklist items: EA-13 (L1), EA-14 (L2).

Machine checks:

- `ecl.rule.coupling-results-permit-admit.v1`: an admit response carries only permitting consequence-coupling results: budget authorized, witness satisfied, quorum met, and no blocker reason.

Record entries that showed this gap (7): [Record 1: Knight Capital, 2012](https://externalcontrollayer.ai/record-1), [Record 6: Boeing 737 MAX, 2018–2019](https://externalcontrollayer.ai/record-6), [Record 7: Rite Aid, 2012–2020](https://externalcontrollayer.ai/record-7), [Record 9: Zillow Offers, 2021](https://externalcontrollayer.ai/record-9), [Record 25: OpenClaw, 2026](https://externalcontrollayer.ai/record-25), [Record 27: OpenAI–Hugging Face, 2026](https://externalcontrollayer.ai/record-27), [Record 28: UK AISI cyber range, 2026](https://externalcontrollayer.ai/record-28).

Left open: At L1 the register states each action class's largest hourly and daily aggregate effect, and no budget is required. Budgets that count every session, workflow and instance start at L2, for the consequence classes that ECL1N-0173 names. A single message shows only that an admit carried an exhausted budget; counting across sessions is checked by an assessor.

## G6 No independent evidence

Definition: The action, or the approval of it, was based on the system's own output or on a single unverified input, and evidence that would have shown the error was never gathered, was thrown away, or was available and not consulted.

| Requirement | Level | Summary |
| --- | --- | --- |
| DCMP2-052 | L1 | An `admit` response MUST NOT carry, in `ecl.ext.consequence-coupling.v1`, a `budget_result` whose outcome is not `authorized`, a `witness_result` whose outcome… |
| DCMP2-053 | L1 | A response that carries `ecl.ext.decision-basis.v1` MUST NOT list one `input` more than once, MUST NOT record an `actor_supplied` or `judgment` input, or an… |
| ECL1N-0164 | L1 | For each in-scope action class, the Consequential Action Register MUST state each decision input's source and class, distinguishing actor-controlled assertions… |
| ECL1N-0178 | L1 | For each in-scope action class, the Consequential Action Register MUST declare, for each decision input that ECL1N-0164 requires it to state, its class as… |
| ECL1N-0179 | L1 | An `actor_supplied` or `judgment` input MUST NOT be the basis of an `admit`. |
| ECL1N-0180 | L1 | An `admit` MUST be justified by policy evaluated over `verifiable` inputs alone: its verifiable-only outcome is `admit`, and its authorization is that outcome's… |
| ECL1N-0181 | L1 | The evidence of each decision MUST identify, by reference and digest, the version of the Consequential Action Register under which the decision was made, and… |
| ECL1N-0187 | L1 | Required proof for a release that is missing, of a kind that the enforcement point does not support, stale, failed, or bound to another action, request… |
| ECL1N-0165 | L2 | For `L2` and above, a decision to admit an action of a class with financial, legal, identity, infrastructure, or physical consequence MUST rest on at least one… |

Binding profiles. These requirements apply only to an implementation that claims the profile:

| Requirement | Profile | Summary |
| --- | --- | --- |
| AB1-003 | AARM-BINDING-1 | The ECL outcome for an action that an AARM decision governs MUST be at least as strict, in the strictness order of the core standard (Section 4.3), as the… |
| AB1-006 | AARM-BINDING-1 | The outputs of AARM R2 (context accumulation, including the data classifications it records), R3 (policy evaluation with intent alignment, including any… |
| AB1-013 | AARM-BINDING-1 | The `inputs` of an exchange record MUST be the entries of the decision basis that its `response` records in `ecl.ext.decision-basis.v1`: each input of the… |
| AC1-004 | ACS-BINDING-1 | The ECL outcome for an action that a Guardian decision governs MUST be at least as strict, in the strictness order of the core standard (Section 4.3), as the… |
| AC1-012 | ACS-BINDING-1 | When an exchange record holds a `response`, the record's `inputs` MUST be the entries of the decision basis that the response records in… |

Checklist items: EA-15 (L1), EA-21 (L1), EA-22 (L1), EA-23 (L1), EA-27 (L1), EA-16 (L2).

Machine checks:

- `ecl.rule.decision-basis-one-way.v1`: a response that records its decision basis lists each input once, input names compared after the case normalization of RFC 3986 section 6.2.2.1 and RFC 8141 section 3.1; cites no actor_supplied or judgment input, and no input that was not available or was computed from one that was not, as supporting it; records no input computed from an input that is not verifiable as verifiable; and has no input computed from itself, directly or through other inputs. An admit cites at least one verifiable input as supporting it and no required input that was not available or was computed from one that was not. The outcome is no less strict than a recorded verifiable-only outcome; while that outcome is not admit, no input supports the outcome, and when it is admit, a verifiable input supports it and no required verifiable input was not available. No input obtained after the decision is recorded as available, and no value describes a time after the decision or after the input was obtained; a record that gives when an input was obtained gives when the request was received, no later than the decision, and a record that gives when the request was received gives both times of each available input. A verifier that holds the request refuses an input recorded as verifiable whose source is the request's actor, and a request received before it was issued. Each decision response that an AARM, ACS or MCP exchange record holds carries exactly one decision basis and is checked with the request the record holds.
- `ecl.rule.coupling-results-permit-admit.v1`: an admit response carries only permitting consequence-coupling results: budget authorized, witness satisfied, quorum met, and no blocker reason.

Machine checks of the binding profiles, applied to the records they define:

- `ecl.rule.decision-basis-one-way.v1`: a response that records its decision basis lists each input once, input names compared after the case normalization of RFC 3986 section 6.2.2.1 and RFC 8141 section 3.1; cites no actor_supplied or judgment input, and no input that was not available or was computed from one that was not, as supporting it; records no input computed from an input that is not verifiable as verifiable; and has no input computed from itself, directly or through other inputs. An admit cites at least one verifiable input as supporting it and no required input that was not available or was computed from one that was not. The outcome is no less strict than a recorded verifiable-only outcome; while that outcome is not admit, no input supports the outcome, and when it is admit, a verifiable input supports it and no required verifiable input was not available. No input obtained after the decision is recorded as available, and no value describes a time after the decision or after the input was obtained; a record that gives when an input was obtained gives when the request was received, no later than the decision, and a record that gives when the request was received gives both times of each available input. A verifier that holds the request refuses an input recorded as verifiable whose source is the request's actor, and a request received before it was issued. Each decision response that an AARM, ACS or MCP exchange record holds carries exactly one decision basis and is checked with the request the record holds.
- `ecl.rule.aarm-judgment-inputs.v1`: AARM R2, R3 and R7 outputs, and every AARM output in the judgment-source role, are judgment inputs in every decision basis that the record holds, the modification response's included; the judgment-source role lists the AARM decision exactly once as an R4 input; and an admit rests on verifiable inputs only.
- `ecl.rule.aarm-outcome-no-weaker.v1`: the ECL outcome is no weaker than the outcome the AARM decision maps to.
- `ecl.rule.aarm-inputs-match-basis.v1`: the inputs of an AARM exchange record are the entries of the decision basis that its decision response records in ecl.ext.decision-basis.v1, each once and equal to its entry apart from the AARM requirement it names; the decision basis of the modification response carries the same register reference, member for member, and records the same inputs with the same declarations.
- `ecl.rule.acs-judgment-guardian.v1`: a Guardian decision from an agent or composite evaluator, or from an evaluator that is not stated, is a judgment input; a deterministic Guardian decision that a hook point carried to the decision point is actor_supplied; any other takes the least trusted class of the inputs its request carried and is verifiable only when the record names them; the Guardian decision has that class in every decision basis that the record holds, the modification response's included; a response that records the Guardian decision has exactly one input marked as it; and an admit rests on verifiable inputs only.
- `ecl.rule.acs-outcome-no-weaker.v1`: the ECL outcome is no weaker than the outcome the Guardian's disposition maps to.
- `ecl.rule.acs-inputs-match-basis.v1`: the inputs of an ACS exchange record that holds a decision response are the entries of the decision basis that the response records in ecl.ext.decision-basis.v1, each once and equal to its entry apart from the Guardian marker; the decision basis of the modification response carries the same register reference, member for member, and records the same inputs with the same declarations.

Record entries that showed this gap (7): [Record 2: Michigan MiDAS, 2013–2015](https://externalcontrollayer.ai/record-2), [Record 4: Robodebt, Australia, 2016–2019](https://externalcontrollayer.ai/record-4), [Record 6: Boeing 737 MAX, 2018–2019](https://externalcontrollayer.ai/record-6), [Record 8: Detroit Police, 2020](https://externalcontrollayer.ai/record-8), [Record 11: Mata v. Avianca, 2023](https://externalcontrollayer.ai/record-11), [Record 16: Whisper in clinics, 2024](https://externalcontrollayer.ai/record-16), [Record 20: Deloitte Australia, 2025](https://externalcontrollayer.ai/record-20).

Left open: At every level, no admit rests on the AI system's own output or on a model's judgment. An input from a system of record, an independent state witness or an authenticated external party is required from L2, for the consequence classes that ECL1N-0165 names. The machine check reads the recorded basis of a decision; an assessor checks the record against the register (EA-23). A state witness that a decision defers to enforcement is satisfied only by proof that the enforcement point checks before the release, never by the signed admit alone (ECL1N-0187).

## G7 Review in name only

Definition: A person was supposed to catch the error but lacked the information, time, training, or practical means to do it, so the review did not work as a check.

| Requirement | Level | Summary |
| --- | --- | --- |
| EBMP2-063 | L1 | A human intervention event that approves or rejects and carries `ecl.ext.approval-record.v1` MUST have an `issued_at` no earlier than `presented_at` plus… |
| ECL1N-0174 | L1 | When a person approves or rejects a consequential action, the approval MUST be made on a human-readable presentation of its operation, target, every parameter… |
| ECL1N-0175 | L2 | For `L2` and above, a claim MUST declare a minimum review time for each action class that requires approval, and an approval recorded sooner than that time… |
| ECL1N-0176 | L3 | For `L3` and above, the claimant MUST measure, for each approver and action class, the approval rate and the review times, and MUST treat a declared anomaly… |

Checklist items: EA-17 (L1), EA-18 (L2), EA-19 (L3).

Machine checks:

- `ecl.rule.approval-review-time-respected.v1`: a human approval or rejection that records its presentation is decided no sooner than the minimum review time after that presentation.

Record entries that showed this gap (9): [Record 3: Tesla Autopilot, 2016](https://externalcontrollayer.ai/record-3), [Record 5: Uber ATG, Tempe, 2018](https://externalcontrollayer.ai/record-5), [Record 6: Boeing 737 MAX, 2018–2019](https://externalcontrollayer.ai/record-6), [Record 7: Rite Aid, 2012–2020](https://externalcontrollayer.ai/record-7), [Record 8: Detroit Police, 2020](https://externalcontrollayer.ai/record-8), [Record 11: Mata v. Avianca, 2023](https://externalcontrollayer.ai/record-11), [Record 16: Whisper in clinics, 2024](https://externalcontrollayer.ai/record-16), [Record 20: Deloitte Australia, 2025](https://externalcontrollayer.ai/record-20), [Record 27: OpenAI–Hugging Face, 2026](https://externalcontrollayer.ai/record-27).

Left open: The text fixes what the approver is shown, a minimum review time from L2, and monitoring of approval rates and review times from L3. Whether an approver understood what was shown cannot be read from a record.

## G8 No human decision

Definition: A decision that needed a person went through without one; the need can come from law, from policy, from the product's own design, or from the user's explicit instruction.

| Requirement | Level | Summary |
| --- | --- | --- |
| ECL1N-0007 | L1 | Each claim MUST publish a Consequential Action Register containing: - action class identifier; - classification decision (`consequential` or… |
| ECL1N-0177 | L1 | When the Consequential Action Register declares a human-approval threshold for an action class (ECL1N-0007), the Decision Layer MUST NOT return `admit` for an… |
| FR-109 | L2 | Human-in-the-loop workflows MUST be available for actions above configured risk thresholds. |

Binding profiles. These requirements apply only to an implementation that claims the profile:

| Requirement | Profile | Summary |
| --- | --- | --- |
| AB1-005 | AARM-BINDING-1 | A `hold` or `challenge` mapped from DEFER or STEP_UP MUST carry an `expires_at` no later than the deadline of the deferral or approval, and a `safe_state` under… |
| AC1-007 | ACS-BINDING-1 | The expiry of an `ask` or a `defer` MUST NOT release an in-scope action, even when the `ask` declares a `timeout_disposition` of `allow` or the `defer` a… |

Checklist items: EA-20 (L1), EA-08 (L2).

Machine checks: none for the core requirements. An assessor checks them, as described under what is left open.

Machine checks of the binding profiles, applied to the records they define:

- `ecl.rule.aarm-deferral-no-release.v1`: a hold or challenge mapped from DEFER or STEP_UP expires no later than the AARM deadline, into a safe state that permits no new effect.
- `ecl.rule.acs-expiry-no-release.v1`: the ECL response to an ask or defer expires no later than the Guardian's deadline, into a safe state that permits no new effect, and nothing is released after it expires.

Record entries that showed this gap (5): [Record 2: Michigan MiDAS, 2013–2015](https://externalcontrollayer.ai/record-2), [Record 4: Robodebt, Australia, 2016–2019](https://externalcontrollayer.ai/record-4), [Record 17: OpenAI Operator, 2025](https://externalcontrollayer.ai/record-17), [Record 22: Replit, 2025](https://externalcontrollayer.ai/record-22), [Record 25: OpenClaw, 2026](https://externalcontrollayer.ai/record-25).

Left open: An action is held until a person approves it when the register declares an approval threshold for its class. Which actions need a person, under law, policy or the user's instruction, is for the claimant to declare in the register.

## G9 Warning with no authority

Definition: Signs that the action was wrong existed before or during the harm, but none of them could stop or hold the action, and nothing required anyone to act on them.

| Requirement | Level | Summary |
| --- | --- | --- |
| ECL1N-0052 | L1 | The Verification Layer MUST: - monitor enforcement and policy integrity; - detect drift between approved and active control state; - export reviewable evidence… |
| ECL1N-0167 | L1 | A claim MUST declare the detections that indicate that the SoI may be acting wrongly, including verification findings, monitoring alerts, anomaly signals, and… |
| ECL1N-0168 | L2 | For `L2` and above, a declared detection MUST bring its response into effect at the Decision Layer without any person's action and within the connected… |
| FR-111 | L2 | Critical verification failures, integrity drift affecting enforcement, or emergency control-plane activation MUST trigger pre-declared response behavior within… |

Checklist items: VF-06 (L1), VF-02 (L2), VF-07 (L2).

Machine checks: none. An assessor checks this gap, as described under what is left open.

Record entries that showed this gap (9): [Record 1: Knight Capital, 2012](https://externalcontrollayer.ai/record-1), [Record 4: Robodebt, Australia, 2016–2019](https://externalcontrollayer.ai/record-4), [Record 5: Uber ATG, Tempe, 2018](https://externalcontrollayer.ai/record-5), [Record 7: Rite Aid, 2012–2020](https://externalcontrollayer.ai/record-7), [Record 8: Detroit Police, 2020](https://externalcontrollayer.ai/record-8), [Record 11: Mata v. Avianca, 2023](https://externalcontrollayer.ai/record-11), [Record 15: NYC MyCity, 2024–2026](https://externalcontrollayer.ai/record-15), [Record 27: OpenAI–Hugging Face, 2026](https://externalcontrollayer.ai/record-27), [Record 28: UK AISI cyber range, 2026](https://externalcontrollayer.ai/record-28).

Left open: At L1 each declared detection has a declared response, which may still wait for a person. From L2 the response takes effect at the Decision Layer without a person's action, within the declared bound. The connection between detections and decisions is checked by negative tests, not by one artifact.

## G10 No independent stop

Definition: Nothing could stop the system in time without relying on the system itself.

| Requirement | Level | Summary |
| --- | --- | --- |
| DCMP2-025 | L1 | A `halt` or `quarantine` control message MUST be issued on the separately authenticated emergency control plane that FR-004 requires at every level, and MUST… |
| FR-004 | L1 | The system MUST provide a separately authenticated and separately audited emergency control plane capable of halt, quarantine, or equivalent pre-declared… |
| TS1-035 | L1 | A revocation-propagation deadline and an emergency-halt acknowledgment bound are distinct obligations and MUST be declared separately; satisfying one MUST NOT… |
| FR-303 | L4 | Human-on-the-loop monitoring MUST be continuous for critical operations, and emergency override MUST be available through at least two independently controlled… |

Checklist items: EA-02 (L1), IA-07 (L4).

Machine checks:

- `ecl.rule.emergency-control-plane-required.v1`: a halt or quarantine control message declares the emergency control plane in its authority context.

Record entries that showed this gap (3): [Record 1: Knight Capital, 2012](https://externalcontrollayer.ai/record-1), [Record 22: Replit, 2025](https://externalcontrollayer.ai/record-22), [Record 25: OpenClaw, 2026](https://externalcontrollayer.ai/record-25).

Left open: Every level requires a separately authenticated emergency control plane, and the claim declares its halt acknowledgment bound. ECL-1 sets no production value for that bound.

## G11 Safeguard off

Definition: A check that could have caught the action existed but was switched off, bypassed, set to approve automatically, or not working when the action happened.

| Requirement | Level | Summary |
| --- | --- | --- |
| EBMP2-064 | L1 | An event that carries `ecl.ext.control-change.v1` MUST name at least one approver, none of whom is the requester, and a change of kind `disable`, `bypass` or… |
| ECL1N-0166 | L1 | A change that disables, bypasses, or sets to automatic approval an in-scope control, including a policy rule, an enforcement point, a human-approval step, a… |
| ECL1N-0169 | L2 | For `L2` and above, the Verification Layer MUST detect, within the declared timing case, an in-scope control that is disabled, bypassed, set to automatic… |

Binding profiles. These requirements apply only to an implementation that claims the profile:

| Requirement | Profile | Summary |
| --- | --- | --- |
| AC1-006 | ACS-BINDING-1 | At an ECL enforcement point, a decision failure MUST end in the declared safe state and MUST NOT release the action, whatever `on_decision_failure` posture the… |

Checklist items: VF-08 (L1), VF-09 (L2).

Machine checks:

- `ecl.rule.control-change-approved-and-bounded.v1`: a recorded control change names approvers other than its requester, and a change that disables, bypasses or automates approval of a control expires after it takes effect.

Machine checks of the binding profiles, applied to the records they define:

- `ecl.rule.acs-decision-failure-closed.v1`: a claim negotiates on_decision_failure deny, and a Guardian decision failure ends in neither an admit nor a release.

Record entries that showed this gap (8): [Record 5: Uber ATG, Tempe, 2018](https://externalcontrollayer.ai/record-5), [Record 6: Boeing 737 MAX, 2018–2019](https://externalcontrollayer.ai/record-6), [Record 21: Amazon Q Developer, 2025](https://externalcontrollayer.ai/record-21), [Record 24: Google Antigravity, 2025](https://externalcontrollayer.ai/record-24), [Record 26: Irregular's test environments, 2026](https://externalcontrollayer.ai/record-26), [Record 27: OpenAI–Hugging Face, 2026](https://externalcontrollayer.ai/record-27), [Record 28: UK AISI cyber range, 2026](https://externalcontrollayer.ai/record-28), [Record 29: OpenAI DNS escape, 2026](https://externalcontrollayer.ai/record-29).

Left open: A recorded change that switches a control off is checked by a rule. Detecting a control that is off without any recorded change is required from L2 and is shown by negative tests.

## G12 Unreviewed change

Definition: The change that introduced the harmful behavior went live without independent review; the change can be code, a prompt, a model, a package, a configuration, or a procedure.

| Requirement | Level | Summary |
| --- | --- | --- |
| EBMP2-064 | L1 | An event that carries `ecl.ext.control-change.v1` MUST name at least one approver, none of whom is the requester, and a change of kind `disable`, `bypass` or… |
| ECL1N-0170 | L1 | A change to the policy, the Consequential Action Register, the tool or capability manifest reachable by the SoI, an enforcement point's configuration, the trust… |
| XR1-023 | L1 | When the registry entry of an extension that a consumer processes names a value schema, the consumer MUST validate the extension's `value` against that schema… |
| ECL1N-0171 | L2 | For `L2` and above, each change to the governed AI system's model, system instructions, or tool set MUST be recorded with a version identifier and digest, and… |

Binding profiles. These requirements apply only to an implementation that claims the profile:

| Requirement | Profile | Summary |
| --- | --- | --- |
| MG1-003 | MCP-GATEWAY-1 | Each in-scope tool MUST have a mapping declared with the Consequential Action Register that names the server (identifier, name and version), the tool name, the… |
| MG1-008 | MCP-GATEWAY-1 | A tool added to or removed from an in-scope server's tool list, a change to any member of a tool definition, and a change of the server's name or version in… |

Checklist items: VF-10 (L1), VF-11 (L2).

Machine checks:

- `ecl.rule.control-change-approved-and-bounded.v1`: a recorded control change names approvers other than its requester, and a change that disables, bypasses or automates approval of a control expires after it takes effect.
- `ecl.rule.extension-value-valid.v1`: the value of an extension whose registry entry names a value schema validates against that schema.

Machine checks of the binding profiles, applied to the records they define:

- `ecl.rule.mcp-tool-mapped-and-reviewed.v1`: an MCP gateway forwards only a request whose method is mapped, a call only to a mapped tool, and only when the tool's definition and server identity are those the mapping reviewed.
- `ecl.rule.mcp-request-from-call.v1`: an MCP gateway's decision request takes its action class, operation, target, risk class and evidence profile from the mapping, its parameters from the call's arguments read from their RFC 8785 form, and carries the critical ecl.ext.mcp-binding.v1 naming them and the digest of the call's complete params; a call with a member other than jsonrpc, id, method and params, or whose id or params holds a number of magnitude greater than 2^53 - 1, gets no decision request.

Record entries that showed this gap (8): [Record 1: Knight Capital, 2012](https://externalcontrollayer.ai/record-1), [Record 6: Boeing 737 MAX, 2018–2019](https://externalcontrollayer.ai/record-6), [Record 12: NEDA's Tessa, 2023](https://externalcontrollayer.ai/record-12), [Record 19: xAI Grok, 2025](https://externalcontrollayer.ai/record-19), [Record 21: Amazon Q Developer, 2025](https://externalcontrollayer.ai/record-21), [Record 23: postmark-mcp, 2025](https://externalcontrollayer.ai/record-23), [Record 26: Irregular's test environments, 2026](https://externalcontrollayer.ai/record-26), [Record 28: UK AISI cyber range, 2026](https://externalcontrollayer.ai/record-28).

Left open: Changes to the policy, the register, the reachable tool manifest, enforcement configuration, the trust policy and detection responses are reviewed at every level. Changes to the AI system's model and instructions are recorded by version and digest from L2 but not reviewed under ECL-1, whose scope is the control layer (Section 2.10).

## G13 Self-reported record

Definition: After the action, the only account of what the system did, or of what could be undone, came from the system itself or from the party that ran it, and that account was wrong or incomplete.

| Requirement | Level | Summary |
| --- | --- | --- |
| EBMP2-057 | L1 | An observation MUST be an EBMP-2 `verification` event; a verifier MUST report one that is not with `ecl.error.semantic-invalid.v1`. |
| EBMP2-058 | L1 | A verifier MUST pair objects by identity and never by an event's claimed decision URI: a request by its `message_id` and by its (`action.action_id`… |
| EBMP2-059 | L1 | A verifier MUST apply DCMP2-044 to DCMP2-051 to every request and response pair, EBMP2-046 to EBMP2-056, EBMP2-070 and EBMP2-072 to EBMP2-075 to every event… |
| EBMP2-060 | L1 | A verifier MUST report exactly one verdict: `invalid` when an object of the bundle, in `envelopes` or `observations`, is not historically valid, a trust… |
| EBMP2-061 | L1 | A verifier MUST report the evidence level of each terminal effect: `none` when the terminal is not historically valid; `issuer-asserted` when it is; and… |
| EBMP2-062 | L1 | A verifier MUST declare finite limits on the number of envelopes and observations and on the decoded payload nodes of a bundle, MUST count the nodes of each… |
| ECL1N-0155 | L1 | A claim MUST maintain an inventory of every evidence-signing key that its trust policy accepts, giving for each key: its key identifier, its registered… |
| ECL1N-0156 | L1 | The governed AI system MUST NOT be able to read or export a private key that signs decision responses, evidence events, observations, or time attestations, or… |
| ECL1N-0157 | L1 | A private key MUST NOT sign for more than one of the decision point, the enforcement point, an observer, and a time authority. |
| ECL1N-0158 | L1 | Each evidence-signing key MUST have a declared maximum active lifetime of no more than 24 months for `L1` and `L2` claims and no more than 12 months for `L3`… |
| ECL1N-0159 | L1 | When an evidence-signing key is known or suspected to be compromised, the claimant MUST publish a trust-policy version that revokes the key with an effective… |
| ECL1N-0181 | L1 | The evidence of each decision MUST identify, by reference and digest, the version of the Consequential Action Register under which the decision was made, and… |
| ECL1N-0189 | L1 | Before it releases an action, an enforcement point MUST durably preserve the recovery information that its declared failure model requires, which includes at… |
| ECL1N-0190 | L1 | Each claim MUST declare, for each enforcement point, which of these failures its recovery information and its evidence survive: the exit of the enforcement… |
| ECL1N-0194 | L1 | A verifier MUST NOT imply that it performed a check that it did not perform or that lay outside its declared scope, MUST report a condition that it could not… |
| IE1-032 | L1 | A trusted-time countersignature MUST be an entry of the envelope's `countersignatures` member with `counter_id`, `claim` set to `ecl.claim.trusted-time.v1`, and… |
| IE1-033 | L1 | A time attestation MUST bind in `covered` the covered envelope's payload type (`media_type`), its payload digest (`digest`) and the signatures that it attests… |
| IE1-034 | L1 | A verifier that evaluates a trusted-time countersignature MUST verify the attestation under the trust-policy version the attestation names, at its attested… |
| IE1-035 | L1 | A verification profile MAY require trusted time. |
| ECL1N-0160 | L2 | For `L2` and above, an evidence-signing private key MUST be held in a key store that does not permit its export in plaintext, and every signing operation MUST… |
| FR-108 | L2 | In addition to ECL1N-0047 and ECL1N-0117, which require tamper-evident, signed evidence at every level, provenance records MUST be independently verifiable… |
| ECL1N-0161 | L3 | For `L3` and above, an evidence-signing private key MUST be generated inside, and never leave, a hardware security module or an equivalent hardware-isolated key… |
| IE1-036 | L3 | A claim at `L3` or `L4` MUST meet ECL1N-0100 for its signed evidence in one of two ways: a trusted-time countersignature on every signed evidence object… |
| ECL1N-0162 | L4 | For `L4`, generating, backing up, restoring, or destroying an evidence-signing key, and changing the trust policy that accepts it, MUST require at least two… |

Binding profiles. These requirements apply only to an implementation that claims the profile:

| Requirement | Profile | Summary |
| --- | --- | --- |
| AB1-008 | AARM-BINDING-1 | The signed ECL evidence bundle MUST be treated as the record of whether an action was authorized and released (EBMP2-045): an AARM receipt supports claims about… |
| AC1-009 | ACS-BINDING-1 | The ACS session chain MUST be treated as a native record that coexists with EBMP-2 evidence under EBMP2-045: the signed ECL evidence bundle is the record of… |
| MG1-010 | MCP-GATEWAY-1 | The gateway MUST record EBMP-2 evidence for each side-effecting request as an enforcement point: for a forwarded request, `authority_consumed`… |
| OE1-001 | OTEL-EVIDENCE-EXPORT-1 | Exported telemetry MUST be a copy of ECL evidence: the signed evidence bundle remains the record for every claim, and a log record, span event or other exported… |

Checklist items: EA-23 (L1), EA-28 (L1), PA-08 (L1), PA-09 (L1), VF-12 (L1), PA-02 (L2), PA-10 (L2), PA-11 (L3), PA-12 (L4).

Machine checks:

- The `evidence-bundle` conformance suite (224 vectors), which verifies signed evidence bundles offline under the verifier's own trust policy.
- The `key-roles` conformance suite (16 vectors), which refuses a trust policy in which one key holds two component roles, and does not count a decision request or decision response signed by a key without that role.
- `ecl.rule.decision-basis-one-way.v1`: a response that records its decision basis lists each input once, input names compared after the case normalization of RFC 3986 section 6.2.2.1 and RFC 8141 section 3.1; cites no actor_supplied or judgment input, and no input that was not available or was computed from one that was not, as supporting it; records no input computed from an input that is not verifiable as verifiable; and has no input computed from itself, directly or through other inputs. An admit cites at least one verifiable input as supporting it and no required input that was not available or was computed from one that was not. The outcome is no less strict than a recorded verifiable-only outcome; while that outcome is not admit, no input supports the outcome, and when it is admit, a verifiable input supports it and no required verifiable input was not available. No input obtained after the decision is recorded as available, and no value describes a time after the decision or after the input was obtained; a record that gives when an input was obtained gives when the request was received, no later than the decision, and a record that gives when the request was received gives both times of each available input. A verifier that holds the request refuses an input recorded as verifiable whose source is the request's actor, and a request received before it was issued. Each decision response that an AARM, ACS or MCP exchange record holds carries exactly one decision basis and is checked with the request the record holds.

Machine checks of the binding profiles, applied to the records they define:

- `ecl.rule.aarm-receipt-bound.v1`: an AARM receipt is bound to the execution_terminal event of its action by identifier, RFC 8785 digest and decision, and records the parameters of the request it governed.
- `ecl.rule.acs-decision-recorded.v1`: the ECL response records the Guardian decision it depends on in ecl.ext.acs-decision.v1, and each recorded chain head is the head of the recomputed ACS session chain after that step.
- `ecl.rule.mcp-result-bound.v1`: the evidence of a forwarded MCP request binds the server's response by RFC 8785 digest, records the state that response reads as and the forward's completion, and the governed AI system receives that response, with the code of a server error that uses one of the error table's codes replaced by -32603; a refused request is recorded in a non-release state, or as cancelled when its authorization was consumed, and a recovered exchange claims only the outcome that the gateway's journal shows.
- `ecl.rule.otel-export-after-evidence.v1`: an exporter reads an object no earlier than its time, and the evidence is the same after an export, failed or not.

Record entries that showed this gap (2): [Record 13: Cruise, San Francisco, 2023](https://externalcontrollayer.ai/record-13), [Record 22: Replit, 2025](https://externalcontrollayer.ai/record-22).

Left open: Evidence that an effect occurred is issuer-asserted unless a separately keyed observer corroborates it, and no level requires such an observer. Verification outside the primary control plane is required from L2 (FR-108); at L1 the evidence is tamper-evident. A verifier keeps a producer's assertion apart from corroboration and reports a check it did not make as unchecked (ECL1N-0194). What is needed to recover an attempt is kept before its release, and an attempt whose outcome cannot be established stays unresolved rather than being reported as known (ECL1N-0189).
