# ECL ACS Binding Profile 1

Requirement-IDs: compiled
Version: 1.0
Status: normative profile of ECL-1 Version 1.0, a published version

This profile states how a deployment of the OWASP Agent Control Standard (ACS)
connects to an ECL-1 deployment. An ACS Guardian becomes a decision source for
an ECL Decision Layer. An ACS hook point can become an ECL enforcement point
only when it runs outside everything the governed AI system can execute code in
or control, and meets the Enforcement Layer requirements; a hook point inside
the governed AI system can carry the Guardian's decision to an ECL decision
point and is never an enforcement point (AC1-002). The ECL guarantee is
unchanged: an action is released only on an ECL `admit` bound to the exact
request, a failure that leaves the action without required proof ends closed,
and the signed ECL evidence bundle is the record that a third party can check
and, from `L2`, verify offline.

The pinned ACS text lets a deployment proceed when its Guardian cannot answer:
the handshake member `on_decision_failure` defaults to `proceed`. This profile
replaces that default for every action that an ECL claim covers. A decision
failure at an ECL enforcement point ends in the declared safe state and never in
the action going ahead (AC1-006).

The profile adds requirements to a claim that declares it. It removes none of
the core requirements or of the requirements of DCMP-2, EBMP-2 and
TRUST-POLICY-1.

Under this profile an action crosses its release boundary (ECL1N-0185) when an
ECL enforcement point releases it on the `admit` of the DCMP-2 response that an
ECL decision point issues for the exact request (AC1-003, AC1-005); a Guardian
decision, and a hook point that is not an enforcement point, release nothing.

## Pinned sources

The machine-readable record of these pins is `conformance/binding-sources.json`.
ACS prose is licensed CC BY-SA 4.0 and its schemas Apache-2.0; this profile
cites ACS identifiers and does not reproduce ACS text.

| Source | Revision | File | SHA-256 |
| --- | --- | --- | --- |
| ACS specification version 0.1.0, Instrument pillar | `GenAI-Security-Project/agent-control-standard` release tag `v0.1.2` (tag object `11871fad2817aa8eefd69944649dbea85bf6085c`), commit `7743826b2ec02e3daf47a08c82170fc7a43b0838` | `docs/spec/instrument/specification.md` | `53fd6658653ea358415c115b6dceff1961ac69e3dd4435556b3a17922942dea3` |
| ACS conformance profiles | same commit | `docs/spec/conformance.md` | `7c9d699efaba9d3fbcf9cc16288b653b1f9ae4cd7e33a874c19ba29d6495176c` |
| ACS hook taxonomy | same commit | `docs/spec/instrument/hooks.md` | `1441751389f0267a96a91e023b2483575368d51ac20c392a2a3c6a956c02576b` |
| Response envelope schema | same commit | `specification/v0.1.0/response-envelope.json` | `145f730c80a7a6ca8c870fe4a68b898d0ef6a8fcd0f2cc575f9ca70e6d43d0d9` |
| Handshake schema | same commit | `specification/v0.1.0/handshake.json` | `9fabf14e732372cdcab4923bd977ecd9fcd32896e4e4126cc460a640e0d627ab` |
| Modifications schema | same commit | `specification/v0.1.0/modifications.json` | `5602fb5ed3adb0ab360f29774f0c58b63fb7270f94130cf77d6d3bd93fe1ecc8` |
| ContextEntry schema | same commit | `specification/v0.1.0/context-entry.json` | `efe01385a6150960c693653a36d38bd7b829697965631295b94a8c3115b95205` |
| ASK details schema | same commit | `specification/v0.1.0/ask-details.json` | `1a8a5348b677b265afa8f2f96394ced1811eddbd4bc4a0cdde3f7ac9322cdf1c` |
| DEFER details schema | same commit | `specification/v0.1.0/defer-details.json` | `5c0f3d28201f20f1aef9a06a7b66922ddd3f8f41a801665cf14432b5ddbaa5cf` |

The release file `version.txt` reads `0.1.2`; the specification inside it is
version 0.1.0. The mapping packet `conformance/crosswalks/owasp-acs-core.json`
captures the same release. Disposition names are the wire values of the
response envelope: `allow`, `deny`, `modify`, `ask` and `defer`.

## Roles and declarations

**AC1-001** — A claim of this profile MUST identify the ACS specification version
and repository release it implements by the revision and digests that this
profile pins, the Guardian by principal identifier and trust domain, and each
hook point that it claims as an ECL enforcement point with the in-scope action
classes that hook point mediates.

**AC1-002** — An ACS hook point MUST NOT be claimed as an ECL enforcement point
unless the governed AI system can neither bypass it, disable it nor change the
decision it applies (ECL1N-0033, ECL1N-0043, ECL1N-0046), and the Consequential
Action Register records its enforcement class with its rationale and residual
bypass risk (ECL1N-0044, ECL1N-0045). A hook point that runs in a process,
container or account in which the governed AI system can execute code, or that
the governed AI system can start, stop or reconfigure, MUST NOT be claimed as
an ECL enforcement point; it MAY carry the Guardian's decision to an ECL
decision point, where AC1-004 gives that decision its class and the decision
is not a `verifiable` input unless the decision point verifies the Guardian's
signature over it under a key that the governed AI system cannot use.

**AC1-003** — A Guardian decision MUST reach an ECL enforcement point only
through a DCMP-2 decision response that an ECL decision point issues and signs
for the exact request (DCMP2-044 to DCMP2-051); an enforcement point MUST
release an action only on that response's `admit`, and a Guardian `allow` MUST
NOT create, widen or extend ECL authority, so the decision point still applies
its native authority, scope, validity, budget and human-approval checks.

## Dispositions

**AC1-004** — The ECL outcome for an action that a Guardian decision governs
MUST be at least as strict, in the strictness order of the core standard
(Section 4.3), as the outcome this mapping gives: `allow` maps to
`admit` only when policy evaluated over `verifiable` inputs permits the action
under the one-way rule of the core standard (Section 5.2), and otherwise to
`deny`; `deny` maps to `deny`; `ask` maps to `challenge` naming the approval
required (ECL1N-0174, ECL1N-0177), or to `hold` or `deny` where the Guardian
substitutes for an approver-incapable client; `defer` maps to `hold` carrying
the resolution condition and deadline (DCMP2-018); `modify` maps to `deny` of
the original request, with the modified action handled under AC1-005. A Guardian
decision whose evaluator is `agent` or `composite`, or that states no
evaluator, is a `judgment` input. Any other Guardian decision is
`actor_supplied` when it reaches the ECL decision point through a hook point or
any other channel that the governed AI system can write, unless the decision
point verifies the Guardian's signature over the decision under a key that the
governed AI system cannot use; an ACS-Core HMAC under a key that the Observed
Agent holds does not qualify, and an ACS-Crypto asymmetric signature under a
key held only by the Guardian does (ECL1N-0178, AC1-009). Otherwise it takes
the least trusted class of the inputs it evaluated, so one that evaluated
SessionContext, Intent or other content the governed AI system wrote is
`actor_supplied`. A Guardian decision that is a `judgment` or `actor_supplied`
input MAY make the outcome stricter and MUST NOT be the basis of an `admit`.
The exchange record MUST state in `guardian.channel` whether the decision point
obtained the decision from the Guardian directly (`direct`), verified a
Guardian signature under a key that the governed AI system cannot use
(`signed`), or received it through a hook point (`hook`), and MUST name, in the
`derived_from` of the Guardian decision's input, each decision input that the
Guardian's request carried other than the action itself. A Guardian decision
whose input has no `derived_from`, or whose channel is `hook`, MUST NOT be
declared `verifiable`. When the response carries `ecl.ext.acs-decision.v1`,
exactly one input MUST carry `guardian: true`. The class that this requirement
gives a Guardian decision holds in every decision basis that the exchange
record holds: an entry of the `ecl.ext.decision-basis.v1` of the record's
`modification_response` whose `input` is the input that the record marks
`guardian` MUST have the class of the marked input. When `guardian.channel` is
`signed`, the record MUST also give, in `guardian.key_id`, the identifier of
the key under which the decision point verified the Guardian's signature and,
in `guardian.request_digest`, the `ecl.digest.sha-256.v1` digest of the RFC
8785 canonical form of the request that the Guardian evaluated. A verifier of
the record cannot itself verify the Guardian's signature, which the record does
not hold: the channel, the key and the digest are the adapter's statements,
which an assessor checks against the deployment.

**AC1-005** — A `modify` decision MUST NOT release the original action. The
action that the modification produces, if it is to go ahead, MUST be submitted
as a new DCMP-2 decision request that carries the effective parameters after
the modification, as the same JSON values, in `action.parameters` and
`action.parameters_digest`, carries the original request's `issuer`, `actor`,
`subject`, `delegation_chain`, `authority_request`, `constraints` and
`integrity_policy`, and its `action` with only `action_id`, `parameters` and
`parameters_digest` changed, names the original request as a causal predecessor
by identifier and digest with the relation `ecl.relation.modification-of.v1`,
and is evaluated and admitted on its own; an enforcement point MUST release only
the parameters that the new request's `admit` binds, and a `modifications`
object that the pinned text forbids (a wholesale replacement combined with
edits, or edits with overlapping targets), or one that cannot be applied under
the next section, MUST end in `deny` of the original with no new request. An
exchange record of a `modify` that holds neither a `modification_request` nor a
`release` records a `deny` of the original with no new request and MUST NOT be
reported for the missing new request, since the record does not show why the
modified action did not go ahead; one that holds a `modification_response`
without its `modification_request` MUST be reported as
`ecl.rule.acs-modification-new-request.v1`. A decision other than `modify`, and
a decision failure, has no new request: the enforcement point MUST release the
action, if at all, only on the `admit` of the original request, and an exchange
record that records a decision failure, or a Guardian decision other than
`modify`, and that holds a `modification_request` or a `modification_response`
MUST be reported as `ecl.rule.acs-modification-new-request.v1`.

## Effective parameters of a modify

The effective parameters of a `modify` follow the pinned modification rules.
Each `parameter_overrides` member replaces the argument of that name, and each
redaction replaces the value at its JSON Pointer, resolved against the tool
call's arguments, with its replacement text (`[REDACTED]` when none is given). A
wholesale `modified_content` replaces the arguments only when its text is a JSON
object within the restricted canonical profile (IE1-001). A redaction path that
does not resolve inside the arguments, or effective parameters outside that
profile, make a modification one that cannot be applied. A modification that
changes the action's target or operation, as the deployment derives them from
the tool call's arguments (for an MCP tool, by the rule of its mapping,
MG1-003), cannot be applied.

The new request keeps the original's target and operation (AC1-005), so a
modification that changed the argument from which the deployment derives the
target would release, under an `admit` for one resource, parameters that act on
another. An exchange record does not show how the deployment derives the target
and operation from the arguments. A checker of the record accepts the record of
such a modification, which ends with no new request and no release (AC1-005), as
it accepts that of any `modify` whose modified action did not go ahead. It
cannot see whether the effective parameters of a new request that went ahead
changed the target or operation; the assessor checks that against the
deployment's mapping, which for an MCP tool is the mapping that MG1-003
declares.

## Failure and timeouts

**AC1-006** — At an ECL enforcement point, a decision failure MUST end in the
declared safe state and MUST NOT release the action, whatever
`on_decision_failure` posture the handshake negotiated. A decision failure is
any of these: no usable Guardian decision within the negotiated timeout; a
transport failure; an error response without a decision; a decision whose
disposition the mapping of AC1-004 does not name; a decision for a `request_id`
other than the hooked step's; a response whose ACS signature, where the session
requires one, does not verify; and a decision that arrives after the
enforcement point applied the safe state for the step. A deployment that claims
this profile MUST negotiate `on_decision_failure` as `deny`, and MUST configure
the startup posture that the pinned text sets out of band as `refuse`, so that
a failed handshake starts no unguarded session for an in-scope action class.

The pinned text's liveness method, `system/ping`, carries no enforcement
semantics there, and its failure is not an enforcement event. This profile maps
no ACS liveness method: the negotiated decision timeout of each step bounds a
silent or unreachable Guardian, and its expiry is a decision failure.

**AC1-007** — The expiry of an `ask` or a `defer` MUST NOT release an in-scope
action, even when the `ask` declares a `timeout_disposition` of `allow` or the
`defer` a `timeout_decision` of `ask`: the ECL response for it MUST carry an
`expires_at` no later than the Guardian's deadline and a `safe_state` under
which the waiting action is not released (`ecl.state.fail-closed.v1`,
`ecl.state.quarantine.v1`, `ecl.state.emergency-halt.v1` or
`ecl.state.restricted.v1`), and the enforcement point MUST record the expiry as
a non-release outcome. The Guardian's deadline is the instant at which the ECL
deployment received the Guardian's decision, which the exchange record holds as
`guardian.observed_at`, plus the `ask_details.timeout_seconds` of an `ask`, in
seconds, or plus the `defer_details.resolution_timeout_ms` of a `defer`, in
milliseconds (the pinned `ask-details.json` and `defer-details.json`).

The pinned text does not say from which instant a Guardian's timeout runs, and
an ACS response carries no time of issue. The profile counts the timeout from
the instant the ECL deployment received the decision, so that the deadline can
be computed from the exchange record and checked. An approval that arrives
after the deadline releases nothing until a new evaluation admits the action.
As in AARM-BINDING-1 (AB1-005), a fail-open or degraded state never decides an
expiry: the degraded state can permit the action that waits.

## Session chain and evidence

**AC1-008** — For each Guardian decision that an ECL decision depends on, the
ECL decision response MUST carry the registered extension `ecl.ext.acs-decision.v1`
with the Guardian's decision, its evaluator, the ACS `request_id`, the
`chain_hash` that the Guardian published for the step, and for a `modify` the
`ecl.digest.sha-256.v1` digest of the RFC 8785 form of its `modifications`
object; when the deployment claims the ACS-Audit profile it MUST also carry the
step's `request_hash`. A verifier that recomputes the ACS session chain under
the chain-hashing rule below MUST find each recorded `chain_hash` as the head
after that step's ContextEntry, which is the entry whose `step_id` is the
recorded `request_id`.

The chain-hashing rule restates section 8.2 of the pinned Instrument
specification. A ContextEntry's `entry_hash` is the lowercase hexadecimal
SHA-256 of the UTF-8 bytes of the RFC 8785 canonical form of the entry with its
`entry_hash` and `previous_hash` members removed, followed by the 32 bytes that
the entry's `previous_hash` encodes in hexadecimal, or by no bytes for the
first entry of a session, whose `previous_hash` is null or absent. Each later
entry's `previous_hash` is the `entry_hash` of the entry before it, and the
chain head after an entry is that entry's `entry_hash`.

**AC1-009** — The ACS session chain MUST be treated as a native record that
coexists with EBMP-2 evidence under EBMP2-045: the signed ECL evidence bundle is
the record of release, an ACS chain or chain head that disagrees with the ECL
evidence MUST be reported as an integrity finding and MUST NOT be repaired by
rewriting either record, and an ACS-Core signature (HMAC-SHA256 under a shared
key) MUST NOT be presented as satisfying FR-108.

**AC1-010** — An adapter that retains exchange records for this profile MUST
write each one as `ecl_acs_exchange_v1`, valid against
`https://externalcontrollayer.ai/ns/schema/binding/acs-exchange/1`, and every
value of `ecl.ext.acs-decision.v1` it emits MUST validate against
`https://externalcontrollayer.ai/ns/schema/extension/acs-decision/1`.

**AC1-011** — When the Observed Agent wraps MCP traffic in the ACS
`protocols/MCP/*` namespace, a request that reaches an in-scope MCP server MUST
also satisfy MCP-GATEWAY-1 at the point where it leaves for that server.

## Decision basis

**AC1-012** — When an exchange record holds a `response`, the record's `inputs`
MUST be the entries of the decision basis that the response records in
`ecl.ext.decision-basis.v1`: each input of the record, without its `guardian`
marker, MUST equal the entry of the extension's value whose `input` is the same,
and each entry MUST appear in the record exactly once. A response that does not
carry the extension records no inputs, and a response that carries it more than
once matches no record. A record that breaks this MUST be reported as the
verification finding `ecl.rule.acs-inputs-match-basis.v1`. The record's
`response`, and its `modification_response` when it holds one, MUST each carry
exactly one `ecl.ext.decision-basis.v1` and MUST also satisfy DCMP2-053, each
with the record's `request` or `modification_request` as the request it answers,
with the response clock-skew allowance of the reference verification profile,
zero (DCMP2-047); a record whose response fails either MUST be reported with
`ecl.rule.decision-basis-one-way.v1`. Each DCMP-2 message that the record holds
MUST satisfy the semantic rules of DCMP-2, and a record that holds one that
fails a rule MUST be reported with that rule. The decision basis of the record's
`modification_response` MUST carry the `register` reference of the decision
basis of the `response`, member for member, and MUST record the same inputs,
compared as input names are, each with the `class`, `required`, `source` and
`derived_from` that the record's `inputs` give it; a record that breaks this
MUST be reported as `ecl.rule.acs-inputs-match-basis.v1`.

The record is the adapter's account of a decision, and the response is the
decision point's signed account of the same decision. If the two could
disagree, each could pass its own check: a record could class an `agent`
Guardian's `allow` as `judgment` while the signed basis classes it `verifiable`
and rests the `admit` on it. The record's inputs use the vocabulary of the
decision basis (an entry of `ecl.ext.decision-basis.v1` with the `guardian`
marker added), so every member is compared, including the status and reference
of an input that was unavailable, late or malformed, the effect of each input
and the inputs a Guardian decision was computed from. Agreement alone would
let a record and its response agree on a basis that breaks the one-way rule,
such as an `admit` while a required input was unavailable; the response is
therefore held to DCMP2-053 as it would be in a signed evidence bundle.

The decision basis of the modification response is compared with the record for
the same reason, since its `admit` releases the modified action. The new request
is the original action with other parameters (AC1-005), of the same action
class, so the register version declares the same inputs for both decisions; the
status, effect, reference and times of each input describe the new decision and
may differ. The new request is decided under the register version of the first
decision; if that version is no longer in force, the modification is not
admitted.

## Disposition mapping (informative)

| ACS disposition | ECL outcome | Release |
| --- | --- | --- |
| `allow` from a `deterministic` evaluator | `admit` when ECL policy over `verifiable` inputs permits it, otherwise `deny` | Only on a verified `admit` |
| `allow` from an `agent` or `composite` evaluator, or one that states no evaluator | As above; the Guardian decision is a `judgment` input and is never part of the basis | Only on a verified `admit` |
| `allow` from a `deterministic` evaluator that a hook point carried to the decision point | As above; the Guardian decision is an `actor_supplied` input and is never part of the basis | Only on a verified `admit` |
| `deny` | `deny` | None |
| `modify` | `deny` of the original; a new request carrying the effective parameters, if the modified action is to go ahead | Only the new request's admitted parameters |
| `ask` | `challenge` until the approval is recorded; `hold` or `deny` for an approver-incapable client | None until a new evaluation admits |
| `defer` | `hold` with the resolution condition and deadline | None |
| Decision failure | Declared safe state, recorded as `denied` with `ecl.error.dependency-unavailable.v1` | None |

## Session chain mapping (informative)

| ACS element | ECL counterpart |
| --- | --- |
| `session_id` | Recorded with the workflow; one ACS session can span several ECL workflows |
| `request_id` of the hooked step | `request_id` in `ecl.ext.acs-decision.v1`; the DCMP-2 `message_id` stays distinct (DCMP2-005) |
| ContextEntry `entry_hash` and the published `chain_hash` | `chain_hash` in `ecl.ext.acs-decision.v1` on the response that the step leads to |
| ContextEntry `request_hash` (ACS-Audit) | `request_hash` in `ecl.ext.acs-decision.v1` |
| Response `signature` | Not mapped; ECL evidence carries its own INTEGRITY-ENVELOPE-1 signatures |

## Exchange record (informative)

An `ecl_acs_exchange_v1` record holds one hooked step's exchange. Its members
are the ACS `session_id` and `hook`; the negotiated `on_decision_failure`
posture and whether the deployment claims ACS-Audit (`audit_profile`); the
`guardian` member with the `status` of the Guardian's answer (`decided` or
`failed`), the kind of `failure` (`timeout`, `transport`, `error`,
`unmapped_disposition`, `request_mismatch`, `signature_invalid` or `late`, the
decision failures of AC1-006), the time the adapter observed it, the `channel`
through which the decision point obtained a decision (`direct`, `signed` or
`hook`, AC1-004) and the Guardian's `result`; the `inputs` of the ECL decision,
which are the entries of the decision basis that the response records in
`ecl.ext.decision-basis.v1` (AC1-012), with the Guardian's decision marked by
`guardian` and the inputs its request carried named in that entry's
`derived_from`; the DCMP-2 `request` and `response`, and for a `modify` whose
modified action went ahead the `modification_request` and
`modification_response`; the session `chain` up to the step; and a `release`
member only when the action was released. The rules registered for this
profile, whose names begin `ecl.rule.acs-`, check a record after its schema.

## Security considerations

ACS-Core assures that the channel between the Observed Agent and the Guardian
is authenticated and that the agent honors the Guardian's decisions; it does
not assure that a hook point is outside the governed AI system's reach, and its
symmetric baseline signature cannot prove to a third party which party wrote a
chain head. The profile therefore places the release decision at an ECL
enforcement point outside the governed AI system (AC1-002), records the ACS
chain heads inside signed ECL evidence, and removes the fail-open defaults for
covered actions, the negotiated `on_decision_failure` and the out-of-band
startup posture among them (AC1-006). An adversary who can delay or drop
Guardian traffic can then cause denials, not unguarded actions. A Guardian
whose agent layer is a language model is steerable by the content it reviews,
which is why its decisions are `judgment` inputs. ACS hooks fire in the
Observed Agent, and the ACS-Core signature is an HMAC under a per-session key
that the Observed Agent holds, so the governed AI system can forge a decision
that a hook carries; such a decision is never `verifiable`, and only a
decision that the decision point obtains from the Guardian or authenticates by
the Guardian's own signature can be (AC1-004).

## Conformance

| Kind | What the citation establishes |
| --- | --- |
| Vectors | The `acs-binding` suite accepts a deny for a Guardian decision that arrived after the safe state was applied, and a `modify` that ends in `deny` with no new request and no release, and refuses a fail-open proceed after a Guardian decision failure, a negotiated `proceed` posture, an admit after a decision failure, a release when an `ask` expires even with `timeout_disposition` `allow`, an expiry into a fail-open state or after the Guardian's deadline, an outcome weaker than the mapped disposition, a modification released under the original request or with other parameters, a new request that carries a number where the effective parameters hold a boolean, a modification response without its new request, a new request recorded, and released, after a Guardian decision other than `modify`, a Guardian `allow` from an `agent` or `composite` evaluator, or from one that states no evaluator, used as `verifiable` or as the basis of an `admit`, a deterministic Guardian decision carried by a hook point used as `verifiable`, a modification admitted on a Guardian decision that a hook point carried or that an `agent` evaluator made, a `signed` channel without the identifier of the key that signed the decision or the digest of the Guardian's request, a released request that declares a negative budget debit, a response that records a Guardian decision that no input marks, a record without the channel of a decision, a release without an `admit`, a response that does not record the Guardian decision, and a recorded chain head that the recomputed ACS chain does not contain; the `binding-basis` suite refuses a record whose inputs disagree with the decision basis of its response, a record whose response or modification response carries no decision basis, and a record whose response's decision basis breaks DCMP2-053, alone or with the request it answers |
| Assessor procedure | Hook-point placement and enforcement class, handshake postures, Guardian identity, and how the deployment derives each action's target and operation from its arguments, which decides whether a modification can be applied, so that no modification that changes them is released (AC1-005) |

The vectors establish the behavior of exchange records, not the conformance of
an ACS product, and this profile claims no ACS conformance and no OWASP
endorsement.
