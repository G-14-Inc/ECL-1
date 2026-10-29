# ECL AARM Binding Profile 1

Requirement-IDs: compiled
Version: 1.0
Status: normative profile of ECL-1 Version 1.0, a published version

This profile states how a control plane that implements AARM (Autonomous Action
Runtime Management) connects to an ECL-1 deployment without weakening the
guarantee: every in-scope action crosses an enforcement boundary that the
governed AI system cannot bypass, under a decision that the governed AI system
cannot change, a failure that leaves the action without required proof ends
closed, and every decision leaves evidence that a third party can check and,
from `L2`, verify offline. An AARM control plane takes one of two
roles for each in-scope action class. It implements the ECL Decision Layer, and
then answers DCMP-2 decision requests itself; or it supplies `judgment` inputs
to a separate ECL Decision Layer, and then its outputs can make an outcome
stricter and nothing else. In both roles the signed ECL evidence bundle is the
record of whether an action was released, and an AARM receipt is bound to it by
digest.

The profile adds requirements to a claim that declares it. It removes none of
the core requirements or of the requirements of DCMP-2, EBMP-2 and
TRUST-POLICY-1.

Under this profile an action crosses its release boundary (ECL1N-0185) when an
ECL enforcement point releases it on the verified `admit` of its DCMP-2 decision
request (AB1-002, AB1-004); where an AARM deployment issues a credential for an
admitted action under R9 (AB1-012), the boundaries to name are the credential's
issuance and the resource server's use of it, as OAUTH-AUTHORITY-1 names them
for an OAuth access token.

## Pinned sources

The AARM text this profile binds to is fixed by revision and SHA-256 digest of
the raw UTF-8 bytes, as `docs/crosswalk.md` fixes the sources it maps. The
machine-readable record is `conformance/binding-sources.json`.

| Source | Revision | File | SHA-256 |
| --- | --- | --- | --- |
| AARM specification version 1.0 (February 2026), rendered at https://aarm.dev/spec | `aarm-dev/aarm` commit `c1f9b27cef60f7035cc8d854b0ae6d1ea9781680` | `src/app/spec/page.tsx` | `9794ca90b4899538459cf25478419fbfe147353dd8e206c31fc6a157c2d1ec11` |
| AARM conformance requirements (last updated 2026-03-26) | `aarm-dev/docs` commit `5bd02fdb5d5f6483a16a42539e38cfe8743c3a97`, unchanged at `8eff208b98786b2c9a578b26cb7eaca440ec4020` | `conformance/requirements.mdx` | `d5b88e2343114a282d04a4b421bf0d13b27eba82f82b9acee0cb62723bb6b5c2` |
| AARM receipt schema (informative component page) | `aarm-dev/docs` commit `8eff208b98786b2c9a578b26cb7eaca440ec4020` | `components/receipts.mdx` | `a105fd2ad75b00fa416fcb3defbfce1f0e4dc2f444506f3ca96dc374c89720c0` |

The conformance requirements file has the same bytes that the mapping packet
`conformance/crosswalks/aarm-r1-r9.json` records. The names of the five
AARM authorization decisions (ALLOW, DENY, MODIFY, STEP_UP and DEFER) and of
requirements R1 to R9 are used as the pinned text spells them.

## Roles and declarations

**AB1-001** — A claim of this profile MUST identify the AARM revision it
implements by the version, revisions and digests that this profile pins, and
MUST declare, for each in-scope action class, whether the AARM control plane
implements the ECL Decision Layer for that class or supplies `judgment` inputs
to a separate ECL Decision Layer.

**AB1-002** — When the AARM control plane implements the Decision Layer, it MUST
answer each DCMP-2 decision request with a DCMP-2 decision response that binds
the exact request (DCMP2-044 to DCMP2-051) and is signed under the claim's trust
policy with a key that the policy accepts for the decision-response purpose
(TRUST-POLICY-1), and an enforcement point MUST release an action only on such a
response; an AARM decision, receipt or other AARM artifact MUST NOT release an
action by itself.

## Decisions

**AB1-003** — The ECL outcome for an action that an AARM decision governs MUST be
at least as strict, in the strictness order of the core standard (Section 4.3),
as the outcome this mapping gives: ALLOW maps to `admit` only
when policy evaluated over `verifiable` inputs permits the action under the
one-way rule of the core standard (Section 5.2), and otherwise to `deny`; DENY
maps to `deny`; STEP_UP maps to `challenge` naming the approval required
(ECL1N-0174, ECL1N-0177), or to `hold`; DEFER maps to `hold`; MODIFY maps to
`deny` of the original request, with the modified action handled under AB1-004.

**AB1-004** — A MODIFY decision MUST NOT release the original action. The
modified action, if it is to go ahead, MUST be submitted as a new DCMP-2
decision request that carries the modified parameters, as the same JSON values,
in `action.parameters` and `action.parameters_digest`, carries the original
request's `issuer`, `actor`, `subject`, `delegation_chain`, `authority_request`,
`constraints` and `integrity_policy`, and its `action` with only `action_id`,
`parameters` and `parameters_digest` changed, names the original request as a
causal predecessor by identifier and digest with the relation
`ecl.relation.modification-of.v1`, and is evaluated and admitted on its own; an
enforcement point MUST release only the parameters that the new request's
`admit` binds. A MODIFY whose modified parameters change the action's target or
operation, as the deployment derives them from the parameters, MUST end in
`deny` of the original with no new request. An exchange record of a MODIFY that
holds neither a `modification_request` nor a `release` records a `deny` of the
original with no new request and MUST NOT be reported for the missing new
request, since the record does not show why the modified action did not go
ahead; one that holds a `modification_response` without its
`modification_request` MUST be reported as
`ecl.rule.aarm-modification-new-request.v1`. A decision other than MODIFY has no
new request: the enforcement point MUST release the action, if at all, only on
the `admit` of the original request, and an exchange record whose
`aarm_decision` is not MODIFY and that holds a `modification_request` or a
`modification_response` MUST be reported as
`ecl.rule.aarm-modification-new-request.v1`.

The new request keeps the original's target and operation, so a MODIFY that
changed the parameter from which the deployment derives the target, such as the
account to be debited, would release, under an `admit` for one resource,
parameters that act on another. An exchange record does not show how the
deployment derives the target and operation from the parameters. A checker of
the record accepts the record of a MODIFY that ends as AB1-004 requires, with no
new request and no release, as it accepts that of any MODIFY whose modified
action did not go ahead. It cannot see whether the modified parameters of a new
request that went ahead changed the target or operation; the assessor checks
that against the deployment's mapping, which for an MCP tool is the mapping that
MG1-003 declares.

**AB1-005** — A `hold` or `challenge` mapped from DEFER or STEP_UP MUST carry an
`expires_at` no later than the deadline of the deferral or approval, and a
`safe_state` under which the waiting action is not released:
`ecl.state.fail-closed.v1`, `ecl.state.quarantine.v1`,
`ecl.state.emergency-halt.v1` or `ecl.state.restricted.v1`. The expiry of that
deadline, or the AARM control plane's failure to answer within its declared
timeout, MUST end in an outcome that releases nothing (DCMP2-018, DCMP2-041).

The registry of operational values marks the first three states
`permits_new_effects` false. It marks `ecl.state.restricted.v1` and
`ecl.state.degraded.v1` profile-bounded, but the two differ for a waiting
action: the restricted state permits only bounded diagnosis, recovery and
safe-shutdown operations, while the degraded state permits a declared subset of
ordinary operations, which can include the action that waits. A fail-open or
degraded state therefore never decides an expiry.

## Judgment inputs

**AB1-006** — The outputs of AARM R2 (context accumulation, including the data
classifications it records), R3 (policy evaluation with intent alignment,
including any confidence score) and R7 (semantic distance), and in the
judgment-source role every AARM output including the AARM decision itself
(R4), MUST be treated as `judgment` inputs: the Consequential Action Register
MUST declare each of them `judgment`; the exchange record MUST list each one
that the decision consulted in `inputs` with that class and its
`aarm_requirement`, and the decision response MUST record it in
`ecl.ext.decision-basis.v1` with that class (AB1-013); each of them MUST NOT be
part of the basis of an `admit`, and an `admit` MUST rest on `verifiable`
inputs only. An AARM DENY, STEP_UP or DEFER that rests on them MAY make the
outcome stricter. In the judgment-source role, the inputs MUST include exactly
one input whose `aarm_requirement` is `R4`, of class `judgment`. These classes
hold in every decision basis that the exchange record holds: an entry of the
`ecl.ext.decision-basis.v1` of the record's `modification_response` whose
`input` is an input that the record lists with an `aarm_requirement` that this
requirement makes `judgment` MUST have the class `judgment`.

R3 covers both static policy and intent alignment. Because the profile classes
all R3 output as `judgment`, a deterministic AARM policy result can support an
`admit` only when the ECL decision point evaluates the same policy over
`verifiable` inputs itself.

## Receipts and evidence

**AB1-007** — Each AARM receipt for an in-scope action MUST be bound to the ECL
evidence of that action: the action's `execution_terminal` event MUST carry the
registered extension `ecl.ext.aarm-receipt.v1` with the receipt's identifier
(its `receipt_id`), the `ecl.digest.sha-256.v1` digest of the RFC 8785 canonical
form of the receipt as retained, signature included, and the AARM decision that
the receipt records in `decision.result`; that decision MUST be the decision the
exchange record holds and consistent with the ECL outcome under AB1-003, and the
receipt's `action.parameters` MUST have, under DCMP2-007, the digest that the
decision request carries in `action.parameters_digest`.

**AB1-008** — The signed ECL evidence bundle MUST be treated as the record of
whether an action was authorized and released (EBMP2-045): an AARM receipt
supports claims about the AARM evaluation, such as the context it accumulated,
the intent alignment it computed, the policy it matched and its reasons, and
MUST NOT be used to establish that an action was authorized or released; a
receipt that disagrees with the ECL evidence MUST be reported as a verification
finding, and the ECL evidence governs.

**AB1-009** — An adapter that retains exchange records for this profile MUST
write each one as `ecl_aarm_exchange_v1`, valid against
`https://externalcontrollayer.ai/ns/schema/binding/aarm-exchange/1`, and every
value of `ecl.ext.aarm-receipt.v1` it emits MUST validate against
`https://externalcontrollayer.ai/ns/schema/extension/aarm-receipt/1`.

## Interception, telemetry and credentials

**AB1-010** — An AARM interception point (a protocol gateway, SDK
instrumentation, a kernel eBPF hook or a vendor integration) MUST NOT be claimed
as an ECL enforcement point unless it meets ECL1N-0043 and ECL1N-0046 and the
Consequential Action Register records its enforcement class with its rationale
and residual bypass risk (ECL1N-0044, ECL1N-0045). An interception point that
runs in a process, container or account in which the governed AI system can
execute code, or that the governed AI system can start, stop or reconfigure,
MUST NOT be claimed as an ECL enforcement point; it MAY carry an AARM decision
to an ECL decision point.

**AB1-011** — Telemetry that the AARM control plane exports under R8 MUST be
treated as a copy: when it carries ECL decisions or evidence it MUST follow
OTEL-EVIDENCE-EXPORT-1, and it MUST NOT be the record a claim relies on for
ECL1N-0047, FR-107 or FR-108.

**AB1-012** — A credential that an AARM deployment issues for an admitted action
under R9 MUST NOT carry more authority than the action's ECL authorization: no
wider scope, no other audience, no later expiry and no more uses; it MUST NOT be
held by the governed AI system; an OAuth access token meets this requirement
when it follows OAUTH-AUTHORITY-1.

## Decision basis

**AB1-013** — The `inputs` of an exchange record MUST be the entries of the
decision basis that its `response` records in `ecl.ext.decision-basis.v1`: each
input of the record, without its `aarm_requirement`, MUST equal the entry of the
extension's value whose `input` is the same, and each entry MUST appear in the
record exactly once. A response that does not carry the extension records no
inputs, and a response that carries it more than once matches no record. A
record that breaks this MUST be reported as the verification finding
`ecl.rule.aarm-inputs-match-basis.v1`. The record's `response`, and its
`modification_response` when it holds one, MUST each carry exactly one
`ecl.ext.decision-basis.v1` and MUST also satisfy DCMP2-053, each with the
record's `request` or `modification_request` as the request it answers, with the
response clock-skew allowance of the reference verification profile, zero
(DCMP2-047); a record whose response fails either MUST be reported with
`ecl.rule.decision-basis-one-way.v1`. Each DCMP-2 message that the record holds
MUST satisfy the semantic rules of DCMP-2, and a record that holds one that
fails a rule MUST be reported with that rule. The decision basis of the record's
`modification_response` MUST carry the `register` reference of the decision
basis of the `response`, member for member, and MUST record the same inputs,
compared as input names are, each with the `class`, `required`, `source` and
`derived_from` that the record's `inputs` give it; a record that breaks this
MUST be reported as `ecl.rule.aarm-inputs-match-basis.v1`.

The record is the adapter's account of a decision, and the response is the
decision point's signed account of the same decision. If the two could
disagree, each could pass its own check: a record could class an AARM output as
`judgment` while the signed basis classes it `verifiable` and rests the `admit`
on it. The record's inputs use the vocabulary of the decision basis (an entry
of `ecl.ext.decision-basis.v1` with the AARM requirement added), so every
member is compared, including the status and reference of an input that was
unavailable, late or malformed and the effect of each input. Agreement alone
would let a record and its response agree on a basis that breaks the one-way
rule, such as an `admit` while a required input was unavailable, or a
`verifiable` input computed from the intent-alignment score; the response is
therefore held to DCMP2-053 as it would be in a signed evidence bundle.

The decision basis of the modification response is compared with the record for
the same reason, since its `admit` releases the modified action. The new request
is the original action with the modified parameters (AB1-004), of the same
action class, so the register version declares the same inputs for both
decisions; the status, effect, reference and times of each input describe the
new decision and may differ. The new request is decided under the register
version of the first decision; if that version is no longer in force, the
modification is not admitted.

## Decision mapping (informative)

| AARM decision | ECL outcome | Release | Notes |
| --- | --- | --- | --- |
| ALLOW | `admit`, or `deny` when ECL policy over `verifiable` inputs does not permit the action | Only on a verified `admit` | The AARM decision is one input; ECL's own authority, scope, validity, budget and approval checks still apply. |
| DENY | `deny` | None | The reason code `ecl.reason.native-policy-disposition.v1` keeps the AARM reason in its detail. |
| MODIFY | `deny` of the original; a new request for the modified action, if it is to go ahead | Only the new request's admitted parameters | The new request names the original with `ecl.relation.modification-of.v1`. A MODIFY that changes the target or operation has no new request (AB1-004). |
| STEP_UP | `challenge` (or `hold`) until the approval is recorded | None until a new evaluation admits | The approval follows ECL1N-0174 and EBMP2-063. |
| DEFER | `hold` | None | The deadline and a `safe_state` that releases nothing decide expiry (AB1-005). |

## Receipt fields (informative)

| AARM receipt field (pinned R5 list) | ECL counterpart |
| --- | --- |
| Action: tool, operation, parameters, timestamp | DCMP-2 request `action.operation`, `action.parameters` and `action.parameters_digest`, `issued_at` |
| Context: session identifier, accumulated context | `workflow.workflow_id`; accumulated context is a `judgment` input recorded by digest |
| Identity: human principal, service identity, agent identity, role or privilege scope | `subject`, `issuer`, `actor`; scope is checked against the ECL authorization |
| Decision: result, policy matched, reason | DCMP-2 response `outcome`, `policy` and `reasons` |
| Approval | EBMP-2 `human_intervention` event with `ecl.ext.approval-record.v1` |
| Deferral | `hold` response, its deadline and the follow-up evaluation |
| Outcome | `execution_terminal` event state and `side_effects` |
| Signature | Not mapped: ECL evidence carries its own INTEGRITY-ENVELOPE-1 signatures, and the receipt keeps its own |

## Exchange record (informative)

An `ecl_aarm_exchange_v1` record holds one action's exchange. Its members are
the `role`; the `aarm_decision` with its `decision`, `decided_at`, the
`deadline` of a DEFER or STEP_UP and the `modified_parameters` of a MODIFY; the
`inputs` of the ECL decision, each an entry of the decision basis (`input`,
`class`, `required`, `status`, `effect` and, where they apply, `reference`,
`source` and `derived_from`) with the `aarm_requirement` it comes from, the AARM
decision itself listed once as `R4` in the judgment-source role; the DCMP-2
`request` and `response`, and for a MODIFY whose modified action went ahead the
`modification_request` and `modification_response`; a `release` member only when
the action was released; and the `receipt` with the `terminal` event that binds
it. The `inputs` are the inputs that the response records in
`ecl.ext.decision-basis.v1` (AB1-013). The rules registered for this profile,
whose names begin `ecl.rule.aarm-`, check a record after its schema.

## Security considerations

In the Decision Layer role a compromised control plane is a compromised
decision point: it can admit requests that policy does not permit, within what
DCMP2-044 to DCMP2-050 bind; the claim's independence class and Section 9.8 of
the core standard bound that risk. In the judgment-source role its outputs
cannot be the basis of an `admit`, so a compromised control plane can make
outcomes stricter and cannot widen ECL authority. Intent alignment and semantic
distance are computed over content that the governed AI system influences, and
an embedding model can be steered; that is why the profile classes them as
`judgment`. An AARM receipt signed with a key that the governed AI system can
use gives no assurance against that system; the ECL evidence-signing key
custody rules (Section 9.8 of the core standard) apply to the ECL evidence that
binds the receipt. Instrumentation inside the governed AI system's own process
can be disabled or bypassed by that system, which is why AB1-010 never lets it
count as an enforcement point. SDK instrumentation can also miss paths it does
not instrument, so the register's reconciliation with the reachable capability
inventory (ECL1N-0008) decides which paths the claim covers.

## Conformance

| Kind | What the citation establishes |
| --- | --- |
| Vectors | The `aarm-binding` suite accepts a MODIFY that ends in `deny` with no new request and no release, and refuses an outcome weaker than the mapped decision, a modification released under the original request, not linked to it, or whose new request carries a number where the modified parameters hold a boolean, a modification response without its new request, a new request recorded, and released, after a decision other than MODIFY, a deferral that outlasts its deadline or expires into a fail-open state, an AARM output classed as anything but `judgment` or used as the basis of an `admit`, the `admit` that releases a modification among them, an AARM decision listed without its requirement in the judgment-source role, a release without an `admit`, outside its window or with other parameters, and a receipt whose digest, decision or parameters disagree with the ECL evidence; the `binding-basis` suite refuses a record whose inputs disagree with the decision basis of its response, and a record whose response or modification response carries no decision basis, or records one that breaks DCMP2-053 |
| Assessor procedure | Role declarations, interception points, telemetry, credential scoping, and how the deployment derives each action's target and operation from its parameters, which decides whether a MODIFY can be applied, so that no modification that changes them is released (AB1-004) |

The vectors establish the behavior of exchange records, not the conformance of
an AARM product, and this profile claims no AARM conformance or endorsement.
