# DCMP-2: Decision and Control Message Protocol

Version: 2.0 (wire `schema_version` `2.0`)
Status: normative companion of ECL-1 Version 1.0, a published version
Schema: `schemas/dcmp-2.schema.json`
Registry dependencies: algorithm suites, extensions, errors, semantic rules

## 1. Purpose

DCMP-2 transports the facts needed to evaluate and control an ECL action. It
does not execute the action and does not itself prove that an external effect
occurred. It connects Decision, Authority, and Enforcement while preserving the
causal inputs that Provenance and Verification need.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL are to be interpreted as
described in BCP 14 when, and only when, they appear in all capitals.

## 2. Conformance surface

**DCMP2-001** — A DCMP-2 producer MUST emit an object that satisfies the
published JSON Schema and all applicable semantic rules.

**DCMP2-002** — A DCMP-2 consumer MUST perform strict JSON parsing before
schema validation. Duplicate members, floating-point values, negative zero,
integers outside the interoperable exact range, invalid Unicode scalar values,
noncharacters and non-JSON constants MUST be rejected, in the order and with the
findings of INTEGRITY-ENVELOPE-1 IE1-037.

**DCMP2-003** — Schema validation alone MUST NOT be represented as complete
DCMP-2 validation.

**DCMP2-004** — Every message MUST carry `protocol`, `schema_version`,
`message_type`, `message_id`, `workflow`, `issuer`, `issued_at`, `extensions`,
and `integrity_policy`.

**DCMP2-005** — The pair of a logical `message_id` and the digest of the
canonical message payload identifies an immutable message version. Reuse of a
logical identifier with different content MUST be treated as a collision or
superseding version, never as the same immutable object.

## 3. Message types

DCMP-2 defines:

- `decision_request`
- `decision_response`
- `challenge`
- `challenge_response`
- `control`

An extension cannot create a message type whose semantics alter a core state
transition unless that extension is registered as critical and explicitly
permitted by the active profile.

### 3.1 Decision request

**DCMP2-006** — A decision request MUST identify the actor, any distinct
subject, the action, target, operation, parameter digest, constraints, risk
class, required evidence profile, requested authority audience, requested
validity, authority use policy, and its expiry time in `expires_at`.

**DCMP2-007** — If parameters are carried in-band in `action.parameters`,
`action.parameters_digest` MUST be the `ecl.digest.sha-256.v1` digest of the
restricted canonical JSON (IE1-001) of that value. A consumer MUST reject a
mismatch with `ecl.rule.parameters-digest-matches.v1`.

**DCMP2-008** — A mutable resource reference used in a consequential decision
MUST include a digest, version, immutable snapshot reference, or a profile-
defined witness that makes the evaluated state reconstructable.

**DCMP2-009** — Actor and subject MUST remain distinct through delegation. A
consumer MUST NOT infer that a workload is the legal, organizational, or human
subject merely because it submitted the request.

**DCMP2-010** — Each delegation hop MUST be independently referencable,
integrity-verifiable, audience-bound, expiry-bounded, and scope-attenuating.
An elevation is a new authority root, not an attenuation hop.

**DCMP2-011** — An idempotency key MAY identify an intended effect boundary,
but MUST NOT replace the unique message, action, attempt, decision, authority,
or receipt identifiers.

**DCMP2-054** — `action.risk_class`, `constraints`, `action.budget_debit`, and
the `witness_reference` and `capability_manifest` of
`ecl.ext.consequence-coupling.v1` in a request are statements of the governed
AI system: each is an `actor_supplied` decision input (ECL1N-0178) unless the
Decision Layer authenticates its origin as ECL-1 Section 4.3 requires. Each MAY
make the outcome stricter, and the Decision Layer MUST debit each consequence
budget by at least the amount its policy computes from the action's parameters,
whatever `budget_debit` declares.

**DCMP2-055** — A request's `action.budget_debit.amount` MUST be written
without a sign, so that no declared debit is negative. A consumer MUST reject a
request whose `amount` begins with `-` with
`ecl.rule.budget-debit-non-negative.v1`.

The registered extension `ecl.ext.runtime-configuration.v1` identifies the
recorded version of the governed AI system that requested the action, as
ECL1N-0171 requires at `L2` and above: its `configuration` member is a reference
that carries a version and a digest. It does not change admission semantics.

### 3.2 Decision response

The response outcomes are:

- `admit`: the Decision responsibility permits the exact request under stated
  policy and obligations;
- `deny`: the request is rejected as a terminal decision for that version;
- `hold`: no release is permitted until a separately defined condition
  changes;
- `challenge`: evaluation cannot finish until specified evidence or input is
  supplied.

**DCMP2-012** — A response whose outcome is not `admit` MUST NOT carry an
`authorization` object.

**DCMP2-013** — An `admit` response MUST carry an authorization object whose
audience, scope digest, validity interval, and use policy bind the exact release
authority. A consumer MUST reject an `admit` response whose `authorization` is
absent or not an object, or lacks any of `authorization_id`, `audience`,
`scope_digest`, `valid_from`, `valid_until` and `use_policy`, with
`ecl.rule.admit-requires-valid-authority.v1`; how these members bind the request
is checked under DCMP2-044 to DCMP2-050, and the order of the interval under
DCMP2-032.

**DCMP2-014** — A deny, hold, challenge, expired, revoked, cancelled, or
superseded message MUST NOT be interpreted as release authority.

**DCMP2-015** — An authorization validity interval MUST be non-empty, MUST be
contained within any governing decision and delegation validity interval, and
MUST NOT exceed the active profile maximum.

**DCMP2-016** — Every response MUST bind the policy identifier, version,
digest, and applicable policy epoch. A label without a digest is insufficient
for a claim requiring replay.

**DCMP2-017** — Obligations with `before_release` satisfaction MUST be proven
at Enforcement before the action is released. An unproven pre-release
obligation converts the effective disposition to the declared safe state.

**DCMP2-018** — `hold` and `challenge` MUST carry or causally reference the
condition for progress, a deadline where time-bounded, and the timeout
disposition.

The registered extension `ecl.ext.consequence-coupling.v1` carries the
consequence-coupling controls that a request invokes (FR-102) and their results
in a response (FR-103). Its value schema is
`https://externalcontrollayer.ai/ns/schema/extension/consequence-coupling/1`. A
response reports a consequence-budget result as `budget_result`, a state-witness
result as `witness_result`, a heterogeneous-quorum result as `quorum_result`,
and a condition that blocks release as `blocker_reason`. A witness result of
`required_before_release` defers the witness check to Enforcement, which proves
it before release under DCMP2-017.

**DCMP2-052** — An `admit` response MUST NOT carry, in
`ecl.ext.consequence-coupling.v1`, a `budget_result` whose outcome is not
`authorized`, a `witness_result` whose outcome is neither `satisfied` nor
`required_before_release`, a `required_before_release` witness result without an
obligation whose satisfaction is `before_release`, a `quorum_result` whose
outcome is not `met`, or a `blocker_reason`. A consumer MUST reject such a
response with `ecl.rule.coupling-results-permit-admit.v1`, after validating the
extension's value against its value schema (XR1-023).

The registered extension `ecl.ext.decision-basis.v1` records the basis of a
decision, as ECL1N-0181 requires of the evidence of each decision. Its value
schema is
`https://externalcontrollayer.ai/ns/schema/extension/decision-basis/1`. Its
`register` member names the version of the Consequential Action Register under
which the decision was made, by reference and digest. Each entry of `inputs`
names a decision input that the register declares for the action class
(`input`), its declared class (`class`: `verifiable`, `actor_supplied`, or
`judgment`), whether the action class requires it (`required`), whether it was
`available`, `unavailable`, `late`, or `malformed` (`status`), its value by
reference and digest when available (`reference`), and its effect on the
outcome (`effect`): `supports` when it is part of the basis on which the
verifiable-only outcome (ECL-1 Section 4.3) permits the action, whatever the
final outcome, `restricts` when it made the outcome stricter, and `none` when
it had no effect. Each entry also names the input's `source`, as the register
declares it, and can name, in `derived_from`, the other inputs of the record
from which the input was computed. The value can also give `verifiable_only_outcome`, the decision's
verifiable-only outcome (ECL-1 Section 4.3), and `received_at`, the time at
which the Decision Layer received the request, from which every deadline is
counted (ECL1N-0178); an entry can give `obtained_at`, the time at which the
Decision Layer obtained the input, and `value_at`, the time that the input's
value describes, whose age is taken at the response's `evaluated_at`, the time
of the decision (ECL1N-0182). A register that declares no input for the action
class gives a record with no `inputs` entry. A DCMP-2 message validated on its
own is valid without the extension; an evidence verifier requires it on every
decision response, as DCMP2-053 states.

**DCMP2-053** — A response that carries `ecl.ext.decision-basis.v1` MUST NOT
list one `input` more than once, MUST NOT record an `actor_supplied` or
`judgment` input, or an input whose `status` is not `available`, with the
`effect` `supports`, and MUST NOT record as `verifiable` an input whose
`derived_from` names an input that is not `verifiable`; each name in
`derived_from` MUST be the `input` of another entry of the record, and the
inputs that `derived_from` names, followed through other entries, MUST NOT
include the entry itself. An `admit` response that carries it MUST record at
least one `verifiable` input with the `effect` `supports`, and MUST NOT record
an input whose `required` is `true` and whose `status` is not `available`. When
the extension gives `verifiable_only_outcome`, the response's `outcome` MUST NOT
come before it in the strictness order `admit`, `challenge`, `hold`, `deny` of
ECL-1 Section 4.3; an entry MUST NOT have the `effect` `supports` unless it is
`admit`; and when it is `admit`, at least one `verifiable` entry MUST have the
`effect` `supports`, and an entry whose `class` is `verifiable` and whose
`required` is `true` MUST have the `status` `available`. In these conditions an
input also counts as not `available` when its `derived_from` names, directly or
through other entries, an input whose `status` is not `available` (ECL-1 Section
4.3). An entry whose `obtained_at` is later than the response's `evaluated_at`
MUST NOT be `available`, and an extension whose entries give `obtained_at` MUST
give `received_at`, no later than `evaluated_at`. When the extension gives
`received_at`, every entry whose `status` is `available` MUST give `obtained_at`
and `value_at`. An entry's `value_at` MUST NOT be later than its `obtained_at`
or than the response's `evaluated_at`. Input names are compared, within the
record and with a register, after the case normalization of RFC 3986 section
6.2.2.1 and RFC 8141 section 3.1: the URI scheme, the namespace identifier of a
URN and the host of an `http` or `https` URI are lowercased, and the two
hexadecimal digits of each percent-encoding are uppercased; no other
normalization is applied. A consumer MUST reject a response that fails these
conditions with `ecl.rule.decision-basis-one-way.v1`, after validating the
extension's value against its value schema (XR1-023). An evidence verifier MUST
reject a decision response that does not carry the extension with
`ecl.rule.decision-basis-required.v1`, and MUST reject,
with `ecl.rule.decision-basis-one-way.v1`, a response whose extension records as
`verifiable` an input whose `source` is the `actor` of the response's request,
compared as input names are, because an input that the governed AI system
produces is `actor_supplied` (ECL-1 Section 4.3, ECL1N-0178), or gives a
`received_at` earlier than the request's `issued_at` by more than the response
clock-skew allowance of DCMP2-047. A verifier MUST refuse, as a usage error, a
register that fails its schema or `ecl.rule.register-declarations-consistent.v1`
(ECL1N-0178), among them a register that declares an action class, or an input
of one class, more than once. A verifier given a version of the register MUST
reject, with `ecl.rule.decision-basis-matches-register.v1`, a response whose
extension names another register version; whose `inputs` are not exactly the
inputs that the register declares for the request's action class, each once,
with its declared class, required flag, `derived_from` (an absent `derived_from`
naming no input) and `source`, the source compared as input names are; or that
records as `available` an input whose `obtained_at` is more than its declared
`deadline_milliseconds` after `received_at`, or whose `value_at` is more than
its declared `maximum_age_seconds` before the response's `evaluated_at`.

The actor check compares one identifier, the request's `actor.id`: an input
that the governed AI system supplies under another name, such as the identity
of one of its tools or of its workload, is not detected by name.

### 3.3 Challenge exchange

**DCMP2-019** — A challenge MUST identify the original request, a unique
challenge, required evidence or actions, a deadline, and `on_timeout`.

**DCMP2-020** — A challenge response MUST reference both challenge and request
and MUST carry immutable evidence references. It is not a decision response.
Evidence that a challenge response references is an `actor_supplied` decision
input (ECL1N-0178) unless the Decision Layer authenticates it from its source,
as ECL-1 Section 4.3 requires.

**DCMP2-021** — Challenge satisfaction MUST cause a new evaluation and a new
decision response. It MUST NOT mutate or retroactively convert an earlier
response.

**DCMP2-056** — A request that continues a request answered with a decision
response whose outcome is `challenge` MUST be a new decision request (DCMP2-021,
DCMP2-026): a new `message_id`; the continued request's `workflow.workflow_id`
and `workflow.root_trace_id`; a `workflow.attempt` greater than the continued
request's; and an `action`, `actor`, `subject` and `authority_request` equal to
the continued request's. It MUST carry `continues` with `request_id`, the
continued request's `message_id`; `response_id`, the `message_id` of the
challenge response; and `approval_id`, the `object_id` of the EBMP-2
`human_intervention` event whose `operation` is `approve` and whose `target_id`
is the continued request's `message_id`. It MUST list that response and that
event among its `workflow.causal_predecessors`, each by identifier and digest.
The continued request keeps its one response, the challenge, and its attempt
ends in the `challenged` state; the continuation's response is the one that can
authorize a release. `protocols/examples/dcmp-2-continuation.json` shows a
continuation with the objects it names.

**DCMP2-057** — The Decision Layer MUST evaluate a continuation afresh under the
policy in force at its evaluation and MUST NOT copy the outcome, authorization or
obligations of the continued response. The approval is a decision input of that
evaluation and nothing more: it stands only for the action, actor, subject and
requested authority of the continued request, as presented to the approver
(ECL-1 ECL1N-0174), and a continuation that changes any of them is not covered by
it. The Decision Layer MUST NOT admit a continuation on an approval that was
issued after the challenge's deadline, whose `expires_at` is at or before the
continuation's evaluation, whose approver or approval key is revoked at that
evaluation, or that a control message has revoked; nor on an approval that
another continuation has already used; nor when the policy in force no longer
accepts that approver for the action. It MUST then answer the continuation with
a new response, a new `challenge` or a `deny`, and never by changing an earlier
response.

### 3.4 Control message

Control operations are `cancel`, `revoke`, `supersede`, `quarantine`, and
`halt`.

**DCMP2-022** — A control message MUST identify the controlled object
(`target_id`), effective time, issuer, authority context, reason, and any
required safe state. The authority context is the `authority` member: the
control plane the message is issued on (`ordinary` or `emergency`) and a
digest-bound reference to the grant under which the issuer acts.

**DCMP2-023** — `supersede` MUST identify the replacement object. The
replacement does not erase the superseded object or its effects.

**DCMP2-024** — A cancellation or revocation received after release MUST be
recorded and applied according to the action's interruptibility and
compensation profile. It MUST NOT be reported as proof that an already
completed effect did not occur.

**DCMP2-025** — A `halt` or `quarantine` control message MUST be issued on the
separately authenticated emergency control plane that FR-004 requires at every
level, and MUST declare `authority.plane` as `emergency`. A consumer MUST reject
a `halt` or `quarantine` declared on the ordinary plane with
`ecl.rule.emergency-control-plane-required.v1`.

## 4. Workflow and causality

**DCMP2-026** — Retries MUST create a new message identifier and attempt
number. The prior attempt remains immutable.

**DCMP2-027** — A message MUST NOT list itself as a causal predecessor.

**DCMP2-028** — A causal reference MUST bind both the predecessor's logical
identifier and canonical digest.

**DCMP2-029** — Within one workflow sequence domain, a predecessor sequence
MUST be lower than its successor sequence. The sequence domain of a message is
the workflow that its `workflow.workflow_id` names (EBMP2-025). Sequence values
do not establish global ordering across domains.

**DCMP2-030** — Forks, joins, delegated sub-workflows, and human interventions
MUST be represented through explicit workflow and causal references rather
than inferred from timestamps.

## 5. Time and expiry

**DCMP2-031** — `issued_at`, `expires_at`, `evaluated_at`, validity intervals,
and deadlines MUST be UTC RFC 3339 values in the restricted ECL timestamp
profile.

**DCMP2-032** — An expiry MUST be later than issue. An authorization end MUST
be later than its start. A nonpositive message or authorization interval MUST
report `ecl.rule.expiry-after-issue.v1`. The authorization interval ordering
fact alone MUST NOT also emit `ecl.rule.admit-requires-valid-authority.v1`;
distinct authority defects remain applicable, and primary selection follows
DCMP2-043.

**DCMP2-033** — Wall-clock timestamps alone MUST NOT override a causal
relationship or trusted sequence observation.

**DCMP2-034** — A verifier MUST apply the declared verification-time and clock-
skew policy. A local parser default is not a trust policy.

## 6. Integrity and extension behavior

**DCMP2-035** — A message used to release an in-scope action MUST satisfy its
payload-bound integrity policy.

**DCMP2-036** — A consumer MUST reject signature-suite substitution, key
substitution, an unmet signature threshold, a missing required signer,
unacceptable trust material, or stale revocation material.

**DCMP2-037** — Extension identifiers and versions MUST be unique within a
message.

**DCMP2-038** — An unknown critical extension, in the sense of XR1-006, MUST
cause rejection before admission or release. An unknown non-critical extension
MUST be preserved and reported and MUST NOT change core semantics.

## 7. Failure and safe behavior

**DCMP2-039** — Failure output MUST identify one stable primary error code and
MAY carry registered subcodes and bounded detail.

**DCMP2-040** — A parse, schema, semantic, integrity, trust, expiry, replay,
revocation, or unknown-critical-extension failure MUST NOT produce an effective
admit.

**DCMP2-041** — A timeout or unavailable remote dependency MUST apply the
profile's declared action-class safe-state rule. Fail-open MUST NOT arise from
an exception handler, library default, or missing configuration.

**DCMP2-042** — A consumer MAY support DCMP-1 during a declared transition
window, but MUST NOT silently coerce a DCMP-1 object into DCMP-2 or claim
DCMP-2 conformance for an unmapped field.

**DCMP2-043** — A conformant validator MUST report exactly one primary error per
invalid artifact: a strict-input failure first, with the finding of the first
check of INTEGRITY-ENVELOPE-1 IE1-037 that fails, then schema invalidity, then
the violated semantic rules in ascending order of the `precedence` value that
the semantic-rule registry gives them; every other violated rule MUST be
reported as a secondary finding, and the primary selection MUST be
deterministic for identical input. A strict-input failure has no secondary
findings. After a schema failure, or a value-schema failure of a registered
extension (XR1-023), a validator MUST evaluate each semantic rule whose input
members are present with the types that the schema requires, and MUST report
its violations as secondary findings. A binding profile's rules apply only to a
record that satisfies the record's schema, so a schema-invalid binding record
has no secondary findings. A signed evidence bundle orders its findings by
EBMP-2 EBMP2-068.

## 8. Response binding

A response is valid for release only as the answer to one exact request. These
rules state what binds the two. A verifier, an enforcement point and an
evidence consumer apply them in the order listed and report the first failure
with the error code named for it, or with `ecl.error.request-binding-invalid.v1`
where none is named. A member a rule reads that is missing or of the wrong type
fails that rule.

**DCMP2-044** — In an `admit`, `authorization.scope_digest` MUST be the
`ecl.digest.sha-256.v1` digest of the restricted canonical JSON of an object
with exactly two members: `request_id`, set to the request's `message_id`, and
`action`, set to the request's complete `action` object. A consumer MUST reject
any other value with `ecl.error.scope-mismatch.v1`.

**DCMP2-045** — A response's `request_id` MUST equal its request's `message_id`,
and its `workflow_id`, `root_trace_id` and `attempt` MUST equal the request's.

**DCMP2-046** — A response MUST carry exactly one causal predecessor with the
relation `ecl.relation.responds-to.v1`; that predecessor's `id` MUST be the
request's `message_id` and its digest MUST be the `ecl.digest.sha-256.v1` digest
of the request's restricted canonical JSON. A consumer MUST report a failure of
this rule with `ecl.error.digest-mismatch.v1`. Predecessors with other
relations are permitted.

**DCMP2-047** — A response's `issued_at` MUST NOT be earlier than its request's
`issued_at` by more than the response clock-skew allowance that the
verification profile declares. The reference verification profile
(`ecl.verification-profile.reference.v1`) declares an allowance of zero.

**DCMP2-048** — In an `admit`, `authorization.audience` MUST equal the request's
`authority_request.audience`, reported as `ecl.error.audience-mismatch.v1` when it
does not, and `authorization.use_policy` MUST equal the request's
`authority_request.use_policy`.

**DCMP2-049** — In an `admit`, the authorization window MUST be non-empty and no
longer than the request's `requested_validity_seconds`; `valid_from` MUST NOT be
earlier than the response's `issued_at`; `valid_until` MUST NOT be later than the
response's `expires_at` when the response has one, and MUST NOT be later than the
response's `issued_at` plus `requested_validity_seconds`.

**DCMP2-050** — In an `admit`, a `single_use` authorization MUST omit `max_uses`
or set it to 1, and when the request carries `authority_request.max_uses` the
authorization MUST carry a `max_uses` that is not greater.

**DCMP2-051** — A consumer MUST NOT release an action on a response that fails
any of DCMP2-044 to DCMP2-050, and an evidence verifier MUST report such a
response as not binding its request.

## 9. Security notes

Parameter digests do not make unsafe parameters safe. Signatures do not prove
the signer was authorized. A fresh nonce does not prove an effect has not
already occurred. A decision response does not prove Enforcement observed or
honored it. Those properties require the Authority, Enforcement, Provenance,
Verification, and Fleet evidence defined by ECL-1 and EBMP-2.
