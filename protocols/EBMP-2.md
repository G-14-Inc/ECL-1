# EBMP-2: Evidence Bundle and Manifest Protocol

Version: 2.0 (wire `schema_version` `2.0`)
Status: normative companion of ECL-1 Version 1.0, a published version
Schemas: `schemas/ebmp-2.schema.json`; signed evidence bundles
`schemas/ecl-evidence-bundle-v1.schema.json`; native adapter bindings
`schemas/ecl-adapter-binding-v1.schema.json`

## 1. Purpose

EBMP-2 is an event-and-manifest protocol for reconstructing why an action was
or was not released, what was observed, what effects remain, how evidence was
verified, and what happened to that evidence over time.

An EBMP-2 record is an authenticated statement by its producer. It does not
make the statement true merely because the signature verifies. Conformance
requires both integrity and evidence-fidelity analysis.

The BCP 14 interpretation stated in DCMP-2 applies to this document.

Requirement identifiers are allocated in the order requirements were added and
never reused, so a later identifier appears among earlier ones where its subject
belongs: EBMP2-065 and EBMP2-066 follow EBMP2-011, EBMP2-070 and EBMP2-071
follow EBMP2-015, EBMP2-069 follows EBMP2-045, EBMP2-072 follows EBMP2-050,
EBMP2-075 follows EBMP2-051, EBMP2-073 follows EBMP2-052, EBMP2-074 follows
EBMP2-055, EBMP2-077 follows EBMP2-029, EBMP2-078 follows EBMP2-058, and
EBMP2-067, EBMP2-068 and EBMP2-076 are in section 11.

## 2. Evidence primitives

EBMP-2 defines:

- event records;
- immutable resource references;
- causal predecessor references;
- bundle manifests;
- closure reports;
- verification events;
- lifecycle events.

**EBMP2-001** — Every record MUST satisfy schema, semantic, canonicalization,
extension, and integrity requirements applicable to its profile.

**EBMP2-002** — Every record MUST identify its logical object, exact content
through a canonical digest when referenced, workflow, root trace, attempt,
sequence, producer, observation time, event type, extensions, and integrity
policy.

**EBMP2-003** — A record producer MUST be identified separately from the actor,
subject, decision service, authority issuer, enforcement point, verifier, and
evidence custodian whenever those roles differ.

**EBMP2-004** — A verifier MUST treat a producer's event as a claim with a
declared observation boundary, not as omniscient ground truth.

## 3. Event types

The core event types are:

- `request_received`
- `decision_recorded`
- `authority_issued`
- `authority_consumed`
- `release_prepared`
- `execution_released`
- `execution_observed`
- `execution_terminal`
- `human_intervention`
- `verification`
- `safe_state_transition`
- `fleet_transition`
- `lifecycle_transition`

**EBMP2-005** — A profile MAY require additional registered critical events.
An unregistered event cannot silently redefine a core state.

Section 9 (EBMP2-046) fixes the event kind, and for authority and execution
events the states, that each core event type carries.

### 3.1 Decision and authority events

**EBMP2-006** — A decision event MUST reference the exact DCMP-2 decision,
record its outcome, and bind the evaluated policy.

**EBMP2-007** — An authority event MUST identify the authority and its state:
`issued`, `active`, `consumed`, `revoked`, `expired`, or `superseded`.

**EBMP2-008** — Consumption MUST be separately recorded for a single-use
authority. A release without provable consumption is nonconformant where the
profile requires replay prevention.

**EBMP2-009** — Revocation, expiry, and supersession MUST NOT delete an
authority record and MUST NOT be treated as proof that a prior release did not
occur.

### 3.2 Execution events

The execution progression is:

`not_started -> prepared -> released -> running -> terminal`

Terminal execution outcomes are:

- `succeeded`
- `failed`
- `partially_succeeded`
- `cancelled`
- `timed_out`
- `rolled_back`
- `compensated`
- `unknown`

Non-execution terminal dispositions are:

- `denied`
- `held`
- `challenged`
- `expired_before_release`

**EBMP2-010** — An execution attempt MUST have a unique attempt identifier.

**EBMP2-011** — A terminal attempt MUST NOT return to a non-terminal state.
Further work requires a new attempt identifier and causal link. A consumer MUST
reject an `execution_terminal` event whose `event.state` is neither a terminal
execution outcome nor a non-execution terminal disposition, and an event of any
other type whose `event.state` is one of them, with
`ecl.rule.terminal-execution-state-consistent.v1`.

The states of one attempt move only forward along the progression above. This
table gives, for each state, the states that may follow it in the same attempt;
an attempt's first state may be any state, and nothing follows a terminal
outcome or a non-execution terminal disposition.

| State | States that may follow it |
|---|---|
| `not_started` | `prepared`, `denied`, `held`, `challenged`, `expired_before_release` |
| `prepared` | `released`, `cancelled`, `timed_out`, `denied`, `held`, `expired_before_release` |
| `released` | `running`, `succeeded`, `failed`, `partially_succeeded`, `cancelled`, `timed_out`, `unknown` |
| `running` | `succeeded`, `failed`, `partially_succeeded`, `cancelled`, `timed_out`, `rolled_back`, `compensated`, `unknown` |

**EBMP2-065** — The execution events of one attempt, those with the same
`event.action_id` and `event.attempt_id`, taken in ascending order of
`workflow.sequence` and then of `object_id`, MUST carry states in which every
state after the first is one that the table lists for the state before it. A
consumer MUST reject a bundle with an attempt that does not with
`ecl.rule.execution-state-transition-valid.v1`.

**EBMP2-066** — Every execution event with the same `event.action_id`,
`workflow.workflow_id` and `workflow.attempt` MUST carry the same
`event.attempt_id`, and one `event.attempt_id` MUST NOT appear with two
different such triples. A bundle verifier MUST report a bundle that breaks
this as invalid with `ecl.error.decision-binding-invalid.v1`.

**EBMP2-012** — `denied`, `held`, `challenged`, and
`expired_before_release` MUST NOT be reported as execution failures because the
governed action was not released.

**EBMP2-013** — A terminal event in `partially_succeeded`, `timed_out`,
`cancelled` or `unknown` MUST carry `side_effects`, listing every known side
effect (an empty array when none is known), and a non-empty `residual_state`
that states the residual uncertainty or references evidence that does. A
consumer MUST reject such an event that lacks either member with
`ecl.rule.terminal-execution-state-consistent.v1`.

**EBMP2-014** — Rollback and compensation are new effects. They MUST have
their own action, attempt, authority, outcome, and causal evidence; they do not
rewrite the original outcome.

**EBMP2-015** — A successful tool or API return MUST NOT be equated with
successful external effect unless the declared observation boundary supports
that conclusion.

The registered extension `ecl.ext.obligation-discharge.v1` records, on an
`execution_released` event, how Enforcement proved before the release the
obligations that DCMP2-017 leaves to it. Its value schema is
`https://externalcontrollayer.ai/ns/schema/extension/obligation-discharge/1`.

**EBMP2-070** — When the decision response that an `execution_released` event
records carries an obligation whose `satisfaction` is `before_release`, or
carries in `ecl.ext.consequence-coupling.v1` a `witness_result` whose `outcome`
is `required_before_release`, the event MUST carry
`ecl.ext.obligation-discharge.v1` with an entry for each such obligation: for an
obligation, an entry whose `obligation_id` and `type` are the obligation's `id`
and `type`; for the witness result, one whose `obligation_id` is the `uri` of
the result's `reference` and whose `type` is `ecl.obligation.verify-witness.v1`.
Each entry MUST record the `result` `satisfied`, the proof that Enforcement
checked by `reference` and by the `ecl.digest.sha-256.v1` digest of the proof's
RFC 8785 canonical form, the proof's `issuer`, when the proof was obtained
(`obtained_at`), when Enforcement checked it (`checked_at`) and, whenever the
proof's type declares a freshness bound, `fresh_until`, the instant after which
the proof no longer shows the obligation met, which MUST NOT be later than the
bound that the proof declares. The obligations that need an entry are those of
the signed response that the bundle holds and that EBMP2-058 pairs with the
event, never a list that the producer states elsewhere. When the proof is an ECL
object, a signed envelope of a registered type, the entry MUST carry it: the
object that `reference` names by its `message_id` or `object_id` is in the
bundle as its own object, a `verification` event among the `observations` and
any other object among the `envelopes`, and `digest` is that object's digest; a
proof that is not an ECL object is recorded by `kind`, `reference` and `digest`
only. The table after this rule gives, for each obligation type, the object
admitted as its proof, the member that binds the proof to the exchange and the
issuer that the decision names for it. A verifier MUST report with
`ecl.rule.prerelease-obligations-discharged.v1` an `execution_released` event
that binds its request and response (section 10) and that lacks the extension or
an entry for one of these obligations, or that carries an entry that:

1. names an obligation that the response does not carry, or one that another
   entry also names;
2. records a `result` other than `satisfied`;
3. has a `checked_at` later than the event's `observed_at`, or earlier than the
   response's `issued_at` by more than the response clock-skew allowance of
   DCMP2-047;
4. has a proof whose `obtained_at` is later than the entry's `checked_at`;
5. carries a proof whose signers, as the trust policy binds their keys to
   principals, are not exactly the issuer that the decision names for the
   obligation, compared as exact strings with no decoding and no
   normalization, or any of whose signing keys the trust policy binds to the
   requesting actor, or, for an approval obligation, carries an approval
   record whose signing keys do not all hold `ecl.purpose.approval.v1` in the
   trust-policy version that the record names; the entry's `issuer` is a
   label and is not the test;
6. names as its proof the `message_id` or `object_id` of an object in the
   bundle and gives a `digest` that is not that object's digest;
7. has a `fresh_until` that is not later than the event's `observed_at` plus
   its `release_guard_ms`, or carries a proof that declares a bound of its own,
   an approval record's `expires_at`, that is not later than the event's
   `observed_at` plus its `release_guard_ms`, whether or not the entry records
   `fresh_until`, or has a `fresh_until` later than that bound; or
8. carries a proof that is not a valid envelope under the trust policy, whose
   object type is not one that the obligation's type admits by the table, or
   that does not bind this exchange by the member that the table gives.

| Obligation type | Object admitted as its proof | Member that binds the proof to the exchange | Issuer that the decision names |
|---|---|---|---|
| `ecl.obligation.approval-record.v1` | A `human_intervention` event whose `operation` is `approve` and whose `actor` is the `approver` of the obligation's value | `target_id` equals the decision request's `message_id`, and one of its `causal_predecessors` names the request by `message_id` and digest | None: the approver is the record's actor, not its signer; in its place, every key that signed the record holds `ecl.purpose.approval.v1`, the purpose of an approval service |
| `ecl.obligation.verify-witness.v1`, a deferred witness result included | A `verification` event whose `decision` is `pass` and whose `subject.uri` is the witness | One of its `causal_predecessors` names the decision request by `message_id` and digest | The `source` of the witness result, when the response gives one; otherwise the decision names none |
| Any other type | Any EBMP-2 event record; a decision request or a decision response is never a proof | One of its `causal_predecessors` names the decision request by `message_id` and digest | None |

The rule belongs to stage 8 of EBMP2-068, and each condition is checked on the
members that are present with the types that the value schema gives them
(DCMP2-043). Conditions 5, 6 and 8 apply only to a proof that the bundle
carries; the first test of condition 7 applies to every entry that has
`fresh_until`, and its other two only to a carried proof. A verifier does not
check the digest, the signer or the type of a proof held elsewhere, and does not
tell from an uncarried proof's `kind` whether it is an ECL object. Where the
decision names no issuer for an obligation, a witness result without `source` or
an obligation of a type for which the table names none, the issuer test of
condition 5 is not made, its other tests stand, and the scope item
`prerelease-obligations-proofs-verified` is not established, with the reason
`issuer-not-named` (EBMP2-076); for an approval obligation the approval purpose
stands for the issuer. A discharge is the enforcement point's statement. A verifier that finds the record complete has checked that it names
every obligation that the response leaves to Enforcement and that it agrees with
the rest of the bundle, and, for a proof that the bundle carries, the proof's
signatures, issuer, type, binding and freshness; it has not checked that a proof
establishes what the obligation requires, or that the obligation was met, and
its report says so (EBMP2-076).

**EBMP2-071** — The `observed_at` of an `execution_released` event MUST be the
enforcement point's observation of the release boundary that its profile
declares, taken after every operation that can block or wait between the
decision and the release, such as writing the evidence of the consumed
authority, waiting for a lock or obtaining the proof of an obligation, other
than the recording of the `execution_released` event itself and the steps that
the enforcement point's profile bounds by a declared release guard; the event
MUST carry that guard as `release_guard_ms`, an integer number of milliseconds
from 1 to 60000, the declared bound on the delay from the observation to the
release, within which the release begins. It MUST NOT be an earlier time, such
as the time at which the event was built, the response was received or the
authority was consumed, when such an operation comes between that time and the
release. An enforcement point that observes, by its own clock immediately after
the release, that the authorization's `valid_until` had passed before the
release completed MUST record that in the terminal event of the attempt, in an
extension that it marks critical (XR1-005), and MUST NOT take that observation
from the time at which the point of effect answered. EBMP2-050 and EBMP2-072
compare these times with the authorization's validity window. A recorded time is
the producer's statement (EBMP2-004): no verifier establishes from the evidence
alone that it is the true time of the event.

An MCP gateway takes its final observation under the lock of MG1-014, after
reading its monotonic clock, then records the `execution_released` event with
its release guard, which it makes durable before the write (MG1-016), and opens
the connection to the server; MG1-014 bounds that interval by the declared
release guard and checks it again by a monotonic clock immediately before the
write. Immediately after the write returns it sets `released_after_valid_until`
in the `ecl.ext.mcp-binding.v1` of the terminal event when its own observation
shows that the write may have come after `valid_until`, and it records the time
at which the server answered as `forward_completed_at`, as MCP-GATEWAY-1
describes (MG1-015).

### 3.3 Human intervention

**EBMP2-016** — A human intervention event MUST identify the human or approved
organizational principal (`actor`), operation, target (`target_id`), authority
(`authority`), issue time (`issued_at`), expiry (`expires_at`), and reason
(`reason`).

**EBMP2-017** — An approval MUST expire, be supersedable, and be transaction-
bound. A generic chat statement or interface click without this binding is not
release authority.

An approval that discharges an obligation before a release shows the obligation
met only while it has not expired: the discharge records the approval's
`expires_at` as `fresh_until`, the enforcement point tests it at its final
observation before the release (MG1-013, MG1-014), and a verifier compares it
with the release time and the release guard (EBMP2-070, condition 7).

**EBMP2-018** — Dual-control profiles MUST preserve each independent approval
and prove that the required threshold was met before release.

The registered extension `ecl.ext.approval-record.v1` records what an approver
was shown (`presented`, a digest-bound reference), when it was shown
(`presented_at`), and the minimum review time that applied
(`minimum_review_seconds`). The registered extension `ecl.ext.control-change.v1`
records a change to an in-scope control: the control (`control`), the kind of
change (`change`: `disable`, `bypass`, `auto_approve`, `modify` or `restore`),
the digest of the change (`change_digest`), its requester (`requested_by`), its
approvers (`approved_by`), and when it takes effect and expires (`effective_at`,
`expires_at`). Their value schemas are named in the extension registry.

**EBMP2-063** — A human intervention event that approves or rejects and carries
`ecl.ext.approval-record.v1` MUST have an `issued_at` no earlier than
`presented_at` plus `minimum_review_seconds`. A consumer MUST reject one that does
not with `ecl.rule.approval-review-time-respected.v1`.

**EBMP2-064** — An event that carries `ecl.ext.control-change.v1` MUST name at
least one approver, none of whom is the requester, and a change of kind
`disable`, `bypass` or `auto_approve` MUST carry an `expires_at` later than its
`effective_at`. A consumer MUST reject an event that does not with
`ecl.rule.control-change-approved-and-bounded.v1`.

### 3.4 Verification and fleet events

**EBMP2-019** — A verification event MUST identify the verifier, subject,
rules applied, decision, findings (`findings`, empty when there are none),
registry versions (`registry_snapshot`, a digest-bound reference), and evidence
boundary (`evidence_boundary`, what the verifier observed and could not
observe).

**EBMP2-020** — `indeterminate` MUST remain distinct from `pass` and `fail`.
Missing evidence MUST NOT default to pass.

**EBMP2-021** — Fleet events MUST record relevant policy, trust-root, registry,
verifier, revocation, and evidence-export frontiers.

## 4. Causal closure

**EBMP2-022** — A causal predecessor reference MUST include the predecessor's
logical identifier and canonical digest.

**EBMP2-023** — A complete bundle MUST contain every required predecessor or
declare it as an external immutable dependency available to the verifier.

**EBMP2-024** — A causal graph MUST be acyclic.

**EBMP2-025** — Within one workflow sequence domain, causal predecessors MUST
have lower sequence values than successors. The sequence domain of a record is
the workflow that its `workflow.workflow_id` names; the sequence of a
predecessor in another workflow is not compared with its successor's.

Note (informative), sequence order across the whole graph: the rule applies to
every edge of the causal graph within one workflow, DCMP-2 messages and
observations included (EBMP2-059). A producer gives a record a sequence greater
than the sequence of every predecessor that it names in the same workflow. A
producer that shares no counter with the others, such as an independent observer
or an approval service, uses one more than the greatest such predecessor, which
it can always do because it holds those predecessors.

**EBMP2-026** — Timestamps MUST NOT be used to fabricate missing causal edges
or override contradictory sequence and digest evidence.

**EBMP2-027** — A bundle manifest MUST declare `complete`, `incomplete`, or
`indeterminate`, and enumerate terminal actions, open actions, and unresolved
predecessors.

**EBMP2-028** — A manifest claiming `complete` MUST be rejected if closure
recalculation yields any open action or unresolved required predecessor.

**EBMP2-029** — Bundle order is not semantic order. Consumers MUST derive
causal order from authenticated references and profile rules.

**EBMP2-077** — A causal predecessor MUST have its successor's
`workflow.root_trace_id`, and MUST be in its successor's workflow or in the
workflow that its successor's `workflow.parent_workflow_id` names, as a
child workflow names its parent. A predecessor in its successor's workflow
MUST NOT have a greater `workflow.attempt` than its successor: a later attempt
can follow an earlier one, never the reverse. A verifier MUST report a
predecessor that the bundle holds and that fails this rule with
`ecl.rule.bundle-causal-context-consistent.v1`.

## 5. Identity and integrity

**EBMP2-030** — A storage path, database primary key, display label, or tenant-
local sequence MUST NOT substitute for canonical content identity.

**EBMP2-031** — The exact immutable version of a record MUST be identified by
the pair of its logical identifier and canonical digest.

**EBMP2-032** — A conflicting digest for the same logical identifier MUST be
reported as a collision, equivocation, or explicit superseding version
according to authenticated lifecycle evidence.

**EBMP2-033** — Evidence needed for offline verification MUST include or
immutably reference the trust policy, verification material, registry
snapshots, revocation state, and time evidence required by the invoked profile.

## 6. Privacy and fidelity

**EBMP2-034** — Evidence collection MUST be limited to declared purpose and
data classes. Expanded evidence does not automatically mean better evidence.

**EBMP2-035** — Secrets, raw credentials, unnecessary personal data, and
unbounded reasoning transcripts MUST NOT be included merely to make a bundle
look complete.

**EBMP2-036** — A redacted artifact is a new derivative with a new identity.
It MUST bind the sealed source digest, redaction policy, transformation,
removed data classes, retained verifier-critical fields, producer, and time.

**EBMP2-037** — Redaction MUST NOT preserve a claim whose required verifier-
critical evidence was removed. The claim becomes bounded, indeterminate, or
failed as defined by the profile.

## 7. Lifecycle

**EBMP2-038** — Seal, verify, retain, export, redact, supersede, revoke, legal
hold, release hold, and destroy MUST be represented as append-only lifecycle
events.

**EBMP2-039** — A lifecycle event MUST reference the prior digest and active
lifecycle policy.

**EBMP2-040** — Redact and supersede MUST reference the derived artifact
(`derived_artifact`), and redact MUST also reference its redaction manifest
(`redaction_manifest`, EL1-014). A consumer MUST reject a
lifecycle event that lacks one of these references with
`ecl.rule.lifecycle-derived-artifact-required.v1`. Destroy MUST reference a
destruction proof where the profile requires one.

**EBMP2-041** — Legal hold MUST take precedence over scheduled destruction
until a separately authorized release-hold event.

**EBMP2-042** — Lifecycle metadata MUST NOT falsely claim physical deletion
beyond the observation and control boundary of its producer.

## 8. Error and version behavior

**EBMP2-043** — Each invalid vector MUST map to one stable primary error and
MAY map to registered subcodes.

**EBMP2-044** — An EBMP-1 adapter MUST identify every lossless, derived,
defaulted, omitted, and impossible field. It MUST NOT label a lossy conversion
as native EBMP-2.

**EBMP2-045** — A richer implementation-native receipt MAY coexist with
EBMP-2 only when a digest-bound causal relation and precedence rule identify
which artifact supports which claim.

**EBMP2-069** — A native adapter binding (`ecl_adapter_binding_v1`) binds one
retained implementation-native object to the ECL objects derived from it. A
consumer MUST reject a binding with `ecl.rule.adapter-source-binding-valid.v1`
unless each of the following conditions holds:

1. `binding_digest` is the `ecl.digest.sha-256.v1` digest of the restricted
   canonical JSON of the binding without its `binding_digest` member.
2. `binding_id` is `https://externalcontrollayer.ai/ns/adapter-binding/sha256/`
   followed by the lowercase hexadecimal SHA-256 digest of the restricted
   canonical JSON of an object with exactly five members: `system`, `contract`
   and `object_id`, each equal to that member of `source`; `object_digest`,
   equal to `source.object_digest.value`; and `ecl_object_ids`, the `object_id`
   of each `ecl_objects` entry, in order.
3. No two `ecl_objects` entries have the same `object_id`.
4. Each `ecl_objects` entry has the `protocol` `DCMP-2` and the `media_type`
   `application/vnd.ecl.dcmp+json`, or the `protocol` `EBMP-2` and the
   `media_type` `application/vnd.ecl.ebmp+json`.
5. No two `field_accounting` entries have the same `source_path`.
6. `loss_class` is `rejected` when the `disposition` of some `field_accounting`
   entry is `rejected`, otherwise `loss_accounted` when the `disposition` of
   some entry is `retained_source_only`, and otherwise `lossless`.
7. Each item of the `target_paths` of a `field_accounting` entry, and the
   `target_path` of each `derived_fields` entry, is a JSON Pointer (RFC 6901)
   whose first reference token is an array index in the sense of RFC 6901,
   section 4, less than the number of `ecl_objects` entries.
8. For each of the six responsibilities, its member of
   `responsibility_coverage` has the `status` `represented` exactly when some
   `ecl_objects` entry lists the responsibility in its `responsibilities`, and
   its `object_ids` are the `object_id` of each such entry, in the order of
   `ecl_objects`.
9. `authority_boundary` equals the one value that the schema allows for it.

On a binding that fails its schema, each condition is checked only when every
member it names is present with the JSON type that the schema requires
(DCMP-2 DCMP2-043), so that a member that one condition cannot read does not hide
the findings of the others. The conditions need only the binding. A consumer that
also holds the retained source object or a derived ECL object can compare that
object's digest with `source.object_digest` or with the `digest` of its entry.
The dispositions and loss classes are values of the binding; the categories of
EBMP2-044 name what an adapter identifies, and are not values of the binding.

## 9. Event kinds and states

**EBMP2-046** — An event record's `event.kind` MUST be the kind its
`event_type` requires, and an authority or execution event's `event.state` MUST
be one its `event_type` permits, as listed below. A consumer MUST reject a
mismatch with `ecl.rule.event-type-kind-consistent.v1`. The state of an
`execution_terminal` event is checked under EBMP2-011 only.

| `event_type` | `event.kind` | Permitted `event.state` |
|---|---|---|
| `request_received` | `request` | not applicable |
| `decision_recorded` | `decision` | not applicable |
| `authority_issued` | `authority` | `issued`, `active` |
| `authority_consumed` | `authority` | `consumed`, `revoked`, `expired`, `superseded` |
| `release_prepared` | `execution` | `prepared` |
| `execution_released` | `execution` | `released` |
| `execution_observed` | `execution` | `running` |
| `execution_terminal` | `execution` | checked under EBMP2-011 |
| `human_intervention` | `intervention` | not applicable |
| `verification` | `verification` | not applicable |
| `safe_state_transition`, `fleet_transition` | `state` | not applicable |
| `lifecycle_transition` | `lifecycle` | not applicable |

## 10. Event binding

These rules state what binds an event to the request and response it records.
An execution event binds its request and response when it meets EBMP2-047 to
EBMP2-049 and, for an `execution_released` event, belongs to an `admit`
response (EBMP2-050), or, for an `execution_terminal` event, meets EBMP2-051;
the validity window of EBMP2-050 is checked apart from the binding.
A verifier applies them in the order listed and reports the first failure with
the error code named for it, or with `ecl.error.decision-binding-invalid.v1`
where none is named. The digest of an object is its `ecl.digest.sha-256.v1`
digest over restricted canonical JSON. A member a rule reads that is missing or
of the wrong type fails that rule.

**EBMP2-047** — An `execution_released` or `execution_terminal` event MUST bind
its request: `event.action_id` MUST equal the request's `action.action_id`; when
the event carries them, `event.operation`, the algorithm and value of
`event.parameters_digest`, and `event.target.uri` MUST equal those of the
request's action; and the event's `workflow_id`, `root_trace_id` and `attempt`
MUST equal the request's.

**EBMP2-048** — When a response to the request exists, an execution event MUST
name it: `event.decision.uri` MUST equal the response's `message_id`,
`event.decision.digest` MUST be the response's digest (otherwise
`ecl.error.digest-mismatch.v1`), and the event's `workflow_id`, `root_trace_id`
and `attempt` MUST equal the response's. When no response exists, the event
MUST NOT carry `event.decision`.

**EBMP2-049** — An execution event that carries `event.authority` MUST belong to
an `admit` response; `event.authority.uri` MUST equal the authorization's
`authorization_id`, and `event.authority.digest` MUST be the digest of the
response's `authorization` object (otherwise `ecl.error.digest-mismatch.v1`).

**EBMP2-050** — An `execution_released` event MUST belong to an `admit`
response, its `observed_at` MUST NOT be earlier than the authorization's
`valid_from`, and its `observed_at` plus its `release_guard_ms` MUST be earlier
than the authorization's `valid_until` (otherwise `ecl.error.expired.v1`).

**EBMP2-072** — A verifier MUST report with `ecl.error.expired.v1`, as a finding
of stage 7 of EBMP2-068, an `execution_terminal` event that binds its request
and response and carries `ecl.ext.mcp-binding.v1` with
`released_after_valid_until` set to `true`, whatever the extension's `critical`
member says: the enforcement point states that its release may have come after
`valid_until`. A `forward_completed_at` at or after `valid_until` is not a
finding, since the answer to a request released inside its window can arrive
after the authority has expired; a verifier MUST report such a completion beside
the scope of its verdict as `completion_after_window` set to `true` (EBMP2-076).
The terminal event's own `observed_at` is not compared with the window, since an
effect can end after its authority has expired.

**EBMP2-051** — The state of an `execution_terminal` event MUST agree with the
outcome of its response under the state-outcome table of the verification
profile. In the reference verification profile
(`ecl.verification-profile.reference.v1`), whose dependency failures resolve to a
fail-closed deny, `held` requires `hold`; `challenged` requires `challenge`;
`denied` requires `deny`, an `admit` later denied at enforcement, or no response;
and every other terminal state requires `admit`.

**EBMP2-075** — When a request carries `ecl.ext.mcp-binding.v1`, an
`execution_released` or `execution_terminal` event of its action that carries
the extension MUST carry, in each occurrence, every member of the request's
value with the same value, so that the evidence names the call that was decided;
and an `execution_terminal` event in state `succeeded` or `failed` MUST carry
the extension with `response_digest`, the digest of the server's response. A
verifier MUST report an event that binds its request and response and breaks
this with `ecl.error.decision-binding-invalid.v1`, as a finding of stage 7 of
EBMP2-068. The request's value is that of its first occurrence of the extension.

MCP-GATEWAY-1 forwards only the call that was decided (MG1-005) and records the
server's response by its digest (MG1-010). With EBMP2-075 a verifier checks that
the gateway's evidence names that call and binds a response; whether the server
returned that response is outside what the bundle shows.

**EBMP2-052** — An `authority_issued` or `authority_consumed` event MUST belong
to an `admit` response whose `authorization.authorization_id` equals the event's
`authorization_id`; exactly one of its causal predecessors MUST name that
response with the response's digest (otherwise `ecl.error.digest-mismatch.v1`);
and its `workflow_id`, `root_trace_id` and `attempt` MUST equal the response's.

**EBMP2-073** — An `authority_consumed` event in state `consumed` that binds its
response under EBMP2-052 and carries `use_count` MUST give a value from 1 to the
number of uses that the authorization allows: 1 when its `use_policy` is
`single_use`, and otherwise its `max_uses` when it has one. A bundle MUST NOT
hold, for one authorization, more such events than the authorization allows, or
two such events with the same `use_count`. A verifier MUST report a bundle that
breaks this with `ecl.error.decision-binding-invalid.v1`, as a finding of stage
7 of EBMP2-068.

**EBMP2-053** — For one action attempt, a non-execution terminal state
(`denied`, `held`, `challenged`, `expired_before_release`) MUST NOT coexist with
consumed authority, an `execution_released` event, an `event.authority`
reference or side effects.

**EBMP2-054** — A `request` or `decision` reference in an event MUST resolve to a
message in the bundle with the same `workflow_id`, `root_trace_id` and `attempt`,
and a digest the reference carries MUST be that message's digest. A
`decision_recorded` event's `outcome` and `policy` MUST equal those of the
response it references.

**EBMP2-055** — A `succeeded` attempt MUST have an `authority_consumed` event in
state `consumed` and an `execution_released` event for the same attempt. A
verifier MUST apply this rule to every attempt of the bundle, whatever the
causal closure of the rest of the bundle, except an attempt one of whose objects
in the bundle (its request, its response or one of its events) names a causal
predecessor that the bundle does not hold, since that predecessor could be the
event that the rule asks for (EBMP2-059).

**EBMP2-074** — An action attempt with an `execution_released` event that binds
its request and response, and whose authorization's `use_policy` is
`single_use`, MUST also have an `authority_consumed` event in state `consumed`
(EBMP2-008), whatever its terminal state. A verifier MUST apply this rule to
every such attempt, whatever the causal closure of the rest of the bundle,
except an attempt one of whose objects in the bundle names a causal predecessor
that the bundle does not hold, since that predecessor could be the consumption
(EBMP2-059). A verifier MUST report an attempt that does not with
`ecl.error.decision-binding-invalid.v1`, as a finding of stage 8 of EBMP2-068.

**EBMP2-056** — A terminal event MUST carry at most one
`ecl.ext.outcome-reason.v1` extension, whose value is exactly `{"code": C}` with
`C` an active registered error code. A `succeeded` terminal MUST NOT carry one.
An `expired_before_release` terminal, and a `denied` terminal whose response is
an `admit` or absent, MUST carry one. A verifier MUST report a terminal event
that fails this rule with `ecl.error.semantic-invalid.v1`.

## 11. Signed evidence bundle verification

A signed evidence bundle (`ecl_evidence_bundle_v1`) carries the ECL-IE-1
envelopes of the DCMP-2 messages and EBMP-2 events of one or more actions in
`envelopes`, and separately keyed observations in `observations`. Its
verification is network-free; the caller supplies the trust policy and earlier
versions of it (TRUST-POLICY-1), the evaluation time and the verification
profile (EBMP2-067). A bundle carries decision requests, decision responses and
EBMP-2 events; the bundle verifier does not verify the other DCMP-2 message
types. The evaluation time is the instant at which the verifier evaluates
current status. It is not a cutoff: Version 1.0 does not define an as-of
assessment, and a verifier does not report what a bundle established at an
earlier instant.

**EBMP2-057** — An observation MUST be an EBMP-2 `verification` event; a
verifier MUST report one that is not with `ecl.error.semantic-invalid.v1`. A
verifier MUST evaluate every envelope under TRUST-POLICY-1: historical validity
at the object's own time under the policy version the object names, and current
status at the evaluation time under the caller's current policy. The object's
purpose is the one that INTEGRITY-ENVELOPE-1 IE1-039 gives its role: the
decision-request purpose for a decision request, the decision-response purpose
for a decision response, the evidence-event purpose for an EBMP-2 event in
`envelopes` and the observation purpose for one in `observations`. The object's
own time is its `issued_at` for DCMP-2 and its `observed_at` for EBMP-2, and its
signed verification-time policy MUST be `ecl.time.issued-at.v1` and
`ecl.time.observed-at.v1` respectively, which IE1-040 step 4 checks; when every
trusted-time countersignature of the envelope is valid (IE1-032 to IE1-036), each
signature that a countersignature covers is evaluated at the earliest attested
time among those that cover it, in place of the object's own time, and each
other signature at the object's own time (IE1-034).
An envelope whose object has no such purpose, no own time or no supplied policy
version (TP1-001) is not historically valid, with
`ecl.error.signature-policy-invalid.v1`. Otherwise every signer of the envelope
MUST pass IE1-040 step 6 (a) to (c) under the object's purpose and principal
(TP1-004, TP1-005), and the envelope's status is then the code of IE1-040.
An object of the bundle, in `envelopes` or `observations`, whose own time, or
the attested time of one of its trusted-time countersignatures, is later than
the evaluation time is not historically valid, with `ecl.error.clock-regressed.v1`: evidence cannot be
later than the instant at which it is verified.

**EBMP2-058** — A verifier MUST pair objects by identity and never by an
event's claimed decision URI: a request by its `message_id` and by its
(`action.action_id`, `workflow_id`, `attempt`); a response by its `request_id`;
an authority event by its `authorization_id`; an execution event by its
(`action_id`, `workflow_id`, `attempt`). Two requests with one identity or one
action attempt, two responses to one request, an authority event without a
unique response, or an event without a request MUST make the bundle invalid,
and a verifier MUST report each with `ecl.error.decision-binding-invalid.v1`.

**EBMP2-078** — A bundle MAY hold a continued request and its continuation
(DCMP-2 DCMP2-056), each with its own response and attempt, and then verifies as
one history. For a request that carries `continues`, a verifier MUST check that
the bundle's objects that `continues` names are the decision request that
`request_id` names; the decision response that `response_id` names, whose
`request_id` is that request's `message_id` and whose `outcome` is `challenge`;
and the `human_intervention` event that `approval_id` names, whose `operation`
is `approve` and whose `target_id` is the continued request's `message_id`; that
the continuation's workflow, attempt, `action`, `actor`, `subject` and
`authority_request` relate to the continued request's as DCMP2-056 requires;
that the continuation lists the response and the approval that `continues`
names among its `workflow.causal_predecessors`, each by identifier and digest;
and that no other request of the bundle continues the same response. When the
continuation's response is an `admit`, the verifier MUST also check that every
key that signed the approval holds `ecl.purpose.approval.v1` in the
trust-policy version that the approval names, and that no key that signed it is
bound to the request's actor, as EBMP2-070 condition 5 asks of an approval
record; and that the approval's `expires_at`, when present, is later than the
`evaluated_at` of that response. A continuation answered with a `deny` or a new
`challenge`, as DCMP2-057 requires for an approval that is late, expired or not
acceptable, is correct evidence and is not refused for its approval. A verifier MUST report a
continuation that fails a check with `ecl.error.decision-binding-invalid.v1`, as
a finding of stage 5 of EBMP2-068. A named object that the bundle does not hold
leaves the causal closure incomplete (EBMP2-059) and keeps `bindings` out of
`established` (EBMP2-076); it exempts no other check of this rule.

**EBMP2-059** — A verifier MUST apply DCMP2-044 to DCMP2-051 to every request
and response pair, EBMP2-046 to EBMP2-056, EBMP2-070 and EBMP2-072 to
EBMP2-075 to every event, and the causal rules of section 4, EBMP2-077 among
them, to every object that the bundle holds: each DCMP-2 message and EBMP-2
event in `envelopes` and each observation. Each object's causal predecessors
MUST be objects of the bundle, with digests equal to the predecessor
references; a signed evidence bundle declares no external dependency
(EBMP2-023), so a predecessor that it does not hold, a DCMP-2 message of a type
that the bundle does not carry included, is unresolved. Identifiers are unique
across `envelopes` and `observations`: a DCMP-2 message is identified by its
`message_id` and an EBMP-2 record by its `object_id`. An object that a causal
predecessor reference or `continues` names and that the bundle does not hold
exempts no other check: a verifier runs every check whose objects the bundle
holds, and a failure of such a check gives its finding and verdict as if nothing
were absent; the absent object makes the causal closure incomplete and keeps out
of `established` every item whose object set names it (EBMP2-076). A proof that
EBMP2-070 lets a discharge entry reference without carrying it is not such an
object: it keeps `prerelease-obligations-proofs-verified` out of `established`,
with the reason that the table gives, and changes no verdict. Registry snapshots
and policy references are not objects of the causal graph.

**EBMP2-060** — A verifier MUST report exactly one verdict: `invalid` when an
object of the bundle, in `envelopes` or `observations`, is not historically
valid, a trust dependency of it among the reasons
(TRUST-POLICY-1 TP1-006), an object fails its schema or semantic rules, a
pairing, binding, outcome-reason or causal rule fails, or causal analysis is
indeterminate; `incomplete` when causal closure is incomplete or a request has
no terminal event; `current-trust-failed` when the bundle would otherwise be
`verified` but some trust dependency, a time authority's key included, is
revoked, expired or otherwise not acceptable under the current policy at the
evaluation time; and `verified` otherwise. A verifier MUST NOT report `verified`
for a bundle with a current trust failure unless its caller has explicitly
accepted current trust failures for that run, and then MUST report the
acceptance with the verdict. The acceptance applies to the
`current-trust-failed` verdict only: it never changes an `invalid` or
`incomplete` verdict, so it cannot restore evidence that is not historically
valid. The primary finding of an `invalid` bundle is the one EBMP2-068 gives,
that of an `incomplete` bundle is `ecl.error.causal-closure-incomplete.v1`, and
that of a `current-trust-failed` bundle is the current status of its trust
dependencies that comes first in the order of stage 4 of EBMP2-068.

**EBMP2-061** — A verifier MUST report the evidence level of each terminal
effect: `none` when the terminal is not historically valid; `issuer-asserted`
when it is; and `corroborated` only when the report establishes
`envelope-signatures` and `causal-completeness` (EBMP2-076) and, for every side
effect of a `succeeded` terminal, some observation
is a historically valid `verification` event with decision `pass` whose
`subject` has the side effect's `uri` and digest, that names the terminal event
among its causal predecessors by `object_id` and digest, that has the
terminal's `workflow.workflow_id`, `workflow.root_trace_id` and
`workflow.attempt`, observed no earlier than the terminal, produced by a
principal other than the terminal's producer, and signed only with key material
disjoint from the terminal's. Corroboration therefore binds one observation to
one terminal event of one attempt.

A bundle can fail several checks. Its checks are taken in stages, and within a
stage the findings have a fixed order, so that every conforming verifier names
the same primary finding for an invalid bundle whatever the order of its
envelopes (EBMP2-029).

**EBMP2-068** — A verifier MAY stop at the first of the stages below that has a
finding, and need not report a bundle's other findings as secondary findings,
but MUST report as the primary finding of an invalid bundle the first finding
of the earliest stage that has one and, within that stage, the finding that
comes first in the order the stage gives, whatever the positions of the objects
in the bundle. The stages are:

1. the input, where a failure stops verification: the earlier policy versions that the caller supplies (TP1-001), `ecl.error.signature-policy-invalid.v1`; the bundle's shape, `ecl.error.schema-invalid.v1`; its limits on envelopes and observations (EBMP2-062), `ecl.error.resource-limit-exceeded.v1`; then its schema, `ecl.error.schema-invalid.v1`;
2. the payloads: each envelope's payload under INTEGRITY-ENVELOPE-1 IE1-040 step 3, whose strict parse takes the nodes that remain of the payload node limit of EBMP2-062 as its value limit (IE1-037, check 3), so that a payload that exceeds them stops verification before its later checks; `ecl.error.resource-limit-exceeded.v1` before `ecl.error.integrity-invalid.v1`;
3. the objects: each object's schema and semantic rules, with the findings that DCMP2-043 gives the object, an object that fails its schema making its envelope not historically valid with `ecl.error.schema-invalid.v1` and one that satisfies its schema but fails a semantic rule with `ecl.error.semantic-invalid.v1`; unique object identifiers; the decision-basis rules of DCMP2-053 (`ecl.rule.decision-basis-required.v1`, `ecl.rule.decision-basis-matches-register.v1`, and `ecl.rule.decision-basis-one-way.v1` for an input recorded as `verifiable` whose source is the request's actor); and the kind of each observation (EBMP2-057); `ecl.error.schema-invalid.v1`, then the registered rules in ascending order of precedence, then `ecl.error.semantic-invalid.v1`, so that a bundle whose only defect is one object has the primary finding that DCMP2-043 gives that object;
4. the signers: each other envelope's historical validity (EBMP2-057, IE1-032 to IE1-036, IE1-040, TRUST-POLICY-1 TP1-006); `ecl.error.clock-regressed.v1`, `ecl.error.signature-policy-invalid.v1`, `ecl.error.trusted-time-invalid.v1`, `ecl.error.trusted-time-required.v1`, `ecl.error.revoked.v1`, `ecl.error.expired.v1`, `ecl.error.resource-limit-exceeded.v1`, `ecl.error.integrity-invalid.v1`, then `ecl.error.threshold-not-met.v1`;
5. pairing (EBMP2-058, EBMP2-066, EBMP2-078); `ecl.error.schema-invalid.v1`, then `ecl.error.decision-binding-invalid.v1`;
6. the binding of each response to its request (DCMP2-044 to DCMP2-051), each pair stopping at its first failure; `ecl.error.request-binding-invalid.v1`, `ecl.error.digest-mismatch.v1`, `ecl.error.audience-mismatch.v1`, then `ecl.error.scope-mismatch.v1`;
7. the binding of each event (EBMP2-047 to EBMP2-054, EBMP2-072, EBMP2-073 and EBMP2-075); `ecl.error.decision-binding-invalid.v1`, `ecl.error.digest-mismatch.v1`, then `ecl.error.expired.v1`;
8. causal analysis (section 4 over every object of the bundle, EBMP2-059, EBMP2-077, EBMP2-055 and EBMP2-074); `ecl.error.resource-limit-exceeded.v1`, then the registered rules in ascending order of precedence, then `ecl.error.decision-binding-invalid.v1`;
9. outcome reasons (EBMP2-056); `ecl.error.semantic-invalid.v1`.

A bundle rule that the registry adds names its stage in its `stage` attribute
(3 or 8) and takes its place in that stage by its precedence, with no change to
this list.

**EBMP2-067** — A verifier MUST apply the verification profile that its caller
names, and the reference verification profile
`ecl.verification-profile.reference.v1` when the caller names none; a bundle
does not select its profile. The verifier MUST report the profile it applied
with the verdict.

**EBMP2-076** — With each verdict a verifier MUST report its scope, as the two
lists of the table below: `established`, the checks that it made for the bundle
and that held, and `not_established`, the other checks that apply to the bundle
and the statements that no verification establishes, each list in the order of
the table. Where the table names a reason for which an item is not established,
the report MUST give that reason with the item. A report whose verdict is
`invalid`, or in which no envelope was evaluated, MUST have an empty
`established`. A verifier MUST NOT list in `established` a check that it did not
make or that failed, and wherever it shows a verdict to a person it MUST show
the `not_established` list with it. The registry `registries/scope-checks.json`
(schema `https://externalcontrollayer.ai/ns/schema/scope-checks/1`) gives, for
each item of the table and for the `corroborated` evidence level of EBMP2-061,
its object set, the checks that must hold over it, the trust knowledge they use
and the waivers that it permits. A waiver changes the verdict only (EBMP2-060):
an item whose failure the waiver accepts stays in `not_established`, and no item
is ever established over less than its whole object set. A verifier MUST NOT list an
item in `established` unless it ran every check that the registry requires for
the item over the item's whole object set and each held, a check with nothing
to check in that set holding; MUST NOT list an item in `established` when its
object set names an object that the bundle does not hold, whatever the verdict;
MUST NOT report the `corroborated` level unless every check and item that the
registry requires for it held; and MUST report, for each item in `established`,
the checks that it ran for the item and the objects that they covered. Every
report MUST state, in the member `evaluation_time`, the evaluation time that it
used, and every report MUST carry the member `unresolved_predecessor_ids`, the
identifiers of the predecessors that it could not resolve, which is non-empty
only when the verdict is `incomplete`. A report MUST carry, beside the scope, the
informational member `completion_after_window` set to `true` when a terminal
event records a `forward_completed_at` at or after the authorization's
`valid_until` (EBMP2-072); the member is not a finding and changes no verdict.
An offline package has the scope of the report that IE1-022 gives it.

| Item | What it says | When it is established |
|---|---|---|
| `envelope-signatures` | Each envelope's and observation's payload digest and signatures verify under the trust-policy version that its object names, at the object's own time or its trusted time, and the caller's current policy revokes none of its trust dependencies at or before its time (EBMP2-057, TRUST-POLICY-1 TP1-006). | The verdict is `verified`, `current-trust-failed` or `incomplete`. |
| `current-trust` | Each trust dependency, each signing key of each envelope and observation and of each time attestation, is acceptable under the caller's current trust policy at the evaluation time (EBMP2-060, TRUST-POLICY-1 TP1-006). | The verdict is `verified` or `incomplete` and every trust dependency's current status is valid; an acceptance of current trust failures never establishes it. |
| `trusted-time` | A separate time authority attests a time for each signature of each envelope and observation, binding that signature (IE1-033), and each signature was valid at that time (IE1-032 to IE1-035); each time authority's key is valid at its attested time under the policy version its attestation names and is not revoked by the caller's current policy at or before that time (TRUST-POLICY-1 TP1-006). | As `envelope-signatures`, and every signature of every envelope and observation is covered by a valid trusted-time countersignature. |
| `object-rules` | Each signed object satisfies its schema and its semantic rules, the one-way rule for a recorded decision basis among them (EBMP2-068, stage 3). | As `envelope-signatures`. |
| `decision-basis-recorded` | Each decision response records its decision basis (DCMP2-053). | As `envelope-signatures`. |
| `decision-basis-register` | Each decision basis agrees with the Consequential Action Register that the caller supplied (DCMP2-053). | As `envelope-signatures`. It applies only when the caller supplies a register. |
| `bindings` | Each response binds its request, each event binds its request, response and authority, with the digests and use counts that they name, each continuation binds the request, challenge and approval that it continues, and each terminal event carries the outcome reason that its state and response require (DCMP2-044 to DCMP2-051, EBMP2-047 to EBMP2-054, EBMP2-056, EBMP2-073, EBMP2-075, EBMP2-078). | As `envelope-signatures`. |
| `release-within-authority` | Each recorded release time lies within the authorization's validity window with the release guard added, and no terminal event records that a release may have come after `valid_until` (EBMP2-050, EBMP2-072). | As `envelope-signatures`, when the bundle records a release; when it records none, it is not established, with the reason `no-release-recorded`. |
| `causal-completeness` | Over every object that the bundle holds, the DCMP-2 messages and EBMP-2 events in `envelopes` and the observations: every causal predecessor is in the bundle with the digest that names it, in the workflow, trace and attempt that EBMP2-077 allows, the graph is acyclic and identifiers are unique, and every request has a terminal event (section 4, EBMP2-055, EBMP2-059, EBMP2-074, EBMP2-077). | The verdict is `verified` or `current-trust-failed`. |
| `prerelease-obligations-discharge-recorded` | Each release records a discharge of every obligation that its decision left to Enforcement before the release, checked no later than the release was observed and fresh at the release (EBMP2-070). | As `envelope-signatures`. It applies only when the verifier applied EBMP2-070 to an `execution_released` event whose response carries such an obligation. |
| `prerelease-obligations-proofs-verified` | Each pre-release discharge carries its proof, and each proof is a valid ECL object under the trust policy, signed by the issuer the obligation names, of a type the obligation admits, bound to this exchange and fresh at the release (EBMP2-070). | As `prerelease-obligations-discharge-recorded`, and only when every entry's proof is an ECL object that the bundle carries and that passes conditions 5 to 8 of EBMP2-070; when an entry's proof is not an ECL object that the bundle carries, it is not established, with the reason `proof-not-ecl-object`, and when the decision names no issuer for an obligation, with the reason `issuer-not-named`; when both apply, the report gives `proof-not-ecl-object`. |
| `prerelease-obligations-met` | That each pre-release obligation was met: the verifier checks a proof's signatures, issuer, type, binding and freshness, not what the proof shows. | Never; it applies as `prerelease-obligations-discharge-recorded` does. |
| `post-release-obligations-met` | That the obligations to be met during or after execution were met, which the verifier does not check. | Never; it applies only when the response that an `execution_released` event records carries an obligation whose `satisfaction` is `during_execution` or `after_execution`. |
| `recorded-times-true` | That each recorded time is the true time of its event: each producer states its own times (EBMP2-004, EBMP2-071). | Never. |
| `effects-occurred` | That the effects happened: a terminal event is its producer's statement, and corroboration is another signed statement, an observation bound to that terminal event and its attempt (EBMP2-015, EBMP2-061). | Never. |
| `deployment-assessed` | That the deployment that produced the evidence has been assessed or meets ECL-1. | Never. |
| `statements-true` | That the statements in the bundle are true (section 1), among them the enforcement point's statements of what it checked and released. | Never. |

**EBMP2-062** — A verifier MUST declare finite limits on the number of
envelopes and observations and on the decoded payload nodes of a bundle, MUST
count the nodes of each payload while it parses it, against those that remain
of the bundle's limit, so that it builds no payload beyond that limit (IE1-029),
and MUST refuse a bundle that exceeds them before verifying signatures, with
`ecl.error.resource-limit-exceeded.v1`. For example, a verifier can declare
limits of 256 envelopes, 256 observations and 100 000 nodes.

