# Formal models of ECL-1

## Distributed evidence paths

This public source contains copies of the recorded evidence with local workspace
paths standardized for portability. File digests and packet inventories identify
these distributed copies. Model inputs, properties, bounds, tool settings, dates,
measurements and outcomes are unchanged. The record of the transformation and
original file digests is `formal/PUBLIC-EVIDENCE-NORMALIZATION.json`. G-14, Inc.
retains the exact original evidence separately. This transformation ran no solver.
References below to original commands, outputs or unchanged retained records
describe the recorded runs; the distributed path strings and associated digests
are the standardized representation described here.

This folder holds two models of the ECL-1 design and the script that checks them.

- `tla/ECLCore.tla` models the runtime control invariant of standard section 5 in TLA+:
  the governed AI system, the decision layer, authority objects, enforcement points, revocation and
  trust changes, timeouts, an outage of the decision service, the separate emergency halt plane,
  human-approval continuations, scoped restriction and lifting, the evidence log and the one-way rule. TLC checks its safety and liveness properties on
  bounded configurations in `tla/configs/`.
- `protocol/DCMP2_Binding.spthy` models the signing and binding of DCMP-2 decision requests
  and responses in Tamarin, against a network adversary that can also reveal keys.
- `run_checks.py` runs every check, compares each outcome with its expectation and records
  results when an explicit `--record` path is supplied. `results.json` is the
  preserved November 7 historical record, not a result for the current model.

The models check the abstractions of the design encoded below; their correspondence to the
normative text is a separate review obligation. They do not check any implementation: the conformance vectors and an implementation's own tests exercise its code, each
only as far as its cases reach, and the section "From the models to an implementation" below
says where an implementation takes several steps where the models take one. A successful TLC
check covers the configured finite state space. Tamarin reasons over the symbolic theory and
its trace restrictions; neither result establishes a property outside the model's assumptions.

Every check has an expected outcome. The correct model must satisfy each selected property
and verify each selected lemma. Each deliberately broken variant changes a rule or restriction
and must produce a counterexample to its designated property. Each reachability witness must
also produce a counterexample to its negated condition, establishing that particular situation
in its own configuration. These checks do not establish nonvacuity of every property in every
configuration or guarantee detection of other defects.

## The TLA+ model

### What it contains

- **The governed AI system**, called the actor in the models and below, submits any request
  through any enforcement point. It chooses the `actor_supplied` input (a self-report) and
  steers the `judgment` input (a risk score) of every decision. It can present any request, named by its identifier and action, together with
  any authority object that exists, at any enforcement point and at any time: replay, use for
  another target, parameters, request or audience, and use after expiry, revocation or halt.
  It has no step that writes a decision, an authority object or evidence, and no path to an
  effect other than an enforcement point.
- **The decision service** answers `admit`, `deny`, `hold` or `challenge` under the current
  policy and trust epoch. Submission refuses a request whose identifier was already used
  with different modeled content, including an earlier request that timed out without a
  decision. The refusal creates no second decision response. Identical retransmission and
  explicit supersession are outside this abstraction of DCMP2-005.
  An `admit` issues one authority object bound to the request identifier and the action (the
  scope digest of DCMP2-044), the requesting enforcement point as audience, a validity window,
  the trust epoch and a single use. A human-approval challenge ends its original attempt.
  An authenticated approval can support a new continuation request, with a fresh identifier,
  the same action and audience, the same abstract workflow root and a higher attempt number.
  Attempts are unique across accepted siblings in that workflow. Its decision is evaluated
  afresh; the approval neither admits nor rewrites the challenge. At most one continuation
  per challenge or approval may receive `admit` (DCMP2-021, DCMP2-056, DCMP2-057, EBMP2-078). The service can fail
  and recover. In this review draft, recovery first enters `reconciling`;
  normal decisions and execution resume only after the abstract reconciliation
  gate described below. Existing cached authority can still be used during an
  outage within the original staleness and authorization bounds.
- **Enforcement points** execute only with an issued authority object that matches the
  presented request, names them as audience, is inside its window, unused, unrevoked in their
  view and of a current epoch, while their control state is fresh and no halt is acknowledged.
  The effect and its evidence record are one step (TE1-004). Decisions are enabled only before
  their request deadlines. A challenge approval may be issued at its deadline but not after
  it, as DCMP2-057 permits; it must remain unexpired and unrevoked at the continuation's
  evaluation. A bounded wait can time out to the declared safe state. Time cannot advance
  past an unresolved wait's deadline; weak fairness requires enabled timeouts eventually to occur.
- **The control plane** revokes authority objects and changes the policy and trust epoch.
  Enforcement points learn of both by refreshing their control state while the control plane
  is reachable.
- **The emergency plane** requests a halt and each enforcement point acknowledges it. It does
  not depend on the decision service.
- **Time** is a discrete tick. Time advances only while the deadlines the control layer owes
  are met: connected propagation within the propagation bound, halt acknowledgment within
  the bound B, and resolution of pending requests and holds at their deadlines. These limits
  constrain the model clock; they do not prove that an implementation can meet a latency bound.

### What it abstracts, and why

| Abstraction | Reason | Consequence |
|---|---|---|
| Signatures, digests and the hash chain are not modelled. Only the decision service can create an authority object; an action's digest is the action itself; the log is a sequence only the control layer appends to. | The model is about which rules prevent which effects. Cryptographic binding is the subject of the Tamarin model and of the conformance vectors. | A forged or colliding digest is outside the model. The broken variants `actor_writes_authority`, `actor_writes_decision` and `actor_erases_evidence` show what follows when the separation fails. |
| Policy is one set of allowed actions over the verifiable inputs. | The one-way rule concerns which inputs may admit, not the content of a policy. | Policy ambiguity, obligations (DCMP2-017) and budgets are not modelled. |
| Human approvals are authenticated control actions bound to a challenge record. Actor, subject, requested-authority fields and approver identity are fixed outside the finite request type; the approval epoch abstracts policy acceptance of the approver. Workflow root follows the predecessor; the next attempt is allocated across the workflow's accepted requests, including siblings. | The continuation model isolates request identity, action/audience binding, expiry, revocation and reuse. | It does not validate concrete approval signatures, causal digest encodings, malformed workflow fields or changes in omitted fields. An epoch change invalidates an old approval conservatively; the model does not decide whether a new policy would accept the same approver. |
| Approval generation is enabled only when the finite campaign has capacity and an unused request identifier for a continuation. Non-human hold progression is omitted; its timeout remains modeled. | Approval events that cannot lead to a continuation add no behavior needed by these checks. | The model does not establish availability of an approval service or a non-human progression profile. |
| One decision service, one global clock and one availability flag. | This keeps the configured state space finite and small. | Clock skew (DCMP2-047, TE1-009) and selective enforcement-point partitions are not modeled. `dsUp` enables both decision service access and control-state refresh for every enforcement point; the emergency halt plane is separate. |
| Each configuration is small: at most two enforcement points, three request identifiers, two targets, two parameter values and the times 0 to 4. | TLC enumerates every state; these bounds keep each check inside its time box. | A property can still fail in a larger configuration that these do not reach. |
| Liveness is checked in `correct-liveness` and `correct-continuation-liveness`, with weak fairness for the steps the control layer owes (time, refresh, halt acknowledgment, timeouts, reconciliation and normal resumption) and none for the actor, the operators or outages. | Liveness needs explicit scheduling and environment assumptions. | Recovery completion is conditional on eventual permanent service availability; it does not require an operator to lift every class restriction. |

Not modelled at all: delegation chains (ECL1N-0031), distributed workflows
(DISTRIBUTED-WORKFLOW-1), evidence bundles and their verdicts (EBMP2-057 to EBMP2-062),
trust-policy versions and historical validity, trusted-time countersignatures, and extension
handling (EXTENSION-REGISTRY-1). The bundle checks of EBMP2-070 to EBMP2-076 are outside the
model for the same reasons: the discharge of pre-release obligations that a release records
(EBMP2-070) rests on obligations, which the model omits; the release observation and the forward
a terminal event records (EBMP2-071, EBMP2-072) separate an effect from its evidence record,
which the model takes as one step; and the use counts, the consumption of single-use authority,
the MCP binding of events and the scope of a verdict (EBMP2-073 to EBMP2-076) are checks on a
bundle and its report. The conformance vectors of the `evidence-bundle` suite test them.

### Recovery in the public-review model

The model distinguishes `unavailable`, `reconciling` and `normal` operation.
`Recover` restores service reachability; it does not authorize normal operation.
`Reconcile` refreshes the enforcement views and records the six TS1-014 frontiers:
policy epochs, revocations, consumed authorities, buffered evidence, unresolved
effects and clock continuity. `ResumeNormal` checks those frontiers and the
current control view before enabling normal operation. While reconciling, the
model permits control refresh, revocation, timeout, evidence recording and
emergency halt, but no ordinary execution or admitting evaluation.

This is an abstract recovery gate. Consumption is already shared globally in
the model, correct-model evidence is atomic, all modeled effects have known
outcomes, and the clock has no jumps. The last four frontiers therefore add no
concrete storage, remote-effect or clock-recovery protocol. Implementations
must establish that refinement separately. A new revocation after normal
resumption remains subject to the declared propagation bound.

The current model also tracks a restriction for the action class represented by
each enforcement point. Every fresh-to-stale crossing of its control-state
staleness bound starts a new fault generation and latches the restriction, including
when an earlier restriction is still active. Further ticks in one continuously stale
interval do not create additional generations. `ObtainFreshProof` records the current
generation only after a current control view is available; a later stale crossing
invalidates that earlier proof. `LiftRestriction` requires current proof and records
the lifting action. Generations preserve this causal ordering when several steps
occur at the same model tick. Refresh alone does not lift the restriction. A short
outage need not trigger one. Still-valid authority issued before repeated faults can
execute after proof for the latest fault and a recorded lift. Authority age and proof
age have separate roles in these checks.

A class restriction may be lifted while global operation remains reconciling.
Execution still waits for global reconciliation to complete. `RecoveryCompletes`
states that, if service availability eventually becomes permanent, fair control
steps return each reconciling state to global normal operation. It neither requires
the external service to recover nor compels an operator to lift a class restriction.

This per-enforcement-point class is an abstraction of the dependency scopes in
ECL1N-0191 to ECL1N-0193, not a model of a deployment-wide dependency graph. Proof
and lift actions are authenticated control-plane steps; their concrete formats and
authorization policy are not modeled. The selected mode requires a recorded lift.
No fairness assumption compels an operator to lift a restriction.

`NoEffectDuringReconciliation`, `RecoveryBeforeNormal` and the restriction
properties apply to every correct configuration. Weak fairness also applies to enabled
`Reconcile` and `ResumeNormal` steps. The separate, earlier 35 recorded TLC checks in
`diagnostics/2026-11-10-recovery/COMBINED-RESULTS.json` comprise the original 32
configuration purposes on the earlier recovery revision plus a deliberately broken
resumption, a recovery witness and the original recovery-trace regression.
Every check matched its expected outcome. The witness resumes normal execution
after an outage and reconciliation; the broken case returns directly to normal
and violates `RecoveryBeforeNormal`. The original unreconciled-revocation trace
is excluded under the same control bounds. That archived packet is not a result
for the later continuation and restriction changes described on this page.

### Properties

| Property | Kind | What it states | Requirements |
|---|---|---|---|
| `EffectHasMatchingAdmit` | invariant | Every effect rests on an `admit` issued for exactly that request identifier and action, at the enforcement point the authority names as audience. | ECL1N-0028, ECL1N-0033, FR-003, DCMP2-013, DCMP2-044, DCMP2-048, DCMP2-051, TE1-008 |
| `EffectWithinAuthority` | invariant | No effect uses authority outside its scope, audience or window. | DCMP2-044, DCMP2-048, DCMP2-049, EBMP2-050, FR-104 |
| `SingleUse` | invariant | No authority object produces two effects. | DCMP2-050, EBMP2-008, TE1-003 |
| `NoEffectAtHaltedEP` | action property | No effect at an enforcement point after it acknowledged a halt. | TS1-025, ECL1N-0104, FR-004 |
| `NoEffectBeyondHaltBound` | invariant | No effect later than the bound B after a halt request. | TS1-036 |
| `RevocationBound` | invariant | No effect later than the propagation bound after a revocation or trust change while the control plane was reachable, and none later than the larger of the propagation and staleness bounds in any case. | ECL1N-0053, ECL1N-0097, FR-110 |
| `NoEffectWithKnownRevocation` | action property | No effect with authority that the enforcement point knows is revoked or of an ended epoch. | DCMP2-014, ECL1N-0053 |
| `EffectHasEvidence` | invariant | Every effect has its evidence record. | TE1-004, ECL1N-0047 |
| `LogAppendOnly` | action property | The evidence log only grows; no record changes or disappears. | EBMP2-038, ECL1N-0047 |
| `DecisionsAppendOnly` | action property | Decisions and authority objects are never withdrawn or rewritten. | DCMP2-021, ECL1N-0046 |
| `OneWayRule` | invariant | Every decision is at least as strict, in the Strictness Order, as the policy over the verifiable inputs alone (the Verifiable-Only Outcome), so no `admit` rests only on `actor_supplied` or `judgment` inputs. | ECL1N-0041, ECL1N-0164, ECL1N-0165, ECL1N-0179, ECL1N-0180 |
| `AdmitOnlyAllowed` | invariant | Every `admit` is for an action the verifiable inputs support. | ECL1N-0046, FR-001 |
| `NoEffectDuringOutage` | invariant | An effect while the decision service is down rests on an `admit` issued before the outage began, with control-state age measured from the enforcement view's last refresh. | DCMP2-041, FR-003, FR-110, ECL1N-0102, ECL1N-0103 |
| `SafeStateHasNoEffect` | invariant | A request that ended in `deny` or the declared safe state has no effect. | DCMP2-014, DCMP2-018, DCMP2-041, TS1-009 |
| `TypeOK` | invariant | Every variable has its declared type. | |
| `DeadlineBound` | invariant | Model time does not pass an unresolved decision or hold deadline. This follows from the encoded scheduling constraint on `Tick`. | DCMP2-018, DCMP2-041, TS1-009 |
| `NoLateDecision` | action property | A new decision for a pending or held request precedes its deadline. The strict boundary is a conservative modeling choice. | DCMP2-018, DCMP2-041, TS1-009 |
| `NoEffectDuringReconciliation` | action property | No effect occurs while operation is reconciling. | TS1-014 |
| `RecoveryBeforeNormal` | action property | A transition back to normal operation follows reconciliation and a current control view. | TS1-014 |
| `UniqueDecisionResponse` | invariant | No request identifier has two different decision responses. A collision refusal creates no response. | DCMP2-005, EBMP2-058 |
| `UniqueWorkflowAttempt` | invariant | Two accepted requests with the same workflow root, action and attempt are the same request. Sibling continuations have distinct attempts. | DCMP2-026, DCMP2-056, EBMP2-058 |
| `ContinuationAdmitBound` | invariant | An admitted continuation binds the challenge, approval, action, audience and workflow progression; approval issuance is not after the challenge deadline, and evaluation precedes approval expiry in the accepted epoch. | DCMP2-056, DCMP2-057, EBMP2-078 |
| `OneAdmittingContinuation` | invariant | At most one continuation is admitted per challenge or approval. | DCMP2-057, EBMP2-078 |
| `NoContinuationWithRevokedApproval` | action property | An approval already revoked cannot support a new admitting continuation. | DCMP2-057 |
| `ControlStateFreshAtEffect` | invariant | Every authorized effect uses a control view within its staleness bound, while connected or disconnected. | FR-110, TS1-013 |
| `NoEffectWhileRestricted` | action property | An effect is refused while its enforcement point's class restriction remains active. | ECL1N-0103, ECL1N-0191 |
| `RestrictionLiftRequiresFreshProof` | action property | A restriction is lifted only with current proof for its generation and a new recorded lifting action. | ECL1N-0193 |
| `FreshStalenessInvalidatesProof` | action property | Every fresh-to-stale crossing starts a new active fault generation and invalidates proof from an earlier generation, including while an earlier restriction remains active. | ECL1N-0193, TS1-013 |
| `LiftLogAppendOnly` | action property | Recorded lifting actions cannot be removed or changed. | ECL1N-0047, ECL1N-0193 |
| `NoRecoveredEffectOnUnreconciledState` | action property | After service returns, a view not refreshed for that recovery cannot release globally revoked authority or authority from an ended epoch. New control changes after reconciliation retain the propagation allowance. | TS1-014, ECL1N-0053 |
| `HoldResolves` | liveness | A bounded hold or challenge wait eventually ends by timeout or, for a challenge, by recording approval. A continuation has its own request obligation. | DCMP2-018 |
| `RequestResolves` | liveness | Every submitted request is eventually decided or ends in the safe state. | DCMP2-041, TS1-009 |
| `HaltTakesEffect` | liveness | A halt request is eventually acknowledged at every enforcement point. | FR-004, TS1-036 |
| `RecoveryCompletes` | liveness | If service availability eventually becomes permanent, each reconciling state eventually reaches global normal operation under fair control steps. A class restriction may still need an operator's lift. | TS1-014; explicit environment and fairness assumptions |

The standard states the one-way rule normatively, since RC-5, as ECL1N-0178 to ECL1N-0182. `OneWayRule` checks
ECL1N-0179 (such inputs are never the basis of an `admit`) and ECL1N-0180 (an `admit` rests on
policy over `verifiable` inputs alone). `Rank` is the Strictness Order of the core standard's
Section 4.3, `admit` < `challenge` < `hold` < `deny`. The model's policy over the verifiable
inputs answers only `admit` or `deny`, and every action is either allowed or not, so the order
of `challenge` and `hold` between them does not change any outcome; the comparison of two
`admit` decisions by the authority they grant is not modelled.

### Configurations

The seven correct configurations differ in what they vary:

| Base | Enforcement points | Request identifiers | Actions | Last tick | Requests | Failures and controls | Bounds |
|---|---|---|---|---|---|---|---|
| binding | 2 | 2 | 4 (one allowed) | 3 | 3 | none | validity 2 |
| control | 2 | 1 | 1 (allowed) | 4 | 1 | one outage, one revocation, one trust change, one halt | validity 4, propagation 1, staleness 2, B 1 |
| liveness | 1 | 1 | 2 (one allowed) | 3 | 2 | one outage, one halt | validity 2, propagation 1, staleness 1, B 1 |
| continuation | 1 | 3 | 2 (both allowed) | 2 | 3 | one revocation, one trust change | validity 2, decision/hold deadlines 2 |
| delayed-continuation | 1 | 2 | 1 (allowed) | 3 | 2 | none | validity 3, decision/hold deadlines 2 |
| continuation-liveness | 1 | 2 | 1 (allowed) | 2 | 2 | one outage, one halt | validity 2, decision/hold deadlines 1, propagation 1, staleness 1, B 1 |
| repeated-staleness | 1 | 1 | 1 (allowed) | 4 | 1 | one outage | validity 5, decision/hold deadlines 1, propagation 2, staleness 1, B 1 |

The current model's correct configurations check 34 distinct properties:
17 state invariants, 13 action properties (30 safety properties in total) and
four liveness properties. The historical Version 1.0.1 record checked 20
properties: 12 state invariants, five action properties and three liveness
properties. Version 1.0 checked 18 properties, before `DeadlineBound` and
`NoLateDecision` were added. These counts exclude the negated properties used
only to obtain reachability witnesses and the recovery-trace regression.

Decision and hold deadlines are one tick in the original three correct configurations.
With the strict decision guard, decisions in those configurations occur in the same tick as
their requests. The `continuation` and `delayed-continuation` configurations use two-tick deadlines,
and the registered later-continuation witness exercises an admission after the original
challenge's tick. The two new configurations use one-tick deadlines.
The model clamps every new deadline to
`Min(now + deadline, MaxTime)`, so requests and holds near the finite horizon can have shorter
waits. Decisions require `now < deadline`; at their request deadline only timeout can resolve
the request. This exclusive decision boundary is a conservative model choice:
TS1-009 says a gate that "exceeds" its deadline enters the safe state, so equality behavior in
an implementation is not established here. A zero decision deadline or submission at
`MaxTime` permits no decision. Approval issuance uses the separate DCMP2-057 boundary:
at or before the challenge deadline, followed by evaluation before approval expiry.
Weak fairness supplies the eventual timeout transition even when `Tick` has reached its horizon.
In the `no_decision_timeout` and `hold_never_times_out` variants, the decision
guards still exclude the deadline and later times while the timeout path is disabled.
Those variants therefore expose requests that remain unresolved after the nominal deadline.

The binding and control configurations use a
symmetry reduction over enforcement points and request identifiers. Neither liveness
configuration uses it, because a symmetry reduction can hide a liveness violation from TLC.
The new repeated-staleness configuration also uses no symmetry reduction.

All seven correct configurations check every safety property on their base;
`correct-liveness` and `correct-continuation-liveness` also check all four liveness
properties. The original liveness configuration has only one request identifier, so it
cannot reach a fresh continuation. The new two-identifier liveness configuration is paired
with witnesses at exactly the same bounds for continuation admission and timeout; another
witness at those bounds reaches post-recovery execution.

The ordinary runner registers 58 TLC checks: seven correct configurations,
35 broken configurations exercising 33 distinct flaws, and 16 witnesses. Recovery and staleness each have two broken configurations to cover
different circumstances. Each broken configuration
checks only the property its flaw must break:

| Configuration | The flaw | Property it breaks | Rule removed |
|---|---|---|---|
| `broken-outage-proceeds` | An enforcement point lets the action go ahead when the decision service is down. | `NoEffectDuringOutage` | DCMP2-041, FR-003 |
| `broken-late-decision-used` | A decision that arrives after the safe state can still release the request. | `SafeStateHasNoEffect` | DCMP2-014, TS1-009 |
| `broken-no-digest-binding` | Parameters are not checked against the authority. | `EffectHasMatchingAdmit` | DCMP2-007, DCMP2-044 |
| `broken-no-target-binding` | The target is not checked against the authority. | `EffectHasMatchingAdmit` | DCMP2-044 |
| `broken-no-audience-binding` | The audience is not checked. | `EffectWithinAuthority` | DCMP2-048 |
| `broken-no-window` | The validity window is not checked. | `EffectWithinAuthority` | DCMP2-049, EBMP2-050 |
| `broken-no-single-use` | Consumed authority is not remembered. | `SingleUse` | DCMP2-050, EBMP2-008 |
| `broken-ignore-revocation` | Known revocations and epochs are ignored. | `NoEffectWithKnownRevocation` | DCMP2-014, ECL1N-0053 |
| `broken-ignore-staleness` | Stale control state is used past the staleness bound during outage. | `ControlStateFreshAtEffect` | FR-110, TS1-013 |
| `broken-no-propagation-deadline` | Revocations need not reach enforcement points within the bound. | `RevocationBound` | ECL1N-0097 |
| `broken-ignore-halt` | An acknowledged halt is ignored. | `NoEffectAtHaltedEP` | TS1-025, FR-004 |
| `broken-halt-unbounded` | Halt acknowledgment has no bound. | `NoEffectBeyondHaltBound` | TS1-036 |
| `broken-evidence-not-atomic` | The effect and its evidence are separate steps. | `EffectHasEvidence` | TE1-004 |
| `broken-bypass` | The actor has a path to the effect around the enforcement point. | `EffectHasMatchingAdmit` | ECL1N-0033, ECL1N-0141 |
| `broken-actor-writes-authority` | The actor can create an authority object. | `EffectHasMatchingAdmit` | ECL1N-0046, FR-001 |
| `broken-actor-writes-decision` | The actor can record an `admit`. | `AdmitOnlyAllowed` | ECL1N-0046, FR-001 |
| `broken-actor-erases-evidence` | The actor can remove an evidence record. | `LogAppendOnly` | EBMP2-038, ECL1N-0047 |
| `broken-judgment-admits` | A low risk score admits. | `OneWayRule` | ECL1N-0165, ECL1N-0179, ECL1N-0180 |
| `broken-self-report-admits` | A favorable self-report admits. | `OneWayRule` | ECL1N-0041, ECL1N-0179, ECL1N-0180 |
| `broken-hold-never-times-out` | A hold has no deadline. | `HoldResolves` | DCMP2-018 |
| `broken-no-decision-timeout` | A request waits for a decision without a deadline. | `RequestResolves` | DCMP2-041, TS1-009 |
| `broken-halt-ack-lost` | Enforcement points never acknowledge a halt. | `HaltTakesEffect` | FR-004 |
| `broken-continuation-binding` | The approval/challenge/action binding is omitted. | `ContinuationAdmitBound` | DCMP2-056, DCMP2-057 |
| `broken-approval-reuse` | A second admitting continuation can reuse a challenge or approval. | `OneAdmittingContinuation` | DCMP2-057, EBMP2-078 |
| `broken-expired-approval` | Approval expiry is not checked at evaluation. | `ContinuationAdmitBound` | DCMP2-057 |
| `broken-revoked-approval` | A revoked approval can support admission. | `NoContinuationWithRevokedApproval` | DCMP2-057 |
| `broken-recovery-without-reconciliation` | Recovery returns directly to normal operation. | `RecoveryBeforeNormal` | TS1-014 |
| `broken-recovered-trust-state` | The same bypass permits execution under a pre-recovery trust view. | `NoRecoveredEffectOnUnreconciledState` | TS1-014, ECL1N-0053 |
| `broken-restriction-bypass` | Execution ignores a latched restriction after refresh. | `NoEffectWhileRestricted` | ECL1N-0103, ECL1N-0193 |
| `broken-stale-recovery-proof` | Restriction lifting omits proof for the current fault generation. | `RestrictionLiftRequiresFreshProof` | ECL1N-0193 |
| `broken-unrecorded-restriction-lift` | Lifting is not recorded. | `RestrictionLiftRequiresFreshProof` | ECL1N-0193 |
| `broken-connected-stale-view` | The stale-view rule is omitted while service remains reachable. | `ControlStateFreshAtEffect` | FR-110, TS1-013 |
| `broken-continuation-attempt-collision` | Each sibling receives its predecessor's attempt plus one, allowing two siblings to share an attempt. | `UniqueWorkflowAttempt` | DCMP2-026, DCMP2-056, EBMP2-058 |
| `broken-repeated-staleness-proof` | A new stale crossing is ignored while an earlier restriction remains active. | `FreshStalenessInvalidatesProof` | ECL1N-0193, TS1-013 |
| `broken-recovery-never-resumes` | The normal-resumption action's guard disables it, despite eventual permanent service availability. | `RecoveryCompletes` | TS1-014; model fairness assumptions |

The witnesses run the correct design and must violate a state invariant or action property
that says their particular situation never occurs. They establish that situation only in the
configuration used, not nonvacuity of every property in every configuration:

| Configuration | What it shows can happen |
|---|---|
| `witness-effect` | An effect occurs. |
| `witness-admit-after-challenge` | A fresh continuation request is admitted after authenticated approval of a challenge. |
| `witness-collision-refusal` | A reused request identifier with other content is refused without a second response (DCMP2-005, EBMP2-058). |
| `witness-effect-during-outage` | An effect occurs during an outage, on an earlier `admit` inside the staleness bound (ECL1N-0102). |
| `witness-effect-in-revocation-window` | An effect uses revoked authority before the enforcement point learns of the revocation: the window that the propagation bound of ECL1N-0097 permits. |
| `witness-effect-in-halt-window` | An effect occurs after a halt request and before its acknowledgment: the window that the bound B of TS1-036 permits. |
| `witness-timeout` | A request ends in the safe state with no decision at all. |
| `witness-approval-replay-refused` | A valid, unexpired approval supports one admission; its reuse for another continuation is denied. |
| `witness-later-continuation` | A continuation is admitted at a later tick than its original challenge. |
| `witness-effect-after-reconciliation` | Normal execution resumes after outage and reconciliation. |
| `witness-effect-after-short-outage` | An outage ends without triggering a staleness restriction, and still-valid prior authority is used. |
| `witness-revalidated-authority-after-restriction` | Authority issued before a fault executes after current proof and a recorded lift. |
| `witness-live-continuation-admit` | A continuation is admitted under the exact two-identifier liveness bounds. |
| `witness-live-continuation-timeout` | A held continuation times out under those same liveness bounds. |
| `witness-live-recovery-resumption` | Execution occurs after recovery under those same liveness bounds. |
| `witness-revalidated-authority-after-repeated-staleness` | Authority issued before two stale-state faults executes after proof for the second fault and a recorded lift. |

The outage, revocation-window and halt-window witnesses exhibit the corresponding permitted
timing windows. Their counterexamples do not establish that every deployment can achieve a
smaller bound.

## The protocol model

### What it contains

An enforcement point signs a decision request for an action, names itself as the requested
audience and sends it to a decision point. It may also retain an authenticated request signed
by an agent. `EP_AdoptRequest` verifies that request under its issuer's request-role key;
adoption alone authorizes no effect. `OneRequestContext` prevents conflicting immutable
request content under one identifier at the same logical enforcement point (DCMP2-005),
while allowing identical context replay. It does not constrain the response digest.
The decision point verifies the request signature
under the key the trust policy registers for the request role, permits at most one decision
per decision-point identity and request identifier (an assumption stronger than DCMP2-005),
and answers with a signed `admit` that names the request by identifier
and digest (DCMP2-045, DCMP2-046) and carries an authorization bound to the audience
(DCMP2-048), the scope digest of the request identifier and action (DCMP2-044), the single-use
policy (DCMP2-050) and a validity window (DCMP2-049). The enforcement point verifies the
response under the key registered for the response role (TP1-004, TP1-005), checks the
binding and executes only within the authorization. Both `EP_Receive` and direct
`EP_Present` compare the response's request identifier and digest with the retained context.
Presentation compares the retained request's action and requested audience with the
presented action and authorization audience, as well as checking the signed audience,
scope and use policy. These consumer checks also apply when an adversary can forge a
response with a revealed response key. Request-context authentication is checked separately
with the request issuer's own key-reveal exception. An unknown context cannot be presented;
an adopted context cannot bypass those checks or single-use consumption. Each key is generated for one role
(ECL1N-0157).

The correct producer accepts only the supported `single_use` request policy. Presentation
still accepts adversarially supplied response fields as input and checks their use policy;
the `no_single_use` variant removes the consumption-store restriction, not the wire-domain rule.

The adversary is the network (Dolev-Yao): it reads, replays, reorders and redirects every
message, and any key can be revealed. The governed AI system is part of it: it proposes any
action, and the rule `EP_Present` lets it present any signed response together with any action
at any enforcement point. Its own request-signing key, where requests are agent-signed, is a
revealed key. The `agent_signed_executable` witness retains an agent-signed request at a
different enforcement point and executes it without revealing any response key.

Signatures and hashes are ideal symbolic primitives. The model includes the payload type in
the signing input using the free constructor `pae`. Honest requests and responses both use the
single symbolic payload type `dcmp`; message tags and key roles distinguish them. The theory
does not exercise replay between different honest protocol media types or validate concrete
DSSE (Dead Simple Signing Envelope) encodings and parsers (IE1-009, IE1-010). The decision point's policy is abstracted to `admit`: `deny`,
`hold` and `challenge` carry no authorization (DCMP2-012) and are covered by the TLA+ model.
The enforcement point's clock is an assumption (restriction `EnforcementClock`): the model
shows that the window an enforcement point checks is the one the decision point signed, not
that its clock is right. The trusted policy holds at most one registered key per principal
and role; this registration cap excludes key rotation and multiple keys for one role.
The request digest covers every field represented in the symbolic request: its tag,
identifier, issuer, audience, action and use policy. The theory does not enumerate every
DCMP-2 field or prove the concrete canonicalization of a complete wire request.

### Lemmas

| Lemma | What it proves, with its key-reveal exception | Requirements |
|---|---|---|
| `executable` | An existence check: some trace in which no key is revealed contains an enforcement point's decision request and an execution for the same enforcement point, request identifier, target and parameters. The execution can come from `EP_Execute` or `EP_Present`; both now record `EP_Accept`. | |
| `request_origin` | A decision point issues authority only for a request that its named issuer signed, unless that issuer's request key was revealed before the issuance. | IE1-009, TP1-004, TP1-005 |
| `response_authenticity` | A response an enforcement point accepts was issued by the decision point it names, unless that decision point's response key was revealed before the acceptance. | IE1-009, IE1-010, TP1-004, TP1-005, ECL1N-0157 |
| `request_response_binding` | The response answers exactly the enforcement point's authenticated request context, including agent-signed contexts, by identifier and digest, with that enforcement point as audience, unless the decision point's response key was revealed before the acceptance. | DCMP2-045, DCMP2-046, DCMP2-048 |
| `authorization_scope_and_audience` | Every execution rests on an authorization that the named decision point issued earlier for that enforcement point as audience and for that request identifier, target, parameters and window value, whoever signed the request, unless that decision point's response key was revealed before the execution. That the execution precedes the window's expiry is the `EnforcementClock` assumption, not part of the lemma. | DCMP2-044, DCMP2-048, DCMP2-049, DCMP2-051 |
| `single_use` | Two executions of one authorization that name the same decision point are one execution, unless that decision point's response key is revealed at any point in the trace, before or after them. | DCMP2-050, EBMP2-008 |
| `one_effect_per_request` | Two executions that carry the same request identifier and name the same decision point are one execution, unless that decision point's response key is revealed at any point in the trace. Executions authorized by different decision points for one request identifier are not covered. | DCMP2-005, TE1-003 |
| `execution_request_binding` | Both execution paths retain the digest of the authenticated request context, and execute authority issued for that digest and identifier, unless the decision point's response key was revealed before execution. | DCMP2-045, DCMP2-046, DCMP2-048 |
| `agent_signed_executable` | An existence check: a request signed by an actor distinct from the enforcement point can be adopted and executed, with only that actor's request key revealed. | ECL1N-0156 |
| `request_context_origin` | A retained context was signed by its named request issuer, unless that issuer's request key was revealed before adoption. A locally created context and its signing event may share one step. | IE1-009, TP1-004, TP1-005 |
| `execution_preserves_request` | Execution retains the authenticated request context's action and requested audience, even if a response key is revealed. The context's origin has the separate request-key exception above. | DCMP2-044, DCMP2-045, DCMP2-046, DCMP2-048 |
| `consumer_authorization_binding` | The consumed authorization's audience, scope and use policy match the enforcement point, executed request/action and `single_use`, even if a response key is revealed. | DCMP2-044, DCMP2-048, DCMP2-050, DCMP2-051 |

The ordinary runner registers 12 Tamarin checks: the correct theory with 12 lemmas
(ten universal properties and two existence witnesses) and 11 deliberately flawed variants.
Each flaw is selected with `-D=<flag>` and must falsify its designated lemma. Ten remove
a named restriction; `shared_role_key` instead adds `Register_shared`, permitting one key to
serve the request and response roles:

| Flag | The flaw | Lemma falsified |
|---|---|---|
| `skip_response_signature` | The enforcement point accepts a response without verifying its signature. | `response_authenticity` |
| `shared_role_key` | One key serves the request and response roles. | `response_authenticity` |
| `response_not_bound` | The enforcement point does not check the response's request identifier and digest. | `request_response_binding` |
| `presentation_not_bound` | Direct presentation omits request identifier/digest binding while retaining context authentication and uniqueness. | `execution_request_binding` |
| `no_scope_check` | The enforcement point does not check the scope digest, including in a response forged with a revealed response key. | `consumer_authorization_binding` |
| `no_audience_check` | The enforcement point does not check the audience. | `authorization_scope_and_audience` |
| `no_single_use` | The enforcement point does not remember consumed authorizations. | `single_use` |
| `dp_no_message_identity` | The decision point does not refuse a reused identifier. | `one_effect_per_request` |
| `dp_skips_request_signature` | The decision point does not verify the request signature. | `request_origin` |
| `skip_context_signature` | The enforcement point adopts a request context without verifying the issuer's request signature. | `request_context_origin` |
| `presentation_context_not_bound` | Direct presentation omits equality with the retained request's action and requested audience. | `execution_preserves_request` |

Replay inside the validity window is covered by `single_use` and `one_effect_per_request`;
expiry is covered only as far as the clock assumption allows.

## From the models to an implementation

The model results do not prove a program. TLC explores each configured finite state space;
Tamarin proves or falsifies lemmas over its symbolic rules and restrictions. Neither establishes
a refinement from an implementation that orders steps differently, splits an atomic transition
into several steps, or omits a rule. Each transition of the TLA+ model is one atomic step, and an
implementation usually takes several steps where the model takes one. The normative text says
what must hold between those steps. What the models abstract away, and where the text binds an
implementation:

- **Obligations and budgets.** The model's policy is a set of allowed actions, so a
  before-release obligation (DCMP2-017) and a consequence budget (ECL1N-0173) have no
  counterpart.
- **The effect and its evidence as one step.** `EffectHasEvidence` holds because the model
  appends the record in the step that makes the effect (TE1-004), and
  `broken-evidence-not-atomic` shows what follows when it does not. Where a local journal cannot
  be atomic with a remote call, the enforcement point preserves its recovery information durably
  before the release, and recovery classifies an attempt whose outcome it cannot establish
  (ECL1N-0189); an MCP gateway under MCP-GATEWAY-1 also makes each record that
  evidences a release durable before the release, and a record that cannot be made durable
  prevents it (MG1-016, MG1-017).
- **One global clock, and no time inside a step.** The interval between a check and the release
  is zero in the model. In an implementation the clock advances and other requests run between
  them, so the enforcement point establishes at the release boundary itself that the
  authorization is valid there, and a timestamp it gives for the release describes that boundary
  (ECL1N-0186, ECL1N-0188). An MCP gateway under MCP-GATEWAY-1 checks the authorization's
  window and every proof's freshness again at the final observation before the release, and
  refuses a wall clock that stepped back between two readings (MG1-013, MG1-014). The model has
  one global discrete clock, with no skew between components (DCMP2-047, TE1-009).
- **The use of an authorization.** The model consumes an authorization only together with the
  effect. Under TRANSACTIONAL-EFFECT-1 a charge is consumed at most once for an action key, and a
  charged action later denied still consumes its charge (TE1-010); an MCP gateway under
  MCP-GATEWAY-1 takes the use before its last checks, and leaves it spent when one of them
  refuses (MG1-014).
- **An effect that is certain.** The model has no failed send, timeout or lost response. The
  release boundary, where a call is sent, comes before the effect boundary, where the server
  acts; in an MCP gateway under MCP-GATEWAY-1 the arrival of the answer is recorded apart from the
  release (MG1-014, MG1-015). An outcome that cannot be established stays unresolved, and no use
  is repeated (ECL1N-0189).
- **Crashes and storage failures.** No step of either model ends a process or loses storage. A
  conformance claim declares which of them it covers (ECL1N-0190). The state machine
  represents service outages and abstract reconciliation, up to each configuration's
  `MaxOutages`; it does not represent interrupted durable-journal writes or replay.
  Its correct-design evidence log only grows (`LogAppendOnly`).
  In an MCP gateway under MCP-GATEWAY-1, recovery records its decision before it writes any
  resulting record or bundle and
  settles each journal once, so a repeated recovery writes the same records and never a second
  signed terminal (MG1-016).
- **Revocation, halt and trust changes.** Propagation is one step within a bound in the model
  (`RevocationBound`), and a halt is acknowledged in one step within its bound. An enforcement
  point that holds no feed of revocations or halts relies on the authorization's validity to
  bound what a revocation or a halt issued after the decision can miss. That limit
  remains subject to the claim's declared timing and control-state staleness bounds;
  missing, invalid, expired or unavailable required proof still prevents release
  (TS1-012, TS1-013, TS1-018, TS1-032).
- **The protocol model's clock and memory.** `EnforcementClock` requires each `InWindow(a, w)`
  event to precede every `Expired(a, w)` event for that authorization and window. It neither
  forces an expiry event to occur nor models clock arithmetic. `SingleUse` forbids two
  consumption events for the same enforcement-point identity and authorization; each identity
  represents one logical consumption store across its instances. `UniqueRequestIdentifier`
  forbids a decision-point identity from deciding a request identifier twice, including an
  identical replay. That is stronger than DCMP2-005's prohibition on reusing an identifier
  with different content. `OneRequestContext` separately requires each logical enforcement
  point to retain one immutable request digest per identifier; an authenticated agent context
  is allowed, but a conflicting replacement is refused. These are logical memory assumptions,
  not proofs of crash-safe storage. The presentation-only mutant keeps context uniqueness
  intact and still exposes the request-substitution attack when response binding is omitted.
  TE1-003 and TE1-006 separately require effect-store uniqueness where
  the transaction profile applies. The protocol lemma's same-decision-point scope does not
  establish uniqueness across independent decision points, workflows or retries.
  An implementation's timing for the release boundary is
  one that ECL1N-0188 allows: a check made at the release boundary, a declared bound on the delay
  between the check and the release that is enforced, or a check of the authority at the point of
  effect. It counts each use of an authorization atomically with every other use by any instance
  or attempt, a recovered one included, so that a restart cannot use it again (ECL1N-0186 item 3,
  ECL1N-0189); an MCP gateway under MCP-GATEWAY-1 routes every use of an authorization through one
  instance or a shared use store (MG1-005).
- **Bounded configurations.** A property can fail in a configuration larger than those checked;
  the configurations are listed above.

## Running the checks

The [current 70-check packet](#current-results-november-11-2026-utc) retains its
exact inputs, runners and original invocation records. Its two sources used
`--timeout 900` for TLC and `--timeout 120` for Tamarin, each with
`--derivcheck-timeout 10`. Reproduce them in separate result files as below.
To reproduce the earlier November 10 packet's
35 recovery-revision checks from their exact retained inputs,
use `python3 formal/check_recovery.py --jar /path/to/tla2tools.jar --output /new/output/directory`.
This command refuses an existing output directory and preserves the archived
records. The ordinary runner below registers every current model flaw and witness; it does not
reproduce the historical November 7 TLA+ inputs. Those are retained under
`history/v1.0.1/` and in the historical diagnostic packet.

The tools are not dependencies of the package and are not installed with it. The script, which
needs Python 3.10 or later and nothing else, uses these pinned releases and refuses others unless `--allow-unpinned` is given:

| Tool | Version | Download | SHA-256 |
|---|---|---|---|
| TLA+ tools (TLC) | 1.7.4 | `https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar` | jar `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88` |
| Tamarin prover | 1.12.0 | `https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz` | archive `201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6`, binary `9d3fcbaa65aeea244cff5b8074338d129427161cc8b02e5aee72d30ee072acc9` |
| Maude | 3.5.1 | `https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/Maude-3.5.1-linux-x86_64.zip` | archive `72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c`, binary `9dd4044e693944aae97ad72086bc70275fa34bf635f9b377a5b2100bf3ed8655` |

TLC runs with the JVM heap option `-Xmx1500m` and one worker. Tamarin runs with
`+RTS -N1 -M1500m -RTS`. The runner requires an executable Java runtime
that can run the pinned JAR, records its actual version and imposes no Java version gate.
The original published record reports Java 17.0.20.1 in its top-level field; it does not
identify the runtime of each earlier invocation merged into that record. Point the script
at the tools with options or environment variables:

```bash
export ECL_TLA2TOOLS_JAR=/path/to/tla2tools.jar
export ECL_TAMARIN_PROVER=/path/to/tamarin-prover
export ECL_MAUDE_DIR=/path/to/maude-directory
python3 formal/diagnostics/2026-11-11-runner-compatibility/inputs/formal/run_checks.py \
  --skip-tamarin --timeout 900 --derivcheck-timeout 10 \
  --record tlc-results-new.json --log-dir tlc-logs-new
python3 formal/diagnostics/2026-11-11-runner-compatibility/inputs/formal/run_checks.py \
  --skip-tlc --timeout 120 --derivcheck-timeout 10 \
  --record tamarin-results-new.json --log-dir tamarin-logs-new
```

Without the tools the script prints their sources and digests and exits with status 2.
The ordinary runner writes `ecl_formal_results_v2` records. Every check, including a
timeout or tool failure, records its model-input hashes, runner hash, command, start and
finish times, output hash and actual Java version for TLC. `--log-dir` retains complete
tool output in a new directory. `--record` can merge compatible v2 invocations, preserving
each check's provenance; it refuses stale retained inputs, incompatible settings and legacy
v1 records. Use one writer per record path. The different 900-second and 120-second settings
therefore require separate v2 result files. A partial run is not a complete current record.
In a v2 record, the top-level `java` value is only the runtime of the most recently recorded
TLC invocation; per-check fields control mixed-runtime records.

The current packet uses `ecl_formal_results_v3` to aggregate the original TLC record and
Tamarin receipt, as its [provenance format](diagnostics/2026-11-11-runner-compatibility/AGGREGATE-FORMAT.md)
specifies. Each source retains its exact file, hash, format and settings; every check
maps to one source and preserves its original dictionary, output and invocation runner.
Settings, dates and Java runtimes remain attached to their original invocations. The retained
current runner is identified separately from the runners that performed the checks. Input
hashes must also match the current model, theory and configurations. Reproducing those inputs
with the latest retained runner does not change which runner produced an earlier result.

Keep `formal/results.json`, the historical logs and prior packets unchanged. The runner's
`--readme` option renders that historical result table; it does not render the current v3
aggregate. Assembly or documentation of an aggregate performs no formal-tool execution.

From the source root, `python3 formal/check_recorded_results.py` checks the
selected packet's structure, hashes, source partition, retained runners and
compatibility with the current model inputs. It reads the retained records;
it does not execute TLC or Tamarin.

The archived Version 1.0 runner constructs its Tamarin command with
`--derivcheck-timeout=0`, disabling message-derivation diagnostics. That command
construction alone does not identify the setting of an unrecorded historical invocation.
The current runner defaults to ten seconds, and the retained November 7 v1.0.1, earlier November 11, closing-review and provenance-refresh invocations explicitly
use ten seconds. An explicit zero remains available for historical command compatibility.
A positive value enables the diagnostic, including in deliberately flawed variants, and is
recorded in the settings. A diagnostic timeout or failure must be assessed from the retained
output; absence of a warning from the disabled diagnostic is not evidence that it passed.

## Current results: November 11, 2026 UTC

The current record contains 58 TLC checks and 12 Tamarin checks, all with
their expected outcomes. Across the seven correct TLC configurations, all 30 selected
safety properties held; `correct-liveness` and `correct-continuation-liveness` also
satisfied the four liveness properties. The 35 broken configurations exercise 33 distinct flaws,
and the 16 witnesses establish their stated reachable situations. Tamarin verified
all 12 lemmas of the correct theory, including two existence witnesses, and falsified
the designated lemma for each of 11 flaws. Every theory reported successful
well-formedness checks with message-derivation diagnostics enabled at ten seconds.

[The current aggregate](diagnostics/2026-11-11-runner-compatibility/RESULTS.json) binds each
result to its exact input and original invocation record. [The packet manifest](diagnostics/2026-11-11-runner-compatibility/MANIFEST.json)
binds those records, their runners, the current input copies and complete logs. TLC's
per-check timeout was 900 seconds and Tamarin's was 120 seconds. The separate commands
above reproduce the checked definitions with those settings. The assumptions and bounds
on this page govern these results.

The current compatibility packet preserves the November 11 TLC and Tamarin
results and checks their compatibility with the repaired runner. Its assembly
performed no new solver runs. The preceding
[provenance-refresh packet](diagnostics/2026-11-11-provenance-refresh/MANIFEST.json)
and [closing-review packet](diagnostics/2026-11-11-closing-review/MANIFEST.json)
remain preserved with their original input hashes and invocation records.

## Earlier contract-review results: November 11, 2026 UTC

The preserved [59-check record](diagnostics/2026-11-11-contract-review/RESULTS.json)
contains 49 TLC checks and ten Tamarin checks on the preceding model revision, all with
their expected outcomes. Its five correct TLC configurations satisfied 28 safety properties;
its `correct-liveness` also satisfied three liveness properties. Its 32 broken
configurations exercise 30 distinct flaws, and its 12 witnesses establish their stated
reachable situations. Tamarin verified nine lemmas of that correct theory, including two
existence witnesses, and falsified a designated lemma for each of nine flaws.

[That packet's manifest](diagnostics/2026-11-11-contract-review/MANIFEST.json) preserves
its exact input copies, runner and complete logs. Its retained runner reproduces those
inputs using a fresh record and log directory, `--timeout 900` and
`--derivcheck-timeout 10`. That historical pass is not a result for the subsequent
continuation, repeated-staleness or protocol-consumer changes.

## Historical results: November 7, 2026

The table records the local repair checks performed on November 7, 2026, on the
model preserved in `history/v1.0.1/`: 32 TLC checks
and nine Tamarin checks, all with their expected outcomes. Each correct TLC configuration
satisfied its 17 selected safety properties; `correct-liveness` also satisfied the three
liveness properties. Each of the 22 broken variants and seven witnesses produced the named
counterexample. Tamarin verified the seven lemmas of the correct theory and falsified the
selected lemma for each of eight flaws. Message-derivation diagnostics were enabled with a
10-second limit, and every theory's output reported successful well-formedness checks.

`results.json` preserves each check's command, input hashes, runtime metadata and output hash.
Complete captured tool output is retained in `formal/evidence/`, under the basename in each
check's `log_file` field (stdout followed by stderr). The exact driver used for these runs is
also retained there as `run_checks-<runner_sha256>.py`; subsequent runner robustness repairs
do not relabel a previous invocation. The original published v1 record remains
in the unchanged original release archive. The repaired TLA+ model strengthens deadline
behavior, so its state counts need not match the original. Durations reflect these local
runs on a shared host and are not deployment latency claims.

<!-- formal:results -->
| TLC check | Expected | Observed | Distinct states | States generated | Depth | Trace states | Seconds |
|---|---|---|---:|---:|---:|---:|---:|
| `correct-binding` | no error | no error | 453,291 | 1,081,821 | 14 |  | 13.9 |
| `correct-control` | no error | no error | 4,606,888 | 17,564,984 | 24 |  | 104.4 |
| `correct-liveness` | no error | no error | 58,148 | 136,618 | 17 |  | 9.2 |
| `broken-outage-proceeds` | `NoEffectDuringOutage` | `NoEffectDuringOutage` | 230 | 397 | 5 | 5 | 0.7 |
| `broken-late-decision-used` | `SafeStateHasNoEffect` | `SafeStateHasNoEffect` | 10,136 | 36,434 | 6 | 6 | 1.1 |
| `broken-no-digest-binding` | `EffectHasMatchingAdmit` | `EffectHasMatchingAdmit` | 216 | 478 | 4 | 4 | 0.7 |
| `broken-no-target-binding` | `EffectHasMatchingAdmit` | `EffectHasMatchingAdmit` | 216 | 478 | 4 | 4 | 0.7 |
| `broken-no-audience-binding` | `EffectWithinAuthority` | `EffectWithinAuthority` | 216 | 478 | 4 | 4 | 0.7 |
| `broken-no-window` | `EffectWithinAuthority` | `EffectWithinAuthority` | 6,760 | 17,343 | 6 | 6 | 0.9 |
| `broken-no-single-use` | `SingleUse` | `SingleUse` | 1,373 | 3,708 | 5 | 5 | 0.8 |
| `broken-ignore-revocation` | `NoEffectWithKnownRevocation` | `NoEffectWithKnownRevocation` | 435 | 839 | 6 | 6 | 0.7 |
| `broken-ignore-staleness` | `NoEffectDuringOutage` | `NoEffectDuringOutage` | 5,064 | 11,167 | 8 | 8 | 0.8 |
| `broken-no-propagation-deadline` | `RevocationBound` | `RevocationBound` | 2,067 | 4,158 | 7 | 7 | 0.8 |
| `broken-ignore-halt` | `NoEffectAtHaltedEP` | `NoEffectAtHaltedEP` | 493 | 957 | 6 | 6 | 0.7 |
| `broken-halt-unbounded` | `NoEffectBeyondHaltBound` | `NoEffectBeyondHaltBound` | 5,116 | 12,035 | 8 | 8 | 0.9 |
| `broken-evidence-not-atomic` | `EffectHasEvidence` | `EffectHasEvidence` | 215 | 476 | 4 | 4 | 0.7 |
| `broken-bypass` | `EffectHasMatchingAdmit` | `EffectHasMatchingAdmit` | 25 | 38 | 3 | 3 | 0.7 |
| `broken-actor-writes-authority` | `EffectHasMatchingAdmit` | `EffectHasMatchingAdmit` | 254 | 568 | 4 | 4 | 0.7 |
| `broken-actor-writes-decision` | `AdmitOnlyAllowed` | `AdmitOnlyAllowed` | 39 | 59 | 3 | 3 | 0.7 |
| `broken-actor-erases-evidence` | `LogAppendOnly` | `LogAppendOnly` | 1,373 | 3,692 | 5 | 5 | 0.8 |
| `broken-judgment-admits` | `OneWayRule` | `OneWayRule` | 36 | 54 | 3 | 3 | 0.7 |
| `broken-self-report-admits` | `OneWayRule` | `OneWayRule` | 37 | 54 | 3 | 3 | 0.7 |
| `broken-hold-never-times-out` | `HoldResolves` | `HoldResolves` | 55,603 | 143,625 |  | 16 | 3.8 |
| `broken-no-decision-timeout` | `RequestResolves` | `RequestResolves` | 58,448 | 134,613 |  | 13 | 3.8 |
| `broken-halt-ack-lost` | `HaltTakesEffect` | `HaltTakesEffect` | 28,677 | 62,758 |  | 12 | 2.0 |
| `witness-effect` | `WitnessNoEffect` | `WitnessNoEffect` | 215 | 476 | 4 | 4 | 0.7 |
| `witness-admit-after-hold` | `WitnessNoAdmitAfterHold` | `WitnessNoAdmitAfterHold` | 219 | 510 | 4 | 4 | 0.7 |
| `witness-collision-deny` | `WitnessNoCollisionDeny` | `WitnessNoCollisionDeny` | 506 | 1,309 | 5 | 5 | 0.7 |
| `witness-effect-during-outage` | `WitnessNoEffectDuringOutage` | `WitnessNoEffectDuringOutage` | 126 | 225 | 5 | 5 | 0.7 |
| `witness-effect-in-revocation-window` | `WitnessNoEffectInRevocationWindow` | `WitnessNoEffectInRevocationWindow` | 114 | 207 | 5 | 5 | 0.7 |
| `witness-effect-in-halt-window` | `WitnessNoEffectInHaltWindow` | `WitnessNoEffectInHaltWindow` | 129 | 234 | 5 | 5 | 0.7 |
| `witness-timeout` | `WitnessNoTimeout` | `WitnessNoTimeout` | 58 | 91 | 4 | 4 | 0.7 |

| Tamarin check | Lemma | Result | Proof steps | Seconds |
|---|---|---|---:|---:|
| `protocol-correct` | `executable` | verified | 14 | 6.9 |
|  | `request_origin` | verified | 7 |  |
|  | `response_authenticity` | verified | 7 |  |
|  | `request_response_binding` | verified | 7 |  |
|  | `authorization_scope_and_audience` | verified | 12 |  |
|  | `single_use` | verified | 72 |  |
|  | `one_effect_per_request` | verified | 60 |  |
| `protocol-skip-response-signature` | `response_authenticity` | falsified - found trace | 8 | 3.7 |
| `protocol-shared-role-key` | `response_authenticity` | falsified - found trace | 10 | 5.8 |
| `protocol-response-not-bound` | `request_response_binding` | falsified - found trace | 13 | 4.1 |
| `protocol-no-scope-check` | `authorization_scope_and_audience` | falsified - found trace | 13 | 4.0 |
| `protocol-no-audience-check` | `authorization_scope_and_audience` | falsified - found trace | 13 | 4.0 |
| `protocol-no-single-use` | `single_use` | falsified - found trace | 16 | 4.6 |
| `protocol-dp-no-message-identity` | `one_effect_per_request` | falsified - found trace | 20 | 11.1 |
| `protocol-dp-skips-request-signature` | `request_origin` | falsified - found trace | 5 | 3.5 |
<!-- /formal:results -->

"Depth" is the search depth TLC reported when it stopped; TLC reports none for a liveness
counterexample. "Trace states" is the length of the counterexample TLC printed. A Tamarin check
of a flaw analyzes only the lemma named for it.

TLC checks liveness at intervals of time during its search, so the states and the trace length
it reports for the three broken liveness variants change from run to run with the machine's
speed; the required violated property remains the same. The original published record's
October-run history is preserved in the original release archive. The November 7 repair
record above is separate evidence for the new input hashes. Fourteen additional reduced-model
diagnostics exercised decision priority, zero/one-tick deadlines, the finite-horizon clamp,
and four deliberate removals of the new guards. All matched their specified expectations;
these diagnostics are retained in `diagnostics/2026-11-07/` and are not counted among the
32 standard TLC configurations. Three further diagnostics use two-tick decision and hold
deadlines: a safety/liveness check and two witnesses, one for a decision and one for an
authenticated resolution at tick 1 of a request or hold created at tick 0. All three matched
their specified expectations. Together these are 17 focused diagnostics, separate from the
32 standard configurations; their complete inputs, records, exact drivers and
outputs are in `diagnostics/2026-11-07/`. `PACKET.json` binds the retained files.
These 17 checks were not rerun for this draft and do not qualify the recovery revision.

## Limits

- The TLA+ checks are exhaustive only within each configuration's bounds.
- Both models check stated abstractions; correspondence with the normative text requires
  separate review. Implementation defects must be sought through conformance vectors,
  implementation tests and review; these methods do not guarantee detection of every defect.
  "From the models to an implementation" describes departures from the models' atomic steps.
- TLA+ omits cryptographic operations and enforces creation and separation through its
  transition relation. Tamarin uses ideal symbolic primitives under its equational theory.
  Concrete encoding attacks, weak keys and side channels are outside these checks.
- The protocol model assumes the enforcement point's clock (restriction `EnforcementClock`) and a
  trust policy that holds at most one key per principal and role (restriction `OneRegistration`),
  so key rotation and several keys for one role are outside it. Each modeled key is generated for
  one role (rule `Register`, ECL1N-0157). TRUST-POLICY-1 requires separation of request and response purposes (TP1-009), and counts a
  decision request or response only under a key of its role (TP1-010). It does not limit a
  principal to one key per role. The flaw `shared_role_key` exercises role sharing; the correct
  theory assumes separate role keys and has no verifier-refusal transition.
- What the TLA+ model leaves out is listed under "What it abstracts, and why".
