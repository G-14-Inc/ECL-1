# Formal models of ECL-1

This folder holds two models of the ECL-1 design and the script that checks them.

- `tla/ECLCore.tla` models the runtime control invariant of standard section 5 in TLA+:
  the governed AI system, the decision layer, authority objects, enforcement points, revocation and
  trust changes, timeouts, an outage of the decision service, the separate emergency halt plane,
  the evidence log and the one-way rule. TLC checks its safety and liveness properties on
  bounded configurations in `tla/configs/`.
- `protocol/DCMP2_Binding.spthy` models the signing and binding of DCMP-2 decision requests
  and responses in Tamarin, against a network adversary that can also reveal keys.
- `run_checks.py` runs every check, compares each outcome with its expectation and records
  the results in `results.json`.

The models check the design as the normative text states it. They do not check any
implementation: the conformance vectors and an implementation's own tests exercise its code, each
only as far as its cases reach, and the section "From the models to an implementation" below
says where an implementation takes several steps where the models take one. A model that passes says that the rules it encodes are enough
for the property in every behavior of the bounded configuration, and nothing about
configurations or rules outside it.

Every check has an expected outcome. The correct design must pass every property and prove
every lemma. Each deliberately broken variant removes one rule and must produce a
counterexample to the property that rule protects, which shows that the property can fail and
that the check would notice. Each reachability witness must also produce a counterexample,
which shows that the situation a property speaks about occurs, so the property does not hold
only because nothing happens.

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
  policy and trust epoch. A request identifier reused with other content is denied (DCMP2-005).
  An `admit` issues one authority object bound to the request identifier and the action (the
  scope digest of DCMP2-044), the requesting enforcement point as audience, a validity window,
  the trust epoch and a single use. An authenticated approval resolves a hold or challenge
  with a new decision over the verifiable inputs (DCMP2-021, ECL1N-0177). The service can fail
  and recover.
- **Enforcement points** execute only with an issued authority object that matches the
  presented request, names them as audience, is inside its window, unused, unrevoked in their
  view and of a current epoch, while their control state is fresh and no halt is acknowledged.
  The effect and its evidence record are one step (TE1-004). A request without a decision by
  its deadline, and a hold without an answer by its deadline, end in the declared safe state.
- **The control plane** revokes authority objects and changes the policy and trust epoch.
  Enforcement points learn of both by refreshing their control state while the control plane
  is reachable.
- **The emergency plane** requests a halt and each enforcement point acknowledges it. It does
  not depend on the decision service.
- **Time** is a discrete tick. Time advances only while the deadlines the control layer owes
  are met: connected propagation within the propagation bound, and halt acknowledgment within
  the bound B.

### What it abstracts, and why

| Abstraction | Reason | Consequence |
|---|---|---|
| Signatures, digests and the hash chain are not modelled. Only the decision service can create an authority object; an action's digest is the action itself; the log is a sequence only the control layer appends to. | The model is about which rules prevent which effects. Cryptographic binding is the subject of the Tamarin model and of the conformance vectors. | A forged or colliding digest is outside the model. The broken variants `actor_writes_authority`, `actor_writes_decision` and `actor_erases_evidence` show what follows when the separation fails. |
| Policy is one set of allowed actions over the verifiable inputs. | The one-way rule concerns which inputs may admit, not the content of a policy. | Policy ambiguity, obligations (DCMP2-017) and budgets are not modelled. |
| One decision service, one global clock. | Several decision services and clock skew multiply the state space without a new rule to check at this level. | Clock skew between enforcement points and the decision service (DCMP2-047, TE1-009) is not modelled. |
| Each configuration is small: at most two enforcement points, two request identifiers, two targets, two parameter values and the times 0 to 4. | TLC enumerates every state; these bounds keep each check inside its time box. | A property can still fail in a larger configuration that these do not reach. |
| Liveness is checked only in the liveness configuration, with weak fairness for the steps the control layer owes (time, refresh, halt acknowledgment, timeouts) and none for the actor, the operators or outages. | Liveness needs fairness assumptions; the control layer is the only party ECL-1 can oblige. | A control layer that never takes its steps is outside the guarantee. |

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
| `NoEffectDuringOutage` | invariant | An effect while the decision service is down rests on an `admit` issued before the outage began, inside the staleness bound counted from its start. | DCMP2-041, FR-003, FR-110, ECL1N-0102, ECL1N-0103 |
| `SafeStateHasNoEffect` | invariant | A request that ended in `deny` or the declared safe state has no effect. | DCMP2-014, DCMP2-018, DCMP2-041, TS1-009 |
| `TypeOK` | invariant | Every variable has its declared type. | |
| `HoldResolves` | liveness | A held or challenged request is eventually decided or ends in the safe state. | DCMP2-018 |
| `RequestResolves` | liveness | Every submitted request is eventually decided or ends in the safe state. | DCMP2-041, TS1-009 |
| `HaltTakesEffect` | liveness | A halt request is eventually acknowledged at every enforcement point. | FR-004, TS1-036 |

The standard states the one-way rule normatively, since RC-5, as ECL1N-0178 to ECL1N-0182. `OneWayRule` checks
ECL1N-0179 (such inputs are never the basis of an `admit`) and ECL1N-0180 (an `admit` rests on
policy over `verifiable` inputs alone). `Rank` is the Strictness Order of the core standard's
Section 4.3, `admit` < `challenge` < `hold` < `deny`. The model's policy over the verifiable
inputs answers only `admit` or `deny`, and every action is either allowed or not, so the order
of `challenge` and `hold` between them does not change any outcome; the comparison of two
`admit` decisions by the authority they grant is not modelled.

### Configurations

The three base configurations differ in what they vary:

| Base | Enforcement points | Request identifiers | Actions | Last tick | Requests | Failures and controls | Bounds |
|---|---|---|---|---|---|---|---|
| binding | 2 | 2 | 4 (one allowed) | 3 | 3 | none | validity 2 |
| control | 2 | 1 | 1 (allowed) | 4 | 1 | one outage, one revocation, one trust change, one halt | validity 4, propagation 1, staleness 2, B 1 |
| liveness | 1 | 1 | 2 (one allowed) | 3 | 2 | one outage, one halt | validity 2, propagation 1, staleness 1, B 1 |

Decision and hold deadlines are one tick in each. The binding and control configurations use a
symmetry reduction over enforcement points and request identifiers; the liveness configuration
does not, because a symmetry reduction can hide a liveness violation from TLC.

`correct-binding`, `correct-control` and `correct-liveness` check every safety property on
their base; `correct-liveness` also checks the three liveness properties. Each broken variant
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
| `broken-ignore-staleness` | Stale control state is used past the staleness bound. | `NoEffectDuringOutage` | FR-110, TS1-013 |
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

The witnesses run the correct design and must violate an invariant that says the situation
never occurs:

| Configuration | What it shows can happen |
|---|---|
| `witness-effect` | An effect occurs. |
| `witness-admit-after-hold` | A held request is admitted after an authenticated approval. |
| `witness-collision-deny` | A reused request identifier with other content is denied (DCMP2-005). |
| `witness-effect-during-outage` | An effect occurs during an outage, on an earlier `admit` inside the staleness bound (ECL1N-0102). |
| `witness-effect-in-revocation-window` | An effect uses revoked authority before the enforcement point learns of the revocation: the window that the propagation bound of ECL1N-0097 permits. |
| `witness-effect-in-halt-window` | An effect occurs after a halt request and before its acknowledgment: the window that the bound B of TS1-036 permits. |
| `witness-timeout` | A request ends in the safe state with no decision at all. |

The last three record windows that the normative text permits on purpose. A deployment that
needs them closed declares smaller bounds; the model shows that the bounds, not some other
rule, are what limit them.

## The protocol model

### What it contains

An enforcement point signs a decision request for an action, names itself as the requested
audience and sends it to a decision point. The decision point verifies the request signature
under the key the trust policy registers for the request role, refuses a message identifier
it has seen (DCMP2-005), and answers with a signed `admit` that names the request by identifier
and digest (DCMP2-045, DCMP2-046) and carries an authorization bound to the audience
(DCMP2-048), the scope digest of the request identifier and action (DCMP2-044), the single-use
policy (DCMP2-050) and a validity window (DCMP2-049). The enforcement point verifies the
response under the key registered for the response role (TP1-004, TP1-005), checks the
binding and executes only within the authorization. Each key is generated for one role
(ECL1N-0157).

The adversary is the network (Dolev-Yao): it reads, replays, reorders and redirects every
message, and any key can be revealed. The governed AI system is part of it: it proposes any
action, and the rule `EP_Present` lets it present any signed response together with any action
at any enforcement point. Its own request-signing key, where requests are agent-signed, is a
revealed key.

Signatures are perfect and digests are perfect hashes. The DSSE pre-authentication encoding
is a free constructor of payload type and payload, so the payload type is part of every
signing input (IE1-009, IE1-010). The decision point's policy is abstracted to `admit`: `deny`,
`hold` and `challenge` carry no authorization (DCMP2-012) and are covered by the TLA+ model.
The enforcement point's clock is an assumption (restriction `EnforcementClock`): the model
shows that the window an enforcement point checks is the one the decision point signed, not
that its clock is right. The trust policy is trusted and holds one key per principal and role.

### Lemmas

| Lemma | What it proves, unless the named key was revealed | Requirements |
|---|---|---|
| `executable` | The honest flow completes with no key revealed (a sanity check that the model is not vacuous). | |
| `request_origin` | A decision point issues authority only for a request that its named issuer signed. | IE1-009, TP1-004, TP1-005 |
| `response_authenticity` | A response an enforcement point accepts was issued by the decision point it names. | IE1-009, IE1-010, TP1-004, TP1-005, ECL1N-0157 |
| `request_response_binding` | The response answers exactly the request the enforcement point sent, by identifier and digest, with that enforcement point as audience. | DCMP2-045, DCMP2-046, DCMP2-048 |
| `authorization_scope_and_audience` | Every execution was admitted for exactly that enforcement point, request identifier, target and parameters, inside the window the decision point signed. | DCMP2-044, DCMP2-048, DCMP2-049, DCMP2-051 |
| `single_use` | An authorization is executed once. | DCMP2-050, EBMP2-008 |
| `one_effect_per_request` | One request identifier yields at most one effect. | DCMP2-005, TE1-003 |

Each flaw, selected with `-D=<flag>`, removes one check and must falsify the lemma it
protects:

| Flag | The flaw | Lemma falsified |
|---|---|---|
| `skip_response_signature` | The enforcement point accepts a response without verifying its signature. | `response_authenticity` |
| `shared_role_key` | One key serves the request and response roles. | `response_authenticity` |
| `response_not_bound` | The enforcement point does not check the response's request identifier and digest. | `request_response_binding` |
| `no_scope_check` | The enforcement point does not check the scope digest. | `authorization_scope_and_audience` |
| `no_audience_check` | The enforcement point does not check the audience. | `authorization_scope_and_audience` |
| `no_single_use` | The enforcement point does not remember consumed authorizations. | `single_use` |
| `dp_no_message_identity` | The decision point does not refuse a reused identifier. | `one_effect_per_request` |
| `dp_skips_request_signature` | The decision point does not verify the request signature. | `request_origin` |

Replay inside the validity window is covered by `single_use` and `one_effect_per_request`;
expiry is covered only as far as the clock assumption allows.

## From the models to an implementation

Passing bounded models are not proofs of a program. A model that passes shows that the rules
it encodes are enough for its properties in every behavior of its bounded configurations; it
says nothing about an implementation that takes a step in another order, splits it into
several, or leaves a rule out. Each transition of the TLA+ model is one atomic step, and an
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
  conformance claim declares which of them it covers (ECL1N-0190). Recovery can itself be
  interrupted or repeated, which the model has no step for: its log only grows (`LogAppendOnly`).
  In an MCP gateway under MCP-GATEWAY-1, recovery records its decision before it writes and
  settles each journal once, so a repeated recovery writes the same records and never a second
  signed terminal (MG1-016).
- **Revocation, halt and trust changes.** Propagation is one step within a bound in the model
  (`RevocationBound`), and a halt is acknowledged in one step within its bound. An enforcement
  point that holds no feed of revocations or halts relies on the authorization's validity to
  bound what a revocation or a halt issued after the decision can miss.
- **The protocol model's clock and memory.** The restriction `EnforcementClock` assumes the
  enforcement point's clock, and the lemma `single_use` assumes one enforcement point that
  remembers every consumed authorization. An implementation's timing for the release boundary is
  one that ECL1N-0188 allows: a check made at the release boundary, a declared bound on the delay
  between the check and the release that is enforced, or a check of the authority at the point of
  effect. It counts each use of an authorization atomically with every other use by any instance
  or attempt, a recovered one included, so that a restart cannot use it again (ECL1N-0186 item 3,
  ECL1N-0189); an MCP gateway under MCP-GATEWAY-1 routes every use of an authorization through one
  instance or a shared use store (MG1-005).
- **Bounded configurations.** A property can fail in a configuration larger than those checked;
  the configurations are listed above.

## Running the checks

The tools are not dependencies of the package and are not installed with it. The script, which
needs Python 3.10 or later and nothing else, uses these pinned releases and refuses others unless `--allow-unpinned` is given:

| Tool | Version | Download | SHA-256 |
|---|---|---|---|
| TLA+ tools (TLC) | 1.7.4 | `https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar` | jar `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88` |
| Tamarin prover | 1.12.0 | `https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz` | archive `201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6`, binary `9d3fcbaa65aeea244cff5b8074338d129427161cc8b02e5aee72d30ee072acc9` |
| Maude | 3.5.1 | `https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/Maude-3.5.1-linux-x86_64.zip` | archive `72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c`, binary `9dd4044e693944aae97ad72086bc70275fa34bf635f9b377a5b2100bf3ed8655` |

TLC runs on Java 21 with a 1,500 MB heap and one worker. Point the script at the tools with
options or environment variables:

```bash
export ECL_TLA2TOOLS_JAR=/path/to/tla2tools.jar
export ECL_TAMARIN_PROVER=/path/to/tamarin-prover
export ECL_MAUDE_DIR=/path/to/maude-directory
python3 formal/run_checks.py                   # every check
python3 formal/run_checks.py --only correct-binding --only protocol-correct
python3 formal/run_checks.py --skip-tamarin --record formal/results.json
python3 formal/run_checks.py --readme          # render the tables below
```

Without the tools the script prints these sources and digests and exits with status 2.
`--record` writes each result with the SHA-256 of the model files it ran on and keeps the results
of checks that did not run, so a long run can be split. The maintainer's tests fail when a
recorded result does not match the committed models, when a check is missing or unexpected, or
when the tables below differ from the record.

## Results

All 32 TLC checks and nine Tamarin checks give their expected outcome. The correct design
passes every safety property in all three base configurations and every liveness property in
the liveness configuration. Each of the 22 broken variants and seven witnesses yields a
counterexample to the property named for it. The seven lemmas are proved for the correct
protocol, and each of the eight flaws falsifies its lemma. The times were measured on a shared
machine with two CPUs and are indicative only.

<!-- formal:results -->
| TLC check | Expected | Observed | Distinct states | States generated | Depth | Trace states | Seconds |
|---|---|---|---:|---:|---:|---:|---:|
| `correct-binding` | no error | no error | 1,724,911 | 7,528,740 | 14 |  | 69.4 |
| `correct-control` | no error | no error | 7,613,132 | 29,655,925 | 24 |  | 160.6 |
| `correct-liveness` | no error | no error | 131,839 | 456,742 | 17 |  | 22.5 |
| `broken-outage-proceeds` | `NoEffectDuringOutage` | `NoEffectDuringOutage` | 235 | 407 | 5 | 5 | 0.7 |
| `broken-late-decision-used` | `SafeStateHasNoEffect` | `SafeStateHasNoEffect` | 10,302 | 26,836 | 6 | 6 | 1.1 |
| `broken-no-digest-binding` | `EffectHasMatchingAdmit` | `EffectHasMatchingAdmit` | 216 | 478 | 4 | 4 | 0.7 |
| `broken-no-target-binding` | `EffectHasMatchingAdmit` | `EffectHasMatchingAdmit` | 216 | 478 | 4 | 4 | 0.7 |
| `broken-no-audience-binding` | `EffectWithinAuthority` | `EffectWithinAuthority` | 216 | 478 | 4 | 4 | 0.7 |
| `broken-no-window` | `EffectWithinAuthority` | `EffectWithinAuthority` | 8,855 | 22,926 | 6 | 6 | 1.0 |
| `broken-no-single-use` | `SingleUse` | `SingleUse` | 1,449 | 3,863 | 5 | 5 | 0.8 |
| `broken-ignore-revocation` | `NoEffectWithKnownRevocation` | `NoEffectWithKnownRevocation` | 439 | 871 | 6 | 6 | 0.7 |
| `broken-ignore-staleness` | `NoEffectDuringOutage` | `NoEffectDuringOutage` | 5,375 | 12,011 | 8 | 8 | 0.9 |
| `broken-no-propagation-deadline` | `RevocationBound` | `RevocationBound` | 2,243 | 4,610 | 7 | 7 | 0.8 |
| `broken-ignore-halt` | `NoEffectAtHaltedEP` | `NoEffectAtHaltedEP` | 497 | 989 | 6 | 6 | 0.7 |
| `broken-halt-unbounded` | `NoEffectBeyondHaltBound` | `NoEffectBeyondHaltBound` | 5,455 | 13,013 | 8 | 8 | 0.9 |
| `broken-evidence-not-atomic` | `EffectHasEvidence` | `EffectHasEvidence` | 215 | 476 | 4 | 4 | 0.7 |
| `broken-bypass` | `EffectHasMatchingAdmit` | `EffectHasMatchingAdmit` | 25 | 38 | 3 | 3 | 0.7 |
| `broken-actor-writes-authority` | `EffectHasMatchingAdmit` | `EffectHasMatchingAdmit` | 254 | 568 | 4 | 4 | 0.7 |
| `broken-actor-writes-decision` | `AdmitOnlyAllowed` | `AdmitOnlyAllowed` | 39 | 59 | 3 | 3 | 0.7 |
| `broken-actor-erases-evidence` | `LogAppendOnly` | `LogAppendOnly` | 1,449 | 3,847 | 5 | 5 | 0.8 |
| `broken-judgment-admits` | `OneWayRule` | `OneWayRule` | 36 | 54 | 3 | 3 | 0.7 |
| `broken-self-report-admits` | `OneWayRule` | `OneWayRule` | 37 | 54 | 3 | 3 | 0.7 |
| `broken-hold-never-times-out` | `HoldResolves` | `HoldResolves` | 62,599 | 175,151 |  | 12 | 3.7 |
| `broken-no-decision-timeout` | `RequestResolves` | `RequestResolves` | 64,374 | 172,087 |  | 12 | 3.7 |
| `broken-halt-ack-lost` | `HaltTakesEffect` | `HaltTakesEffect` | 64,506 | 212,548 |  | 13 | 3.6 |
| `witness-effect` | `WitnessNoEffect` | `WitnessNoEffect` | 215 | 476 | 4 | 4 | 0.7 |
| `witness-admit-after-hold` | `WitnessNoAdmitAfterHold` | `WitnessNoAdmitAfterHold` | 219 | 510 | 4 | 4 | 0.7 |
| `witness-collision-deny` | `WitnessNoCollisionDeny` | `WitnessNoCollisionDeny` | 510 | 1,329 | 5 | 5 | 0.7 |
| `witness-effect-during-outage` | `WitnessNoEffectDuringOutage` | `WitnessNoEffectDuringOutage` | 126 | 229 | 5 | 5 | 0.7 |
| `witness-effect-in-revocation-window` | `WitnessNoEffectInRevocationWindow` | `WitnessNoEffectInRevocationWindow` | 114 | 211 | 5 | 5 | 0.7 |
| `witness-effect-in-halt-window` | `WitnessNoEffectInHaltWindow` | `WitnessNoEffectInHaltWindow` | 129 | 238 | 5 | 5 | 0.7 |
| `witness-timeout` | `WitnessNoTimeout` | `WitnessNoTimeout` | 61 | 95 | 4 | 4 | 0.7 |

| Tamarin check | Lemma | Result | Proof steps | Seconds |
|---|---|---|---:|---:|
| `protocol-correct` | `executable` | verified | 14 | 8.9 |
|  | `request_origin` | verified | 7 |  |
|  | `response_authenticity` | verified | 7 |  |
|  | `request_response_binding` | verified | 7 |  |
|  | `authorization_scope_and_audience` | verified | 12 |  |
|  | `single_use` | verified | 72 |  |
|  | `one_effect_per_request` | verified | 60 |  |
| `protocol-skip-response-signature` | `response_authenticity` | falsified - found trace | 8 | 1.5 |
| `protocol-shared-role-key` | `response_authenticity` | falsified - found trace | 10 | 6.0 |
| `protocol-response-not-bound` | `request_response_binding` | falsified - found trace | 13 | 2.3 |
| `protocol-no-scope-check` | `authorization_scope_and_audience` | falsified - found trace | 13 | 2.7 |
| `protocol-no-audience-check` | `authorization_scope_and_audience` | falsified - found trace | 13 | 2.8 |
| `protocol-no-single-use` | `single_use` | falsified - found trace | 16 | 5.2 |
| `protocol-dp-no-message-identity` | `one_effect_per_request` | falsified - found trace | 20 | 20.5 |
| `protocol-dp-skips-request-signature` | `request_origin` | falsified - found trace | 5 | 1.5 |
<!-- /formal:results -->

"Depth" is the search depth TLC reported when it stopped; TLC reports none for a liveness
counterexample. "Trace states" is the length of the counterexample TLC printed. A Tamarin check
of a flaw analyzes only the lemma named for it.

TLC checks liveness at intervals of time during its search, so the states and the trace length
it reports for the three broken liveness variants change from run to run with the machine's
speed; the property it falsifies does not. The table records the run of 5 October 2026, made
after the models' comments last changed. The run recorded before it, with the same tools and
settings and the earlier comments, gave every check the same outcome and the same counts except
those of the three variants: 28,485, 27,545 and 33,709 distinct states, with traces of 11, 10
and 11 states.

## Limits

- The TLA+ checks are exhaustive only within each configuration's bounds.
- Both models check the design as stated; a defect in an implementation is found by the
  conformance vectors, the implementation's own tests and review, not here. "From the models to
  an implementation" says where an implementation departs from the models' atomic steps.
- Cryptography is perfect in both models. Encoding attacks below the DSSE pre-authentication
  encoding, weak keys and side channels are out of scope.
- The protocol model assumes the enforcement point's clock and a trust policy with one key per
  principal and role. TRUST-POLICY-1 now requires that assumption: a verifier refuses a trust
  policy whose key carries the purposes of two roles (TP1-009), and counts a decision request or
  response only under a key of its role (TP1-010). The flaw `shared_role_key` shows what the rule
  prevents; the model itself is unchanged and does not represent the refusal.
- What the TLA+ model leaves out is listed under "What it abstracts, and why".
