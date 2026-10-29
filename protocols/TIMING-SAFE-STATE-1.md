# ECL Timing, Availability, and Safe-State Semantics 1

Version: 1.0
Status: normative companion of ECL-1 Version 1.0, a published version

Requirement identifiers are allocated in the order requirements were added and
never reused, so a later identifier appears among earlier ones where its subject
belongs: TS1-034 to TS1-036 follow TS1-009, and TS1-031 to TS1-033 follow TS1-018.

## 1. Time classes

ECL distinguishes:

- issuer wall time;
- observer wall time;
- trusted external time;
- monotonic duration;
- causal order;
- policy and revocation epoch.

**TS1-001** — A producer MUST identify the time class it records.

**TS1-002** — Wall time MUST use the restricted UTC RFC 3339 profile.

**TS1-003** — Monotonic evidence MUST identify the clock instance, ticks, and
unit. It is comparable only within the declared clock domain.

**TS1-004** — A verifier MUST apply an explicit clock-skew and trusted-time
policy.

**TS1-005** — Causal order and authenticated sequence evidence MUST take
precedence over conflicting unauthenticated wall-clock order.

## 2. Latency declaration

**TS1-006** — An enforcement deployment profile MUST state the local-gate
latency measurement points, percentile method, sampling interval, warm-up
handling, hardware or runtime class, and action classes measured.

**TS1-007** — A product latency claim MUST identify the tested configuration
and evidence. The standard does not define one universal performance number.

**TS1-008** — Remote synchronization, evidence export, and hosted policy
management MUST NOT be included in the hot-path latency claim unless they are
actually required before release.

**TS1-009** — A gate that exceeds its declared deadline MUST apply the timeout
safe-state rule and record the breach.

**TS1-034** — Every declared timing bound MUST name its observation points
(the events between which the interval is measured), its objective type
(a maximum, or a stated percentile with its window), the clock that measures it,
and the load and fault conditions under which it holds.

**TS1-035** — A revocation-propagation deadline and an emergency-halt acknowledgment
bound are distinct obligations and MUST be declared separately; satisfying one
MUST NOT be presented as satisfying the other.

**TS1-036** — A control acknowledgment bound (B) is the maximum interval, at the
declared observation points, between a control operation's request and its
durable acknowledgment, after which no effect depending on the changed scope
or authority may commit; a deployment declaring B MUST state its termination
or escalation mechanism for conflicting work.

## 3. Dependency failure

**TS1-010** — Each dependency MUST declare whether it is hot-path, cached,
asynchronous, or advisory.

**TS1-011** — A local gate MUST be capable of applying the profile's decision
and safe-state rules without an undeclared network dependency.

**TS1-012** — Policy, trust-root, registry, revocation, and evidence-export
staleness budgets MUST be separately declared.

**TS1-013** — Exceeding a staleness budget MUST cause the specified restricted,
degraded, deny, quarantine, or halt state.

**TS1-014** — Recovery after partition MUST reconcile policy epochs,
revocations, consumed authorities, buffered evidence, unresolved effects, and
clock discontinuities before normal mode resumes.

## 4. Fail behavior

**TS1-015** — Fail-open, fail-closed, restricted, degraded, quarantine, and
emergency halt MUST be treated as distinct dispositions.

**TS1-016** — Fail-open MUST be an explicit action-class policy decision with
owner, rationale, expiry, evidence obligations, and prohibited conditions.

**TS1-017** — Fail-open MUST NOT be used for an action when the invoked
profile, law, contract, or irreversible-risk classification requires
fail-closed.

**TS1-018** — Missing or invalid policy, identity, authority, integrity,
critical extension, or pre-release evidence MUST fail closed.

**TS1-031** — A consumer MUST treat required proof as the set of inputs that
TS1-018 names: policy, identity, authority, integrity, critical-extension handling,
and pre-release evidence. A consumer MUST classify a dependency as advisory for
an action exactly when its loss leaves required proof present, valid, and
unexpired, and leaves locally validatable authority sufficient for that action.

**TS1-032** — A failure whose consequence is that any required proof is absent,
invalid, expired, or unavailable MUST be classified as missing required proof
and MUST fail closed under TS1-018, whatever its proximate cause. Reclassifying
such a failure as a dependency outage, timeout, or other generic failure class
in order to reach a fail-open disposition MUST NOT occur. The dispositions that
fail closed are `fail_closed`, `quarantine` and `emergency_halt`: in a
safe-state profile document, a dependency whose `supplies_required_proof` is
`true` MUST declare one of them as its `loss_disposition`, and a consumer MUST
reject any other disposition for it, `restricted` and `degraded` included, with
`ecl.rule.required-proof-dependency-fails-closed.v1`.

**TS1-033** — A fail-open policy under TS1-016 MUST name the advisory dependencies
it covers, and MUST NOT cover any dependency whose loss removes required proof.

The core standard sets which action classes a loss of required proof restricts
and when the restriction ends (ECL1N-0191 to ECL1N-0193). Under the claim's
dependency model, the loss of a dependency that only one action class requires
restricts that class, and the loss of one that several classes require, directly
or through other dependencies, restricts each of them. A loss whose scope cannot
be established restricts the enclosing scope that the model declares, or the
whole deployment where it declares none, and a critical integrity failure or an
emergency control activation applies to the whole deployment. Within that scope
each action is refused with a disposition that fails closed under TS1-032, and
the dependency keeps its classification as one that supplies required proof
(TS1-031).

**TS1-019** — Degraded mode MUST state what remains permitted, for how long,
under which cached epochs, and how it expires into restricted mode or halt.

**TS1-020** — Restricted mode MUST state the bounded operations that remain
available for diagnosis, recovery, or safe shutdown.

## 5. Buffering and backpressure

**TS1-021** — Local evidence buffering MUST declare capacity, durability,
encryption, ordering, overflow, and export behavior.

**TS1-022** — Evidence buffer exhaustion MUST NOT silently drop verifier-
critical events.

**TS1-023** — A deployment MUST declare whether exhaustion denies new actions,
enters restricted mode, sheds only non-critical telemetry, or uses another
profile-approved response.

**TS1-024** — Recovery MUST prove which buffered events were exported, rejected,
duplicated, reordered, or remain unresolved.

## 6. Emergency and precedence

**TS1-025** — Emergency halt and quarantine MUST take precedence over ordinary
admission and cached allow decisions.

**TS1-026** — Revocation, exhausted budget, legal hold, and critical
verification failure precedence MUST be deterministic and profile-declared.

**TS1-027** — A lower-precedence decision MUST NOT revive an object placed in a
higher-precedence safe state.

**TS1-028** — Emergency-channel availability and independence MUST be tested at
the profile-defined interval and after material architecture change.

## 7. Evidence

**TS1-029** — Timing claims MUST retain raw observations, calculation method,
exclusions, breaches, and environment identity.

**TS1-030** — Availability evidence MUST distinguish measured behavior,
designed behavior, and untested assumption.
