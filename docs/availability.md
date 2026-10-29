# Keeping fail-closed control available

This page is informative. It adds no requirement, and it recommends nothing
that the normative text forbids; where the normative text leaves a choice to the
deployment or to its assessor, the page says so.

ECL-1 requires that a failure ends in denial, restricted mode or halt, never in
the action going ahead: missing or invalid required proof fails closed
(TS1-018, TS1-032), and the Enforcement Layer fails closed on control-path
ambiguity, policy ambiguity or integrity failure (ECL1N-0043). A deployment that answers every
fault by refusing everything becomes fragile: the outage of one decision
service stops every consequential action, including actions whose proof is
intact. The four patterns below keep a deployment useful during faults without
weakening that rule. Each is checked against TIMING-SAFE-STATE-1, the authority
rules and the budget rules. The section after them says what a check at the
release boundary shows about time, and what it does not.

## 1. Redundant decision points

Two or more decision service instances answer the same enforcement points, so
that the loss of one instance does not stop decisions. The pattern stays within
the rules when:

- each instance is a declared hot-path dependency (TS1-010). The loss of every
  instance removes required proof, so it fails closed with the disposition the
  safe-state profile declares for each action class, never with an admit
  (TS1-018, TS1-031, TS1-032);
- each response names the policy version, digest and epoch it applied, so that
  each outcome can be reproduced from the logged request, policy version and
  trust state (ECL1N-0040). An enforcement point treats a response under a
  policy or trust epoch older than its staleness budget allows as missing
  required proof (TS1-012, TS1-013);
- each instance signs with its own key, which the trust policy binds to that
  instance for the decision-response purpose, so that a verifier accepts each
  response only from a key bound to its issuer (TP1-004, TP1-005);
- the instances share one budget ledger, or divide each budget into
  allocations that together do not exceed it. ECL1N-0173 requires a budget to
  count the actions of every session, workflow and instance and to cause a
  `deny` or `hold` for an action that would exceed it; an instance that cannot
  reach the ledger, and holds no allocation, cannot show that an action stays
  within the budget, and answers `deny` or `hold` for the budgeted classes;
- an action key produces at most one committed effect and a charged use of
  authority at most one effect, across retries and duplicates (TE1-003). When
  an enforcement point asks a second instance after the first timed out, both
  may answer; the enforcement point uses at most one authorization for the
  action key and returns the committed outcome to a retry (TE1-006, TE1-008,
  TE1-010);
- a halt reaches every instance and every enforcement point, and takes
  precedence over ordinary admission and cached allow decisions (TS1-025). The
  halt acknowledgment bound and the revocation propagation deadline are
  declared separately (TS1-035) and hold for the slowest instance.

The ECL incident replay suite's outage steps (`record-1-knight-2012` and
`record-17-operator-2025` in `../conformance/scenarios/`) show the behavior that
remains when every decision point is unavailable: no effect, and restricted
mode for every class that the decision service decides until it answers again
(the second row of the table in section 2, ECL1N-0191).

## 2. Restricted mode scoped by action class

The safe-state deployment profile
(`../schemas/ecl-safe-state-profile-v1.schema.json`) declares, for each action
class, its disposition on a timeout, on the loss of a dependency, on a stale
dependency and on exhaustion of the evidence buffer, and the operations that
remain available in restricted mode (TS1-020). Each dependency declares whether
it supplies required proof. With these declarations a deployment refuses the
classes whose required proof a fault has removed and keeps running the classes
whose proof is intact: a dependency is advisory for an action exactly when its
loss leaves the action's required proof present, valid and unexpired
(TS1-031). For example, when the system of record that supplies a payment's
independent input (ECL1N-0165) is unreachable, payments are refused, while
actions that do not rest on it continue.

The rules still bound the pattern. A fail-open disposition for a class is an explicit policy
decision with an owner, a rationale, an expiry and evidence obligations
(TS1-016); it is never used where law, contract or irreversible risk requires
fail-closed (TS1-017), it never covers a dependency whose loss removes required
proof (TS1-033), and a deployment that claims STRICT-FAILURE-1 declares none
(SF1-001, SF1-002). Triggers that concern the whole deployment still bring at
least the state that ECL1N-0146 gives them, in its order of precedence:
emergency halt for a critical integrity failure or an emergency control
activation, and restricted mode when cached state expires or the degraded-mode
window is exceeded (ECL1N-0029, ECL1N-0146). Within its scope, restricted mode
denies every new consequential action except explicit safe-state or
containment actions (ECL1N-0103).

ECL1N-0146 also gives "proof missing" as a trigger for restricted mode, and
ECL1N-0191 to ECL1N-0193 set the scope of the restriction it brings. The scope
follows from the claim's dependency model, which the claim declares with its
mode definitions (ECL1N-0101, ECL1N-0192): for each action class, every
dependency whose loss can remove its required proof, directly or through
another dependency, and for each dependency the enclosing scope to restrict
when the scope of a loss cannot be established.

| Fault or condition | Scope and state | Example |
|---|---|---|
| Required proof unobtainable for one action class only | Restricted mode for that class; each other class continues only with its own required proof and controls intact | The system of record behind payments is unreachable: payments are refused, and calendar changes continue |
| A dependency that several classes require fails or goes stale | Restricted mode for every class that requires it, directly or through other dependencies | The decision service stops answering: every class it decides is restricted |
| Critical integrity failure or emergency control activation | The state that ECL1N-0146 gives it, for the whole deployment; no class scope or local exception applies | The enforcement point's policy bundle has been altered: emergency halt |
| A loss of required proof whose scope cannot be established | Restricted mode for the enclosing scope that the dependency model declares, or for the whole deployment where it declares none | A shared cache of state witnesses fails, and no one can tell whose witnesses it held |

A restriction ends for a class only when its required proof has been obtained
again after the fault, not taken from a cache made before it, and the
authorization that the mode definitions declare for lifting it is recorded; a
deployment-wide state brought by an integrity failure or an emergency
activation ends only by a recorded control action (ECL1N-0193). A single action
whose required proof is missing, such as one whose before-release obligation is
unproven, is refused whatever the mode (ECL1N-0187).

None of this relabels required proof. A dependency that supplies a class's
required proof stays required for that class, and calling it advisory to keep
the class outside the scope is what ECL1N-0191 forbids (TS1-031, TS1-032). In
the safe-state profile, each such dependency declares a loss disposition that
fails closed (TS1-032). The profile's schema does not record which classes
require which dependency, so the dependency model is part of the mode
definitions, and the assessor checks the model against the deployment's
dependencies and its fault tests (checklist item EA-29).

## 3. Pre-declared degraded modes

Degraded mode continues only bounded actions under signed cached state
(ECL1N-0102). A local gate can apply the profile's decision and safe-state
rules without an undeclared network dependency (TS1-011), so an enforcement
point that holds signed policy and trust state can keep deciding for a short,
declared time when the decision service is unreachable. The pattern stays
within the rules when:

- the mode states what remains permitted, for how long, under which cached
  epochs, and how it expires into restricted mode or halt (TS1-019), and it
  does expire into one of them when its window ends or a critical integrity
  failure occurs (ECL1N-0029);
- the policy, trust-root, registry, revocation and evidence-export staleness
  budgets are declared separately (TS1-012), and none exceeds the offline
  control-state staleness that the declared timing case allows (ECL1N-0097,
  ECL1N-0098);
- the permitted classes are those whose required proof is local and signed.
  An action whose independent input (ECL1N-0165) or recorded approval
  (ECL1N-0177) cannot be obtained during the outage is not admitted (TS1-032);
- the local gate's decisions follow the one-way rule as every decision does
  (ECL1N-0178 to ECL1N-0182): the gate consults only the inputs that the
  register declares for the class, records the basis of each decision, and
  treats a cached input as late once it is older than its declared maximum
  age. A required input that the outage leaves unavailable or late prevents an
  `admit`, and an optional one does not affect the outcome;
- budgets are spent from allocations granted before the outage, which
  together do not exceed the budget (ECL1N-0173);
- evidence is buffered with declared capacity, durability, encryption,
  ordering, overflow and export behavior (TS1-021); exhaustion has a declared
  response and never silently drops verifier-critical events (TS1-022,
  TS1-023); and recovery reconciles policy epochs, revocations, consumed
  authorities, buffered evidence, unresolved effects and clock
  discontinuities before normal operation resumes (TS1-014, TS1-024).

## 4. Revocation propagation bounds and the timing case

Each claim publishes a declared timing case with three bounds: connected
revocation propagation, maximum offline control-state staleness before
restricted mode or halt, and the delay from the first approved transfer path to
completed evidence export (ECL1N-0097). Each bound names its observation
points, its objective type, its clock, and the load and fault conditions under
which it holds (TS1-034); the default values by level are in ECL1N-0098. A
revocation-propagation deadline and a halt acknowledgment bound are separate
obligations (TS1-035).

Redundancy and isolation lengthen propagation: every decision instance and
every enforcement point has to learn of a revocation, and federated domains
meet the same connected revocation timing case (ECL1N-0099). A deployment that
adds instances measures propagation to the slowest of them, monitors the timing
case continuously and keeps breach evidence (FR-112), and applies its timeout
safe-state rule when a gate exceeds its deadline (TS1-009).

The authorization validity window bounds what a revocation can still miss. The
claim declares a maximum authorization validity that producer, consumer and
verifier each enforce (TE1-009), and after a control change is acknowledged no
effect that depends on the revoked authority may commit (TE1-005). An
enforcement point that checks its control state at release, rather than relying
on the authorization alone, closes the window between a revocation and the
expiry of authorizations issued before it. Either way, the halts, quarantines
and revocations that the declared timing case requires to have reached the
enforcement point are among the checks it makes at the release boundary
(ECL1N-0186).

## Release timing and remote effects

An authorization is usable from its `valid_from` until before its
`valid_until`, and the enforcement point establishes that it is usable at the
release boundary itself (ECL1N-0188). Work that can block between the last
check and the release, such as writing or signing evidence, waiting for a lock
or obtaining an obligation's proof, lies inside the timing argument. A
deployment that writes a durable record before the release (ECL1N-0189)
therefore checks the authority again after that write, at the release boundary,
and refuses when the authority is no longer usable there, or it enforces a
declared bound on the time from its check to the release and allows for that
bound in the check. It does not release under a time it read before the write
with no such bound, and it does not give the release record an earlier time to
fit the window.

A check made just before a gateway sends a call shows that the authority was
usable when the send began. It does not show when the remote server acted on
the call. A response can be lost after the server acted, so the outcome stays
unresolved until the server's own record or an authoritative status query
settles it (ECL1N-0189), and a retry can repeat the effect unless the server
applies each call at most once. Where the time of the remote effect matters,
the deployment needs an authority check at the point of effect, as a resource
server checks a presented token under OAUTH-AUTHORITY-1, or a declared bound on
the delay between release and effect that it can enforce. A transaction that
admits and commits on one store, as under TRANSACTIONAL-EFFECT-1, binds the
effect to its admission instant, and its commit follows that instant by the
time the transaction takes to finish.

## Summary

| Pattern | What it keeps available | Rules it is checked against |
|---|---|---|
| Redundant decision points | decisions when one instance fails | TS1-010, TS1-012, TS1-013, TS1-018, TS1-025, TS1-031, TS1-032, TS1-035, ECL1N-0040, ECL1N-0173, TE1-003, TE1-006, TE1-008, TE1-010 |
| Restricted mode scoped by action class | the classes whose required proof is intact | TS1-016, TS1-017, TS1-020, TS1-031, TS1-032, TS1-033, SF1-001, SF1-002, ECL1N-0029, ECL1N-0101, ECL1N-0103, ECL1N-0146, ECL1N-0187, ECL1N-0191, ECL1N-0192, ECL1N-0193, FR-008 |
| Pre-declared degraded modes | bounded classes under signed cached state for a declared time | ECL1N-0029, ECL1N-0097, ECL1N-0098, ECL1N-0102, ECL1N-0165, ECL1N-0173, ECL1N-0177, TS1-011, TS1-012, TS1-014, TS1-019, TS1-021 to TS1-024, TS1-032 |
| Revocation propagation bounds | containment that keeps pace with added instances | ECL1N-0097, ECL1N-0098, ECL1N-0099, FR-112, TS1-009, TS1-034, TS1-035, TE1-005, TE1-009 |

None of these patterns admits an action whose required proof is missing, or
reclassifies such a failure as an outage or a timeout to reach a fail-open
disposition (TS1-032). None lets a lower-precedence decision revive an object
placed in a higher-precedence safe state (TS1-027), and none counts a budget
for each instance separately (ECL1N-0173).
