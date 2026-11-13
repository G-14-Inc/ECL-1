# ECL Distributed and Long-Running Workflow Semantics 1

Version: 1.0
Status: normative companion in the ECL-1 Version 1 public-review local candidate
Source build: `1.0.2-review.1`; prepared `2026-11-10`

## 1. Scope

This profile defines semantics for multi-agent, multi-service, delegated,
retried, concurrent, partially completed, and long-running actions. It does not
require a central coordinator or global consensus.

**DW1-001** — Every action workflow MUST have a workflow identifier and root
trace identifier.

**DW1-002** — A child workflow MUST identify its parent workflow and the exact
causal object that created or delegated it. For EBMP-2 evidence, the child
record's causal ancestry identifies that object through the digest-bound path
specified in EBMP2-077; the parent identifier alone is insufficient. In an
`ECL-WI-1` work intent, either `parent_workflow.uri` or
`workflow.parent_workflow_id` identifies the parent of a child workflow. If
both are present, they MUST name the same logical identifier, and neither MAY name the child's own `workflow.workflow_id`. A
child work intent MUST carry at least one digest-bound causal predecessor
identifying its creation or delegation. A consumer MUST reject an inconsistent
parent declaration or a child with no causal predecessor with
`ecl.rule.work-intent-context-consistent.v1`. Checking this declaration alone
does not establish the referenced object's contents or complete ancestry.

**DW1-003** — Every retry MUST create a new attempt identity. Prior attempt
state and side effects remain evidence.

**DW1-004** — An idempotency key identifies an intended effect boundary and
MUST NOT be treated as proof that a duplicate effect did not occur.

## 2. Causal graph

**DW1-005** — Causality MUST be represented by logical identifier plus
canonical digest.

**DW1-006** — The causal graph MUST be acyclic. A work intent MUST NOT
name its own `intent_id` as a causal predecessor; a consumer MUST reject that
self-reference with `ecl.rule.message-cannot-cause-itself.v1`.

**DW1-007** — Sequence numbers provide ordering only within their declared
sequence domain. A consumer MUST NOT infer global order from unrelated
sequences.

**DW1-008** — Wall-clock order MUST NOT override an authenticated causal edge.

**DW1-009** — A fork MUST preserve the common predecessor. A join MUST
reference every branch whose completion or disposition is required.

**DW1-010** — Missing required branches make a join incomplete or
indeterminate; they MUST NOT default to success.

## 3. Delegation and multi-agent action

**DW1-011** — Delegation MUST preserve root actor, immediate actor, subject,
scope, audience, expiry, and attenuation at every hop.

**DW1-012** — An agent that plans an action, an agent that executes it, and a
service that admits it MUST remain separately attributable.

**DW1-013** — Two agents emitting the same logical request MUST still have
distinct message and attempt identities.

**DW1-014** — Conflicting decisions, authorities, or execution observations
MUST be retained and reconciled by a declared precedence or adjudication rule.
Last-writer-wins is prohibited for security-relevant conflicts unless a
profile explicitly defines and justifies it.

**DW1-015** — An agent's declared intent is not execution authority. Intent,
Decision, Authority, Enforcement, and observed effect MUST remain distinct.
An `ECL-WI-1` work intent MUST state its advisory validity interval as
`issued_at` and `expires_at`, with expiry strictly later than issue; a consumer
MUST reject an empty or reversed interval with
`ecl.rule.expiry-after-issue.v1`. Expiry ends the intent's applicability as a
current coordination advisory, not the retention of its historical record.
Neither a valid intent nor its validity interval grants execution authority.

## 4. Epochs and stale work

**DW1-016** — A long-running workflow MUST bind the relevant policy, trust,
registry, capability, and source epochs at each decision boundary.

**DW1-017** — A changed dependency or epoch MUST trigger the profile's
re-evaluation rule before any affected unreleased action.

**DW1-018** — An epoch change MUST NOT retroactively mark previously released
work unauthorized; that work MUST instead be evaluated under revocation,
interruption, compensation, and incident policy.

**DW1-019** — A stale worker MUST NOT merge, release, or certify work whose
required source or policy epoch no longer matches.

## 5. Partial and uncertain outcome

**DW1-020** — A timeout, lost response, process crash, or partition MUST NOT be
reported as a failed external effect unless failure is actually observed.

**DW1-021** — `unknown` MUST be treated as a terminal observation state and
MUST carry residual-uncertainty evidence and reconciliation policy.

**DW1-022** — Partial success MUST enumerate known completed, failed, pending,
and unknown sub-effects.

**DW1-023** — Compensation and rollback MUST be separately authorized,
executed, and evidenced.

**DW1-024** — A parent workflow MUST NOT claim complete success while a
required child is open, unknown, or causally unresolved.

## 6. Human and automated coordination

**DW1-025** — Human approval, rejection, cancellation, override, and emergency
action MUST be represented as first-class causal events with authority and
expiry.

**DW1-026** — A human review of one attempt MUST NOT silently authorize a later
attempt whose parameters, target, policy, or evidence digest changed.

**DW1-027** — Automated adjudication of conflicts MUST itself have a Decision,
Authority, Provenance, and Verification boundary appropriate to consequence.

## 7. Bundle closure

**DW1-028** — A complete workflow bundle MUST have causal closure for every
required decision, authority, execution attempt, intervention, terminal
outcome, and invoked lifecycle event.

**DW1-029** — External predecessors MAY remain outside the bundle only when
their immutable references and retrieval or inclusion policy permit the
intended offline verification claim.

**DW1-030** — Closure tools MUST report complete, incomplete, or indeterminate
and enumerate open actions and unresolved predecessors.
