# Design choices in the Version 1 public-review draft

Robert F. Tilley Jr. and G-14, Inc.

This guide records contract choices made while preparing the public-review
draft and identifies proposed extensions that it does not implement. The
linked requirements govern; the examples below explain their scope.

## Request expiry and continuation histories

An admitting decision must be evaluated before the request expires. Equality
is expired. This check uses the recorded instants at nanosecond precision,
without an expiry-skew allowance. A refusal may document evaluation at or
after expiry. The resulting authorization can outlive the request, subject
to the response validity interval and requested-duration bounds in
[DCMP-2](../protocols/DCMP-2.md). Request expiry limits admitting evaluation;
authorization expiry limits use of the issued authority.

An evidence history can include an admitted continuation and a subsequent
refused reuse of its challenge. Two admitted continuations of the same
challenge remain invalid. The remaining binding, approval, signer-role,
expiry and causal-closure checks still apply. Missing approval evidence
alone leaves the history incomplete. This distinction in [EBMP2-078](../protocols/EBMP-2.md)
allows a history to retain the refusal required by DCMP2-057.

Approval checks do not establish every runtime decision duty. The offline
continuation check binds the challenge and approval digests, checks the
approval target and signer role, requires that none of the approval signing keys be bound to the requesting
actor, and checks approval expiry at admitting evaluation.
DCMP2-057 separately requires fresh policy evaluation and the approved actor,
action and authority scope. Signing-key separation does not establish that
two different people approved and requested an action.

Digest-bound approval causality, approval-time ordering and separation of
human principals are proposals for further review. Adding them requires a
precise approval representation and clock policy. The present record checks
must not be used as evidence that these additional conditions were checked.

## Trust history and recorded times

Trust-policy issuers should carry relevant compromise revocations, effective
dates and key bindings into later caller trust policies. When a revocation
is corrected or withdrawn, retain an attributable correction and its reason.
The verifier continues to apply the named historical policy and the caller's
current policy under [TP1-006](../profiles/TRUST-POLICY-1.md). It does not union
unrelated historical policies, and a policy carried inside an evidence bundle
does not become a caller trust anchor.

The pre-release proof checks retain the recorded-time comparisons specified
by EBMP2-070. Comparing a proof type's own issue time with `checked_at` would
require that type's timestamp meaning and a clock/skew rule. That broader
comparison is not implemented by this draft. Consistency between recorded
timestamps also does not establish trusted time.

This public-review draft supports only `single_use` DCMP-2 authority, with
`max_uses` absent or the integer 1. An explicit request limit of 1 still
requires the admit to carry that limit. `bounded_multi_use` retains its registry
allocation as a reserved, unsupported value and is rejected at both the request
and authorization boundaries.

This is a capability restriction and a compatibility change. The earlier
multi-use representation counted consumptions and OAuth presentations, but
the evidence contract did not consistently represent a separate release and
terminal outcome for each use. Enabling that capability requires a complete
per-use contract for identity, consumable proofs, consequence budgets,
idempotency and recovery. This draft leaves the existing single-use evidence
contract intact. The [migration notes](single-use-authorization-migration.md)
describe the affected interfaces and producer obligations.

## Package and assessment consumers

The offline package verifier checks the archive, manifest, artifact sizes and
digests, required presence, and the evidence roles specified by
[IE1-022](../protocols/INTEGRITY-ENVELOPE-1.md). A successful package check does
not mean that every auxiliary document was interpreted or assessed. Carried
trust-policy and registry snapshots are producer evidence; the caller supplies
the policy and register used for verification.

An observation-only package is incomplete and establishes no verification
scope. The present ordered algorithm parses its observations but does not run
full bundle verification until an envelope is present. Cryptographic checking
of partial observation-only material is a proposed extension to that
algorithm, not an assurance supplied by an incomplete result.

An assessment consumer obtains the claim's conditions from the referenced
`claim_artifact`. Checking the assessment package's schema does not resolve
that reference or assess its contents. A consumer relying on the claim needs
the artifact and its integrity binding, then checks the actual conditions
and scope. The draft does not duplicate those conditions in a second schema
location.

## Producer conventions and helper APIs

For a witness result deferred to release, a producer can use the same
identifier and type for the corresponding `before_release` obligation and
witness reference when they denote the same check. If they use different
keys, EBMP2-070 requires both discharge entries. Both entries may name the
same proof when it satisfies both checks; one entry does not silently cover
two different keys.

The safe-state selection helper requires a nonempty failure set. An empty
set raises `ValueError`; it does not invent a transition to a healthy state
or select a safe-state label without a triggering failure.

The public-review model now represents recovery reconciliation before normal
operation. Its globally shared consumption state, atomic correct-model
evidence, known effect outcomes and continuous clock remain abstractions.
[The formal-model guide](../formal/README.md) identifies the concrete recovery
work that an implementation must establish separately.

Further review may define machine-checkable hold progress, cross-instance
timeout closure, future-effective control scheduling, version selection for
control targets, continuation cancellation/delegation propagation, additional
timing scopes, and nested diagnostic paths. These extensions need explicit
representations and tests. Existing timeout, immutable-evidence, binding and
causal-closure requirements continue to apply.
