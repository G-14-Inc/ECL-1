# ECL-1 guide for buyers

This guide describes the Version 1 public-review candidate, source
`1.0.2-review.1`. Identify its draft status and exact source digest when
requesting or evaluating a claim.

ECL-1 is a technical standard for controlling the actions of AI systems
that can change things outside themselves: records, payments, messages,
accounts or equipment. It requires a control layer outside the AI system whose
actions it governs, which the standard calls the governed AI system. Every such
action that the supplier's claim declares in scope must pass that layer before
it runs, and the governed AI system must not be able to bypass or change it
(standard, Sections 5.1 and 5.4). The layer
decides, enforces the decision, and denies, restricts or halts when proof is
missing, integrity fails or the policy is ambiguous. It produces signed
evidence that a third party, someone other than the supplier, can verify
offline. From L2, the evidence must be independently verifiable outside the
primary control plane (FR-108). An instruction given to the AI does not count as a
control. Scores from AI models and the governed AI system's own statements can
make a decision stricter, but they never approve an action; each decision
records which inputs it rested on (Section 5.2).

ECL-1 does not judge what an action means, measure model quality or replace a
governance program; it is not a substitute for those (Section 2.7).

## What you need to do

1. Ask for the supplier's claim statement and check it against the list below.
2. Ask for a sample evidence bundle and its trust policy, and verify the
   bundle yourself with the [offline verifier](../web/verifier/index.html),
   which processes the selected files locally without uploading them. From L2 the standard
   requires that evidence be independently verifiable outside the primary
   control plane (FR-108).
3. Ask for the records listed under "What to ask a supplier for".
4. Check the level and independence class against your own risk, using the
   standard's Section 7.
5. Check the version the claim names. A claim cites ECL-1 Version 1.0, or a
   later version, with the companion versions it uses, the applied correction
   release and errata, and an immutable source identity. For this candidate,
   record source `1.0.2-review.1`, its draft status and its digest. The historical
   corrected source is `v1.0.1` with `ERR-1.0-001` and that archive's SHA-256.
   A claim against one source version does not establish conformance against
   another source version.

## What a claim must tell you

A valid ECL-1 claim names the system it covers, its level, its status, its
boundary, its independence class, the versions and corrections it uses, its
immutable source identity, its assessment, affirmation or evidence-refresh date, and
its limits (standard, Section 7.7). "ECL-1 compliant" on its own is not a valid
claim.

- **Levels.** L1 Foundational, L2 Standard, L3 Advanced, L4 Critical
  Infrastructure. Each level includes the ones below it. The required level
  follows the riskiest of autonomy, data sensitivity and action consequence.
- **Independence.** Class A: one operator, with separated roles and keys and no
  principal holding unilateral power to change both the governed AI system
  and a control responsibility. Class B: approval of controls and verification of evidence both sit in a
  separately administered domain that the governed AI system and its ordinary
  operators cannot change on their own. Class C: Class B, held by an authority
  outside the operator. L2 and L3 need at least Class B, and L4 needs Class C.
- **Status.** Full conformance, conditional conformance (L2 and L3 only, with
  deadlines), or assessment-only (evidence exists, assessment is not complete).
- **Boundary.** A claim at L1 through L4 covers full-system mediation or bounded
  action classes. A component or profile implementation report states its
  applicable requirement results, capabilities, versions, evidence and limits;
  it carries no overall ECL level and cannot replace deployment assessment.

An assessment-only statement labels an evidence-refresh date as such, for
example "evidence refreshed 2027-01-15; assessment in progress". It does not
describe that date as a completed assessment.

## What to ask a supplier for

- the claim statement, and the list of in-scope actions with the paths that are
  excluded;
- the declared timing case: how fast a revocation takes effect, how long the
  system may run on cached decisions, how fast evidence is exported;
- a sample evidence bundle and the trust policy to verify it with, so that you
  can run the verifier yourself;
- the latest drill records for revocation and for emergency halt;
- for L2 and above, the independent assessment report, the assessor's
  independence statement and the negative-test report;
- the key custody record for the keys that sign evidence (standard, Section 9.8).

## What signed evidence shows, and what it does not

An evidence bundle holds records that say different things. The authorization
says what an action may do and under which conditions. The enforcing
component's records say what it checked and released. The record of the
outcome, or a separate observer's record, says what happened. A bundle that
verifies shows that keys your trust policy accepts signed these exact records
and that the records belong together. It does not show that the enforcing
component checked and released as its records say, and on its own it does not
show that an effect occurred: the verifier lists both among what its verdict
does not establish. A matching record from a separately keyed observer makes
the effect corroborated, which is stronger evidence but still not proof. The verifier
reports one of four verdicts: verified, invalid, incomplete, or a current trust
failure: the evidence passes the historical checks, but the applicable current
trust or expiry checks fail at the selected evaluation time.

## Where the standard stands

G-14, Inc. maintains this local public-review candidate while community
working-group roles are being established. The published v1.0 and v1.0.1
artifacts remain historical references. Publication, approval and any dated
review window for the candidate are separate recorded decisions.

The [coverage denominator](../conformance/coverage-denominator.json) identifies
the measured message formats, extension values, claim/report documents and
checking rules. Coverage must be computed for this candidate's exact sources;
historical coverage counts do not establish its current coverage. Runtime
behavior and a deployment's actual boundary require assessment evidence.

The [review design guide](review-design-decisions.md) explains the repaired
request-expiry and continuation-history contracts. A passing record check is
bounded by its stated verification scope and cannot establish all runtime
policy or approval duties.

A conformance claim is self-declared by its supplier. The ECL-1 repository
lists submitted claims as self-declared, and lists an assessor's assessment
separately when the supplier provides one; G-14 certifies nothing.

The text of ECL-1 is licensed under CC BY 4.0 and its code and machine-readable
artifacts under Apache-2.0. Within the scope and conditions of
[PATENTS.md](../PATENTS.md), G-14, Inc. pledges, royalty-free, not to assert its
Essential Claims against Covered Implementations. G-14 has
patents pending.
