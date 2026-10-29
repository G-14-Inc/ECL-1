# ECL-1 in one page, for buyers

ECL-1 is a technical standard for controlling the actions of AI systems
that can change things outside themselves: records, payments, messages,
accounts or equipment. It requires a control layer outside the AI system whose
actions it governs, which the standard calls the governed AI system. Every such
action that the supplier's claim declares in scope must pass that layer before
it runs, and the governed AI system must not be able to bypass or change it
(standard, Sections 5.1 and 5.4). The layer
decides, enforces the decision, and denies, restricts or halts when proof is
missing, integrity fails or the policy is ambiguous. It produces signed
evidence that a third party, someone other than the supplier, can check and,
from L2, verify offline. An instruction given to the AI does not count as a
control. Scores from AI models and the governed AI system's own statements can
make a decision stricter, but they never approve an action; each decision
records which inputs it rested on (Section 5.2).

ECL-1 does not judge what an action means, measure model quality or replace a
governance program; it is not a substitute for those (Section 2.7).

## What you need to do

1. Ask for the supplier's claim statement and check it against the list below.
2. Ask for a sample evidence bundle and its trust policy, and verify the
   bundle yourself with the [offline verifier](../web/verifier/index.html),
   which runs in your browser and sends nothing anywhere. From L2 the standard
   requires that evidence be independently verifiable outside the primary
   control plane (FR-108).
3. Ask for the records listed under "What to ask a supplier for".
4. Check the level and independence class against your own risk, using the
   standard's Section 7.
5. Check the version the claim names. A claim cites ECL-1 Version 1.0, or a
   later version, with the companion versions it uses; a claim against an
   earlier release candidate is not a claim against Version 1.0.

## What a claim must tell you

A valid ECL-1 claim names the system it covers, its level, its status, its
boundary, its independence class, the versions it uses, its assessment date and
its limits (standard, Section 7.7). "ECL-1 compliant" on its own is not a valid
claim.

- **Levels.** L1 Foundational, L2 Standard, L3 Advanced, L4 Critical
  Infrastructure. Each level includes the ones below it. The required level
  follows the riskiest of autonomy, data sensitivity and action consequence.
- **Independence.** Class A: one operator, with separated roles and keys.
  Class B: approval of controls and verification of evidence both sit in a
  separately administered domain that the governed AI system and its ordinary
  operators cannot change on their own. Class C: Class B, held by an authority
  outside the operator. L2 and L3 need at least Class B, and L4 needs Class C.
- **Status.** Full conformance, conditional conformance (L2 and L3 only, with
  deadlines), or assessment-only (evidence exists, assessment is not complete).

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
failure, which means that a signing key is revoked or expired today although
the evidence was valid when it was made.

## Where the standard stands

ECL-1 Version 1.0 is a published standard, maintained by G-14, Inc. and
developed in the open by the ECL-1 Working Group. Its conformance tests have a
passing and a failing case for every unit of the published coverage
denominator (`conformance/coverage-denominator.json`): each branch of the
message formats, the extension values and the claim and assessment documents,
and each checking rule. Three units cannot be tested on their own, and the
denominator gives the reason for each. The denominator counts message formats
and checking rules, not the runtime behavior of a deployment, which an
assessor examines.

A conformance claim is self-declared by its supplier. The ECL-1 repository
lists submitted claims as self-declared, and lists an assessor's assessment
separately when the supplier provides one; G-14 certifies nothing.

The text of ECL-1 is licensed under CC BY 4.0 and its code and machine-readable
artifacts under Apache-2.0, and G-14, Inc. pledges not to assert its essential
patent claims against implementations, royalty-free ([PATENTS.md](../PATENTS.md)). G-14 has
patents pending.
