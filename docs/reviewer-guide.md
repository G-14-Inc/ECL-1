# Assessor guide

This guide is for a person who checks an ECL-1 conformance claim and its
evidence as an assessor does, and for a person who reviews the standard itself.
It says how to verify what you were given, check a claim against the standard,
verify its evidence offline, score the checklist with the assessment
procedures, run the negative tests and report what you find, with the files of
this package alone.

The guide is informative. Sections 7 and 11 of the
[standard](../standard/ECL-1_Standard.md) state what an assessment must do;
following this guide is not an assessment, and neither the guide, the
conformance tests nor the verifier certifies anything.

## What you need to do

1. Verify the files you were given: the ECL-1 release you assess against, and
   the claim's documents and evidence.
2. Check the claim statement and the claim documents against the standard.
3. Verify the claim's evidence offline, under a trust policy that you hold.
4. Score the conformance checklist of Section 11 with the assessment procedures.
5. Run the negative tests that the claim's level requires.
6. Check your own independence against the level, and disclose it.
7. Report findings: on a claim to the party you assess for, on the standard in
   the ECL-1 repository, and on a security problem privately.

## Verify what you were given

A release of ECL-1 is published as an archive with a manifest that lists every
file of the archive with its SHA-256 digest. Obtain the digest of the archive,
or of its manifest, from the published release through a channel you trust,
compare it first, then verify each file of the unpacked archive against the
manifest. An unsigned digest establishes that the files are the ones the
publisher listed; it does not identify a signer.
[release/VERSION_SET.json](../release/VERSION_SET.json) gives the version of
every document that a claim against the release cites.

Obtain the claim's evidence and the trust policy that verifies it through two
separate channels. An evidence bundle cannot bring its own verifier trust
policy (TP1-001), and the trust policy, keys and snapshots inside an offline
package are evidence, never trust (IE1-022).

## Check the claim

A claim's public statement names the version, the level, the status and the
claim boundary as Section 7.7 requires. Check each part against its section:

| Part of the claim | Where the standard states it |
|---|---|
| The claim class: full-system mediation, bounded action-class mediation, or a component or profile implementation, which does not provide the guarantee | Section 2.5 |
| The System of Interest, the Consequential Action Register and the Negative Boundary Annex | Sections 2.4 and 2.5 (ECL1N-0007 to ECL1N-0011) |
| The level, at least the required minimum level | Sections 7.1 and 7.2 |
| The independence class, at least the minimum for the level | Section 7.5 (ECL1N-0142 to ECL1N-0144) |
| The status: full, conditional or assessment-only | Section 7.6 |
| The version set, the assessment date and the limits | Sections 7.7 and 7.12 (ECL1N-0087) |

The claim and assessment documents have schemas in [schemas/](../schemas/), and
[CONFORMANCE-CLAIMS-1](../profiles/CONFORMANCE-CLAIMS-1.md) describes them;
[profiles/examples/claims/](../profiles/examples/claims/) holds worked
examples. Check a document against its schema with any JSON Schema draft
2020-12 validator, or with `evaluateDocument` from the TypeScript package
[packages/ecl-ts](../packages/ecl-ts/README.md), which also applies the
registered rules for a document. A document check shows that a document has
the form its schema requires; it does not show that the deployment it
describes has the declared properties.

## Verify the evidence

Verify each bundle or offline package with the offline verifier, under your
trust policy and at the instant at which you verify, which the report states as
its evaluation time; evidence dated after it is invalid, and Version 1.0 defines
no assessment as of an earlier instant
([EBMP2-057](../render/ebmp-2.html#EBMP2-057),
[EBMP2-076](../render/ebmp-2.html#EBMP2-076)): in a browser with
[web/verifier/index.html](../web/verifier/index.html), or on the command line
with `ecl-verify-ts` (`--trust-policy`, `--now`, and `--json` for the
report). Pass the claim's Consequential Action Register with `--register`, so
that the verifier checks each decision basis against the inputs that the
register declares for the action's class.

Read each report's scope as well as its verdict (EBMP2-076). A `verified`
bundle is signed, bound and complete; its records remain their producers'
statements. The verifier lists what the verdict does not establish: that the
enforcement point checked and released as its events record, that the recorded
times are true, that the effects happened and that the deployment has been
assessed. An effect is `issuer-asserted` unless a separately keyed observation
matches it, which makes it `corroborated` (EBMP2-061). What the evidence cannot
show, such as the absence of another path or of another credential, you
establish by procedure.

You can check the verifier before you rely on it. In
[packages/ecl-ts](../packages/ecl-ts/README.md), after `npm ci` and
`npm run build`, `npm test` runs its unit tests, `npm run test:browser` the
browser page's tests in Chromium, `node scripts/build-verifier.mjs --check`
shows that the page's script is a fresh build of the package's own sources,
and `node scripts/check-corpus.mjs` runs `ecl-verify-ts` on every bundle and
package vector and on the sample evidence and compares each result with the
expected one. To see a refusal, verify
`conformance/fixtures/evidence/tampered.json` under the trust policy beside
it: the verdict is `invalid`.

## Score the checklist

Section 11 of the standard is the checklist that you score: its usage rules
(11.1), its rating method (11.2), and the items by control family (11.3), each
with the minimum level at which it applies.
[conformance/requirement-evaluations.json](../conformance/requirement-evaluations.json)
gives, for every requirement, how it is evaluated, the procedure to follow,
the pass and fail criteria, the evidence to obtain and the conformance roles it
applies to. Its `implementation_groups` name the assessment area that a
requirement belongs to, so that the requirements you assess together share a
name. The evaluation classes are described in
[conformance/README.md](../conformance/README.md): a `vector-tested`
requirement has a failing vector that an implementation must refuse, while an
`assessor-procedure` or `self-declaration` requirement is established only by
the procedure, and a `reference-tested` one needs your own test of the
implementation under assessment.

[docs/l1-minimum.md](l1-minimum.md) lists every requirement and checklist item
that an `L1` claim answers. [registries/guarantee-trace.json](../registries/guarantee-trace.json)
traces each requirement to the element of the guarantee it serves, and
[docs/gap-coverage.md](gap-coverage.md) shows how the requirements address each
control gap. For a claim that covers an agent host, a tool server, a gateway or
a policy engine, the [integration contract](integration-contract.md) states
what each must expose and must not hold, with the requirements behind each
statement.

## Run the negative tests

At `L2` and above the assessment includes at least these negative tests
(ECL1N-0151): an attempted bypass of the enforcement path; an attempted
fail-open on missing proof or an invalid contract; an emergency halt or
quarantine replay; a validation of the Negative Boundary Annex against the
reachable effect paths; and a revocation and restricted-mode transition test.
The checklist adds, at every level, the release contract's tests (item EA-27),
whose predicate and negative tests the [implementer
guide](implementer-guide.md#the-release-contract) sets out, the recovery tests
(EA-28) and the scope of restriction under the dependency model (EA-29).

The conformance vectors are negative tests of the formats and rules: each
failing vector names the primary finding that an implementation must report.
For a component under assessment, give it the failing vectors of the
capabilities it declares ([conformance/README.md](../conformance/README.md)),
and confirm that the verifier refuses a copy of a bundle that the component
produced in which one byte of a signed payload was changed. An adverse input
that is refused is evidence for the rule it tests, not for the whole system.

## Known limits

- The coverage denominator
  ([conformance/coverage-denominator.json](../conformance/coverage-denominator.json))
  counts the units of the message formats and the checking rules, not the
  runtime behavior of a deployment; three units are excluded, each with its
  reason.
- The incident scenarios ([conformance/scenarios/](../conformance/scenarios/README.md))
  state what a replay must observe; this package holds no runner for them.
- A conformance claim is self-declared by its implementer. An assessment that
  you make is listed beside a claim only when the implementer provides it, and
  G-14 certifies nothing.

## Check your independence

The assessment baseline of Section 7.11 sets who may assess at each level: at
`L1` a reviewer who is not the primary implementer, and from `L2` an
independent assessor with no implementation, operation or claim-approval
authority over the System of Interest and no compensation contingent on the
claim (ECL1N-0086, ECL1N-0148).
[governance/ASSESSOR_INDEPENDENCE.md](../governance/ASSESSOR_INDEPENDENCE.md)
says what an assessor discloses. Disclose your identity, your organization and
its relationships to the claimant and to the maintainer, and any conflict.

## Report findings

Use [the findings template](review-findings-template.md). A finding about a
supplier's claim goes to the party for whom you assess; the claimant may
publish your assessment beside its claim. A finding about the standard, its
schemas, its vectors or its verifier goes to the ECL-1 repository as an issue,
and during a public review window it is a review comment that receives a
published disposition ([governance/PUBLIC_REVIEW.md](../governance/PUBLIC_REVIEW.md)). A security finding goes
privately, as [SECURITY.md](../SECURITY.md) describes, never to a public issue.

In an assessment of a claim, classify each failed checklist item as
`critical`, `major` or `minor` as ECL1N-0147 defines them, and record as
`critical` each condition that ECL1N-0154 lists. Classify a finding about the
standard's texts, schemas, vectors or verifier as:

- **Critical:** permits an in-scope unauthorized effect, invalid authority, or
  a material false qualification, with no boundary control that stops it.
- **Important:** invalidates a stated invariant or evidence claim and needs
  correction before the text can be relied on.
- **Minor:** a bounded clarity or hardening issue that leaves those invariants
  intact.
