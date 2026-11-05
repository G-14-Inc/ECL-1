# Implementer guide

This guide is for a team that implements ECL-1 Version 1.0 in its own
component, such as an agent host, a tool server, a gateway, a decision service,
an enforcement point or a verifier. It explains what to implement, how to run
the conformance tests against the component, how to record the run in a
conformance report, how to exchange signed evidence with another
implementation, and how to state and submit a claim. The guide is informative:
where it and a requirement differ, the requirement governs. Following it is not
an assessment.

The texts of ECL-1 are licensed under CC BY 4.0, and its code and
machine-readable artifacts, the schemas, vectors and verifier among them, under
Apache-2.0. G-14, Inc.'s patent pledge ([PATENTS.md](../PATENTS.md)) covers implementations of
Version 1.0 that conform to its normative requirements
([README](../README.md#rights)).

## What you need to do

1. Read the core standard and the companions your component implements
   ([the document set](../README.md#the-document-set)), and the
   [integration contract](integration-contract.md) for your component's role.
2. Implement from the specifications, the schemas and the registries.
3. Run every vector of the shared corpus that your capabilities cover, and
   record one result for each.
4. Verify the evidence your component produces with the offline verifier, and
   verify the sample evidence with your own verifier if you build one.
5. Record the run in the conformance report template.
6. State your claim as Section 7.7 of the standard requires, and submit it
   with its report.

## What to implement

Implement [the core standard](../standard/ECL-1_Standard.md), its companion
protocols, and the profiles your claim names:

- the one-way rule (Section 5.2 of the core standard): classify each decision
  input in the Consequential Action Register, with whether the action class
  requires it, its source, its maximum age, its deadline and the inputs it is
  computed from, and record the basis of every decision in
  `ecl.ext.decision-basis.v1` (ECL1N-0178 to ECL1N-0182, DCMP2-053);
- [DCMP2-HTTP-1](../profiles/DCMP2-HTTP-1.md): the HTTP binding for decision
  exchange;
- [TRANSACTIONAL-EFFECT-1](../profiles/TRANSACTIONAL-EFFECT-1.md): the
  declared store and the admission transaction that bounds an effect;
- [AUTHZEN-BINDING-1](../profiles/AUTHZEN-BINDING-1.md): an optional mapping to
  an AuthZEN policy decision point, with strict acceptance of its responses,
  while authority stays with the native ECL checks;
- [TRUST-POLICY-1](../profiles/TRUST-POLICY-1.md): the trust policy that the
  verifier's caller supplies;
- the binding profiles, for a component that works with AARM, OWASP ACS, MCP,
  OpenTelemetry or OAuth ([bindings guide](bindings.md)).

[The rendered index](../render/index.html) links every normative source. The
minimum set of requirements for an `L1` implementation is listed in
[docs/l1-minimum.md](l1-minimum.md).

Derive your implementation and your adverse test cases from the normative
texts, the schemas and the vectors. The vectors show expected results; they do
not describe how an implementation should be built.

## The release contract

An enforcement point releases each action at one point, its release boundary,
after which refusing the action no longer stops it. Name that point for each
action class, and the later point at which the effect takes place where it
differs ([ECL1N-0185](../render/ecl-1_standard.html#ECL1N-0185)). Before the
release, establish every condition below at that point
([ECL1N-0186](../render/ecl-1_standard.html#ECL1N-0186)). Read as a predicate:

```text
Release(action, boundary_time) implies
    exact_request_and_audience_binding
    and authority_usable_at_boundary_time
    and use_available_under_atomic_accounting
    and required_control_state_current
    and no_applicable_halt_or_revocation
    and all_before_release_obligations_satisfied
    and required_evidence_capacity_available
```

| Term | Requirements | What a negative test at your enforcement point does |
|---|---|---|
| `exact_request_and_audience_binding` | [ECL1N-0186](../render/ecl-1_standard.html#ECL1N-0186) item 1; [DCMP2-044](../render/dcmp-2.html#DCMP2-044) to [DCMP2-051](../render/dcmp-2.html#DCMP2-051) | Presents an admit for another request, another action, changed parameters or another audience; nothing is released |
| `authority_usable_at_boundary_time` | ECL1N-0186 item 2; [ECL1N-0188](../render/ecl-1_standard.html#ECL1N-0188); [DCMP2-049](../render/dcmp-2.html#DCMP2-049); [EBMP2-050](../render/ebmp-2.html#EBMP2-050) | Delays each operation that can block between the last check and the release until the authorization has expired, and lets one expire at the boundary itself; nothing is released, and the recorded release time is the final observation that precedes the release, with the release beginning within the declared bound after it |
| `use_available_under_atomic_accounting` | ECL1N-0186 item 3; [DCMP2-050](../render/dcmp-2.html#DCMP2-050); [EBMP2-008](../render/ebmp-2.html#EBMP2-008) | Uses a single-use authorization twice at once, again after a restart, and from two instances; it is released at most once (an enforcement point that counts uses per instance routes every use through one instance or shares the use store, as MG1-005 asks of an MCP gateway) |
| `required_control_state_current` | ECL1N-0186 item 4; [ECL1N-0102](../render/ecl-1_standard.html#ECL1N-0102); [FR-110](../render/ecl-1_standard.html#FR-110) | Lets the cached policy and trust epoch go stale; nothing is released |
| `no_applicable_halt_or_revocation` | ECL1N-0186 item 5; [ECL1N-0053](../render/ecl-1_standard.html#ECL1N-0053); [ECL1N-0097](../render/ecl-1_standard.html#ECL1N-0097); [ECL1N-0104](../render/ecl-1_standard.html#ECL1N-0104) | Delivers a halt and a revocation before the release; nothing is released once the declared timing case says they have arrived |
| `all_before_release_obligations_satisfied` | ECL1N-0186 item 6; [ECL1N-0187](../render/ecl-1_standard.html#ECL1N-0187); [DCMP2-017](../render/dcmp-2.html#DCMP2-017) | Presents an admit whose before-release obligation has missing, unsupported, stale, wrongly bound or replayed proof, an admit whose proof stops being fresh between its check and the release, an admit that names one obligation twice, and an admit with several obligations of which one is unproven; nothing is released |
| `required_evidence_capacity_available` | ECL1N-0186 item 7; [ECL1N-0189](../render/ecl-1_standard.html#ECL1N-0189); [FR-003](../render/ecl-1_standard.html#FR-003) | Fills the evidence store, then makes its writes fail; nothing is released |

A positive test with valid proof and current authority releases the action
exactly once. Unproven, unsupported, stale, failed or wrongly bound proof
prevents the release and ends the action in its declared safe state, and a
signed `admit` alone never satisfies an obligation that the response defers to
enforcement ([ECL1N-0187](../render/ecl-1_standard.html#ECL1N-0187)). Checklist
item EA-27 is the assessor's version of these tests.

The predicate is an assurance checklist. It is not a proof, an implementation
or a sufficient assessment of a deployment, and it says nothing about an action
that never reaches the enforcement point. Complete mediation (ECL1N-0028,
ECL1N-0033, ECL1N-0141, checklist item EA-25) and the protection of the
enforcement point, and of the credentials that reach a point of effect, from
the governed AI system (ECL1N-0046, ECL1N-0156, checklist items EA-25 and
PA-08) are separate premises: a correct predicate does nothing for an in-scope
effect that has another path. A verified evidence bundle does not show that the
enforcement point checked an obligation or released at the time it recorded;
the verifier reports what it did not check
([ECL1N-0194](../render/ecl-1_standard.html#ECL1N-0194)).

### Time at the release boundary

Check the authorization's window at the release boundary and record that time
as the release time. Do not reuse a time read before writing or signing
evidence, waiting for a lock or checking an obligation's proof: that work lies
between the check and the release, so check again after it, or bound it and
allow for the bound (ECL1N-0188). Record the bound you allow for with the
release event (`release_guard_ms`), so that a verifier tests the observation
plus the bound against the window (EBMP2-050, EBMP2-071); read a monotonic
clock before the wall clock at each check, so that a wall clock stepped back
between two checks cannot extend the window; and test each proof's freshness
again at the final observation, not only when you obtained it (ECL1N-0186,
item 6). A check just before you send a call shows that
the authority was usable when the send began, not when the remote server acted.
If the response is lost, the outcome is unresolved until the server's own
record or a status query settles it, and a retry can repeat the effect unless
the server applies each call at most once. Where the time of the effect
matters, check the authority at the point of effect, as a resource server does
with a token under [OAUTH-AUTHORITY-1](../profiles/OAUTH-AUTHORITY-1.md).

Before the release, keep the attempt's identity, the authority and the use it
consumes, and its binding to the request, durably enough to survive the
failures that the claim declares covered; after a failure, classify each
outstanding attempt as executed, not executed or unresolved, and never infer
one of them from a missing terminal record
([ECL1N-0189](../render/ecl-1_standard.html#ECL1N-0189),
[ECL1N-0190](../render/ecl-1_standard.html#ECL1N-0190)). Give one instance at
a time the store of that information, record a recovery's decision durably
before it writes anything, so that a repeated or interrupted recovery writes
the same records and never a second signed terminal, and keep and report
recovery information you cannot read rather than settle it. MG1-016 states
these rules for an MCP gateway's journal.

## Run the conformance tests

[conformance/README.md](../conformance/README.md) states, for each stage of the
conformance tests, the input your component takes, the steps it makes in order
and the findings it reports, and how one primary finding is selected.
[shared-corpus.json](../conformance/shared-corpus.json) names the frozen input
vectors and the capability each one needs; each vector's manifest, in
[conformance/manifest.json](../conformance/manifest.json) or in a suite of
`conformance/suites/`, gives its expected result. For each vector, give its
artifact to your component at the vector's stage and compare what it reports
with the expected result.

Required capabilities: `strict-json`, `canonical-digest`, `semantic-rules` and
`safe-state-profile-rules`. Optional capabilities: `schema-validation`,
`trust-policy-load`, `envelope-signature-verification`,
`evidence-bundle-verification`, `control-extension-rules`,
`binding-profile-rules`, `decision-basis-rule`, `document-validation`,
`extension-version-rule`, `document-extension-rules`, `key-role-separation`,
`binding-basis-agreement-rule`, `otel-export-keyed-digests` and
`offline-package-verification`. `shared-corpus.json` gives each vector's
capability.

- `evidence-bundle-verification` covers every vector of the `evidence-bundle`
  stage, one whose primary finding is a schema failure included: each names
  the verdict of a signed bundle (EBMP2-060), which only a bundle verifier
  produces.
- `control-extension-rules` covers the rules of the registered control
  extensions (DCMP2-052, EBMP2-063, EBMP2-064 and XR1-023) that the
  `control-extensions` suite exercises.
- `binding-profile-rules` covers the rules of the five binding profiles, which
  their suites exercise ([bindings guide](bindings.md)).
- `decision-basis-rule` covers the vectors whose decision response carries
  `ecl.ext.decision-basis.v1`: its value schema and the one-way rule for a
  recorded decision basis (DCMP2-053), and the register documents that
  `ecl.rule.register-declarations-consistent.v1` refuses (ECL1N-0178).
- `document-validation` covers the claim and assessment documents of the
  `document-coverage` suite, which are checked against their schemas.
- `extension-version-rule` covers the failing vectors outside the `document`
  stage that expect `ecl.rule.extension-single-version.v1`: one object carries
  each extension identifier at one version (XR1-010).
- `document-extension-rules` covers the other document vectors that a
  registered rule refuses: the extension rules that apply to a work intent
  (XR1-006, XR1-009, XR1-010, XR1-017).
- `key-role-separation` covers the `key-roles` suite: a trust-policy key holds
  one role, and a DCMP-2 request or response counts only under a key of its
  role (TP1-009, TP1-010).
- `binding-basis-agreement-rule` covers the `binding-basis` suite: an AARM or
  ACS record's inputs agree with the decision basis of its response and with
  that of the response to a modified action, and each basis satisfies the
  one-way rule of DCMP2-053 (AB1-013, AC1-012). Because the
  AARM, ACS and MCP checkers apply that rule to the responses a record holds,
  an implementation that declares this capability or `binding-profile-rules`
  also declares `decision-basis-rule`.
- `otel-export-keyed-digests` covers the `otel-export` suite, whose records
  carry digests keyed with an export key that the manifest's `export_keys_path`
  names, or no digest (OE1-004, OE1-010).
- `offline-package-verification` covers the `package` stage: an
  `ecl.zip.store.v1` archive whose evidence bundle is verified under the
  caller's trust policy (IE1-021, IE1-022).

Rules for results:

- Every vector needs exactly one result. A required-capability vector that is
  missing or marked unsupported fails the run.
- A vector that needs an optional capability you do not implement is marked
  unsupported, with no findings.
- A result agrees with a vector only when its one primary finding is the
  expected one. A different depth of secondary findings is recorded as a
  reporting difference, never treated as agreement.

The TypeScript package that holds the offline verifier shows one way to run
part of the corpus: `node scripts/check-corpus.mjs`, run in
[packages/ecl-ts](../packages/ecl-ts/README.md) after its build, runs
`ecl-verify-ts` on every vector that expects a verdict, those of the
`evidence-bundle` and `package` stages, and compares each verdict and exit
status with the expected ones.

## Record the run in a conformance report

Start from [report-template-v2.json](../conformance/report-template-v2.json).
It is a schema-valid skeleton in the `not_run` state, with empty result rows,
example identities and hash placeholders. It validates only as a shape; it is
never a record of a run. Replace every placeholder with your component's source
identity, the identity of the corpus you ran, one result row for each vector
and the digests of your raw evidence, following [the report
schema](../schemas/ecl-cross-implementation-report-v2.schema.json), and set
`decision` to the outcome of the run. The schema refuses a report that states a
pass or a fail with no results, and a `not_run` report that carries results.
Validate the completed report against the schema with any JSON Schema draft
2020-12 validator.

A failed or unsupported vector stays failed or unsupported in the report. The
report's `claim_boundary` states what it is: a record of a run of the
conformance tests, not an assessment or a certification.

Beside the report, keep the offline verifier's output on the evidence your
component produced: run `ecl-verify-ts` with `--json` on each bundle, under the
trust policy you would give a buyer.

## Exchange evidence in both directions

**Your implementation to a verifier.** Supply a signed bundle and your trust
policy through two separate handoffs. With the TypeScript package built, run
this from the directory that holds the two files, naming the package's command
by its path:

```sh
node <path-to>/packages/ecl-ts/dist/cli/ecl-verify.js \
  peer-bundle.json --trust-policy peer-trust-policy.json --json
```

The browser verifier ([web/verifier/index.html](../web/verifier/index.html))
gives the same verdict. Compare integrity, bindings, causal completeness, state
and authority, and the effect level. A valid signature authenticates an
assertion; it does not show that the effect physically happened
([TRUST-POLICY-1](../profiles/TRUST-POLICY-1.md)). The bundle cannot bring its
own verifier trust policy (TP1-001). An offline package
([OFFLINE-VERIFICATION-1](../profiles/OFFLINE-VERIFICATION-1.md)) can be
exchanged the same way: the verifier reads a file that begins with the bytes
`PK` as a package and verifies the bundle it carries under the trust policy you
supply, never under the one the package carries (IE1-022).

**Sample evidence to your implementation.** Consume
`conformance/fixtures/evidence/succeeded.json` with the separately supplied
`conformance/fixtures/evidence/trust-policy.json`, using your own verifier and
its own command line. The expected result is `verified`, the action
`succeeded`, its authority consumed and its effect `issuer-asserted`. The other
samples beside it give: `denied.json`, `verified` with a denied action;
`corroborated.json`, `verified` with a `corroborated` effect; and
`tampered.json`, `invalid`. Compare your verifier's structured output with that
of `ecl-verify-ts` on the same files, and record both commands and the
comparison of levels in your report.

## Describe and submit a claim

- Name ECL-1 Version 1.0, each companion version and each profile that the
  claim relies on, the level, the claim status and the claim boundary, as
  Section 7.7 of the standard requires, and the capability set of your
  conformance report.
- For a Transactional Effect statement, name the store, the action class, the
  declared bound B and the counterexample-test catalog (TE1-013).
- Label the evidence of an effect `issuer-asserted` unless a separately keyed
  observation matches it under the rule of EBMP2-061, which makes it
  `corroborated`. A verified signature shows who asserted a record, not that
  the assertion is true.
- Keep unsupported cases, your relationship to any other implementation you
  used, and your scope exclusions in the claim.
- A run of the conformance tests, and a conformance report of it, is neither a
  certification nor an assessment. A run that an implementer makes of its own
  implementation is self-testing; an independent assessment needs an assessor
  who meets the independence requirements of Section 7 of the standard
  ([assessor independence](../governance/ASSESSOR_INDEPENDENCE.md)).
- Submit the claim with its conformance report and the verifier's output by
  pull request to the implementers registry of the ECL-1 repository, as
  [governance/CONFORMANCE_CLAIMS.md](../governance/CONFORMANCE_CLAIMS.md) describes. The editors check that the
  submission is complete and list it as self-declared.
