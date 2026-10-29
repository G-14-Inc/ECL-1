# ECL-1: External Control Layer Standard

ECL-1 is a standard for controlling the consequential actions of AI systems:
the actions that change something outside the system, such as a record, a
payment, a message, an account or a piece of equipment. It requires a control
layer outside the AI system whose actions it governs. Each in-scope action is
decided and authorized before it takes effect, and enforced at the point where
it takes effect. Each decision leaves signed evidence that a third party can
check and, from level `L2`, verify offline: which component asserted what, with
which key, about which request and decision.

This repository holds **ECL-1 Version 1.0**, a published standard maintained by
G-14, Inc. [RELEASE-NOTES-1.0.md](RELEASE-NOTES-1.0.md) says what Version 1.0
is and what changed from the last release candidate, and
[CHANGELOG.md](CHANGELOG.md) lists the requirements that each version
introduced, changed and retired.

## Start here

[Choose your first task](docs/start-here.md): verify supplied evidence, run one
[bounded teaching workflow](examples/bounded_workflow/README.md), implement a
boundary, assess a claim or contribute a correction. The
[release brief](docs/release-brief.md) lists the public materials and their
limits. `CITATION.cff` identifies the exact standard version for citation.

## The guarantee

A deployment that conforms to ECL-1 under a full-system or bounded action-class
mediation claim provides this for each consequential action that the claim
declares in scope. The action crosses an enforcement boundary that the governed
AI system cannot bypass, under a decision that the governed AI system cannot
change. A failure that leaves the action without required proof, including an
integrity failure, policy ambiguity or a decision service that does not answer,
ends in denial, restricted mode or halt, and never in the action going ahead.
Each decision leaves tamper-evident evidence that a third party can check and,
from `L2`, verify offline outside the primary control plane.

The guarantee holds only within the boundary, level, independence class and
trust assumptions that a claim states, and only as far as the claim's
assessment establishes it. The opening section of the
[standard](standard/ECL-1_Standard.md), "The ECL-1 Guarantee", lists its seven
elements with the requirements that carry each one, and
[registries/guarantee-trace.json](registries/guarantee-trace.json) traces every
requirement to them. ECL-1 does not judge what an action means, evaluate model
quality or govern an organization; Section 2.10 of the standard says how those
functions connect to a control layer.

## The document set

Every normative document is in Markdown in this repository and, with requirement
anchors, in [static HTML](render/index.html) that needs no script or server.
[release/VERSION_SET.json](release/VERSION_SET.json) binds the designation and
the version of every companion, so that a claim can cite them.

| Document | Version | What it specifies |
|---|---|---|
| [ECL-1 core standard](standard/ECL-1_Standard.md) | 1.0 | Scope and claim boundary, architecture and the runtime control invariant, functional requirements, conformance levels, deployment models and timing, threat model and key custody, and the conformance checklist |
| [DCMP-2](protocols/DCMP-2.md) | 2.0 | Decision and control messages: requests, decisions, authority, challenges and controls |
| [EBMP-2](protocols/EBMP-2.md) | 2.0 | Evidence records, evidence bundles and their offline verification |
| [INTEGRITY-ENVELOPE-1](protocols/INTEGRITY-ENVELOPE-1.md) | 1.0 | The signed envelope of every record, strict JSON, canonical form and resource limits |
| [TIMING-SAFE-STATE-1](protocols/TIMING-SAFE-STATE-1.md) | 1.0 | Timing, availability and safe-state behavior |
| [DISTRIBUTED-WORKFLOW-1](protocols/DISTRIBUTED-WORKFLOW-1.md) | 1.0 | Distributed and long-running workflows |
| [EVIDENCE-LIFECYCLE-1](protocols/EVIDENCE-LIFECYCLE-1.md) | 1.0 | Retention, holds, redaction, export and destruction of evidence |
| [EXTENSION-REGISTRY-1](protocols/EXTENSION-REGISTRY-1.md) | 1.0 | Extensions and registries |
| [TRUST-POLICY-1](profiles/TRUST-POLICY-1.md) | 1.0 | The trust policy that a verifier's caller supplies |
| [DCMP2-HTTP-1](profiles/DCMP2-HTTP-1.md) | 1.0 | The decision exchange over HTTPS |
| [TRANSACTIONAL-EFFECT-1](profiles/TRANSACTIONAL-EFFECT-1.md) | 1.0 | Admission and effect in one store transaction |
| [STRICT-FAILURE-1](profiles/STRICT-FAILURE-1.md) | 1.0 | No fail-open disposition for an in-scope action class |
| [AUTHZEN-BINDING-1](profiles/AUTHZEN-BINDING-1.md) | 1.0 | An AuthZEN policy engine as an additional policy check |
| [AARM-BINDING-1](profiles/AARM-BINDING-1.md) | 1.0 | An AARM control plane as a decision layer or a source of judgment inputs |
| [ACS-BINDING-1](profiles/ACS-BINDING-1.md) | 1.0 | An OWASP Agent Control Standard Guardian and its hooks |
| [MCP-GATEWAY-1](profiles/MCP-GATEWAY-1.md) | 1.0 | An enforcement point in front of MCP servers |
| [OTEL-EVIDENCE-EXPORT-1](profiles/OTEL-EVIDENCE-EXPORT-1.md) | 1.0 | Copies of decisions and evidence in OpenTelemetry log records |
| [OAUTH-AUTHORITY-1](profiles/OAUTH-AUTHORITY-1.md) | 1.0 | One `admit` as one sender-constrained OAuth access token |

Three informative profiles state no requirement of their own:
[CONFORMANCE-CLAIMS-1](profiles/CONFORMANCE-CLAIMS-1.md) (the claim and
assessment documents), [DEPLOYMENT-PROFILES-1](profiles/DEPLOYMENT-PROFILES-1.md)
(the deployment models) and
[OFFLINE-VERIFICATION-1](profiles/OFFLINE-VERIFICATION-1.md) (the offline
package). The machine-readable artifacts are the JSON Schemas in
[schemas/](schemas/) and the registries in [registries/](registries/), among
them the compiled requirements
([registries/requirements-compiled.json](registries/requirements-compiled.json))
and the requirement ledger
([registries/requirement-ledger.json](registries/requirement-ledger.json)).

## Conformance

A conformance claim names the System of Interest it covers and its claim class:
full-system mediation, bounded action-class mediation, or a component or
profile implementation, which does not provide the guarantee (standard,
Section 2.5). It declares one of four levels: `L1` Foundational, `L2` Standard,
`L3` Advanced and `L4` Critical Infrastructure, each including the ones below
it (Section 7.1). It states an independence class, `Class A`, `Class B` or
`Class C`, at least the minimum for its level (Section 7.5), and its status:
full conformance, conditional conformance or assessment-only (Section 7.6). The
public claim statement of Section 7.7 names the version, the level, the status
and the claim boundary; "ECL-1 compliant" on its own is not a claim.

An assessor scores a claim against the conformance checklist of Section 11 of
the standard, with the procedure, pass criteria and fail criteria that
[conformance/requirement-evaluations.json](conformance/requirement-evaluations.json)
gives for every requirement. [docs/l1-minimum.md](docs/l1-minimum.md) lists
every requirement and checklist item that an `L1` claim answers.

A conformance claim is self-declared. An implementer publishes its claim with
its conformance report, the results of the conformance tests and the offline
verifier's output on its evidence, by pull request to the implementers registry
of this repository ([community/implementers.yaml](community/implementers.yaml)), as
[governance/CONFORMANCE_CLAIMS.md](governance/CONFORMANCE_CLAIMS.md) describes. The
editors check that the submission is complete and list it as self-declared; an
assessor's assessment is listed separately when the implementer provides it.
G-14 certifies nothing. "ECL-1" may be used descriptively
([marks](governance/TRADEMARKS_AND_MARKS.md)).

## The conformance tests

[conformance/](conformance/README.md) holds the conformance tests with their
expected results: positive and negative vectors in
[conformance/manifest.json](conformance/manifest.json) and in the suites of
`conformance/suites/`, and
[conformance/shared-corpus.json](conformance/shared-corpus.json), which names
every vector and the capability it needs. Its README states, for each stage,
the input, the steps in order and the findings that an implementation reports,
and every measured unit of the coverage denominator
([conformance/coverage-denominator.json](conformance/coverage-denominator.json))
has a passing and a failing vector. Sample evidence, signed bundles with the
trust policy that verifies them, is in `conformance/fixtures/evidence/`. A run
of the tests is recorded in the conformance report template
[conformance/report-template-v2.json](conformance/report-template-v2.json).
[conformance/scenarios/](conformance/scenarios/README.md) holds ten incident
scenarios from the Control Gap Record, each with the outcome every step must
have.

## Formal models

[formal/](formal/README.md) holds a TLA+ model of the runtime control invariant
and a Tamarin model of DCMP-2 signing and binding. Their runner uses pinned
tool releases and records every result in `formal/results.json`. Correct
configurations must satisfy their properties, deliberately broken variants
must expose the property each removed rule protects, and reachability
witnesses keep the checks from passing vacuously. These are bounded models of
the design; they do not prove an implementation, and their README states each
abstraction and limit.

## The offline verifier

The offline verifier checks a signed evidence bundle, or an offline package
that carries one, under a trust policy that you choose, with no account and no
network request.

- In a browser, open [web/verifier/index.html](web/verifier/index.html) from
  disk ([how it works](web/verifier/README.md)).
- On the command line, use `ecl-verify-ts` from the TypeScript package
  [packages/ecl-ts](packages/ecl-ts/README.md), with Node.js 22:

```sh
cd packages/ecl-ts
npm ci
npm run build
node dist/cli/ecl-verify.js ../../conformance/fixtures/evidence/succeeded.json \
  --trust-policy ../../conformance/fixtures/evidence/trust-policy.json
```

Python (`ecl-verify`) and Go (`ecl-verify-go`) command-line verifiers are also
published in [packages/ecl-verify](packages/ecl-verify/README.md) and
[go/crosscheck](go/crosscheck/README.md). The [quickstart](docs/quickstart.md)
runs all three and the shared corpus from this package alone.

It prints the verdict (`verified`, `invalid`, `incomplete` or
`current-trust-failed`), what the verdict establishes and what it does not, and
it exits with 0 for a verified bundle. `--json` prints the report as JSON. The
package's own unit and browser tests ship with it (`npm test`,
`npm run test:browser`), and `node scripts/check-corpus.mjs` runs
`ecl-verify-ts` on every bundle and package vector of the conformance tests and
compares each verdict with the expected one.

## Guides

The guides are informative; where a guide and a requirement differ, the
requirement governs.

- [Buyer summary](docs/buyer-summary.md): ECL-1 in one page, what a claim must
  say and what to ask a supplier for.
- [Implementer guide](docs/implementer-guide.md): what to implement, how to run
  the conformance tests and how to report the run.
- [Assessor guide](docs/reviewer-guide.md): how to check a claim and its
  evidence with this package, and how to report findings
  ([findings template](docs/review-findings-template.md)).
- [Agent and tool integration contract](docs/integration-contract.md): what an
  agent host, a tool server, a gateway or a policy engine must expose to a
  control layer, and must not hold.
- [Bindings guide](docs/bindings.md) and [AuthZEN guide](docs/authzen-binding.md):
  how ECL-1 works with AARM, ACS, MCP, OpenTelemetry, OAuth and AuthZEN.
- [Keeping fail-closed control available](docs/availability.md): redundancy,
  scoped restricted mode and degraded modes within the rules.
- [Threat model](docs/threat-model.md): the threats that the protocols and
  profiles address, and what remains.
- [Crosswalks](docs/crosswalk.md) to AARM and the OWASP Agent Control Standard,
  and [control-gap coverage](docs/gap-coverage.md) of the 13 gaps of the
  Control Gap Classification.

## Taking part

G-14, Inc. and Robert Tilley Jr. provide the interim editorial and contact
function while the community working group is being formed. ECL-1 is open to
community participation and stewardship under the charter. Community roles,
working-session dates and agendas will be announced publicly as they are
established; no outside appointment or completed meeting is implied.
Contact ecl@g14.ai to participate.

ECL-1 is developed in the open by the ECL-1 Working Group. Anyone may join, at
no cost, by signing up through this repository, as [community/WORKING_GROUP.md](community/WORKING_GROUP.md)
describes; the working group meets in public working sessions and keeps public
notes. The [charter](governance/CHARTER.md) sets out how it works: the editors
propose, the working group discusses, and the editors decide by rough consensus
and record the reason. [governance/](governance/README.md) holds the change,
errata, registry, release and appeals procedures.

- Comment, ask or propose in this repository's issues, discussions and pull
  requests. Every commit carries a Developer Certificate of Origin sign-off
  ([governance/DCO.txt](governance/DCO.txt), [contributing](governance/CONTRIBUTING.md)).
- Each new minor version has a public review window of 30 days, and each new
  major version one of 60 days, announced on externalcontrollayer.ai. Every
  comment receives a published disposition ([governance/PUBLIC_REVIEW.md](governance/PUBLIC_REVIEW.md)).
- Report an error in a published text as an issue
  ([errata](governance/ERRATA.md)).
- Report a security problem privately, never in a public issue
  ([SECURITY.md](SECURITY.md)).

The working group's contact address is ecl@g14.ai.

## Rights

The specification text and documentation are licensed under Creative Commons
Attribution 4.0 International, CC BY 4.0 ([LICENSE-CC-BY-4.0](LICENSE-CC-BY-4.0)). The machine-readable
artifacts and the code, among them the schemas, registries, conformance tests,
sample evidence and the offline verifier, are licensed under the Apache License,
Version 2.0 ([LICENSE](LICENSE)). [LICENSING.md](LICENSING.md) says which license applies to which
files. G-14, Inc. pledges, royalty-free, not to assert its essential patent
claims against implementations of ECL-1 Version 1.0 and its companion
specifications, on the terms of [PATENTS.md](PATENTS.md). G-14 has patents pending. Third-party material keeps its own
license and notices ([licenses/THIRD_PARTY_NOTICES.md](licenses/THIRD_PARTY_NOTICES.md)).

## Maintainer

ECL-1 is maintained by G-14, Inc., which hosts this repository, provides the
editors and the chair of the working group, runs public review, and publishes
releases and errata. G-14 is developing a commercial implementation of ECL-1. Nothing in the
standard depends on it, and an implementation's conformance claim, G-14's
included, is self-declared under the same rules as any other.
