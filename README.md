# ECL-1: External Control Layer Standard

**ECL-1 Version 1 public-review candidate — source `1.0.2-review.1`.**
This local candidate incorporates the review repairs and explicit contract
choices described in [the design guide](docs/review-design-decisions.md).
Its source identity is separate from the published Version 1.0 release of
5 November 2026 and correction release v1.0.1. Publication, artifact-bound
approval and a dated public-review window require their own recorded decisions.
The historical source archives and Version 1 reference editions remain
preserved; cite the exact candidate source and digest when discussing this draft.

ECL-1 is a standard for controlling the consequential actions of AI systems:
the actions that change something outside the system, such as a record, a
payment, a message, an account or a piece of equipment. It requires a control
layer outside the AI system whose actions it governs. Each in-scope action is
decided and authorized before it takes effect, and enforced at the point where
it takes effect. Each decision leaves signed evidence that a third party can
check and, from level `L2`, verify offline: which component asserted what, with
which key, about which request and decision.

This candidate is authored and produced by Robert F. Tilley Jr. and G-14, Inc.,
and maintained by G-14, Inc. [RELEASE-NOTES-1.0.md](RELEASE-NOTES-1.0.md) preserves
the published release history and review disclosures.
[CHANGELOG.md](CHANGELOG.md) and the versioned repair records distinguish the
historical releases from the changes proposed in this candidate.

## Start here

[Choose your first task](docs/start-here.md): verify supplied evidence, run one
[bounded teaching workflow](examples/bounded_workflow/README.md), implement a
boundary, assess a claim or contribute a correction. The
[release brief](docs/release-brief.md) lists the public materials and their
limits. [CITATION.cff](CITATION.cff) identifies this candidate for citation.

## Candidate and historical release files

[release/VERSION_SET.json](release/VERSION_SET.json) identifies the candidate
source separately from the core, companion and wire-format versions. The
[design-decision receipt](release/DESIGN-DECISIONS-2026-11-10.json) records the
request-expiry and continuation-history changes and the exact fixture
expectation migration. Release packaging and approval records must bind the
candidate's final bytes before publication.

The historical [v1.0.1 correction release](https://github.com/G-14-Inc/ECL-1/releases/tag/v1.0.1)
contains `ecl-1-1.0.1.zip`, `ecl-1-1.0.1-manifest.json`,
`ecl-verify.cdx.json`, `ecl-ts.cdx.json` and `SHA256SUMS`, together with the
Version 1 reference PDF, font notices and correction record. The archive contains
the public specification, supporting documents, formal models, conformance
corpus, verifiers and teaching workflow. The two CycloneDX SBOMs describe the
Python and TypeScript verifiers' exact public dependency locks.

For that historical release, `SHA256SUMS` covers every supplied asset other
than itself. Download that release's assets into one directory, then check:

```sh
sha256sum --check --strict SHA256SUMS
```

On Windows, `Get-FileHash -Algorithm SHA256 <filename>` computes a file's
digest for comparison with `SHA256SUMS`. The manifest also lists every archive
member's size and SHA-256. G-14, Inc. supplies no separate maintainer
signature for v1.0.1. Hashes establish file integrity;
any hosting-service attestation has its own identity and verification scope.
The [original v1.0 release](https://github.com/G-14-Inc/ECL-1/releases/tag/v1.0)
and its five assets remain available under their original names and digests.

The [release notes](RELEASE-NOTES-1.0.md#review-status) disclose the review
status and the maintainer's
[correction-release exception](governance/RELEASE_POLICY.md#correction-release-exception-v101).
The [formal specification and model-checking description](#formal-specification-and-model-checking)
separates the current 58 TLC and 12 Tamarin checks from the preserved
earlier records, with their assumptions,
reproduction commands and limits. These results apply to the modeled design; implementation and
deployment conformance require their own evidence.

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

A conformance claim names the System of Interest it covers and either
full-system mediation or bounded action-class mediation (standard, Section 2.5).
Only these mediation claims declare one of four levels: `L1` Foundational, `L2` Standard,
`L3` Advanced and `L4` Critical Infrastructure, each including the ones below
it (Section 7.1). It states an independence class, `Class A`, `Class B` or
`Class C`, at least the minimum for its level (Section 7.5), and its status:
full conformance, conditional conformance at L2 or L3, or assessment-only
(Section 7.6). A component or profile implementation instead publishes a
[component implementation report](schemas/ecl-component-implementation-report-v1.schema.json)
with its identity, applicable requirement results, named capabilities and
profile versions, evidence and limitations. It carries no overall ECL level
and cannot replace a mediation assessment. The public claim statement of Section 7.7 names the version, the level, the status
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
and the [coverage denominator](conformance/coverage-denominator.json)
defines the measured schema branches and checking rules. Coverage must be
computed against this candidate's exact sources; historical counts do not
establish coverage of the revised corpus. Sample evidence, signed bundles with the
trust policy that verifies them, is in `conformance/fixtures/evidence/`. A run
of the tests is recorded in a report following the conformance report template
[conformance/report-template-v3.json](conformance/report-template-v3.json).
[conformance/scenarios/](conformance/scenarios/README.md) holds ten incident
scenarios from the Control Gap Record, each with the outcome every step must
have.

## Formal specification and model checking

The TLA+ model describes the runtime control invariant: request and action
binding, authority, enforcement, revocation, timeouts, emergency halt, evidence
and the one-way rule. TLC explores the finite configurations supplied with the
model. TLA+ is the specification language, TLC is the model checker, and TLAPS
is a separate deductive proof system. The checks here use TLC; a deployed
control layer must perform its own authorization and enforcement checks.

The [current formal record](formal/diagnostics/2026-11-11-runner-compatibility/RESULTS.json)
contains **70 checks**, each with its documented expected outcome. Its
**58 TLC checks** comprise seven correct configurations, 35 deliberately broken
configurations and 16 reachability witnesses. The correct configurations select
**34 distinct properties: 30 safety and four liveness properties**. Its
**12 Tamarin checks** comprise the correct theory with 12 lemmas—ten
universal properties and two existence witnesses—and 11 deliberately flawed
variants.

| Artifact | What it supplies |
|---|---|
| [ECLCore.tla](formal/tla/ECLCore.tla) and [MC.tla](formal/tla/MC.tla) | Current transitions, properties, concrete model values and witness assertions |
| [Configuration files](formal/tla/configs/) | Finite bounds and selected properties |
| [Current evidence packet](formal/diagnostics/2026-11-11-runner-compatibility/MANIFEST.json) | The 70 checks' exact retained inputs, invocation records, complete outputs and SHA-256 bindings |
| [Retained current runner](formal/diagnostics/2026-11-11-runner-compatibility/inputs/formal/run_checks.py) | Repeats the current model inputs with the separate invocation settings below |
| [Earlier November 11 packet](formal/diagnostics/2026-11-11-contract-review/MANIFEST.json) | The preserved 59-check record for the preceding model revision |
| [Formal guide](formal/README.md) | All properties, requirements, configuration bounds, expected outcomes and abstraction limits |
| [Historical v1.0.1 results](formal/results.json) and [earlier recovery packet](formal/diagnostics/2026-11-10-recovery/) | Separate November 7 and November 10 results for their original input hashes |
| [Tamarin model](formal/protocol/DCMP2_Binding.spthy) | Symbolic request context, response binding, scope, audience and single-use checks |

### What the current model checks

An effect requires issued authority for the exact request, target and
parameters, the intended enforcement-point audience, an unconsumed use and
time inside the half-open authorization window. The enforcement point must
have sufficiently fresh control state, no known revocation or ended trust
epoch, and no acknowledged halt. The correct modeled transition consumes the
authority, produces the effect and appends its evidence atomically.

The one-way rule prevents actor-supplied information or judgment from
improving the outcome supported by verifiable inputs. The policy abstraction
returns `admit` or `deny`; other inputs may tighten that outcome under
`admit < challenge < hold < deny`. It does not compare different authority
scopes granted by two admitting decisions. The model refuses reuse of a request
identifier for different modeled content, including after a request timed out
without a decision. That refusal creates no second decision response;
identical retransmission and explicit supersession are outside this abstraction.

A human-approval challenge ends its original attempt. An authenticated approval
can support a new continuation request with a fresh identifier, the same action
and audience, the same abstract workflow root and a higher attempt number.
Sibling continuations receive distinct attempts. The continuation receives a new
decision; approval does not itself authorize the action. At most one continuation
per challenge or approval may receive `admit`. The model checks approval expiry,
revocation and reuse, but abstracts
concrete approval signatures, approver identity policy and fields outside its
finite request type.

Recovery now moves through `unavailable`, `reconciling` and `normal` operation.
Restoring service reachability does not itself resume ordinary execution.
`Reconcile` records the six TS1-014 frontiers, and `ResumeNormal` requires them
and a current control view. `NoEffectDuringReconciliation` and
`RecoveryBeforeNormal` check this gate. Control-state staleness also latches a
restriction on the modeled action class. Every fresh-to-stale crossing starts
a new fault generation, even while an earlier restriction remains active.
A current control view, proof obtained for the new generation and a recorded
lifting action are required before it is lifted. A class restriction may be
lifted during reconciliation, while execution remains blocked until normal
operation resumes. A short outage need not trigger a restriction. Still-valid
authority issued before one or more faults may remain usable after revalidation,
fresh proof and any required recorded lift. The consumption store remains globally
shared, evidence is atomic,
effects have known outcomes and the global discrete clock has no jumps. These
abstractions do not implement a distributed store, uncertain remote-effect
reconciliation or a real clock-recovery protocol.

The Tamarin theory retains authenticated request contexts, including requests
signed by an agent. Both response receipt and direct presentation bind the
response to that context's request identifier and digest. Separate lemmas check
request-context origin and preserve the requested action and audience at
execution. The consumer also checks scope, audience and use policy even when
the response-signing key is revealed; those checks do not establish the origin
of a forged response. Ideal symbolic cryptography, each lemma's key-reveal
exceptions, role-separated registration, clock restrictions and logical
consumption memory qualify the results. They do not establish concrete
encoding security, key custody, clock correctness or durable distributed use.

Decisions precede their modeled deadlines. The clock cannot pass an unresolved
deadline; timeouts eventually close the request under weak fairness. Liveness
also assumes fairness for time advancement, control refresh, halt
acknowledgment, reconciliation and normal resumption. It assumes none for the
actor, human approval, an operator's halt or restriction-lifting action, or
restoration of a failed service. `RecoveryCompletes` is conditional: if service
availability eventually becomes permanent, fair control steps eventually return
each reconciling state to global normal operation. A class restriction may still
need an operator's lift. Separate liveness bounds provide two request identifiers;
matching witnesses reach an admitted continuation and a continuation timeout.
Safe closure can satisfy resolution. The clock stops at the configured finite
horizon and the configurations disable deadlock checking.

The configurations use small fleets, action sets and time horizons. A
negative check succeeds only when it finds an allowed counterexample to its
specified property; a witness finds a trace demonstrating a named reachable
situation. Neither establishes nonvacuity of every property in every
configuration. The outage, revocation and halt witnesses retain the permitted
residual windows: previously issued authority can still operate within its
applicable freshness and propagation bounds. A result for these bounds is not
an inductive proof for arbitrary deployments.

### Current reproduction and historical evidence

To reproduce the 70 current checks from their retained inputs, use Python
3.10 or later, Java and the pinned TLC, Tamarin and Maude tools. Keep the two
invocations' distinct time limits and use separate fresh result files and log
directories:

```sh
python3 formal/diagnostics/2026-11-11-runner-compatibility/inputs/formal/run_checks.py \
  --skip-tamarin --tla2tools /path/to/tla2tools.jar \
  --timeout 900 --derivcheck-timeout 10 \
  --record /path/to/new-tlc-results.json \
  --log-dir /path/to/new-tlc-logs

python3 formal/diagnostics/2026-11-11-runner-compatibility/inputs/formal/run_checks.py \
  --skip-tlc --tamarin /path/to/tamarin-prover \
  --maude-dir /path/to/maude-directory \
  --timeout 120 --derivcheck-timeout 10 \
  --record /path/to/new-tamarin-results.json \
  --log-dir /path/to/new-tamarin-logs
```

The script refuses an existing log directory. The
[reproduction guide](formal/README.md#running-the-checks) supplies the tool pins.
The current compatibility packet preserves the original invocation records
and checks them against the repaired runner. Its assembly performed no new
solver runs and retains the per-check commands, dates, runtime settings and
original runner identities. TLC used
a 900-second limit per check; Tamarin used 120 seconds. Input and complete-output
hashes bind each result. Tamarin's message-derivation diagnostic limit is ten
seconds, both in these invocations and in the current runner's default. The
archived Version 1.0 runner supplied zero in its command, disabling that
diagnostic; the command construction alone does not identify an unrecorded
historical invocation.
A timeout or missing expected outcome is not a successful check. State counts
describe separate state spaces, and recorded durations are not deployment
latency measurements.

The preserved November 7 v1.0.1 record contains **32 TLC checks**: three
correct configurations, 22 broken variants and seven witnesses. That model
checked **20 properties**, including 12 invariants, five action properties and
three liveness properties. Its nine Tamarin checks comprise one correct theory
with seven lemmas and eight deliberately flawed variants. The original v1.0
model checked 18 TLC properties before the two deadline properties were added.
The separate 17 November 7 diagnostics remain historical and were not rerun to
qualify the current model. The historical models, records, outputs and exact
runners remain linked from the
[formal guide](formal/README.md#historical-results-november-7-2026).

The [November 10 recovery record](formal/diagnostics/2026-11-10-recovery/COMBINED-RESULTS.json)
contains **35 TLC checks** on the earlier recovery model, whose correct
configurations selected **22 properties: 19 safety and three liveness**.
It precedes the current continuation and restriction changes. To reproduce
that historical packet, use `formal/check_recovery.py` with a fresh output
directory as the formal guide describes. The earlier November 11 contract-review
packet preserves 49 TLC and ten Tamarin checks on its own model inputs; its
correct configurations selected 28 safety and three liveness properties. All
three earlier records remain separate evidence for their recorded revisions.

Implementation conformance and deployment assessment still require evidence
for real mediation boundaries, credential custody, storage and crashes,
release/effect timing, clock behavior, obligations and budgets, causal bundles,
trust-policy history, trusted time and extensions. The models abstract these
or omit them. [From the models to an implementation](formal/README.md#from-the-models-to-an-implementation)
maps the gaps to the requirements an implementation must satisfy.

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
  --trust-policy ../../conformance/fixtures/evidence/trust-policy.json \
  --now 2026-10-01T00:00:00Z
```

Python (`ecl-verify`) and Go (`ecl-verify-go`) command-line verifiers are also
included in [packages/ecl-verify](packages/ecl-verify/README.md) and
[go/crosscheck](go/crosscheck/README.md). The [quickstart](docs/quickstart.md)
runs all three and the shared corpus from this source package.

The `ecl-verify-ts` command prints the verdict (`verified`, `invalid`, `incomplete` or
`current-trust-failed`), what the verdict establishes and what it does not, and
it exits with 0 for a verified bundle. Its `--json` option prints the report as
JSON. The TypeScript package's unit and browser tests ship with that package (`npm test`,
`npm run test:browser`), and `node scripts/check-corpus.mjs` runs
`ecl-verify-ts` on every bundle and package vector of the conformance tests and
compares each verdict with the expected one.

## Guides

The guides are informative; where a guide and a requirement differ, the
requirement governs.

- [Review design choices](docs/review-design-decisions.md): the request-expiry
  boundary, refusal histories and proposals beyond the implemented checks.
- [Buyer summary](docs/buyer-summary.md): what a claim must say and what to
  ask a supplier for.
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

G-14, Inc. and Robert F. Tilley Jr. provide the interim editorial and contact
function while the community working group is being formed. ECL-1 is open to
community participation and stewardship under the charter. Community roles,
working-session dates and agendas will be announced publicly as they are
established; no outside appointment or completed meeting is implied.
Contact ecl@g14.ai to participate.

The charter provides for open development through the ECL-1 Working Group.
Anyone may join, at no cost, by signing up through this repository, as
[community/WORKING_GROUP.md](community/WORKING_GROUP.md) describes. Working
sessions and public notes will follow the charter's procedures once sessions
are established and announced. The [charter](governance/CHARTER.md) sets out how it works: the editors
propose, the working group discusses, and the editors decide by rough consensus
and record the reason. [governance/](governance/README.md) holds the change,
errata, registry, release and appeals procedures.

- Comment, ask or propose in this repository's issues, discussions and pull
  requests. Every commit carries a Developer Certificate of Origin sign-off
  ([governance/DCO.txt](governance/DCO.txt), [contributing](governance/CONTRIBUTING.md)).
- Each new minor version has a public review window of 30 days, and each new
  major version one of 60 days, announced on externalcontrollayer.ai. Every
  comment receives a published disposition ([governance/PUBLIC_REVIEW.md](governance/PUBLIC_REVIEW.md)).
  A candidate label alone does not open or complete a review window.
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
