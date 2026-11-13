# ECL-1 public-review candidate brief

This guide accompanies the local Version 1 public-review candidate, source
`1.0.2-review.1`. Its preparation does not establish a publication date,
artifact-bound approval or an opened public-review window. Historical v1.0
and v1.0.1 releases retain their own source identities and disclosures.

ECL-1 is the External Control Layer Standard. It specifies how a control layer
outside a governed AI system decides and authorizes consequential actions
before release, enforces the exact authorized action, responds when required
proof is missing, and records evidence that others can verify.

A mediation claim declares the actions, boundaries, level, independence class
and assumptions it covers. A component or profile implementation report names
its capabilities and requirement results without an overall ECL level. A verified
bundle establishes only the checks and limits stated in its report. The standard supplies no automatic legal
compliance, model-quality assessment or proof that a recorded assertion is true.

## What people can use

- The versioned standard, companion protocols and profiles.
- Schemas, registries, signed examples and a shared conformance corpus.
- Python, TypeScript and Go verifiers, plus a browser verification interface.
- An offline verification quickstart and a runnable simulated workflow.
- Integration and assessment guides, a minimum L1 map, and contribution rules.

Start at [Start with ECL-1](start-here.md). The text/documentation uses CC BY
4.0; code and machine-readable artifacts use Apache-2.0 under the
[license matrix](../licenses/LICENSE-MATRIX.md). The [patent pledge](../PATENTS.md)
states its exact scope, conditions and review status. Cite the exact
source version using [CITATION.cff](../CITATION.cff), together with the source
digest; distinguish this candidate from the historical release artifacts.

## How it relates to existing work

The [AuthZEN guide](authzen-binding.md) explains that profile, and the
[binding guide](bindings.md) covers AARM, ACS, MCP, OAuth and OpenTelemetry.
Their pinned versions and residual duties matter. These relationships establish no endorsement, universal superiority
or automatic conformance to the other framework.

Version 1.0's OAuth profile carries obligation-free admits only. A workflow
requiring release-time proof uses an enforcement path that can carry and
discharge it. [Decision examples](decision-examples.md) cover input authority,
human approval, retention conflicts and administrator/root separation.

## Contract changes in this candidate

An admitting response must be evaluated before the request expires; equality
is expired. Refusal evidence may record evaluation at or after expiry, and a
validly issued authorization may outlive the request within the response and
requested-duration bounds. A complete continuation history may include one
admitted continuation followed by denied or challenged reuse. Two admitted
continuations remain invalid, and missing approval evidence alone leaves the
history incomplete. The [design guide](review-design-decisions.md) states the
assurance limits; the [migration receipt](../release/DESIGN-DECISIONS-2026-11-10.json)
binds the changed fixture expectations.

## Current evidence and participation

The [current formal record](../formal/diagnostics/2026-11-11-runner-compatibility/RESULTS.json)
contains 70 checks, all with their expected outcomes: 58 TLC checks (seven
correct configurations, 35 broken configurations and 16 reachability witnesses)
and 12 Tamarin checks. The correct TLC configurations select 30 safety and
four liveness properties. The correct Tamarin theory has 12 lemmas—ten
universal properties and two existence witnesses—and 11 flawed variants each
falsify a designated lemma.

The current models cover distinct sibling continuation attempts, one admitting
continuation per challenge or approval, and new proof after each fresh-to-stale
crossing. Recovery progress is conditional on eventual permanent service
availability and fair control steps; a class restriction may still require an
operator's lift. The symbolic consumer checks preserve the requested action and
audience even under response-key compromise, with request-origin and response authenticity
assumptions stated separately.

Their finite bounds, symbolic assumptions, exact retained inputs and reproduction
commands are in the [formal guide](../formal/README.md). The current aggregate
preserves separate invocation limits: 900 seconds per TLC check and 120 seconds
per Tamarin check, with ten-second message-derivation diagnostics. The November 7
record (32 TLC and nine Tamarin checks), November 10 recovery packet (35 TLC checks)
and earlier November 11 record (49 TLC and ten Tamarin checks) remain historical
evidence for their own model inputs. The
[release notes](../RELEASE-NOTES-1.0.md) retain historical tests, limits and
outside-review disclosures. Corpus coverage requires a report computed against
the candidate's final sources. The three verifiers are
maintainer implementations; agreement among them supplies bounded consistency
evidence. Outside implementations and assessments remain separate evidence.

The working group welcomes implementation reports, reproducible problems,
proposed corrections and public review comments through the
[participation process](../community/WORKING_GROUP.md). Governance, issue
dispositions and errata provide a continuing way to examine and improve the work.
