# ECL-1 release brief

ECL-1 is the External Control Layer Standard. It specifies how a control layer
outside a governed AI system decides and authorizes consequential actions
before release, enforces the exact authorized action, responds when required
proof is missing, and records evidence that others can verify.

An implementation declares the actions, boundaries, level, independence class
and assumptions it covers. A verified bundle establishes only the checks and
limits stated in its report. The standard supplies no automatic legal
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
version using `CITATION.cff`; repository, release notes and checksums identify
the version actually obtained.

## How it relates to existing work

The [binding guide](bindings.md) explains ECL-1's profiles for AuthZEN, AARM,
ACS, MCP, OAuth and OpenTelemetry. Their pinned versions and residual duties
matter. These relationships establish no endorsement, universal superiority
or automatic conformance to the other framework.

Version 1.0's OAuth profile carries obligation-free admits only. A workflow
requiring release-time proof uses an enforcement path that can carry and
discharge it. [Decision examples](decision-examples.md) cover input authority,
human approval, retention conflicts and administrator/root separation.

## Current evidence and participation

Read the [release notes](../RELEASE-NOTES-1.0.md) for the version's tests, known
limits, outside-review status and prohibited claims. The three verifiers are
maintainer implementations; agreement among them supplies bounded consistency
evidence. Outside implementations and assessments remain separate evidence.

The working group welcomes implementation reports, reproducible problems,
proposed corrections and public review comments through the
[participation process](../community/WORKING_GROUP.md). Governance, issue
dispositions and errata provide a continuing way to examine and improve the work.
