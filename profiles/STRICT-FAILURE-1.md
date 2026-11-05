# ECL Strict Failure Profile 1

Requirement-IDs: compiled
Version: 1.0
Status: normative profile of ECL-1 Version 1.0, a published version

**SF1-001** — A deployment claiming this profile MUST NOT declare a fail-open
disposition for any in-scope action class.

**SF1-002** — Under this profile, the loss of any dependency MUST resolve to a
disposition other than `fail_open`, and the loss of a dependency that supplies
required proof MUST resolve to one of the dispositions that fail closed, which
TIMING-SAFE-STATE-1 TS1-032 lists.

**SF1-003** — An unexpected failure before effect commit MUST block the effect
and MUST be recorded with its failure class.

**SF1-004** — A safe-state profile document claims this profile by listing
`STRICT-FAILURE-1` in its `claimed_profiles` member; its `profile_id` and name
decide nothing. A document that claims it MUST validate against the
safe-state-profile schema, which requires `supplies_required_proof` for every
dependency, with no `fail_open` disposition present.

**SF1-005** — A deployment that claims this profile MUST set
`supplies_required_proof` to `true` for exactly those dependencies whose loss
removes required proof (TIMING-SAFE-STATE-1 TS1-031). This obligation binds the
deployment and lies outside document validation: a validator checks the form of
the document under SF1-004, and an assessor checks the classification against
the deployment's dependencies and failure tests.

Document validation cannot prove that a deployment classified its dependencies
truthfully. Deployment evidence comes from the claimant's own failure tests,
for example a test that the loss of a dependency produces a denial with no
artifact fabricated for it, and a test that malformed or oversized input is
refused before any other work.

This profile adds nothing to the scope of a restriction. The loss of a
dependency that supplies required proof refuses the actions of every class that
requires it, with a disposition that fails closed (SF1-002), and the core
standard sets which classes those are and when the whole deployment stops
(ECL1N-0191 to ECL1N-0193).
