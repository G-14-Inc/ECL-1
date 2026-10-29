# ecl-verify: the ECL-1 verifier in Python

`ecl-verify` checks ECL-1 evidence offline. Given a signed evidence bundle or
an offline package and a trust policy that you choose, it reports whether the
evidence verifies, and it states, item by item, what that verdict establishes
and what it does not. It makes no network request and needs no account.

The package contains verification and read-only metadata. Evidence signing,
time-attestation construction, token issuance, decision builders, archive
assembly and telemetry exporters belong to G-14's private producer library.
Binding checks recompute expected values from records already in hand.

It is one of three verifiers of ECL-1 Version 1.0, each written separately
from the same text: this Python package, the TypeScript package
(`packages/ecl-ts`, with the command `ecl-verify-ts` and the browser verifier)
and the Go module (`go/crosscheck`, with the command `ecl-verify-go`). The
three are maintained by the same operator, G-14, Inc. Their agreement on the
conformance tests is a check of each against the text, not an independent
assessment.

## Install

From the root of the ECL-1 package (Python 3.10 or later):

```
python3 -m venv .venv
.venv/bin/pip install ./packages/ecl-verify
```

The dependencies are `cryptography`, `jsonschema` and `referencing`. With uv,
`uv sync --locked` in this folder installs the versions and hashes of
`uv.lock`. The wheel carries the ECL-1 schemas and registries that the
verifier reads; in a checkout of the package the modules read the top-level
`schemas/` and `registries/`.

## Verify evidence

```
.venv/bin/ecl-verify conformance/fixtures/evidence/succeeded.json \
  --trust-policy conformance/fixtures/evidence/trust-policy.json \
  --now 2026-09-29T10:00:02.000000Z
```

The first line of the report is the verdict. The `not-established:` and
`established:` lines are the scope items of EBMP2-076, each with what it
means; then come each envelope's checks, the bindings, the causal status and
each effect's evidence level, then the findings. `--json` writes the same
report as canonical JSON.

A file that begins with the bytes `PK` is verified as an offline package
(OFFLINE-VERIFICATION-1) of at most 1 GiB; any other file as a JSON evidence
bundle of at most 1 MiB. The options:

| Option | Meaning |
| --- | --- |
| `--trust-policy FILE` | the current trust policy (required) |
| `--trust-policy-history FILE` | an earlier version of the trust policy that the evidence names; repeat for each |
| `--now RFC3339` | the evaluation time at which current trust is checked; the clock when omitted |
| `--require-trusted-time` | require a valid countersignature covering every signature entry (IE1-035) |
| `--register FILE` | check each decision basis against this Consequential Action Register (DCMP2-053) |
| `--accept-current-trust-failure` | report `verified`, with the acceptance stated, when a trust dependency is not acceptable now and the evidence remains historically valid |
| `--json` | the report as canonical JSON |

### Exit status

| Status | Verdict |
| --- | --- |
| 0 | `verified` |
| 1 | `invalid` |
| 2 | usage error: an unreadable or malformed trust policy, register or bundle, or an invalid `--now` |
| 3 | `incomplete` |
| 4 | `current-trust-failed` |

These are the statuses of EBMP2-060, the same for `ecl-verify-ts` and
`ecl-verify-go`.

## The samples

`conformance/fixtures/evidence/` holds sample evidence with its trust policy:
`succeeded.json`, `denied.json` and `corroborated.json` verify at the
evaluation time `2026-09-29T10:00:02.000000Z`, and `tampered.json`, the
succeeded bundle with one bit of its last signature flipped, is `invalid`. The bundle and package
vectors of `conformance/suites/evidence-bundle/` and
`conformance/suites/offline-package/` each name the verdict they must receive.

## What it verifies

The command applies the reference verification profile,
`ecl.verification-profile.reference.v1` (EBMP2-057 to EBMP2-062): strict JSON
within the declared limits (IE1-028, IE1-037), the schema and semantic rules of
each signed object, each envelope's signatures under the trust-policy version
its object names and under the current trust policy (TRUST-POLICY-1), trusted
time where required, the bindings between requests, responses and events, the
causal relations of the bundle's objects, and, for an offline package, the
checks of IE1-022 in their order. The modules also check binding records
(`ecl_verify.bindings`), documents and the other wire formats; the corpus
runner, `scripts/run_conformance.py` at the root of the ECL-1 package, runs
them over every conformance suite.

The causal graph covers messages, events and observations. A missing named causal
object does not exempt checks over objects that are held. Time attestations bind
the exact signature entries in `covered.signatures`; historical validity and
current acceptability are reported for every trust dependency, time authorities
included. Current compromise knowledge matches key identifiers or public keys,
and accepting a current trust failure cannot restore historically invalid evidence.
An object or attested time later than `--now` is invalid; no as-of assessment is
provided. Each report states its evaluation time, dependencies, checks and covered
objects for every established scope item. `unresolved_predecessor_ids` is present
in every report and nonempty only when its verdict is `incomplete`.

## What it does not verify

A `verified` bundle is signed, bound and complete as the scope items listed
under `established:` say. It does not show that the statements in the bundle
are true, that the recorded times are the true times of their events, that
the effects happened, or that the deployment that produced the evidence has
been assessed; the report lists each of these under `not-established:`.
Without `--register` it does not check a decision basis against a register.

## Tests

From the root of the ECL-1 package, with `pytest` and `hypothesis` installed
in the same environment:

```
.venv/bin/python -m pytest packages/ecl-verify/tests
```

## Rights

Copyright 2026 G-14, Inc. Licensed under the Apache License, Version 2.0
(`LICENSE`); the package declares `Apache-2.0`, and `NOTICE` says what the
distribution holds. G-14's patent pledge for implementations of ECL-1 is in
the repository's `PATENTS.md`; G-14 has patents pending. Its dependencies
`cryptography`, `jsonschema` and `referencing` keep their own licenses. The
ECL-1 texts are licensed under CC BY 4.0, as `LICENSING.md` at the root of the
ECL-1 package states.

The canonical JSON report includes `primary`: the registered identifier of the
primary finding, or `null` for `verified`. An `incomplete` report names
`ecl.error.causal-closure-incomplete.v1`; `current-trust-failed` names the first
failing current status in the standard's order, with package expiry first for an
expired offline package. This agrees with the text report's `primary:` line.

`ecl_verify.bundle_verification.report_to_json(report)` returns that same
JSON-compatible shape for Python callers.

`ecl_verify.resources.schema_is_valid(schema_id, value)` checks a schema and
returns a boolean. `validator_for(schema_id)` remains available when callers
need a mutable validator or detailed schema errors; each such validator is isolated.
