# ECL-1 verifier in Go

This Go module reads, checks and verifies ECL-1 objects. It parses the
restricted JSON that ECL objects use, computes canonical digests, validates
objects against the embedded ECL schemas and the protocol rules, verifies
ECL-IE-1 integrity envelopes and trust policies, verifies signed evidence
bundles and the offline packages that carry them, checks the records of the five
binding profiles and checks the claim and assessment documents against their
schemas and, for a work intent, against the extension rules. It uses only the Go
standard library and makes no network request.

It is one of the three verifiers of ECL-1 Version 1.0, with the Python package
`ecl-verify` (`packages/ecl-verify`) and the TypeScript package
(`packages/ecl-ts`). All three are maintained by G-14, Inc.: this module is a
same-operator second implementation, written to be compared with the Python
verifier on the conformance corpus. That comparison is implementation
diversity under one operator; it is not an independent assessment.
`NOTICE.md` says how the code relates to the Python verifier. In short: the
foundation rules come from a separately maintained Go core, and the other
packages follow the Python verifier's documented behavior. On every vector of
the shared conformance corpus, the module reaches the expected result and the
same primary finding as the Python verifier, and the same verdict for each
evidence bundle and offline package.

## Requirements

Go 1.26.10 or later. The release is qualified with Go 1.27.3. The module has
no dependencies outside the standard library.

The module path is `externalcontrollayer.ai/ecl-1/go/crosscheck`, the folder
`go/crosscheck` of the ECL-1 package. Build and test from this folder, with no
network access needed:

```
go vet ./...
go build ./...
go test ./...
```

## Commands

`cmd/ecl-verify-go` verifies an evidence bundle or an offline package, with the
interface and exit statuses of the Python `ecl-verify`:

```
go run ./cmd/ecl-verify-go ../../conformance/fixtures/evidence/succeeded.json \
  --trust-policy ../../conformance/fixtures/evidence/trust-policy.json \
  --now 2026-09-29T10:00:02.000000Z
```

It takes `--trust-policy FILE`, `--trust-policy-history FILE` (repeated),
`--now`, `--accept-current-trust-failure`, `--require-trusted-time`,
`--register FILE` and `--json`. The exit status is 0 for `verified`, 1 for
`invalid`, 2 for a usage error, 3 for `incomplete` and 4 for
`current-trust-failed` (EBMP2-060).

`cmd/ecl-corpus-check` evaluates the shared conformance corpus
(`conformance/shared-corpus.json`) and writes a cross-implementation report
with the raw evidence of each result:

```
go run ./cmd/ecl-corpus-check --repo-root ../.. --report /tmp/ecl-go-report.json \
  --revision 0000000000000000000000000000000000000000
```

`--repo-root` is the root of the ECL-1 package, `--report` a file that does not
exist yet, and `--revision` the 40-character revision of the source the report
names. Its exit status is 0 when every vector meets its expectation, 1 when one
does not and 2 when the corpus cannot be evaluated.

## Packages

| Package | What it does |
| --- | --- |
| `strict` | Parses restricted JSON: one UTF-8 value, no repeated member, integers only within plus or minus 2^53 - 1, no surrogate code point or noncharacter. It runs the checks of IE1-037 in their order, so the first that fails names the one finding of a refusal, and the imported core builds the value once every check has passed. |
| `canon` | Writes canonical JSON (RFC 8785 restricted to integers, with no noncharacter in a string or member name) and its SHA-256 digest. |
| `schema` | Validates values against the embedded ECL-1 schemas (JSON Schema Draft 2020-12, the keywords the schemas use). |
| `semantic` | Checks the rules that schemas cannot express, for DCMP-2 messages, EBMP-2 objects, bundles of records, adapter bindings and safe-state profiles, the registered control-extension rules, the one-way rule for a recorded decision basis (DCMP2-053) among them, and the extension rules of every object that carries extensions (one version of an extension per object, XR1-010, among them). |
| `bindings` | Checks the records of AARM-BINDING-1, ACS-BINDING-1, MCP-GATEWAY-1, OTEL-EVIDENCE-EXPORT-1 and OAUTH-AUTHORITY-1: the record's schema, then the profile's 28 registered rules, among them the agreement of an AARM or ACS record's inputs with its response's decision basis and with that of a modification's response, which records them with their declarations (AB1-013, AC1-012), and OpenTelemetry digests keyed with HMAC-SHA-256 under an export key (OE1-004, OE1-010). It has RFC 8785 for the content the profiles bind and compact JWS for OAuth access tokens and DPoP proofs (ES256 and EdDSA, RFC 7638 thumbprints). |
| `documents` | Checks the claim and assessment documents (the action register, conformance claim, assessment package, mapping packet, deployment profile, lifecycle policy, offline verification package and work intent) against their schemas, a work intent against the extension rules, and an action register against `ecl.rule.register-declarations-consistent.v1`. |
| `envelope` | Verifies ECL-IE-1 envelopes: canonical base64, payload digest, DSSE pre-authentication encoding, Ed25519 and ECDSA P-256 signatures, and the integrity policy inside the payload; under a keyring from a trust policy, each DCMP-2 message counts only under a key of its role (TP1-010, IE1-039). A refusal carries the error code of the step of IE1-040 that fails. |
| `trust` | Loads trust policies (TRUST-POLICY-1), refusing a key that holds two roles (TP1-009) and a document past a declared limit with the resource-limit error (TP1-007), and turns them into keyrings and verification contexts. |
| `evidence` | Verifies signed evidence bundles: historical and current signer status, trusted time, bindings, causal closure, the recorded discharge of pre-release obligations and the proofs the bundle carries (EBMP2-070), the release with its declared guard (EBMP2-050), the release a terminal event records (EBMP2-072) and effect evidence levels, with the verdicts `verified`, `invalid`, `incomplete` and `current-trust-failed`. Each report carries `Scope`, the checks that held and what the verdict does not establish, with the reason of each item the table of EBMP2-076 names one for, and `CompletionAfterWindow` (EBMP2-076). |
| `offline` | Verifies offline packages (OFFLINE-VERIFICATION-1): a strict reader of the `ecl.zip.store.v1` archive, over bytes and without decompression, and the checks of IE1-022 in order, which give a package the verdict of the evidence bundle it carries or the error of the first check it fails. Entry names are the POSIX portable filename characters, compared after ASCII case folding. |

## Verifying a bundle

```go
bundle, _ := os.ReadFile("bundle.json")
policy, _ := os.ReadFile("trust-policy.json")
report, _, err := evidence.VerifyBytes(bundle, policy, nil, evidence.Options{Now: "2026-10-01T00:00:00Z"})
if err != nil {
	// The files could not be verified at all: a malformed trust policy, a
	// bundle that is not strict JSON, or an invalid evaluation time.
}
fmt.Println(report.Verdict)
```

`Now` is the evaluation time at which current trust is checked. Pass earlier
versions of the trust policy as the third argument when the evidence names
them. A `current-trust-failed` verdict means the historical checks passed, but at
least one trust dependency, including a time authority, is not acceptable under
the current trust policy at the evaluation time. Set `AcceptCurrentTrustFailure`
only when you have decided to rely on such evidence; the report then records the
acceptance.

Every report carries `evaluation_time`, `trust_dependencies`, the checks and
objects behind each established scope item, and `unresolved_predecessor_ids`.
Unresolved identifiers are nonempty only for an `incomplete` verdict. A named
causal object that is absent prevents its dependent scope item from being
established; checks over held objects still run. An uncarried proof permitted
by EBMP2-070 narrows the proof-verification claim without changing the verdict.

A time attestation binds the exact signature entries listed in its
`covered.signatures`; a covered signature uses its earliest attested time and
an uncovered signature uses the object's own time. The caller's current
compromise revocations apply to every trust dependency, matched by identifier
or public key. Accepting a current trust failure cannot restore historical
invalidity. A non-verifying extra signature may leave a policy threshold met
while keeping the scope item that depends on that signature unestablished.
Evidence later than `Now` is invalid; `Now` does not select an as-of assessment.

### What the evidence verifier applies

`evidence.Verify`, `evidence.VerifyBytes` and `ecl-verify-go` apply what the
Python `ecl-verify` applies, under `ecl.verification-profile.reference.v1`
(EBMP2-057 to EBMP2-062):

- the schema of the bundle and of each signed payload, and each payload's
  semantic rules, among them the one-way rule for a recorded decision basis
  (`ecl.rule.decision-basis-one-way.v1`, DCMP2-053), which also refuses an
  input recorded as `verifiable` whose source is the actor of the response's
  request;
- each envelope's signatures, under the trust-policy version that the object
  names at its own time and under the current trust policy at the evaluation
  time, and trusted-time countersignatures when they are required (IE1-032 to
  IE1-035);
- the pairing and binding of requests, responses and events, the causal
  closure of every object, including messages and observations, and the evidence
  level of each effect;
- that every decision response carries its decision basis
  (`ecl.rule.decision-basis-required.v1`);
- when the caller supplies a Consequential Action Register (`--register FILE`,
  or `Options.Register`, which `evidence.LoadRegister` reads), that each
  decision basis names that register version and lists exactly the inputs that
  it declares for the request's action class, with their declared derivations,
  and that no input it records as available was late by its recorded times
  (`ecl.rule.decision-basis-matches-register.v1`). A register that fails its
  schema or `ecl.rule.register-declarations-consistent.v1`, for example one
  that declares an action class twice, is refused as a usage error.

A verified bundle shows that its records are signed, bound and complete, not
that their statements are true: not that the enforcement point checked and
released as its events record, and not that the effects happened. Each
report's `Scope` lists these among what the verdict does not establish, with
the reason of each item that the table of EBMP2-076 names one for
(`no-release-recorded`, `proof-not-ecl-object`, `issuer-not-named`)
(EBMP2-076). Without a
register the verifier cannot tell whether a decision consulted an input that
the register does not declare, and with one it still cannot see an input that a
decision consulted and did not record. It compares a decision with its
verifiable-only outcome only when the record states that outcome, since
computing it needs the policy (ECL1N-0179).

## Verifying an offline package

```go
data, _ := os.ReadFile("evidence.zip")
document, _ := os.ReadFile("trust-policy.json")
policy, err := trust.Load(document)
if err != nil {
	// A malformed trust policy.
}
report, err := offline.Verify(data, policy, offline.Options{Options: evidence.Options{Now: "2026-10-01T00:00:00Z"}})
if err != nil {
	// An invalid option or limit: the package was not read.
}
fmt.Println(report.Verdict, offline.Identifiers(report))
```

The trust policy, earlier versions and evaluation time are yours, never the
package's: the trust policy, keys and snapshots inside a package are evidence
(IE1-022). `offline.Options` embeds `evidence.Options`, which reaches the
package's bundle unchanged, so the decision basis is required and a register
applies exactly as for a bundle on its own, and `Limits` declares the
verifier's resource limits (IE1-028), `offline.DefaultLimits` when nil. A
package over a limit is `invalid` with `ecl.error.resource-limit-exceeded.v1`.
`ReadArchive` reads the archive itself. Archive assembly is used only by test fixtures.
`offline.VerifyBytes` verifies a package file against trust policy files, as
`evidence.VerifyBytes` verifies a bundle file. `ecl-verify-go` uses it for a
file that begins with the bytes `PK`, up to 1 GiB, the declared archive limit.

## Checking a binding record

```go
data, _ := os.ReadFile("exchange.json")
record, err := strict.Parse(data)
if err != nil {
	// Not restricted JSON.
}
findings, err := bindings.EvaluateRecord(bindings.MCPExchangeSchema, record)
if err != nil {
	// The Python verifier raises on this record (a *bindings.PythonError), or the
	// schema is unknown.
}
for _, finding := range findings {
	fmt.Println(finding.RuleID, finding.Path, finding.Detail)
}
```

`EvaluateRecord` is the conformance runner's `binding` stage: one
schema-invalid finding when the record fails its schema, otherwise the findings
of the profile's rules. `EvaluateRecordWithKeys` takes the OpenTelemetry export
keys that `LoadExportKeys` reads, and compares a record's keyed digests under
them (OE1-004, OE1-010). `documents.Evaluate` is the `document` stage: the
document's schema, and the registered rules whose `applies_to` names its type.

## Testing against the Python verifier

`go test ./...` runs the module's tests. `ecl-corpus-check` runs every vector
of the shared corpus, and the Python verifier's report of the same corpus
(`scripts/run_python_corpus.py` at the root of the ECL-1 package) has the same
form, so the two can be compared result by result. G-14 also compares the two
implementations, before each release, on further cases derived
deterministically from the vectors, with tooling of its own that is not part
of this module; it fails on any difference in a primary finding, a pass or fail
result or a verdict.

## Limits

ML-DSA-65 signatures are recognized and refused as unsupported because this
implementation does not enable that suite. No shared vector needs it. On every
shared vector the module's secondary findings equal the Python verifier's.

A package's manifest and its envelope artifacts are read by the module's strict
JSON parser, whose declared limits are the Python verifier's: 256
levels of nesting and 1,000,000 values by default, 16 MiB of input, and a
configured limit is an exact positive integer within its ceiling (2,147,483,647
bytes, 4,096 levels, 100,000,000 values), refused otherwise with
`ecl.error.configuration-invalid.v1` before any input is read. The checks of
IE1-037 and the builder of the parsed value are repository code; the imported
core supplies the error type and the rule identifiers. IE1-022 makes a package
whose manifest or artifact exceeds a limit `invalid` at the check that meets it.

## Rights

Copyright 2026 G-14, Inc. Licensed under the Apache License, Version 2.0
(`LICENSE`, a copy of the ECL-1 package's `LICENSE`). `NOTICE.md` says how the
code was written. G-14's patent pledge for implementations of ECL-1 is in the
repository's `PATENTS.md`; G-14 has patents pending. The module uses only the
Go standard library.

The canonical JSON report includes `primary`: the registered identifier of the
primary finding, or `null` for `verified`. An `incomplete` report names
`ecl.error.causal-closure-incomplete.v1`; `current-trust-failed` names the first
failing current status in the standard's order, with package expiry first for an
expired offline package. This agrees with the text report's `primary:` line.
