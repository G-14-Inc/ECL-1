# ECL-1 verifier in Go: relationship and scope

This module is the Go verifier of ECL-1, maintained by G-14, Inc. and licensed
under the Apache License 2.0 (`LICENSE`). Its module path is
`externalcontrollayer.ai/ecl-1/go/crosscheck`.

It is a same-operator second implementation. G-14 also maintains the Python
verifier (`packages/ecl-verify`) and the TypeScript verifier
(`packages/ecl-ts`), and compares this module with the Python verifier on the
shared conformance corpus. Agreement between the implementations is
implementation diversity under one operator. It does not establish
independent assessment.

The packages `internal/strictjson`, `internal/canonical` and
`internal/validator` are a separately maintained, same-operator clean-room
implementation of the ECL foundation semantics, written from normative text
without importing or translating the Python verifier, and imported into this
module with their import paths changed to the module's. Two changes were made
to `internal/validator/validator.go` after the import, each declared in G-14's
import record: it classifies a DCMP-2 or EBMP-2 object by its protocol before
the bare-bundle shape, and it counts the non-release terminal states of EBMP-2
as terminal.

The other packages are written by the maintainers of the Python verifier. The
schema validator, the envelope, trust-policy, evidence and offline package
verifiers, the control-extension rules, the extension rules of objects that the
imported validator does not classify (`internal/validatorx`), the
binding-profile rules and the document checks follow the Python verifier's
documented behavior without importing or calling it. Where the normative text
leaves a behavior open, such as which records make the Python verifier raise an
exception, the code follows that behavior, so that both reach the same results;
OA1-007 fixes how a token segment is read as JSON.

For three rules the imported validator checks other conditions than the
requirement states: the integrity threshold (IE1-013), the authority of an
admit (DCMP2-013) and the native adapter binding (EBMP2-069). Its findings for
these rules give way to checks of the stated conditions in
`internal/validatorx`; the imported validator is not changed for them. A bare
bundle is analyzed by the module's port of the causal analysis of EBMP-2
section 4 (`evidence.Analyze`), not by the imported validator's bundle rules,
which report the first failure only. On every shared vector the module's
secondary findings equal the Python verifier's.

The corpus runner declares every capability of the shared corpus. ML-DSA-65
signatures are recognized and refused as unsupported, because this Go
implementation does not enable ML-DSA; no shared vector needs it.
