# Core contract and verification report migration

Robert F. Tilley Jr. and G-14, Inc.

The Version 1 public-review draft applies the following contract corrections.
The normative requirements remain the controlling reference.

## Scoped fail-open policies

A safe-state profile's `fail_open_authorization` now includes a nonempty,
unique `covered_advisory_dependencies` array. Each identifier must name a
declared advisory dependency with `supplies_required_proof: false`. Dependency
identifiers must be unique throughout the profile. Existing profiles that
lack this scope need an explicit declaration before they can authorize fail-open.

Python callers of `decide_safe_state` provide
`failed_advisory_dependencies=(...)` and `required_proof_available=True` when
requesting an authorized fail-open transition. The authorization's
`covered_advisory_dependencies` tuple must cover every failed dependency.
Omitting these arguments cannot establish fail-open authority. A false proof
declaration, or `missing_pre_release_evidence`, requires at least fail-closed;
quarantine and emergency halt retain their stronger precedence. Noncritical
telemetry may still be shed under TS1-023 when the required proof remains intact
and the named advisory scope is authorized.

This helper checks supplied declarations. The caller determines dependency
status and proof availability from the actual deployment. Boolean declarations
must be actual booleans; identity text must be nonempty; dependency tuples must
not repeat an identifier. These input checks do not add a deployment assessor.

## Decision input timing reports

`decision-basis-register` retains its structural and conditional timing meaning
under EBMP2-076. The additional `decision-input-timing` scope item records
whether every applicable input-age and acquisition-deadline comparison had
the recorded timestamps it needed.

The item applies only when a caller supplies a register and an available input
has a declared temporal constraint. A maximum-age comparison needs `value_at`
and the decision's `evaluated_at`; a deadline comparison needs `received_at`
and `obtained_at`. Missing operands produce `not_established` with reason
`input-times-not-recorded`. Optional timestamps remain optional and this
omission alone does not invalidate an otherwise valid bundle. Violations
shown by supplied timestamps still invalidate the bundle. No timing item is
reported for an absent register or for inputs without an applicable temporal
comparison. A successful comparison does not establish that a recorded time
is true. Consumers that enumerate scope items or reason codes must accept
the new registered names.

## Parsed bundle resource limits and diagnostics

The parsed-object bundle entry points in Python, TypeScript and Go now apply
the existing depth-256 and 1,000,000-value-node bounds to the entire supplied
bundle before schema and cryptographic verification. Cycles are refused;
shared children count once per serialized occurrence. Excess returns
`ecl.error.resource-limit-exceeded.v1`. These APIs do not impose a new byte cap
on parsed strings. The byte interfaces retain their separately declared
1 MiB input limit under TP1-007.

Malformed extension timestamps retain their registered extension-schema
findings without suppressing unrelated semantic findings. Fractional action
parameters passed directly to the Python or TypeScript semantic API produce
the parameters-digest finding; strict JSON entry points still reject numbers
outside the canonical profile first. When verifiable-only policy already
denies, actor-supplied and judgment inputs must have effect `none`.

DCMP-2 section 8 now states the existing response-binding execution order
explicitly. This wording correction preserves first-failure codes and the
single-use authority contract.

## MCP release progress and completion

Under MG1-014, retained obligation discharge (step 4) or a final release
observation (step 5) requires the earlier `prepared` event (step 3). A refusal
that reached those stages retains consumed authority and is `cancelled`;
removing `prepared` cannot turn it into an unconsumed `denied` attempt. An
initial observation alone does not establish consumption. The MG1-016/017
recovery and journal-failure cases remain applicable when the record contains
no later-stage evidence.

An ordinary forwarded exchange that retains the server's answer must retain
`forward_completed_at` in both `forwarded` and the terminal MCP binding, as
MG1-015 requires. Both locations must agree whenever either retains a time,
including recovered exchanges. Recovery records may omit both observations
when the time is unavailable; a forward without a server answer also need not
invent a completion time. Completion after authorization expiry remains
informational and does not itself establish a late release.

The Python, TypeScript and Go checkers report these inconsistencies under the
existing `ecl.rule.mcp-forward-requires-admit.v1` and
`ecl.rule.mcp-result-bound.v1` rules. The wire schema and rule identifiers are
unchanged. Synthetic corpus records now state their authored completion
observations explicitly. Historical execution records must retain their
actual evidence, including omissions; the fixture migration is not a method
for supplying missing historical timestamps.


## Schema helper input domains

The Python and TypeScript schema validators now reject host `NaN` and
infinities for the JSON Schema `number` type. Finite fractional numbers remain
valid schema inputs where a schema permits them; the restricted ECL wire-number
profile is checked by the strict JSON and canonicalization entry points.
TypeScript's schema `object` type accepts plain objects with `Object.prototype`
or a null prototype. `Map`, `Set`, `Date` and typed arrays cannot stand in for
an empty JSON object.

TypeScript schema diagnostics describe malformed scalar host values without
serializing them, and `objectFindings` converts malformed-input errors from
schema validation into a schema finding. Its existing resource check still
precedes schema and semantic validation. These changes do not coerce values
into JSON or make standalone schema checks a substitute for parsing and the
protocol's other verification stages.

## Integer operands in parsed objects

Schema-backed semantic rules use mathematical integer operands. A finite
whole-number Python `float` or Go `float64` within the interoperable range
−9,007,199,254,740,991 through 9,007,199,254,740,991 receives the same checks as
the corresponding integer. This includes extension versions, integrity
thresholds, approval review intervals and federated timing comparisons.
Retained binding-record use counters and declared OAuth lifetime and proof-window
bounds receive the same integer checks. Embedded canonical objects retain
their separate canonicalization requirements.
Booleans and fractional values do not stand in for integers. Verification
leaves the supplied values unchanged.

Go callers can therefore use the parsed-object checks with the numeric
representation produced by `encoding/json.Unmarshal`. For serialized ECL
inputs, use the strict parser: a general JSON decoder can round a number
before a verifier receives it. The strict wire-number and canonicalization
rules, typed binding helpers and typed Python configuration objects retain
their declared input domains. Schema acceptance alone does not establish
that a value can be used as a canonical digest preimage.

The Go semantic integer accessor bounds its fallback for manually supplied
`json.Number` representations before exact rational expansion: at most 4,300 mantissa
digits, an exponent magnitude at most 4,300 and a total token length at most
4,316 characters. Values outside that host-representation budget are
unreadable to that accessor. Existing general numeric comparison behavior is
unchanged. These limits preserve the values produced by the repository's
strict and JOSE parsers.

## Standalone rule stages

TypeScript `evaluateDocument` and Go `documents.Evaluate` are document stages
for already parsed inputs. Callers supply acyclic JSON values within their
application's resource limits; the conformance runners establish those
bounds through strict parsing before invoking the stage. Serialized input
should follow that same sequence. These stages combine schema and applicable
semantic checks, while the rule-only helpers omit schema validation.

Python's configurable `SemanticValidator` uses the caller's `value_validators`
mapping for registered extension-value schemas. Omitting the mapping leaves
those checks unconfigured. The standard `object_findings` entry point loads
the shipped extension schemas and registries for DCMP-2, EBMP-2 and ECL-IE-1
objects. A custom validator must supply coherent implemented versions,
applicability declarations and value validators for its registry snapshot.
