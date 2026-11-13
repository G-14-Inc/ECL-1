# Assessment and deployment declaration validation

ECL-1 Version 1 public-review candidate. Robert F. Tilley Jr. and G-14, Inc.

The document validators check supplied declarations against the assessment and
deployment requirements. The following changes reject contradictory declarations
that the earlier schemas or helper methods accepted.

## Assessment documents

At L2, L3 and L4, an assessment package now requires the boolean field
`independence.direct_implementation_within_24_months` with value `false`.
It records direct implementation during the assessment period or preceding
24 months, as required by ECL1N-0086. It is distinct from being the primary
implementer. Existing packages must supply the declaration from the assessor's
actual history; an omitted value cannot establish independence. The fictional
examples now supply this field explicitly. At L1 it remains optional, and the
existing non-primary-implementer requirement remains.

At L2 and above, the managed-operator and claim-approval conflicts must also be
`false`. A material affiliate or reseller relationship requires the existing
published sector exception reference. The separate minimum control-independence
classes remain A at L1, B at L2/L3 and C at L4 (ECL1N-0142); these classes do not
replace the assessor conflict declarations.

An unresolved critical finding permits only `assessment_only`. An unresolved
major finding prevents `full_conformance`. For these checks, `open` and
`accepted_condition` remain unresolved; `remediated` and `rejected` do not.
Accepted minor caveats remain permitted under ECL1N-0147. A failed checklist item
requires a critical, major or minor finding somewhere in the package. This schema
check does not associate each failed checklist item with its finding. The Python
`AssessmentOutcome` helper's explicit per-item mapping is documented in
[the helper migration guide](claim-helper-api-migration.md).

The assessment package may continue to reference conditional remediation in its
`claim_decision.claim_artifact`; the conditions need not be duplicated in the
package. A conformance claim with `full_conformance` status cannot carry the
structured conditional-remediation `conditions` object. Expiry dates on full
claims, empty limitations when none are known, and remediation plans on
assessment-only claims remain permitted.

## Deployment documents

The declared default timing baseline must match the level's three values in
ECL1N-0098. A longer interval requires the existing assessor approval reference;
nondefault declarations retain their rationale, assumptions and residual-risk
disclosures. Stricter bounds remain permitted. L3/L4 declarations must explicitly
establish trusted time or secure monotonic ordering (ECL1N-0100).

A federated deployment identifies a hosted or self-managed control plane and
declares its federated exchange interval. The interval must not exceed the
connected revocation interval (ECL1N-0092 and ECL1N-0099).
`ecl.rule.deployment-timing-case-consistent.v1` performs this sibling-field
comparison in the Python, TypeScript and Go document validators. Malformed
operands are schema errors and are not compared as numbers.

The optional corpus capability `deployment-timing-case` covers that comparison,
including equality and zero-boundary cases. Implementations supporting only the
document schemas do not thereby claim this semantic capability. The comparison
checks the relationship between declared intervals; measured propagation and
the deployment evidence supporting the declarations remain assessment inputs.

## Python helper inputs

`ClaimBoundary.validate()` enforces the claimed level's minimum independence
class and disjoint included/excluded effect paths. `PublicClaim.validate()`
accepts only the four registered mapping-validation states. Assessment artifact
digests must contain exactly 64 lowercase hexadecimal characters.
`AssessmentOutcome` permits general observations, but an observation cannot
classify a failed checklist item.

`DeclaredTimingCase` requires an integer level from 1 to 4, nonnegative integer
intervals, and a boolean trusted-order declaration. Booleans are not integers
for these inputs. Its optional federated interval may remain `None` when the
caller is not declaring a federated exchange bound.

`recovery_is_complete()` requires each `RecoveryEvidence` frontier declaration
to be a boolean and `unresolved_effect_ids` to be a tuple of nonempty strings.
An empty tuple is permitted. A false frontier or any unresolved effect keeps
recovery incomplete; malformed declarations raise `SafeStateError` rather than
being coerced by truthiness. The caller supplies the reconciliation evidence.

The deployment, fallback, federation, security, privacy and redaction helpers
also validate their declared input types. Flags must be booleans. Cache intervals
must be nonnegative integers; floating-point values and booleans are rejected.
References and names must be nonempty strings, and collections must contain
strings rather than using a string as the collection. Optional reference fields
may remain `None`. Redaction source, derivative and manifest digests must each
be exactly 64 lowercase hexadecimal characters. Malformed declarations raise
`DeploymentError`.

`DeclaredTimingCase` checks the types of its rationale, residual risk, control
assumptions and approval reference as well as its numeric bounds. A truthy
number or object cannot substitute for the declared approval reference. Empty
restricted-action sets, zero cache intervals, and an absent escrow reference
when context is not materially hidden remain permitted.


The timing helpers use their declared Python domains: clock ticks, epochs,
nanosecond observations, staleness budgets and drill intervals are integers,
with booleans excluded. Required flags are booleans; identifiers and explanatory
text are nonempty strings. Declared collections are tuples of their named
items rather than bare strings. Configuration digests are exactly 64 lowercase
hexadecimal characters. Zero observations, epochs and staleness budgets remain
valid; a drill interval is positive. These checks validate supplied evidence,
not whether a measurement or independence declaration is true.

`ActionSafeStatePolicy.action_class` must be nonempty text, and
`restricted_operations` must be a tuple of distinct nonempty operation
identifiers. An empty tuple remains a valid declaration that no restricted
operations are available.

`MappingPacket` requires a nonempty residual-obligation disclosure for each
mapped obligation. Cited ECL surfaces are tuples of nonempty strings; an
`out_of_scope` obligation may retain an empty surface tuple. Checklist items
need nonempty identifiers and typed evidence-link tuples. An assessment
package needs at least one item and must not repeat an item identifier; this
check does not establish coverage of the full applicable checklist.
`validate_procurement_gate` accepts only `award`, `conditional_award`, `deny`,
`defer` and `not_evaluated`. It retains ECL1N-0135's recommendation and the
existing treatment of a departure; a misspelled decision cannot evade that
check.

An `EmergencyChannelDrill` records an already completed test as of
`evaluated_at`. Its `last_tested_at` cannot be later than that evaluation time.
The helper compares the recorded instants exactly: a test at the evaluation
time and evaluation exactly at the declared interval remain valid. This
chronology check does not authenticate either timestamp.
