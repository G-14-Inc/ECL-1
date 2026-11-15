# Python assessment helper inputs

ECL-1 Version 1 public-review candidate. Robert F. Tilley Jr. and G-14, Inc.

The `ecl_verify.claims` helpers check declarations supplied by their caller.
The caller supplies the assessment records supporting those declarations.

## Named text and collection inputs

Direct callers of `ecl_verify.claims` must supply the declared Python input
shapes. Text fields checked by these helpers must be strings containing at
least one non-whitespace character. Optional text uses `None` when absent;
an empty string, whitespace, a number or a boolean does not stand in for an
identifier, disclosure, reference or exception rationale.

Fields annotated as tuples of strings require tuples with nonblank string
members. Path and model inventories annotated as `frozenset[str]` require
frozensets with nonblank string members. Bare strings are not collections of
identifiers, and lists or mutable sets are not silently converted. Mapping
fields accept `Mapping` implementations, including read-only mapping proxies;
their declared text keys and values must be nonblank strings. The action
register and assessment package require their named nested declaration types.

For example, a capability path named `ab` is supplied as `("ab",)`. The string
`"ab"` is rejected; it cannot satisfy a boundary inventory containing separate
paths `a` and `b`. A checklist item and the finding it links to retain distinct,
nonblank identifiers even when the item passes or the finding is general.

Existing applicability and cardinality rules remain in force. Empty optional
profile or limitation tuples, an empty all-pass finding map, and an empty
negative-boundary inventory remain allowed where the relevant helper permits
them. A human-approval threshold declaration is `None` or a tuple of mappings
with named fields; this helper does not validate each threshold against the
complete action-register schema. An invoked industrial-control or automotive
sector declaration must name its applicable standard and supply a
`ReferenceUse`; the rule is not applied to other sectors.

The malformed text and collection inputs described here raise `ClaimError`
before collection operations. Callers that previously supplied strings, lists
or sets in place of the annotated collections must construct the intended
tuple or frozenset explicitly. These checks validate the supplied declarations
and the relationships each helper implements. They do not replace
document-schema validation, assess the truth or sufficiency of supporting
evidence, validate arbitrary custom mapping implementations, or establish a
complete conformance assessment.

## Link failed checklist items to findings

`AssessmentOutcome.checklist_findings` maps each failed checklist item ID to
its finding ID. It must contain exactly the failed items, and every referenced
finding must exist in `finding_severities`. Checklist IDs and finding IDs remain
separate identifiers. One finding may apply to several failed items; general
findings may remain outside this mapping.

```python
AssessmentOutcome(
    checklist_results={"EA-01": "fail", "EA-02": "pass"},
    finding_severities={"finding:documentation": "minor"},
    claim_status="full_conformance",
    procurement_decision="not_evaluated",
    checklist_findings={"EA-01": "finding:documentation"},
).validate()
```

This example assumes the assessor has disclosed and accepted the minor caveat
under ECL1N-0147. A major finding blocks full conformance; a critical finding
permits only assessment-only status. A finding link does not change its severity.

Existing calls with no failed items may omit `checklist_findings` or supply an
empty mapping. Calls with failed items must now supply the links. Missing links,
unknown findings, and links from passed or not-applicable items raise `ClaimError`.

## Declare direct implementation history

`AssessorIndependence.direct_implementation_within_24_months` records whether
the assessor directly implemented the assessed system during the assessment
period or the preceding 24 months (ECL1N-0086). At L2, L3 and L4 the caller must
explicitly supply `False`; `True` or an omitted declaration raises `ClaimError`.
Use a keyword argument when updating existing calls:

```python
AssessorIndependence(
    level=2,
    assessor_id="urn:example:assessor",
    primary_implementer=False,
    managed_operator_within_24_months=False,
    claim_approval_authority_within_24_months=False,
    compensation_contingent_on_claim=False,
    material_affiliate_or_reseller=False,
    direct_implementation_within_24_months=False,
).validate()
```

At L1, the existing requirement that the assessor is not the primary implementer
remains; the new history field may be omitted. Every supplied independence flag
must be a Python `bool`, except that this new field may be `None` at L1. Values
such as `0`, `1`, `"false"` and an empty string are rejected.

## Supply typed scope and claim declarations

Boolean declarations throughout `ecl_verify.claims` require Python `True` or
`False`. Strings, numbers, null values and containers are not converted by
truthiness. The system-scope, conversational-scope and action-classification
inputs additionally permit `None` for an unknown value; their existing pending
classification remains. A malformed value raises `ClaimError`, even when
another value is unknown.

This rule also applies to positioning statements, trace Fleet responsibility,
public claims, reference and sector declarations, equivalence dossiers, mapping
endorsement, version-transition flags, procurement inputs, the assessment's
static-artifact flag and supplier-deliverable declarations. A declared
`consecutive_conditional_periods` or `deprecation_window_days` is a nonnegative
Python integer, excluding booleans. Zero defaults, the conditional-period
ceiling and the documented emergency deprecation exception retain their
existing meanings.

`TraceBoundary` rejects self-parent and longer cycles in its declared action
parent links. It permits multiple roots and several children sharing a parent.
These checks establish the consistency of the supplied declarations; the
caller still supplies the underlying evidence, and digest-bound causal bundle
verification remains a separate operation.

## Declare action isolation before claiming an exemption

`classify_action` now accepts the keyword-only input
`fully_confined_to_isolated_context: bool | None = None`. An action is
`non_consequential` only when all five consequence flags are `False` and this
additional declaration is explicitly `True` (ECL1N-0004 to ECL1N-0006).
Previously, the five flags alone produced that classification. Calls that omit
the isolation declaration now return `consequential_pending_review` in that
case. `False` and `None` also leave the exemption unestablished.

Known consequential actions and unknown consequence flags retain their
existing consequential or pending results. Isolation never overrides a
consequential trigger. Supply the declaration explicitly after establishing it
from the action's execution context; the helper checks the supplied facts and
does not inspect a sandbox or deployment.

```python
classification = classify_action(
    consequence_flags,
    fully_confined_to_isolated_context=True,
)
```
