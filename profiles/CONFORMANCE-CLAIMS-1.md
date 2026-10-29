# ECL Conformance Claims 1

Status: informative guide for ECL-1 Version 1.0, a published version. It states no
requirement of its own: every obligation it describes is allocated, with an ID, in
the core standard or a normative companion it cites.  
Schemas:

- `https://externalcontrollayer.ai/ns/schema/action-register/1`
- `https://externalcontrollayer.ai/ns/schema/conformance-claim/1`
- `https://externalcontrollayer.ai/ns/schema/assessment-package/1`
- `https://externalcontrollayer.ai/ns/schema/mapping-packet/1`

These schemas serialize requirements allocated in the core standard: the claim
form of Sections 7.6 and 7.7, the checklist and package of Section 11, and the
mapping rules of Section 10. They do not make an implementation conformant
merely because an object validates.

## Claim tuple

A complete public claim binds:

`System of Interest × level × status × boundary class × independence class × version set × deployment profile × assessment package × refresh time`

The claim carries all six responsibilities, the action register, the Negative
Boundary Annex, limitations, and any conditional operating bounds. L4 cannot
be conditional. Mapping language remains inseparable from the framework
edition, obligation slice, support class, residual gap, and validation state.

## Evidence hierarchy

The assessment package preserves four separate decisions:

1. checklist item results;
2. structured findings and residual risks;
3. conformance claim decision;
4. procurement decision.

Not Applicable is a predicate result backed by evidence, not a waiver.
Procurement remains owned by the buyer and is never inferred from the
conformance decision.

## External mappings

A mapping packet classifies each external obligation as direct runtime
support, supporting evidence only, or out of scope. Every row carries exact
ECL surfaces, evidence, assumptions, residual obligations, framework edition,
and validation state. A mapping never asserts automatic legal compliance,
framework certification, or framework-owner endorsement.
