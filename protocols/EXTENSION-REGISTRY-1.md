# ECL Extension and Registry Protocol 1

Version: 1.0
Status: normative companion of ECL-1 Version 1.0, a published version

## 1. Extension descriptor

**XR1-001** — Every extension MUST declare identifier, version, criticality,
applicable object types, affected fields, interpretation or schema, owner
class, status, and compatibility class.

**XR1-002** — An identifier MUST be globally collision-resistant within the
ECL registry namespace.

**XR1-003** — An extension version MUST be immutable after allocation. A
semantic change creates a new version.

**XR1-004** — Criticality MUST be evaluated per occurrence and MAY be
constrained by the registry or active profile.

**XR1-005** — A sender MUST mark an extension critical when ignoring it could
change admission, authority, enforcement, evidence interpretation, safe state,
or conformance result.

A registry entry states the descriptor in its attributes: `applies_to` (the
object types), `affected_fields`, `interpretation`, and, when the value has a
defined form, `value_schema`, the identifier of the JSON Schema that the value
satisfies. An entry whose versions may appear together in one object sets
`composable_versions` to `true`; that is the registry's explicit definition of
composability for XR1-010.

**XR1-023** — When the registry entry of an extension that a consumer processes
names a value schema, the consumer MUST validate the extension's `value` against
that schema and MUST reject a value that does not validate with
`ecl.rule.extension-value-valid.v1`; a critical extension whose value does not
validate MUST prevent admission or release.

## 2. Consumer behavior

The rules of this section apply to every ECL object that carries an
`extensions` member: DCMP-2 messages, EBMP-2 objects, ECL-IE-1 envelopes and
ECL-WI-1 work intents. Their registered rules name each of these object types in
`applies_to`.

**XR1-006** — Unknown critical extensions MUST be rejected. An extension
occurrence is unknown to a consumer unless the registry snapshot that the
consumer applies holds an active entry with the occurrence's identifier and
version and the consumer implements that entry; a deprecated, prohibited,
superseded or reserved entry does not make an occurrence known. A consumer MUST
reject an unknown critical extension with
`ecl.rule.unknown-critical-extension-rejected.v1`.

The shared conformance vectors expect a consumer that implements every active
entry of this version's extension registry. An identifier that the registry
holds under any status is allocated for XR1-017 all the same.

**XR1-007** — Unknown non-critical extensions MUST be preserved intact and
reported when the object is forwarded, transformed, or re-emitted.

**XR1-008** — A non-critical extension MUST NOT alter core semantics.

**XR1-009** — Duplicate extension identifier/version pairs in one object MUST
be rejected.

**XR1-010** — Conflicting versions of one extension in one object MUST be
rejected unless the registry explicitly defines composability. Two occurrences
of one extension identifier with different versions conflict, whether or not
the consumer knows either version, unless the registry entry of that identifier
sets `composable_versions` to `true`; a consumer MUST reject an object that
carries a conflict with `ecl.rule.extension-single-version.v1`.

## 3. Registry operations

**XR1-011** — Registry entries MUST have an append-only allocation history.

**XR1-012** — Active, deprecated, prohibited, superseded, and reserved status
MUST be distinguishable.

**XR1-013** — Deprecation MUST identify replacement, transition window, and
compatibility impact where applicable.

**XR1-014** — Emergency prohibition MUST identify security rationale,
effective time, affected profiles, and review or appeal path.

**XR1-015** — An offline verification package MUST bind the registry snapshot
used by the verifier.

**XR1-016** — Registry recognition MUST NOT grant trust or authority. Policy
MUST still determine whether an allocated item is acceptable.

## 4. Private-use extensions

**XR1-017** — A private-use extension identifier MUST be either an absolute URI
under a namespace its owner controls, other than
`https://externalcontrollayer.ai/`, or a reverse-domain token of a domain its
owner controls that ends in a version (for example `com.example.audit-tag.v1`).
An extension identifier in the `ecl.*` namespace MUST be allocated in the
registry snapshot the consumer applies; a consumer MUST reject an unallocated
`ecl.*` identifier, critical or not, with
`ecl.rule.extension-namespace-allocated.v1`.

**XR1-018** — A conformance claim MUST disclose critical private extensions
needed to interpret the claim package.

**XR1-019** — A public interoperability claim MUST NOT depend on an
undocumented private critical extension.

## 5. Compatibility

**XR1-020** — Adding an optional non-critical extension MUST be treated as an
additive change.

**XR1-021** — Making an extension critical, changing its interpretation,
narrowing accepted values, or changing core state behavior MUST be treated as
breaking unless a versioned profile explicitly provides compatibility.

**XR1-022** — A converter MUST report preserved, translated, defaulted,
dropped, and impossible extension mappings.
