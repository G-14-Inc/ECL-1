# ECL-1 registry and namespace policy

This policy says how the identifiers, registries and namespaces of ECL-1 are
allocated and kept. The editors apply it, under the working group's decision
process ([CHARTER](CHARTER.md), section 8).

## Allocation invariants

- Every public identifier has one immutable semantic identity.
- An identifier is never reused after deprecation, prohibition, withdrawal, or
  abandonment.
- Each entry records owner class, status, introduced version, compatibility
  class, description, and type-specific attributes.
- The machine registry and normative use must agree before release.
- An allocation does not by itself endorse an implementation or grant a
  conformance claim.

## Namespaces

- `ecl.*` registry tokens and URIs under `https://externalcontrollayer.ai/ns/`
  are the public namespaces of ECL-1, which the maintainer, G-14, Inc., holds.
  G-14 keeps the `externalcontrollayer.ai` domain for as long as the
  identifiers are used. These URIs are identifiers: a consumer
  compares them as strings and never dereferences one to decide validity, and
  a validator resolves every schema identifier from its local schema set.
- An identifier path under that namespace never contains `:`; a derived
  identifier (a field, a wire value or a content digest) keeps the path form
  its registry defines.
- ECL media types use the IANA vendor tree: `application/vnd.ecl.dcmp+json`,
  `application/vnd.ecl.ebmp+json`, `application/vnd.ecl.integrity-envelope+json`,
  `application/vnd.ecl.time-attestation+json` and
  `application/vnd.ecl.bundle+zip`. They are not yet registered with IANA;
  the maintainer files their registration under RFC 6838, which needs the
  published specifications.
- The standard is cited as "ECL-1" or "ECL-1 Version 1.0", never "ECL-1.0",
  which is the SPDX identifier of the Educational Community License 1.0.
- Vendor or organization extensions use a collision-resistant namespace under
  that owner and disclose ownership.
- Private extensions cannot alter core semantics unless marked critical and
  processed under the declared critical-extension rule.
- Example identifiers remain examples and are not production allocations.

## Allocation process

1. Request the allocation in an issue or a pull request, with the requested
   identifier, owner, semantics, compatibility class, schema or deterministic
   interpretation, security considerations, lifecycle, and vectors.
2. Run collision, normative-use, schema-wire-value, and reserved-identifier
   checks.
3. Obtain the approval of an editor and a second reviewer, under the
   working group's decision process.
4. Record the allocation and effective release.
5. Publish the registry delta with the release manifest.

First-come submission does not override safety, collision, or semantic-quality
review. Functionally equivalent requests should reuse an existing identifier.

## Status lifecycle

`provisional` → `active` → `deprecated` → `prohibited` is the normal forward
path. `reserved` prevents assignment. `withdrawn` records a proposal that never
became active. Status changes are append-only decisions; history is retained.

## Emergency allocations

An emergency security allocation:

- is clearly provisional and collision-checked;
- has a named owner, reason, scope, expiry, and rollback plan;
- requires the security response lead and a second authorized reviewer;
- is reconciled into the normal registry or withdrawn before expiry;
- never rewrites an already released identifier.

## Collision and dispute handling

Exact collision blocks release. Semantic overlap receives review and may
result in reuse, a narrower identifier, or an explicit relation. Disputes use
`APPEALS.md`; the disputed allocation remains non-active while the appeal could
materially change its meaning.
