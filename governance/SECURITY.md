# ECL-1 security response policy

The maintainer, G-14, Inc., operates the security response of ECL-1. Report a
suspected vulnerability privately, as the repository's `SECURITY.md` says:
through the public repository's private vulnerability reporting, or by email
to the security contact. Never report one in a public issue, discussion or
pull request.

## Scope

Reports may cover normative or companion ambiguities, validator bypass,
canonicalization or signature defects, authority widening, evidence
suppression, lifecycle tampering, unsafe default or recovery behavior,
malicious vectors, dependency compromise, release-manifest defects, or
conformance false positives.

## Intake boundary

A release names an authenticated private reporting channel and a backup
channel: the public repository's private vulnerability reporting, and the
security contact's address. The maintainer configures and tests both before
the repository is published; until both work, the security-intake gate of
[RELEASE_POLICY](RELEASE_POLICY.md) is blocked. An empty public repository, or
one that holds only a placeholder that is not a file of the release, created so
that its private vulnerability reporting can be enabled and tested before the
release's content is pushed to it, is not a publication: publication begins
when the release's content is pushed. Public issue trackers are never recommended
for unpatched, exploitable details.

## Triage

The security response lead records:

- reporter contact and requested attribution;
- affected versions, components, and deployment conditions;
- reproducibility and evidence;
- consequence to Decision, Authority, Enforcement, Provenance, Verification,
  Fleet, availability, or conformance claims;
- severity, embargo, owners, milestones, and reassessment effect.

Potential release bypass, signature acceptance, authority widening, or false
conformance pass is presumed high severity until disproved.

## Response controls

- Least-privilege access applies to embargoed material.
- The response lead cannot be the sole approver of a permanent fix.
- Fixes include intended-reason regression tests and a compatibility review.
- A temporary mitigation is labeled temporary, bounded, and expiring.
- No reporter is asked to destroy evidence needed for validation.

## Coordinated disclosure

Disclosure timing balances affected-user remediation with public risk and is
recorded. The eventual advisory names affected and fixed versions, impact,
conditions, mitigations, credit if permitted, reassessment implications, and
artifact digests. G-14 does not promise a response-time SLA until an
operational response team and channels are formally staffed.

## Overruling a consensus for a security reason

When the maintainer overrules a recorded consensus for a security reason
([CHARTER](CHARTER.md), section 8), it says in the issue concerned that a
security reason applies, and publishes the reason in writing when the embargo
ends.

## Safe-harbor boundary

No legal safe-harbor promise is made by this policy. Any future safe-harbor
statement requires legal approval and must define authorized systems and
methods precisely.
