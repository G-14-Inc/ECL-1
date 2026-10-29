# ECL Evidence Lifecycle Protocol 1

Version: 1.0
Status: normative companion of ECL-1 Version 1.0, a published version

## 1. Principle

Evidence lifecycle actions are new, authenticated facts. They do not mutate
history in place.

**EL1-001** — Evidence MUST have a declared lifecycle policy at or before
sealing.

**EL1-002** — The policy MUST identify retention, legal hold, export, redaction,
supersession, revocation, destruction, residency, encryption, and access
requirements applicable to the evidence class.

**EL1-003** — A lifecycle transition MUST record actor, authority, policy,
prior digest, operation, time, and resulting artifact or proof where
applicable.

## 2. Sealing and verification

**EL1-004** — Sealing MUST establish canonical content identity and the
integrity policy used.

**EL1-005** — Verification MUST produce a separate verification event.
Verification status MUST NOT be written into and thereby alter the sealed
source.

**EL1-006** — Verification failure MUST retain the failed object and finding
unless a higher legal or safety requirement prohibits retention.

## 3. Retention and hold

**EL1-007** — Retention periods MUST be calculated from explicit events and
policy, not filesystem modification time.

**EL1-008** — Legal hold MUST suspend destruction for its scope unless the
recorded legal determination under ECL1N-0195 to ECL1N-0199 requires otherwise.

**EL1-009** — Releasing a hold MUST require separate authority and MUST NOT
itself destroy evidence.

**EL1-010** — Retention extension MUST be non-destructive. Retention shortening
MUST require the change-control and authority class defined by the profile.

## 4. Export and chain of custody

**EL1-011** — Export MUST produce a manifest binding source objects, exported
objects, transformations, custody actors, transfer times, and destination
boundary.

**EL1-012** — An air-gapped export MUST preserve offline verification material
and record removable-media or transfer-channel custody where the profile
requires it.

**EL1-013** — Receipt of an export MUST be a separate event; dispatch does not
prove receipt.

## 5. Redaction and minimization

**EL1-014** — Redaction MUST create a new derivative and redaction manifest.

**EL1-015** — The manifest MUST identify the sealed source digest, redaction
policy, transformation implementation, removed data classes, preserved
verifier-critical fields, producer, and resulting digest.

**EL1-016** — Selective disclosure MUST NOT be described as proof of an
undisclosed field unless a registered cryptographic disclosure scheme supports
that exact claim.

**EL1-017** — A verifier MUST downgrade or reject a claim when redaction removes
evidence required for that claim.

## 6. Supersession and revocation

**EL1-018** — Supersession MUST identify a preferred successor while preserving
the predecessor and its historical validity interval.

**EL1-019** — Revocation MUST state that an artifact is no longer acceptable
for a specified purpose and time, and MUST NOT assert that the artifact never
existed.

**EL1-020** — A revocation MUST identify scope, effective time, reason,
authority, and replacement where one exists.

## 7. Destruction

**EL1-021** — Destruction MUST be prohibited while a governing hold is active
unless the recorded legal determination under ECL1N-0195 to ECL1N-0199 requires otherwise.

**EL1-022** — A destruction event MUST identify the target digest, method,
scope, actor, authority, time, replicas or media addressed, residual limits,
and proof required by the profile.

**EL1-023** — A producer MUST NOT claim destruction outside its observable or
controlled boundary.

**EL1-024** — Destruction of data MUST NOT destroy the minimum lifecycle proof
required to establish that authorized destruction occurred, unless law or the
active profile requires otherwise.

## 8. Precedence

**EL1-025** — Legal hold MUST take precedence over scheduled destruction,
subject to the recorded legal determination under ECL1N-0195 to ECL1N-0199.

**EL1-026** — Emergency preservation may extend retention but MUST be reviewed
and bounded.

**EL1-027** — Conflicting lifecycle instructions MUST enter hold or
indeterminate state until an authorized precedence decision is recorded under
ECL1N-0050, within the applicable deadline. A hold MUST NOT authorize retention
that the legal determination prohibits. Unavailable evidence MUST remain
disclosed, with verification and assessment limited to the evidence retained.
