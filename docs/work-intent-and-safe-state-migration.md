# Work-intent and safe-state declaration validation

The public-review candidate requires one policy declaration per `action_class`
in a safe-state profile (TS1-016). Repeated identifiers are rejected with
`ecl.rule.action-class-policy-unambiguous.v1`, even when different list entries
would individually pass. Consolidate each class into one deliberate policy;
first-wins and last-wins are not valid conflict resolution. The earlier
one-declaration-per-dependency requirement remains in force (TS1-033).

A child `ECL-WI-1` work intent names its parent in `parent_workflow.uri`,
`workflow.parent_workflow_id`, or both. When both appear they agree, and the
parent differs from the child's own workflow identity. A child carries at least
one digest-bound creating or delegating causal predecessor (DW1-002). The parent
resource reference need not have its own digest: the predecessor binds the exact
causal object. A work intent cannot list its own `intent_id` as a predecessor
(DW1-006). Standalone validation checks these declarations; it does not resolve
the predecessor, establish the complete ancestry or prove the producer's account.

DW1-015 now states the work intent's advisory interval explicitly: `expires_at`
is strictly later than `issued_at`. This clarifies the previously unspecified
cross-field validity contract. Historical intents remain evidence after expiry;
the interval never grants execution authority. Empty or reversed intervals now
produce `ecl.rule.expiry-after-issue.v1`; inconsistent parent declarations produce
`ecl.rule.work-intent-context-consistent.v1`, and a direct self-causal edge uses
`ecl.rule.message-cannot-cause-itself.v1`. A child without any predecessor also
fails the schema. Consumers report schema and applicable semantic findings
independently.

The work-intent wire `schema_version` remains `1.0-rc.1`; the existing optional
`integrity_policy` stays optional. Schema validation does not authenticate an
advisory. Consumers apply the integrity and trust requirements of their context.

An empty restricted-operations set deliberately permits no restricted operations.
An empty list of additional fail-open prohibitions cannot waive the unconditional
TS1-018 required-proof restrictions, including missing pre-release evidence.
Fail-open still requires the explicit, valid advisory scope and proof conditions
of TS1-033. The reference helper enforces that distinction at a failure transition.

The Python, TypeScript and Go document validators implement the work-intent rules.
The portable `work-intent-contract` capability records their scope separately from
extension processing. `scripts/generate_work_intent_vectors.py` reproduces the
shared positive and negative cases, including exact nanosecond boundaries,
permutation controls for conflicting policies, and current extension-applicability
controls. These document checks do not establish runtime enforcement behavior.
