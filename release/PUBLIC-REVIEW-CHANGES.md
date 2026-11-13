# Changes in the Version 1 public-review draft

Robert F. Tilley Jr. and G-14, Inc.

This change log identifies source build `1.0.2-review.1`, frozen at
[`v1.0.2-review.1`](https://github.com/G-14-Inc/ECL-1/tree/v1.0.2-review.1).
It compares the draft with the earlier published source `v1.0.1`. The
[review announcement](../PUBLIC-REVIEW.md) identifies the review dates and
exact package digests.

## Contract and implementation changes

- Admitting evaluation must precede request expiry; equality is expired.
  Refusal evidence may record evaluation at or after expiry. A validly issued
  authorization can outlive the request within its applicable bounds.
- Continuation histories distinguish an admitted continuation followed by
  refused reuse from two admitted uses of the same challenge. The
  [design guide](../docs/review-design-decisions.md) states the checks and scope.
- The draft supports single-use authority. `bounded_multi_use` is reserved and
  rejected until a complete per-use evidence contract is specified. The
  [migration guide](../docs/single-use-authorization-migration.md) identifies
  the affected interfaces and producer obligations.
- The verifier and helper interfaces have corresponding migration guidance:
  [evidence verification](../docs/evidence-verification-api-changes.md),
  [core contracts](../docs/core-contract-api-migration.md),
  [declaration validation](../docs/declaration-validation-migration.md),
  [claim helpers](../docs/claim-helper-api-migration.md),
  [work intent and safe states](../docs/work-intent-and-safe-state-migration.md),
  and [lifecycle policy](../docs/lifecycle-policy-migration.md).
- The current formal models and recorded results cover additional continuation,
  recovery, freshness and compromised-key cases. The
  [formal guide](../formal/README.md) gives each check's input, expected outcome,
  bounds and assumptions. There are 58 TLC checks and 12 Tamarin checks.
- The [shared corpus](../conformance/shared-corpus.json) contains 1,416 vectors.
  The [conformance guide](../conformance/README.md) distinguishes verifier
  capabilities and the evidence each result supplies.
- The corpus reader handles Windows path and file-handle timestamps without
  falsely rejecting unchanged files. Fixture generators use portable manifest
  paths, and test fixtures use explicit text encodings and native executable
  paths across the supported hosts.
- The reference edition brings together 98 Markdown documents and formal
  source listings in a 713-page PDF. The reviewed PDF and source archive are
  identified by the digests in the review announcement.

## Exact requirement-text changes

All 628 requirement identifiers are retained. Compared with `v1.0.1`,
**136 compiled requirement texts differ**. No identifier is introduced or
removed, and no requirement status changes in this comparison.
The [machine-readable comparison](PUBLIC-REVIEW-REQUIREMENT-CHANGES.json)
contains the exact before/after text, source location and text digests.
This count concerns requirement text; it does not count explanatory, schema,
verifier, test or model changes as requirement changes.

| Requirement | Current source |
|---|---|
| `AB1-002` | [profiles/AARM-BINDING-1.md](../profiles/AARM-BINDING-1.md) |
| `AB1-007` | [profiles/AARM-BINDING-1.md](../profiles/AARM-BINDING-1.md) |
| `AC1-003` | [profiles/ACS-BINDING-1.md](../profiles/ACS-BINDING-1.md) |
| `AC1-004` | [profiles/ACS-BINDING-1.md](../profiles/ACS-BINDING-1.md) |
| `AC1-005` | [profiles/ACS-BINDING-1.md](../profiles/ACS-BINDING-1.md) |
| `AC1-006` | [profiles/ACS-BINDING-1.md](../profiles/ACS-BINDING-1.md) |
| `AC1-008` | [profiles/ACS-BINDING-1.md](../profiles/ACS-BINDING-1.md) |
| `AC1-010` | [profiles/ACS-BINDING-1.md](../profiles/ACS-BINDING-1.md) |
| `AZB1-006` | [profiles/AUTHZEN-BINDING-1.md](../profiles/AUTHZEN-BINDING-1.md) |
| `DCMP2-013` | [protocols/DCMP-2.md](../protocols/DCMP-2.md) |
| `DCMP2-047` | [protocols/DCMP-2.md](../protocols/DCMP-2.md) |
| `DCMP2-049` | [protocols/DCMP-2.md](../protocols/DCMP-2.md) |
| `DCMP2-050` | [protocols/DCMP-2.md](../protocols/DCMP-2.md) |
| `DCMP2-053` | [protocols/DCMP-2.md](../protocols/DCMP-2.md) |
| `DCMP2-056` | [protocols/DCMP-2.md](../protocols/DCMP-2.md) |
| `DW1-002` | [protocols/DISTRIBUTED-WORKFLOW-1.md](../protocols/DISTRIBUTED-WORKFLOW-1.md) |
| `DW1-006` | [protocols/DISTRIBUTED-WORKFLOW-1.md](../protocols/DISTRIBUTED-WORKFLOW-1.md) |
| `DW1-015` | [protocols/DISTRIBUTED-WORKFLOW-1.md](../protocols/DISTRIBUTED-WORKFLOW-1.md) |
| `EBMP2-008` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-046` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-047` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-050` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-055` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-065` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-067` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-068` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-069` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-070` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-073` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-074` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-075` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-076` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-077` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `EBMP2-078` | [protocols/EBMP-2.md](../protocols/EBMP-2.md) |
| `ECL1N-0001` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0004` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0005` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0007` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0009` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0010` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0016` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0017` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0022` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0024` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0029` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0039` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0040` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0042` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0043` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0047` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0048` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0050` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0052` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0053` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0055` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0056` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0071` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0073` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0077` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0078` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0087` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0089` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0091` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0092` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0094` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0096` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0097` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0098` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0101` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0109` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0110` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0116` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0124` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0125` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0127` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0136` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0142` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0146` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0147` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0151` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0152` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0153` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0154` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0174` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0177` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0178` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0181` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0186` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `ECL1N-0191` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `EL1-002` | [protocols/EVIDENCE-LIFECYCLE-1.md](../protocols/EVIDENCE-LIFECYCLE-1.md) |
| `EL1-007` | [protocols/EVIDENCE-LIFECYCLE-1.md](../protocols/EVIDENCE-LIFECYCLE-1.md) |
| `FR-104` | [standard/ECL-1_Standard.md](../standard/ECL-1_Standard.md) |
| `IE1-003` | [protocols/INTEGRITY-ENVELOPE-1.md](../protocols/INTEGRITY-ENVELOPE-1.md) |
| `IE1-011` | [protocols/INTEGRITY-ENVELOPE-1.md](../protocols/INTEGRITY-ENVELOPE-1.md) |
| `IE1-013` | [protocols/INTEGRITY-ENVELOPE-1.md](../protocols/INTEGRITY-ENVELOPE-1.md) |
| `IE1-022` | [protocols/INTEGRITY-ENVELOPE-1.md](../protocols/INTEGRITY-ENVELOPE-1.md) |
| `IE1-023` | [protocols/INTEGRITY-ENVELOPE-1.md](../protocols/INTEGRITY-ENVELOPE-1.md) |
| `IE1-037` | [protocols/INTEGRITY-ENVELOPE-1.md](../protocols/INTEGRITY-ENVELOPE-1.md) |
| `IE1-038` | [protocols/INTEGRITY-ENVELOPE-1.md](../protocols/INTEGRITY-ENVELOPE-1.md) |
| `IE1-039` | [protocols/INTEGRITY-ENVELOPE-1.md](../protocols/INTEGRITY-ENVELOPE-1.md) |
| `IE1-040` | [protocols/INTEGRITY-ENVELOPE-1.md](../protocols/INTEGRITY-ENVELOPE-1.md) |
| `MG1-002` | [profiles/MCP-GATEWAY-1.md](../profiles/MCP-GATEWAY-1.md) |
| `MG1-005` | [profiles/MCP-GATEWAY-1.md](../profiles/MCP-GATEWAY-1.md) |
| `MG1-006` | [profiles/MCP-GATEWAY-1.md](../profiles/MCP-GATEWAY-1.md) |
| `MG1-007` | [profiles/MCP-GATEWAY-1.md](../profiles/MCP-GATEWAY-1.md) |
| `MG1-008` | [profiles/MCP-GATEWAY-1.md](../profiles/MCP-GATEWAY-1.md) |
| `MG1-010` | [profiles/MCP-GATEWAY-1.md](../profiles/MCP-GATEWAY-1.md) |
| `MG1-013` | [profiles/MCP-GATEWAY-1.md](../profiles/MCP-GATEWAY-1.md) |
| `MG1-014` | [profiles/MCP-GATEWAY-1.md](../profiles/MCP-GATEWAY-1.md) |
| `MG1-015` | [profiles/MCP-GATEWAY-1.md](../profiles/MCP-GATEWAY-1.md) |
| `OA1-001` | [profiles/OAUTH-AUTHORITY-1.md](../profiles/OAUTH-AUTHORITY-1.md) |
| `OA1-003` | [profiles/OAUTH-AUTHORITY-1.md](../profiles/OAUTH-AUTHORITY-1.md) |
| `OA1-004` | [profiles/OAUTH-AUTHORITY-1.md](../profiles/OAUTH-AUTHORITY-1.md) |
| `OA1-005` | [profiles/OAUTH-AUTHORITY-1.md](../profiles/OAUTH-AUTHORITY-1.md) |
| `OA1-006` | [profiles/OAUTH-AUTHORITY-1.md](../profiles/OAUTH-AUTHORITY-1.md) |
| `OA1-007` | [profiles/OAUTH-AUTHORITY-1.md](../profiles/OAUTH-AUTHORITY-1.md) |
| `OA1-008` | [profiles/OAUTH-AUTHORITY-1.md](../profiles/OAUTH-AUTHORITY-1.md) |
| `OA1-011` | [profiles/OAUTH-AUTHORITY-1.md](../profiles/OAUTH-AUTHORITY-1.md) |
| `OE1-003` | [profiles/OTEL-EVIDENCE-EXPORT-1.md](../profiles/OTEL-EVIDENCE-EXPORT-1.md) |
| `OE1-004` | [profiles/OTEL-EVIDENCE-EXPORT-1.md](../profiles/OTEL-EVIDENCE-EXPORT-1.md) |
| `OE1-008` | [profiles/OTEL-EVIDENCE-EXPORT-1.md](../profiles/OTEL-EVIDENCE-EXPORT-1.md) |
| `OE1-009` | [profiles/OTEL-EVIDENCE-EXPORT-1.md](../profiles/OTEL-EVIDENCE-EXPORT-1.md) |
| `OE1-010` | [profiles/OTEL-EVIDENCE-EXPORT-1.md](../profiles/OTEL-EVIDENCE-EXPORT-1.md) |
| `SF1-004` | [profiles/STRICT-FAILURE-1.md](../profiles/STRICT-FAILURE-1.md) |
| `TE1-003` | [profiles/TRANSACTIONAL-EFFECT-1.md](../profiles/TRANSACTIONAL-EFFECT-1.md) |
| `TE1-008` | [profiles/TRANSACTIONAL-EFFECT-1.md](../profiles/TRANSACTIONAL-EFFECT-1.md) |
| `TE1-010` | [profiles/TRANSACTIONAL-EFFECT-1.md](../profiles/TRANSACTIONAL-EFFECT-1.md) |
| `TE1-011` | [profiles/TRANSACTIONAL-EFFECT-1.md](../profiles/TRANSACTIONAL-EFFECT-1.md) |
| `TP1-003` | [profiles/TRUST-POLICY-1.md](../profiles/TRUST-POLICY-1.md) |
| `TS1-013` | [protocols/TIMING-SAFE-STATE-1.md](../protocols/TIMING-SAFE-STATE-1.md) |
| `TS1-016` | [protocols/TIMING-SAFE-STATE-1.md](../protocols/TIMING-SAFE-STATE-1.md) |
| `TS1-031` | [protocols/TIMING-SAFE-STATE-1.md](../protocols/TIMING-SAFE-STATE-1.md) |
| `TS1-033` | [protocols/TIMING-SAFE-STATE-1.md](../protocols/TIMING-SAFE-STATE-1.md) |
| `XR1-006` | [protocols/EXTENSION-REGISTRY-1.md](../protocols/EXTENSION-REGISTRY-1.md) |
| `XR1-007` | [protocols/EXTENSION-REGISTRY-1.md](../protocols/EXTENSION-REGISTRY-1.md) |
| `XR1-017` | [protocols/EXTENSION-REGISTRY-1.md](../protocols/EXTENSION-REGISTRY-1.md) |

## Earlier publications

The [earlier change log](../CHANGELOG.md),
[release notes](../RELEASE-NOTES-1.0.md) and archived releases retain their
original history. The source files frozen for this review remain unchanged
throughout the comment period under the
[public-review procedure](../governance/PUBLIC_REVIEW.md).
