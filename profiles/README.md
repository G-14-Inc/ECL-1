# ECL-1 profiles and compatibility mappings

Profiles tighten the core for a declared deployment or assurance context. They
may add requirements and prohibit optional behavior; they may not weaken core
requirements while claiming the same conformance scope.

## Informative guides

These carry no requirement IDs; the obligations they describe are compiled from
the documents they cite.

- `DEPLOYMENT-PROFILES-1.md` describes the hosted, federated, sovereign,
  offline-edge, and air-gapped topology controls of the core standard.
- `OFFLINE-VERIFICATION-1.md` describes the offline package: one signed
  evidence bundle and the material its producer verified it with, in the
  canonical `ecl.zip.store.v1` container, verified under the caller's trust
  policy as IE1-021 and IE1-022 of `INTEGRITY-ENVELOPE-1` require.
- `CONFORMANCE-CLAIMS-1.md` describes the claim grammar and assessment
  boundaries of the core standard.

## Normative profiles

Each of these has compiled requirement IDs and its own version.

- `TRUST-POLICY-1.md` binds caller-supplied policy versions, key roles, principals, revocation and byte-loading limits. Its vectors are in the `trust-policy`, `key-roles`, `envelope` and `evidence-bundle` suites of `conformance/suites/`.
- `STRICT-FAILURE-1.md` forbids fail-open dispositions for in-scope action classes and requires that required proof fail closed; a safe-state profile document claims it in its `claimed_profiles` member.
- `DCMP2-HTTP-1.md` binds HTTPS framing, bearer principals, limits, signed outcomes and failure classes.
- `TRANSACTIONAL-EFFECT-1.md` binds transaction, time, privilege and evidence obligations with the CE catalog.
- `AUTHZEN-BINDING-1.md` binds the extra policy check, strict response mapping and native ECL responsibilities.

## Binding profiles

The binding profiles state how ECL-1 works with other systems. Each has a vector
suite in `conformance/suites/`, and [the bindings guide](../docs/bindings.md)
explains them in plain language.

- `AARM-BINDING-1.md` maps AARM decisions to ECL outcomes, binds AARM receipts to EBMP-2 evidence and treats AARM's context, intent and semantic-distance outputs as `judgment` inputs.
- `ACS-BINDING-1.md` maps Agent Control Standard dispositions and failure postures to ECL outcomes and keeps the ACS session chain beside the ECL evidence.
- `MCP-GATEWAY-1.md` places an ECL enforcement point, the gateway, in front of MCP servers and fixes the order in which it releases a call.
- `OTEL-EVIDENCE-EXPORT-1.md` copies ECL decisions and evidence into OpenTelemetry log records, outside the decision and enforcement path.
- `OAUTH-AUTHORITY-1.md` expresses one ECL `admit` as one sender-constrained OAuth access token.

## Compatibility profiles outside this repository

Implementation-specific compatibility profiles are maintained by their
implementers outside this repository. They are informative and cannot make
implementation-private semantics normative ECL behavior.
