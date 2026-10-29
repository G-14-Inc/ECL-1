# ECL-1 conformance tests

This folder holds the conformance tests of ECL-1 Version 1.0 and their expected
results:

- positive and negative vectors, listed in `manifest.json` and in the manifest
  of each suite under `suites/`;
- `shared-corpus.json`, which names every vector and the capability it needs;
- the coverage denominator, `coverage-denominator.json`, which defines the
  units that the vectors cover and lists those it excludes;
- `binding-sources.json`, the revisions and digests of the outside texts that
  the binding profiles bind to;
- integrity, evidence-bundle and offline-package vectors;
- `fixtures/evidence/`, signed sample evidence bundles and the trust policy to
  verify them with;
- the assessment procedures, `requirement-evaluations.json`;
- the incident replay suite, `scenarios/`;
- the crosswalks to AARM and to the OWASP Agent Control Standard, `crosswalks/`;
- the conformance report template, `report-template-v2.json`.

A schema-valid object is not necessarily semantically conformant.

## Runner stages

Each vector names an artifact (`path`), a stage and an expected result. This
section is normative for every runner of the conformance tests and for every
implementation that reports against the shared corpus: a stage takes exactly
the input listed, makes its steps in order, stops where a step says so, and
reports the findings listed. A finding is a registered rule ID or error code.
At the `evidence-bundle` and `package` stages the result also has a verdict.

The steps that several stages share:

- **Parse.** Read the artifact's bytes as strict JSON (IE1-001, IE1-002), under
  the limits that the vector's `strict_json_limits` declares when it has them
  (IE1-028: the encoded bytes, the nesting depth counted from 0 for the
  top-level value, and the number of values), and otherwise under the
  implementation's own declared limits, which no other vector comes near. When
  they are not strict JSON, the only finding is the strict-input rule or error
  code that INTEGRITY-ENVELOPE-1 assigns to the failure, for example
  `ecl.rule.json-no-duplicate-members.v1` for a repeated member name or
  `ecl.rule.json-restricted-numbers.v1` for a number outside the restricted
  profile, and the stage stops.
- **Object.** A value that is not a JSON object gives `ecl.error.schema-invalid.v1`
  alone, and the stage stops.
- **Schema.** Validate the value under JSON Schema draft 2020-12 against the
  schema whose `$id` the vector's `schema` names, resolving references among
  the schemas in `../schemas/`. Any failure gives one
  `ecl.error.schema-invalid.v1`.
- **Rules for X.** Evaluate every active rule of
  `../registries/semantic-rules.json` whose `applies_to` names X; each rule that
  fails gives its rule ID once.

| Stage | Input | Steps, in order | Findings |
|---|---|---|---|
| `strict-json` | The artifact, and the vector's `strict_json_limits` when it has them. | Parse. | None, or the strict-input finding. |
| `canonical` | The artifact and the vector's `expected_canonical_sha256`. | Parse; canonicalize the value under RFC 8785 as IE1-001 to IE1-004 restrict it; when canonicalization succeeds, compare the SHA-256 of the canonical bytes with `expected_canonical_sha256`. A failing canonical vector has no canonical bytes and carries the SHA-256 of zero bytes, as the manifest schema requires. | `ecl.error.canonicalization-mismatch.v1` when they differ. |
| `protocol` | A DCMP-2 message, EBMP-2 record or adapter binding, and the vector's `schema`. | Parse; Object; Schema; Rules for the object's `protocol` (`DCMP-2` or `EBMP-2`), for `ECL-IE-1` (the integrity policy it carries) and, for an adapter binding, for `ECL adapter binding`. The rules are evaluated whatever the Schema step found. | `ecl.error.schema-invalid.v1` when Schema fails, and every rule finding. |
| `semantic` | As `protocol`. | As `protocol`. | As `protocol`. The two stages make the same checks; the manifests use both names. |
| `safe-state-profile` | A safe-state profile document and the vector's `schema`. | Parse; Object; Schema; Rules for `SAFE-STATE-PROFILE`, whatever Schema found. | As `protocol`. |
| `document` | A claim or assessment document or a work intent, and the vector's `schema`. | Parse; Object; Schema; Rules for the document's `protocol` member (`ECL-WI-1` for a work intent) and for the vector's `schema` (`ecl.rule.register-declarations-consistent.v1` for an action register), whatever Schema found. | As `protocol`. |
| `binding` | A binding record, the vector's `schema` and, for the OpenTelemetry suite, the export keys that the manifest's `export_keys_path` names (OE1-010). | Parse; Object; Schema, and stop when it fails; Rules for the `$id` of the record's schema and, for an AARM, ACS or MCP exchange record, `ecl.rule.decision-basis-one-way.v1` on each decision response that the record holds (for an MCP record, that of a decision whose `status` is `answered`), with the response's outcome and `evaluated_at` and the decision request that the record pairs with it, and the semantic rules of DCMP-2 on each DCMP-2 message that the record holds, other than the response of an MCP decision whose `status` is `invalid` (AB1-013, AC1-012, MG1-007). | `ecl.error.schema-invalid.v1` alone, or every rule finding. |
| `envelope` | An ECL-IE-1 envelope, the vector's `schema` and the suite's trust policy (the manifest's `trust_policy_path`). | Parse; Object; Schema, and stop when it fails; decode the payload as canonical JSON; take the payload's own time, `issued_at` for DCMP-2 and `observed_at` otherwise (`ecl.error.schema-invalid.v1` when it has none); verify the envelope under the suite's trust policy at that time, with the verification-time policy `ecl.time.issued-at.v1` or `ecl.time.observed-at.v1` (IE1-023). | None, or the error code that INTEGRITY-ENVELOPE-1 assigns to the first verification check that fails. |
| `trust-policy` | The artifact. The vector's `schema` names `trust-policy/1` and is not otherwise read. | Load the bytes as a trust policy (TRUST-POLICY-1): at most 262,144 bytes of strict JSON, then `trust-policy/1`, then the profile's conditions on keys, roles and revocations. | None, or the one error code that TRUST-POLICY-1 assigns to the first layer that fails. |
| `bundle` | An object whose `records` member holds EBMP-2 records offered as one complete bundle (`https://externalcontrollayer.ai/ns/schema/conformance-bundle-input/1`). | Parse; a value that is not an object with a `records` array gives `ecl.error.schema-invalid.v1` alone; analyse the records as one causal graph by the Rules for `EBMP-2 bundle`: unique object identifiers, predecessor digests, increasing `workflow.sequence` along each edge within a workflow, no cycle, and valid execution-state transitions within each attempt (the execution events with one `action_id` and `attempt_id`, ordered by `workflow.sequence` and then `object_id`). No predecessor outside the records is allowed. | Every rule finding, with `ecl.error.schema-invalid.v1` for a record that is not an object or whose `workflow`, `sequence`, causal predecessors or execution event is malformed, and `ecl.error.resource-limit-exceeded.v1` beyond 1,000,000 records or 128 predecessors of one record (EBMP2-062). When there is no finding and a predecessor is unresolved or an attempt has not reached a terminal state, `ecl.error.causal-closure-incomplete.v1`. The records are not validated against the EBMP-2 schema at this stage. |
| `evidence-bundle` | A signed evidence bundle (EBMP-2 section 11) and the vector's `trust_policy_path`, `trust_policy_history_paths`, `evaluated_at`, and optional `require_trusted_time`, `register_path` and `accept_current_trust_failure`. | Parse; verify the bundle under the trust policy that `trust_policy_path` names, the earlier versions that `trust_policy_history_paths` names and the evaluation time `evaluated_at`, as EBMP2-057 to EBMP2-062 require, in the order of checks of EBMP2-068; require trusted time when `require_trusted_time` is true (IE1-035); require every decision response to carry `ecl.ext.decision-basis.v1` (DCMP2-053); refuse a decision basis that records as `verifiable` an input whose source is the request's actor (DCMP2-053); and when `register_path` names a Consequential Action Register, refuse it as a usage error when it fails its schema or `ecl.rule.register-declarations-consistent.v1`, and otherwise check each decision basis against it (DCMP2-053); and accept current trust failures for the run when `accept_current_trust_failure` is true, which changes a `current-trust-failed` verdict to `verified` and no other (EBMP2-060). | The verdict of EBMP2-060 and the findings in the order of EBMP2-068, the first being the primary finding. For `invalid`, the codes of the bundle's findings; for `incomplete`, those codes, or `ecl.error.causal-closure-incomplete.v1` when there is none; for `current-trust-failed`, the current status of each trust dependency that is not valid (TRUST-POLICY-1 TP1-006), in the order of stage 4 of EBMP2-068. |
| `package` | An offline package, an `ecl.zip.store.v1` archive read as bytes and never parsed as JSON, and the same caller inputs as `evidence-bundle`. | The checks of IE1-022, in order, under the corpus's declared package limits (IE1-028): 1,073,741,824 archive bytes, 100,000 members or artifacts, 536,870,912 bytes per member and 4,294,967,296 in all, a compression ratio of 1,000 and 4,096 bytes per path; its bundle is verified as at the `evidence-bundle` stage, under the same inputs. | The verdict that IE1-022 gives and the package's findings in order, the first being the primary finding: the code of the first check of IE1-022 that fails, or the bundle's findings as at the `evidence-bundle` stage; for `current-trust-failed`, also the current status of each trust dependency that is not valid. |

From the findings of a vector a runner selects one primary finding: a
strict-input rule (the one with the lowest `precedence` value), otherwise
`ecl.error.schema-invalid.v1`, otherwise the stage's one other error code,
otherwise the registered rule with the lowest `precedence` value. A stage that
would report two error codes other than `ecl.error.schema-invalid.v1` for one
vector is a defect of that vector. The other findings are secondary. At the
`evidence-bundle` and `package` stages the primary finding is instead the first
finding in the order that EBMP2-068 gives (after the checks of IE1-022 for a
package), and a signed bundle has no required secondary findings, so its vector
lists none. A passing vector expects no finding; a failing vector expects its
`expected_primary_id` and its `expected_secondary_ids`; an `evidence-bundle` or
`package` vector also expects its `expected_verdict`. An `evidence-bundle` vector
may also carry `expected_scope`, the scope that EBMP2-076 requires with its
verdict, which a runner compares exactly: `established` and `not_established`
as lists in the order of the scope table, and `reasons` as a map from each item
to the reason the table names for it; and `expected_effects`, the evidence level
of EBMP2-061 for the terminal effect of each listed action, which a runner
compares for each listed action and which may appear on a row whose verdict is
`invalid`. A vector whose `expected_verdict` is `incomplete` may name
`expected_unresolved_predecessor_ids`: the identifiers that the report must list
in `unresolved_predecessor_ids` (EBMP2-076), compared as a set; an empty list
means that the report lists none.

The verification-time policy of each stage that verifies signatures is fixed
for the corpus, and a conformance report states it in its `time_policies`
member (IE1-023): `envelope` verifies each envelope at its payload's own time,
under `ecl.time.issued-at.v1` for a DCMP-2 payload and `ecl.time.observed-at.v1`
for an EBMP-2 payload; `evidence-bundle` and `package` verify under
`ecl.verification-profile.reference.v1`, or under
`ecl.verification-profile.reference-trusted-time.v1` when the vector sets
`require_trusted_time`.

## Coverage

Every measured unit of the published coverage denominator
(`coverage-denominator.json`) has a passing and a failing vector, as ECL1N-0058
requires for `L2` and above: each branch of the wire, extension-value, claim and
assessment document schemas and each active semantic rule. The denominator
states how units are counted (`unit_rules`) and lists the schemas and the units
it excludes, each with its reason (`excluded_schemas`, `unit_exclusions`). It
counts wire units, not runtime behavior: how an enforcement point or a verifier
behaves when it runs is shown by the deployment's own tests, which an assessor
examines by the procedures in `requirement-evaluations.json`.

The `document-coverage` suite evaluates the action register, conformance claim,
assessment package, mapping packet, deployment profile, evidence lifecycle
policy, offline verification package and work intent at the `document` stage:
strict parsing, then the schema the vector names, then, for a work intent, the
registered extension rules whose `applies_to` names ECL-WI-1. Its passing
vectors are the published examples in `../profiles/examples/`, or authored
documents where none is published, and each failing vector changes one of them
in one place. A document vector shows that a document has the form its schema
requires; it does not show that the deployment the document describes has the
declared properties. Shared-corpus runners evaluate these vectors under the
optional `document-validation` capability, and a document vector that a
registered rule refuses under `document-extension-rules`; the TypeScript
library in `../packages/ecl-ts/` implements both (`evaluateDocument`).

## Incident replay suite

`scenarios/` holds the ECL incident replay suite: 10 scenarios derived from the
Control Gap Record, version 0.2, © 2026 G-14, Inc.,
https://externalcontrollayer.ai, licensed under CC BY 4.0
(https://creativecommons.org/licenses/by/4.0/), each a deployment, a timed
sequence of agent proposals and external events, the outcome each step must
have and the requirements each step tests. A replay checks the decision basis
of every decision response, accepts `hold` or `challenge` wherever ECL1N-0177
allows either, and requires each admit that ECL1N-0165 covers to rest on a fact
from a system of record, an independent state witness or an authenticated
external party. [scenarios/README.md](scenarios/README.md) describes the format
and what a replay checks. This package holds the scenarios and their schema; it
does not hold a runner. A scenario is not a vector: a passing scenario shows how
a deployment configured as declared behaves on the replayed steps, and the
requirement evaluation classes below do not count it.

## How each requirement is evaluated

`requirement-evaluations.json` gives every compiled requirement exactly one
evaluation class, with the method, the procedure, the evidence obligations and
the pass and fail criteria that an assessor applies:

- **vector-tested**: a failing vector in a manifest negates the requirement,
  and a runner refuses it with the expected primary result. Any implementation
  can be checked against the same vector.
- **reference-tested**: the maintainer's own implementation has tests for the
  requirement, which fail when its behavior regresses. They are not part of
  this package; another implementation needs equivalent tests of its own, and
  an assessor applies the entry's procedure.
- **assessor-procedure**: only an assessor's examination of the claimant's
  evidence, by the stated procedure, can establish the requirement.
- **self-declaration**: the claimant's own declaration establishes the
  requirement, and an assessor checks that it is present, complete and
  consistent.

Each identifier in `evaluation_refs` and `traceability_refs` begins with
`conformance.vector:` and names a vector of this folder: in `evaluation_refs`
a vector that negates the requirement, and in `traceability_refs` one that
cites it without negating it, which traces the requirement and is not an
evaluation. A reference-tested entry lists no vector in `evaluation_refs`. An entry's procedure, evidence
obligations and criteria come from the groups that its `implementation_groups`
member names, each a set of requirements that are assessed together.

## External-framework mappings

The [crosswalk to AARM and ACS-Core](../docs/crosswalk.md) and its packets in
`crosswalks/` identify cited ECL support, evidence and residual obligations.
They are technical mappings, with explicit no-conformance, no-endorsement and
no-automatic-legal-compliance boundaries.

## Recording a run and claiming conformance

An implementer that runs the conformance tests against its component records the
run in the conformance report template,
[report-template-v2.json](report-template-v2.json), whose form the schema
[ecl-cross-implementation-report-v2.schema.json](../schemas/ecl-cross-implementation-report-v2.schema.json)
defines: the implementation's identity and source revision, the corpus it ran,
the capabilities it declares, one result for each vector of the shared corpus,
the time policies above and the raw evidence that each result rests on. The
template is a schema-valid skeleton in the `not_run` state, with example
identities and all-zero digest placeholders; it is never a result. With the
report goes the offline verifier's output on the implementation's own
evidence, from the [browser verifier](../web/verifier/README.md) or from
`ecl-verify-ts` in the [TypeScript package](../packages/ecl-ts/README.md), run
under a trust policy that the verifier's caller supplies and never one taken
from the evidence.

A conformance claim made with that report is self-declared. The implementer
submits it to the implementers registry by the process in
[governance/CONFORMANCE_CLAIMS.md](../governance/CONFORMANCE_CLAIMS.md); the editors check that the submission is
complete and list it as self-declared. G-14 certifies nothing. An assessor's
assessment is listed separately when the implementer provides one. The claim
names the version, the level and the claim boundary, as Section 7.7 of the
[standard](../standard/ECL-1_Standard.md) requires.
