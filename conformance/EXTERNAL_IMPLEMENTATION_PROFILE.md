# ECL-1 conformance report profile

Version: 2

Status: reporting profile of ECL-1 Version 1.0, for an implementer, an
assessor or an integrator who reports a run of the conformance tests. A report
under this profile qualifies nothing beyond the integrity of its binding.

This profile states everything an implementation needs, beside the corpus
itself, to produce a report that `scripts/verify_external_implementation_report.py`
accepts. The key words MUST and MUST NOT are used as in RFC 2119.

## What a report covers

A report covers one implementation, whoever runs it. It declares the
implementation's source revision, exact source-tree digest, runtime,
dependencies and authorship, and its organization, funding or control
relationships to G-14. The implementation consumes normative artifacts without
importing, calling, vendoring or translating the Python reference, which is
G-14's own implementation; a report of an implementation that does tests the
reference instead. A report by the operator of the implementation is that
operator's own test, not an independent assessment.

## Frozen input for each replay

`conformance/shared-corpus.json` version 1 names every vector of every v3
manifest and the one capability it requires. The report binds its exact digest
and the implementation's source revision; a changing working-tree file is not
the same frozen input. `conformance/README.md` states, for each runner stage,
its input, its steps in order and its findings.

The required capabilities are `strict-json`, `canonical-digest`,
`semantic-rules` and `safe-state-profile-rules`. The optional capabilities are
`schema-validation`, `trust-policy-load`, `envelope-signature-verification`,
`evidence-bundle-verification`, `control-extension-rules`,
`binding-profile-rules`, `decision-basis-rule`, `document-validation`,
`extension-version-rule`, `document-extension-rules`, `key-role-separation`,
`binding-basis-agreement-rule`, `otel-export-keyed-digests` and
`offline-package-verification`.

The capability of a vector is given by the first of these rules that applies to
it. The expected findings of a vector are its `expected_primary_id` and its
`expected_secondary_ids`; a passing vector has none.

1. A vector of the key-roles suite takes `key-role-separation`, one of the
   binding-basis suite `binding-basis-agreement-rule`, and one of the
   otel-export suite `otel-export-keyed-digests`.
2. A vector of the `document` stage whose expected findings include
   `ecl.rule.register-declarations-consistent.v1` takes `decision-basis-rule`,
   and any other vector of that stage whose expected findings include a
   registered rule (an identifier that starts with `ecl.rule.`) takes
   `document-extension-rules`.
3. A vector whose expected findings include
   `ecl.rule.extension-single-version.v1` takes `extension-version-rule`, and
   one whose expected findings include `ecl.rule.aarm-inputs-match-basis.v1` or
   `ecl.rule.acs-inputs-match-basis.v1` takes `binding-basis-agreement-rule`.
4. A vector of the `binding` stage takes `binding-profile-rules`, one of the
   `document` stage `document-validation`, one of the `evidence-bundle` stage
   `evidence-bundle-verification`, and one of the `package` stage
   `offline-package-verification`, because only a bundle verifier produces the
   verdict that an `evidence-bundle` or `package` vector names.
5. A vector of the `protocol` or `semantic` stage whose artifact carries the
   extension `ecl.ext.decision-basis.v1` takes `decision-basis-rule`.
6. A failing vector whose expected primary finding is
   `ecl.error.schema-invalid.v1` takes `schema-validation`, and one whose
   expected primary finding starts with `ecl.rule.json-` takes `strict-json`.
7. A vector of the control-extensions suite takes `control-extension-rules`, and
   one of the aarm-binding, acs-binding, mcp-gateway or oauth-authority suite
   takes `binding-profile-rules`.
8. Otherwise the vector takes the capability of its stage: `strict-json` for
   `strict-json`, `canonical-digest` for `canonical`, `semantic-rules` for
   `protocol`, `semantic` and `bundle`, `safe-state-profile-rules` for
   `safe-state-profile`, `trust-policy-load` for `trust-policy` and
   `envelope-signature-verification` for `envelope`.

An implementation that declares `evidence-bundle-verification` MUST also
declare `decision-basis-rule`, because a bundle verifier applies the one-way
rule of DCMP2-053 to the decision basis of every response it verifies, and the
register declarations rule to a register it is given. An implementation that
declares `binding-profile-rules` or `binding-basis-agreement-rule` MUST also
declare `decision-basis-rule`, because the AARM, ACS and MCP checkers apply the
same rule to the decision responses that an exchange record holds (AB1-013,
AC1-012, MG1-007). An
implementation that declares `offline-package-verification` MUST also declare
`evidence-bundle-verification`, because a package is verified as the evidence
bundle it carries (IE1-022).

An `evidence-bundle` or `package` vector also names the verdict that EBMP2-060
or IE1-022 requires; the reference runner compares it. No agreeing
intersection qualifies: every corpus vector has exactly one result. A missing
result, or an unsupported result for a required capability, is refused.

## Report

A report MUST validate against
`schemas/ecl-cross-implementation-report-v2.schema.json`. Its members, beside
the implementation's identity and capabilities:

- `suite.manifest_sha256` is the SHA-256, in lowercase hexadecimal, of the
  exact bytes of `conformance/shared-corpus.json`. The member keeps the name it
  had in report version 1, where it bound the RC-3 suite manifest.
  `suite.vector_count` is the number of vectors the corpus names, and
  `suite.corpus_version` its `version`.
- `time_policies` states the verification-time policies the implementation
  applied (IE1-023), stage by stage, and MUST name exactly the stages that its
  declared capabilities evaluate: `envelope` when it declares
  `envelope-signature-verification`, with the value
  `["ecl.time.issued-at.v1", "ecl.time.observed-at.v1"]`; `evidence-bundle`
  when it declares `evidence-bundle-verification`, and `package` when it
  declares `offline-package-verification`, each with the value
  `["ecl.verification-profile.reference-trusted-time.v1", "ecl.verification-profile.reference.v1"]`.
  `conformance/README.md` gives the meaning of each value. An implementation
  that declares none of these capabilities states `{}`.
- `vector_results` has one row for each corpus vector. A row's `status` is
  `met`, `not-met` or `unsupported`. A supported row has one primary
  identifier, or null when there are no findings, and distinct secondary
  identifiers; a null primary requires empty secondaries. An unsupported row
  names the optional capability it lacks in `unsupported_capability` and has
  no primary or secondary findings. `artifact_sha256` is the SHA-256 of the
  exact bytes of the vector's artifact.
- `decision` is `fail` when any vector the implementation evaluated is
  `not-met`, and `pass` otherwise, including when vectors of optional
  capabilities that the implementation does not declare are `unsupported`.
  `not_run` appears only in the unexecuted template
  (`conformance/report-template-v2.json`), which is never replay evidence.

For a failing vector, met means that the primary is exactly the manifest's
expected primary. For a passing vector, met means no findings. An
`evidence-bundle` or `package` vector expects as its primary the first finding
in the order of checks of EBMP2-068 (after the checks of IE1-022 for a
package) and lists no secondary finding, because a signed bundle has no
required secondary findings; a verifier that stops at the first failure meets
it (`conformance/README.md`, "Runner stages"). Secondary depth is recorded as
an implementation-reporting difference, not equated. The report keeps a `fail`
decision when any evaluated vector is not-met, even if a comparison disposition
explains it.

## Scope and evidence levels

Some `evidence-bundle` rows of the corpus name more than a verdict and findings. A row with
`expected_scope` gives the scope that the verifier reports under EBMP2-076: the items established
and the items not established, each list in the order of EBMP2-076's table, and the reason for
each item that the table gives one, as a map from item to reason. A row with `expected_effects`
gives, for each action it lists, the evidence level that EBMP2-061 requires the verifier to
report for that action's terminal effect. A row whose `expected_verdict` is `incomplete` may give
`expected_unresolved_predecessor_ids`: the identifiers of the predecessors that the report must
list in `unresolved_predecessor_ids` (EBMP2-076) because it could not resolve them; an empty list
means that the report lists none. A row with `accept_current_trust_failure` is verified with the
caller's current-trust waiver applied, as the row states. For such a row, an implementation's
result is compared on its scope, its evidence levels and its unresolved predecessors as well as on
its verdict and its findings: the two scope lists and the reasons are compared exactly, each
listed action's level must equal the row's, and the unresolved predecessor identifiers are
compared as a set. The row is `met` only when every one of these comparisons
holds, and `not-met` otherwise. `conformance/README.md` gives the stage contract: the inputs of
each `evidence-bundle` row, including the waiver, and the form of the comparison.

## Raw evidence

Each row of `vector_results` has its own raw result in an evidence file:

- A raw result MUST be a JSON object with exactly three members and MUST
  validate against `https://externalcontrollayer.ai/ns/schema/external-vector-raw-result/2`
  (`schemas/ecl-external-vector-raw-result-v2.schema.json`):
  `schema_version`, whose value is `ecl_external_vector_raw_result_v2`;
  `implementation_revision`, whose value is the report's
  `implementation.source_revision`; and `result`, whose value is the row with
  every member except `raw_result_sha256`, each with the row's value.
- The evidence file holds the raw result as any JSON text that strict parsing
  accepts (UTF-8 without a byte order mark, no repeated member name, integers
  only within the exact interoperable range). Member order, whitespace and
  escapes are free; the RFC 8785 form is one such text, not a requirement.
- The checker reads the report and each raw result through that strict parser,
  with its 64 MiB per-file byte limit, before schema validation. An input over
  the limit is refused without first being read in full.
- `raw_result_sha256` MUST be the SHA-256 of the evidence file's exact bytes,
  and the report's `evidence` list MUST name that file by its path relative to
  the evidence root and the same digest. No two rows share a raw result.

The source export has no symlinks or `.git` metadata. Its SHA-256 covers UTF-8
JSON with sorted keys and compact separators of the array of
`{path, size_bytes, sha256}` entries, sorted by the UTF-8 bytes of each path: code-point order, which
differs from UTF-16 order for some paths outside ASCII. The checker verifies the source, corpus,
artifact, raw-result and evidence digests, with no network use:

```bash
python3 scripts/verify_external_implementation_report.py report.json \
  --evidence-root <directory of the evidence files> \
  --implementation-root <clean export of the implementation source>
```

Each refusal names the member or vector at fault and what this profile
requires. `verified-report-integrity` verifies the report's binding; it does not
convert not-met or unsupported cases into passes.

## Comparison and reconciliation

A report is compared with the corpus vector by vector: each row with the
vector's expected primary finding, or with no finding for a passing vector. A
disagreement between a report and the corpus, or between two implementations,
is investigated against the normative artifacts, and no implementation wins by
default, the Python reference included. A disagreement that the text resolves
is a defect of the implementation that departs from it; one that the text does
not resolve is reported to the editors as a question about the text
(`governance/ERRATA.md`).

## Earlier report versions

This profile describes report version 2, against the shared corpus of
Version 1.0. The version 1 report and raw-result shapes of the frozen RC-3
candidate are not part of Version 1.0, and a version 1 report says nothing
about the corpus of Version 1.0.

A report supports a named corpus replay with stated unsupported cases and
findings. It qualifies nothing, and it does not imply certification, production
fitness, independent assessment, endorsement or universal interoperability.
