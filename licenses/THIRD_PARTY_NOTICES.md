# Third-party and externally sourced material

This file lists the material of others in the ECL-1 repository and its terms.
G-14, Inc. does not relicense any material listed here: each item keeps its
own terms, whatever the licenses of ECL-1 say for the rest
([`../LICENSING.md`](../LICENSING.md)). The attributions that every copy keeps
are listed in [`ATTRIBUTION.md`](ATTRIBUTION.md). Nothing here is legal
advice.

## NIST ACVP ML-DSA-65 fixture

File:
`conformance/vectors/integrity/mldsa65-nist-acvp-sigver-tc123.json`

The fixture is a bounded extraction from the official `usnistgov/ACVP-Server`
ML-DSA signature-verification prompt and expected-results data:

- repository: <https://github.com/usnistgov/ACVP-Server>, commit
  `2972def23bf9f3680c2c531561ed9bdd0f1086ad` (2026-07-20). NIST replaced both
  files on 2026-07-31 (commit `a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324`),
  and test case 123 of group 9 has other values there.
- prompt path:
  `gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json`
- prompt SHA-256:
  `aeba1135e5dbda1681369cc7a7598c3d53e492d1c9881098556ba4dbe067b376`
- expected-results path:
  `gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json`
- expected-results SHA-256:
  `99c5b82abf37bdf6f7bd11c6976e4d8007d70f9953dc13566232404647865bb8`
- source group: 9
- source test case: 123

NIST's replacement, made "for issue with ModifyZ disposition", generated
every case of the two files again: in the files of 2026-07-20, five of the 36
cases that modify a signature's `z` were refused for a malformed hint rather
than for their `z`. The fixture's case is a valid signature in those files,
and its bytes still verify.

G-14 does not claim authorship of the source vector and does not relicense it;
the source's terms apply (`NOASSERTION` in the license map).

## Control Gap Classification and Control Gap Record

These files are derived from material that G-14, Inc. publishes under the
Creative Commons Attribution 4.0 International license
(<https://creativecommons.org/licenses/by/4.0/>):

- `conformance/scenarios/record-*.json`, the ten scenarios of the incident
  replay suite. Each is derived from one entry of the Control Gap Record,
  version 0.2, © 2026 G-14, Inc., <https://externalcontrollayer.ai>; its
  `source.credit` names the entry and its URL and states the adaptation, and
  its `abstraction` and its steps marked `added` say what was changed.
- `registries/gap-coverage.json` and the gap annex generated from it,
  `docs/gap-coverage.md`. They reproduce the thirteen gap definitions of the
  Control Gap Classification, version 0.2, © 2026 G-14, Inc.,
  <https://externalcontrollayer.ai/classification>, five of them adapted as the
  annex states, and the titles and gap codes of the Record's entries. The
  annex gives the attribution.

G-14, Inc. is the licensor of the Record, of the Classification and of ECL-1.
The derived files take the license of their class in
[`LICENSE-MATRIX.md`](LICENSE-MATRIX.md), and each keeps the attribution that
the source's license asks for.

## Binding profile sources

The binding profiles bind to external texts by revision and SHA-256
(`conformance/binding-sources.json`, and the pinned-sources table of each
profile). The repository does not contain those texts; the profiles, their
schemas and vectors use the identifiers, field names, values and short terms of
each source that interoperation needs. Each source is under its own terms, as
it states them at the pinned revision:

- AARM (AARM-BINDING-1): the README of `aarm-dev/aarm` at
  `c1f9b27cef60f7035cc8d854b0ae6d1ea9781680` states that the specification text
  is licensed under CC BY 4.0 and the website source under the MIT License, and
  that revision has no license file; `aarm-dev/docs` at
  `5bd02fdb5d5f6483a16a42539e38cfe8743c3a97` and
  `8eff208b98786b2c9a578b26cb7eaca440ec4020` carries the MIT License
  (`LICENSE.txt`, whose copyright line names Mintlify, 2023), and its README
  states that the specification is published under the MIT License.
- Agent Control Standard (ACS-BINDING-1): `LICENSING.md` of
  `GenAI-Security-Project/agent-control-standard` at
  `7743826b2ec02e3daf47a08c82170fc7a43b0838` (tag `v0.1.2`) assigns `docs/**`,
  which holds the pinned specification, conformance and hooks pages, to
  CC BY-SA 4.0, and `specification/**`, which holds the pinned JSON schemas, to
  the Apache License 2.0; code samples in its Markdown are Apache-2.0.
- Model Context Protocol (MCP-GATEWAY-1): the `LICENSE` of
  `modelcontextprotocol/modelcontextprotocol` at
  `5f5440bb26a62e2cf3440b92da5a667efa03b267` licenses code and specification
  contributions under the Apache License 2.0, documentation other than
  specifications under CC BY 4.0, and earlier contributions whose authors have
  not agreed to relicense under the MIT License.
- OpenTelemetry (OTEL-EVIDENCE-EXPORT-1): `opentelemetry-specification` at
  `32c0b2c1d9e11f68da0e6e7b63044e57878590de`, `opentelemetry-proto` at
  `b3f75588eb23c5fca62264edd05d382de49beb1a` and `semantic-conventions` at
  `e10a930844c6951757a43b849d364f7d056ac32b` carry the Apache License 2.0, and
  so does `ocsf/ocsf-schema` 1.9.0, which the profile's informative OCSF note
  cites.
- IETF RFCs 7515, 7518, 7519, 7638, 7800, 8037, 8693, 8705, 8707, 8725, 8785,
  9068, 9396 and 9449 (OAUTH-AUTHORITY-1, MCP-GATEWAY-1): each is under the IETF
  Trust Legal Provisions that its copyright notice names (BCP 78).

## License texts

`LICENSE` and `packages/ecl-ts/LICENSE` hold the Apache License, Version 2.0,
and `LICENSE-CC-BY-4.0` holds the Creative Commons Attribution 4.0
International legal code. Each is reproduced unmodified, as its steward
publishes it, from the source that `license-map.json` names with its SHA-256
digest.

## Developer Certificate of Origin

`governance/DCO.txt` reproduces the Developer Certificate of Origin, Version
1.1, verbatim. It is Copyright (C) 2004, 2006 The Linux Foundation and its
contributors, and it may be copied and distributed in verbatim copies only, as
its own text says. Contributors certify it by signing off their commits
([`../governance/CONTRIBUTING.md`](../governance/CONTRIBUTING.md)).

## External specifications

The standard cites external specifications and official publications in its
Section 3 (normative references) and its Bibliography. A citation or short
identifier does not incorporate the cited work or its license. The external
framework crosswalks in `conformance/crosswalks/` record, for each mapped
source, the captured revision, digest and clause extraction in their packet
assumptions; they record clause identifiers and digests of the clause text, not
the text.

## JavaScript dependencies of the verifier

`packages/ecl-ts/package-lock.json` pins every version and integrity hash of the
TypeScript verifier's dependencies. Its runtime dependencies are `@noble/curves`
2.3.0 and `@noble/hashes` 2.3.0 (`MIT`, Copyright (c) 2022 Paul Miller). The
browser verifier's generated script, `web/verifier/verifier.js`, contains their
code and reproduces their full MIT license notice. The build and test tools are
`typescript` 6.0.3 (`Apache-2.0`), `esbuild` 0.28.2 with its platform binary
`@esbuild/linux-x64` 0.28.2 (`MIT`), `@types/node` 22.20.5 and `undici-types`
6.21.0 (`MIT`), and `playwright-core` 1.56.1 (`Apache-2.0`, with its own
third-party notices); they are installed from the lock file and are not part of
the repository. `packages/ecl-ts/.npmrc` stops dependency install scripts from
running. The browser tests drive a Chromium build that the repository does not
contain.
