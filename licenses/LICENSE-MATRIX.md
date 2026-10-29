# ECL-1 license matrix

This matrix gives the license of each class of files of ECL-1. It is not legal
advice; the license texts govern ([`../LICENSING.md`](../LICENSING.md)).

Copyright 2026 G-14, Inc. ECL-1 is maintained by G-14, Inc.

The rules apply in order, and the first rule whose paths match a file decides
its class. [`license-map.json`](license-map.json) states the same rules for
tools.

| Class | Paths | License (SPDX) | Text |
| --- | --- | --- | --- |
| NIST ACVP-derived fixture | `conformance/vectors/integrity/mldsa65-nist-acvp-sigver-tc123.json` | The source's terms (`NOASSERTION`), not relicensed | [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) |
| License texts | `LICENSE`, `LICENSE-CC-BY-4.0`, `packages/ecl-ts/LICENSE`, `packages/ecl-verify/LICENSE`, `go/crosscheck/LICENSE`, `governance/DCO.txt` | Each text's own terms (`NOASSERTION`), reproduced verbatim | Not applicable |
| Browser verifier script | `web/verifier/verifier.js` | `Apache-2.0 AND MIT`: the ECL-1 code under Apache-2.0, and the `@noble/curves` and `@noble/hashes` code it bundles under MIT, not relicensed | [`../LICENSE`](../LICENSE), and the MIT notice inside the file |
| Verifier code | `packages/ecl-ts/**`, `packages/ecl-verify/**`, `go/crosscheck/**`, `web/**` | `Apache-2.0` | [`../LICENSE`](../LICENSE) |
| Text and documentation | every Markdown file (`**/*.md`) and the rendered pages (`render/**`) | `CC-BY-4.0` | [`../LICENSE-CC-BY-4.0`](../LICENSE-CC-BY-4.0) |
| Machine-readable artifacts and code | every other file | `Apache-2.0` | [`../LICENSE`](../LICENSE) |

The verifier-code class names the verifier packages (the TypeScript package,
the Python package `packages/ecl-verify` and the Go module `go/crosscheck`) and
the browser verifier by path, so that each stays under Apache-2.0 as a whole,
its README included. The text-and-documentation class holds the standard
(`standard/`), the companion protocols and profiles (`protocols/*.md`,
`profiles/*.md`), the guides (`docs/`), the governance and community papers,
the rights papers and the top-level documents. The last class holds the
schemas, the registries, the conformance corpus, suites, vectors, fixtures and
manifests, the version set, the claim and deployment examples, the review and
registry templates, the community kit's configuration files, the formal models
of the design with their runner and recorded results (`formal/`) and the public
scripts. The documents beside them, such as `formal/README.md`, the implementer
report profile and the guide to the scenario adapters, are text and
documentation.

Some machine-readable artifacts reproduce text of the standard: the compiled
requirement registry and the requirement evaluation catalog quote each
requirement, and schema descriptions cite requirements. Those artifacts are
licensed as wholes under Apache-2.0, and the same text in the Markdown sources
under CC BY 4.0 ([`../LICENSING.md`](../LICENSING.md), "Requirement text in
two forms").

Some files hold material derived from G-14's Control Gap Record and Control
Gap Classification, which G-14 publishes under CC BY 4.0, and keep its
attribution ([`ATTRIBUTION.md`](ATTRIBUTION.md)). The binding profiles use
identifiers and short terms of the outside texts they bind to, each under its
own terms ([`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)).

## G-14's implementation

`license-map.json` also has a class for G-14's own implementation of ECL-1
and its tooling, which are not part of the standard and are not in its public
repository: "Proprietary. Copyright G-14, Inc. All rights reserved."
(`LicenseRef-G14-Proprietary`). It has one more third-party class, for the
CycloneDX validation schemas that the tooling keeps under their own Apache-2.0
license. No file of the public repository is in either class.

## Precedence

A third-party notice controls over this matrix for the material it covers. A
file whose terms are unknown or conflicting is `NOASSERTION`, never an
inferred grant. One file of ECL-1 carries a per-file license header: the
browser verifier's script, `web/verifier/verifier.js`, whose header states
its Apache-2.0 license and the patent pledge and carries the MIT notices of
the `@noble/curves` and `@noble/hashes` code bundled in it. No other file
carries a per-file license header; the notices of the other material of
others are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Patents and marks

Neither license is a patent pledge for the standard; the pledge is
[`../PATENTS.md`](../PATENTS.md). Neither grants rights in the name "ECL-1" or
in any mark ([`../governance/TRADEMARKS_AND_MARKS.md`](../governance/TRADEMARKS_AND_MARKS.md)).
