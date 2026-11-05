# Licensing

Copyright 2026 G-14, Inc.

ECL-1 is maintained by G-14, Inc. and published under two open licenses, with
a patent pledge for the claims that implementing it makes unavoidable. Nothing
in this file is legal advice; the license texts and the pledge govern.

## The licenses

- **Text and documentation: Creative Commons Attribution 4.0 International**
  (SPDX `CC-BY-4.0`). This covers the standard (`standard/`), the companion
  protocols and profiles (`protocols/`, `profiles/`), the guides (`docs/`),
  the governance and community papers (`governance/`, `community/`), the
  rights papers, the rendered pages (`render/`), the README and every other
  prose document outside the verifier packages named below. The legal
  code is in [`LICENSE-CC-BY-4.0`](LICENSE-CC-BY-4.0).
- **Machine-readable artifacts and code: Apache License, Version 2.0**
  (SPDX `Apache-2.0`). This covers the schemas (`schemas/`), the registries
  (`registries/`), the conformance corpus, suites, vectors, fixtures and
  manifests (`conformance/`), the version set, the examples in
  `profiles/examples/`, the TypeScript verifier package (`packages/ecl-ts/`),
  the browser verifier (`web/verifier/`), the Python verifier package
  (`packages/ecl-verify/`) and the Go verifier module (`go/crosscheck/`), each
  as a whole, its README included, the public scripts and every other
  machine-readable file. The license text is in [`LICENSE`](LICENSE), and each
  verifier package carries a copy.

The license of each file is decided file by file by the rules of
[`licenses/license-map.json`](licenses/license-map.json), applied in order;
[`licenses/LICENSE-MATRIX.md`](licenses/LICENSE-MATRIX.md) states the same
rules in prose, with the paths of each class. A README inside a code package
carries its package's license: the Markdown files of the verifier packages,
`packages/ecl-ts/`, `packages/ecl-verify/`, `go/crosscheck/` and
`web/verifier/`, are under Apache-2.0, and every other Markdown document is
text under CC BY 4.0. Every file of the standard's public repository has one
of these two licenses, except material of others, which keeps its own terms.

Both licenses permit commercial use. CC BY 4.0 permits copying, translating
and adapting the text, provided that attribution is given and changes are
indicated; [`licenses/ATTRIBUTION.md`](licenses/ATTRIBUTION.md) gives a form
of attribution. Apache-2.0 permits use, modification and redistribution of the
code and the machine-readable artifacts, provided that the license text and
the notices are kept.

## Requirement text in two forms

The requirement text of the standard and its companions appears in the
Markdown sources and also inside machine-readable artifacts: the compiled
requirement registry, the requirement evaluation catalog and the schema
descriptions quote or cite it. Each artifact is licensed as a whole under
Apache-2.0, and the same text in the Markdown sources is licensed under
CC BY 4.0. Both grants come from the same licensors, so a reuser may rely on
the license of the form that it uses.

## Patents

G-14, Inc. pledges not to assert its Essential Claims against implementations
of ECL-1 Version 1.0 and its companion specifications, to the extent that an
implementation conforms to their normative requirements. The pledge is
royalty-free, worldwide and non-exclusive, and it ends for a party that
asserts a patent claim against an implementation of ECL-1 or against G-14 over
ECL-1. Its full terms are in [`PATENTS.md`](PATENTS.md). G-14, Inc. has
patents pending.

CC BY 4.0 grants no patent rights. Apache-2.0 includes, in its Section 3, a
patent license from each contributor of code for the claims that the
contributor's own contribution infringes; the pledge is separate from that
license and does not limit it.

## Contributions

A contribution is licensed under the license of the files it changes:
CC BY 4.0 for text and Apache-2.0 for code and machine-readable artifacts.
Every commit carries a Developer Certificate of Origin sign-off, and each
contributor makes the same patent pledge for its contributions as G-14 makes
for its own. There is no contributor license agreement
([`governance/CONTRIBUTING.md`](governance/CONTRIBUTING.md)).

## Names and marks

Neither license grants rights in the name "ECL-1", in any logo, or in any
conformance or certification mark. Descriptive use of the name is permitted
as [`governance/TRADEMARKS_AND_MARKS.md`](governance/TRADEMARKS_AND_MARKS.md)
describes.

## Material of others

Third-party material keeps its own terms and is not relicensed. It is listed,
with its source and terms, in
[`licenses/THIRD_PARTY_NOTICES.md`](licenses/THIRD_PARTY_NOTICES.md). The
license texts in this repository, and the Developer Certificate of Origin in
`governance/DCO.txt`, are reproduced as their stewards publish them.

## Implementations

The licenses cover ECL-1 and the files of its public repository. G-14's own
implementation of ECL-1 is not part of the standard and is not in that
repository; its own terms apply to it. The pledge says which claims it covers
and which it does not ([`PATENTS.md`](PATENTS.md), section 3).
