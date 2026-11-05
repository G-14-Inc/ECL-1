# Attribution

This file gives a form of attribution for reusing ECL-1, and lists the
attributions that the material of others in the repository needs. It is not
legal advice.

## Reusing the text: CC BY 4.0

The text and documentation of ECL-1 are licensed under the Creative Commons
Attribution 4.0 International license ([`../LICENSE-CC-BY-4.0`](../LICENSE-CC-BY-4.0)).
A reuser can give attribution in this form:

> ECL-1: External Control Layer Standard, Version 1.0, by G-14, Inc. and the
> contributors to ECL-1, <https://externalcontrollayer.ai>, licensed under the
> Creative Commons Attribution 4.0 International license
> (<https://creativecommons.org/licenses/by/4.0/>).

A reuser who changes the material says so and says what was changed, for
example "Changed from the original: Section 7.7 is abridged." A changed text
does not imply endorsement by G-14 or by the contributors, conformance or
certification, and it is not presented as ECL-1 itself
([`../governance/TRADEMARKS_AND_MARKS.md`](../governance/TRADEMARKS_AND_MARKS.md)).

## Reusing the code and the machine-readable artifacts: Apache-2.0

The schemas, registries, conformance material, verifier and other
machine-readable files are licensed under the Apache License, Version 2.0
([`../LICENSE`](../LICENSE)). A redistribution carries the license text, keeps
the copyright notice, Copyright 2026 G-14, Inc., and the other notices of the
files, and carries the `NOTICE` file of the package it came from, as the
license's Section 4 requires.

## Material of others

A copy of the repository, or of any part of it that holds the material
concerned, keeps each of these attributions where the list says it is carried.

| Material | Where it is | Attribution it needs | Where the attribution is carried |
| --- | --- | --- | --- |
| `@noble/curves` 2.3.0 and `@noble/hashes` 2.3.0, MIT License, Copyright (c) 2022 Paul Miller | Bundled in `web/verifier/verifier.js` | The copyright notice and the MIT permission notice | In full at the head of `web/verifier/verifier.js`, written by `packages/ecl-ts/scripts/build-verifier.mjs` from the packages' own `LICENSE` files |
| A test case of NIST's ACVP-Server ML-DSA signature-verification data | `conformance/vectors/integrity/mldsa65-nist-acvp-sigver-tc123.json` | The source, its commit, paths and digests; the source's terms | [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), "NIST ACVP ML-DSA-65 fixture" |
| Entries of the Control Gap Record and the definitions of the Control Gap Classification, version 0.2, published by G-14, Inc. under CC BY 4.0 | `conformance/scenarios/record-*.json`, `registries/gap-coverage.json`, `docs/gap-coverage.md` | The credit that the Record's and the Classification's license asks for, and a statement of what was changed | Each scenario's `source.credit`, `abstraction` and steps marked `added`; the `classification` and `record` members of the gap registry, and the attribution lines of the annex generated from it |
| Identifiers, field names, values and short terms of the outside texts that the binding profiles bind to | `profiles/AARM-BINDING-1.md`, `profiles/ACS-BINDING-1.md`, `profiles/MCP-GATEWAY-1.md`, `profiles/OTEL-EVIDENCE-EXPORT-1.md`, `profiles/OAUTH-AUTHORITY-1.md` and their schemas and vectors | The citation of each source by revision and digest | Each profile's pinned-sources table and `conformance/binding-sources.json`; their terms are listed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), "Binding profile sources" |
| The license texts and the Developer Certificate of Origin | `LICENSE`, `LICENSE-CC-BY-4.0`, `packages/ecl-ts/LICENSE`, `governance/DCO.txt` | Each is reproduced verbatim, as its steward permits | The files themselves |
