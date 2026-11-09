# ECL-1 registries

This directory contains machine-readable allocation and traceability records.
An allocation entry under `schemas/ecl-registry-v2.schema.json` records its
identifier, status, owner class, introduced version, compatibility class and
description, with type-specific attributes where applicable. The containing
registry records its version and change-control reference.

Traceability files have other structures and roles. Consult each file's
specification, schema or recorded generator; they include
`requirements-compiled.json`, `requirement-ledger.json`, `gap-coverage.json`,
`guarantee-trace.json` and `scope-checks.json`. A generated trace does not
supersede the requirements it cites.

Generated registries must never be hand-edited. Source registries must pass
collision, reference, lifecycle, and compatibility checks.

`scope-checks.json` is not an allocation registry: it is the claim-to-check map of EBMP-2 EBMP2-076, which lists for
each item of a verification report's scope its object set, the checks that must
hold over it, the trust knowledge they use and the waivers that may narrow it.
Its schema is `schemas/ecl-scope-checks-v1.schema.json`.
