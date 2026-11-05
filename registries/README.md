# ECL-1 registries

Registries are normative machine-readable allocation and traceability
surfaces. Every registry entry has an identifier, version or revision,
status, owner class, compatibility class, and change-control reference.

Generated registries must never be hand-edited. Source registries must pass
collision, reference, lifecycle, and compatibility checks.

`scope-checks.json` is not an allocation registry and its entries carry none of
these members: it is the claim-to-check map of EBMP-2 EBMP2-076, which lists for
each item of a verification report's scope its object set, the checks that must
hold over it, the trust knowledge they use and the waivers that may narrow it.
Its schema is `schemas/ecl-scope-checks-v1.schema.json`.
