# Security

Report a suspected vulnerability in ECL-1 privately, never in a public issue:
in its texts (a requirement that permits an unsafe outcome, for example), its
schemas, its conformance tests, its sample evidence or its offline verifier.

- Use this repository's private vulnerability reporting (the "Report a
  vulnerability" button of its Security tab), or
- write to ecl@g14.ai with "ECL-1 security" in the subject.

Give the affected document, requirement or file, the version (ECL-1 Version
1.0, or the release you used), how to reproduce the problem and what you
expected instead. Keep credentials and other sensitive material out of the
report, or say what you can share privately.

[governance/SECURITY.md](governance/SECURITY.md) describes how a report is
handled and disclosed. A correction to a published text is issued as an
erratum ([governance/ERRATA.md](governance/ERRATA.md)).

A problem in a product that implements ECL-1 goes to that product's supplier.

The Version 1.0 archive, manifest, checksums and verifier SBOMs linked from the
[ECL-1 release page](https://externalcontrollayer.ai/ecl-1) are the release
artifacts. Treat a package-registry distribution as official only when both
that page and the Version 1.0 GitHub release link to it. A package that merely
uses an ECL-1 or verifier name is not an official distribution; verify the
published digest before installing it.
