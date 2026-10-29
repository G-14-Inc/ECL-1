# ECL-1 normative core

`ECL-1_Standard.md` is the sole authoritative source of the ECL-1 core
standard, Version 1.0. Its companion protocols are in [../protocols/](../protocols/)
and its profiles in [../profiles/](../profiles/);
[../release/VERSION_SET.json](../release/VERSION_SET.json) binds the version of
each.

[ISSUES.md](ISSUES.md) records normative questions and, once decided, their
resolution. Recording an issue does not resolve it. ECL-ISSUE-001 (Class B) and
ECL-ISSUE-002 (the scope of restricted mode for one action class's missing
proof) are resolved in the text of Version 1.0.

The requirement ledger ([../registries/requirement-ledger.json](../registries/requirement-ledger.json))
records, for each requirement, the version that introduced it and each version
that changed it, through the release candidates that preceded Version 1.0.

All rendered or excerpted forms must identify the items below. Each page of
[../render/](../render/index.html) ends with a source record that gives them:

- the source path;
- the source SHA-256;
- the release status;
- the license notice.

Protocol schemas, registries, and test vectors are separately versioned
normative companions when invoked by the core. They do not override the core;
any contradiction is a release blocker.
