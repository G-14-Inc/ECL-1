# Run one bounded workflow

This teaching example mediates changes to an in-memory record. It demonstrates
admit, deny, a simulated approval hold, exact action binding, single use,
expiry and loss of fresh proof. It then instantiates the published wire
examples with new action and causal bindings, signs them with the published
test keys, and produces admitted and denied bundles for the public verifiers.

The workflow is a simulation in one process. Its keys, clocks, source assertions
and approval are teaching fixtures. It has no production credentials, durable
recovery, isolated authority, authenticated human interface or assessment.
The signed bundles cover the automatic admit/deny examples; they do not record
the approval exercise or certify the simulation's controls. This is no L1 or
deployment conformance claim. The private platform is not imported.

From the public package root, after installing the Python verifier as described
in [the quickstart](../../docs/quickstart.md):

```sh
.venv/bin/python examples/bounded_workflow/workflow.py --output demo-output
.venv/bin/python -m unittest discover -s examples/bounded_workflow -v
.venv/bin/ecl-verify demo-output/admitted.json --trust-policy demo-output/trust-policy.json --now 2026-10-01T00:00:00Z --json
.venv/bin/ecl-verify demo-output/denied.json --trust-policy demo-output/trust-policy.json --now 2026-10-01T00:00:00Z --json
```

On Windows PowerShell use `.venv\Scripts\python.exe` and
`.venv\Scripts\ecl-verify.exe` for the executables above. The output directory
must be new; the command refuses to overwrite an earlier exercise.

The eight simulation results should be `true`; both bundles should report
`verified`. Their scope remains the verifier's explicit established and
not-established items. The fixed evaluation time belongs to the teaching
fixture. The result is no claim about current production authority or truth.

After the quickstart's TypeScript build, check the same files with:

```sh
node packages/ecl-ts/dist/cli/ecl-verify.js demo-output/admitted.json --trust-policy demo-output/trust-policy.json --now 2026-10-01T00:00:00Z --json
```

For Go, run from `go/crosscheck`:

```sh
go run ./cmd/ecl-verify-go ../../demo-output/admitted.json --trust-policy ../../demo-output/trust-policy.json --now 2026-10-01T00:00:00Z --json
```

Use `denied.json` in each command to check the denied bundle too. Compare the
JSON reports byte for byte. No verifier makes a network request; installing
dependencies can require network access.

To move toward an implementation, choose a real action boundary, give the AI
no direct effect credentials, replace the simulated authority and approval
with separately controlled services, implement durable use/recovery and the
required evidence, and assess every applicable requirement in the
[minimum L1 path](../../docs/l1-minimum.md). Run the failure cases against the
actual deployment. Keep existing safeguards active while evaluating changes.
