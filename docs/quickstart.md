# Quickstart: verify ECL-1 evidence

This guide takes you from the sample evidence in the ECL-1 package to a
verified result with each of the three verifiers of ECL-1 Version 1.0: the
Python package `ecl-verify`, the TypeScript package with `ecl-verify-ts`, and
the Go module with `ecl-verify-go`. You then read a report, see a tampered
bundle fail, verify an offline package and run the conformance corpus. You need
only the ECL-1 package (the release archive, unpacked, or a clone of the public
repository); no step needs an account, and the verifiers make no network
request.

Every command runs from the root of the ECL-1 package unless a step says
otherwise. You need Python 3.10 or later for the Python verifier, Node.js 22
with npm for the TypeScript verifier and Go 1.26.10 or later for the Go verifier; any one
of the three is enough to follow the guide in that language. Installing the
Python and TypeScript dependencies reads them from your package index and npm
registry, or from your local caches; the Go module has no dependency outside
the standard library.

## 1. The sample evidence

`conformance/fixtures/evidence/` holds four signed evidence bundles and the
trust policy that names their signing keys:

| File | What it records | Verdict |
| --- | --- | --- |
| `succeeded.json` | an admitted action that the enforcement point released and that succeeded | `verified` |
| `denied.json` | a denied action that was never released | `verified` |
| `corroborated.json` | the succeeded action with an observer's signed record of its effect | `verified` |
| `tampered.json` | `succeeded.json` with one bit of its last signature flipped | `invalid` |

A bundle is checked under a trust policy that you choose and at an evaluation
time that you choose: the trust policy beside the bundles is the sample's, and
the guide evaluates at `2026-10-01T00:00:00Z`. In your own use, the trust policy
is yours, never the evidence's.

## 2. Python: `ecl-verify`

Install the verifier into a new virtual environment:

```
python3 -m venv .venv
.venv/bin/pip install ./packages/ecl-verify
```

Verify the succeeded bundle:

```
.venv/bin/ecl-verify conformance/fixtures/evidence/succeeded.json \
  --trust-policy conformance/fixtures/evidence/trust-policy.json \
  --now 2026-10-01T00:00:00Z
echo "exit status: $?"
```

The exit status is 0, and the first line of the report is `verdict: verified`.

## 3. Read the report

The report states what the verdict covers. After the verdict come the
`not-established:` lines, then the `established:` lines, each a scope item of
EBMP2-076 with what it means:

- `established:` items are checks that the verifier made and that held, such
  as `envelope-signatures`: each envelope's payload digest and signatures
  verify under the trust-policy version its object names.
- `not-established:` items are checks that did not run or did not hold, and
  statements that no verification establishes: that the statements in the
  bundle are true, that the recorded times are the true times of their events,
  that the effects happened, and that the deployment has been assessed. An
  item with a reason names it, for example `(reason: no-release-recorded)` in
  the report of `denied.json`.

Then come each envelope's checks (its signers, its historical and current
status and its trusted time), the bindings between requests, responses and
events, the causal status, each effect with its evidence level, and the
findings. A `verified` bundle is signed, bound and complete as its
`established:` items say, and no more. Add `--json` for the same report as
canonical JSON.

Compare the reports of the other two bundles:

```
for name in denied corroborated; do
  .venv/bin/ecl-verify conformance/fixtures/evidence/$name.json \
    --trust-policy conformance/fixtures/evidence/trust-policy.json \
    --now 2026-10-01T00:00:00Z
done
```

The `effect` line of `corroborated.json` gives the level `corroborated`, where
`succeeded.json` gives `issuer-asserted`.

## 4. See a tampered bundle fail

```
.venv/bin/ecl-verify conformance/fixtures/evidence/tampered.json \
  --trust-policy conformance/fixtures/evidence/trust-policy.json \
  --now 2026-10-01T00:00:00Z
echo "exit status: $?"
```

The exit status is 1 and the verdict `invalid`; `envelope-signatures` is now
under `not-established:`, the line of envelope 4 gives the error of its
signature, and the finding `ecl.error.signature-policy-invalid.v1` says that
envelope 4 is not historically valid. The
exit statuses of all three verifiers are 0 for `verified`, 1 for `invalid`, 2
for a usage error, 3 for `incomplete` and 4 for `current-trust-failed`
(EBMP2-060).

## 5. Verify an offline package

An offline package carries a bundle and the artifacts it names in one
`ecl.zip.store.v1` archive (OFFLINE-VERIFICATION-1). The verifier reads a file
that begins with the bytes `PK` as a package:

```
.venv/bin/ecl-verify conformance/suites/offline-package/package-valid-verified.zip \
  --trust-policy conformance/suites/offline-package/trust-policy.json \
  --now 2026-10-01T00:00:00Z
```

Its verdict is `verified`. The same command on
`package-invalid-artifact-digest.zip` of the same folder gives `invalid`, with
the finding `ecl.error.integrity-invalid.v1`: an artifact's digest differs from
its manifest entry.

## 6. Run the conformance corpus in Python

The corpus runner evaluates every vector of the conformance suites with the
Python verifier and compares each result with the expected one:

```
.venv/bin/python scripts/run_conformance.py --no-write > python-conformance.json
echo "exit status: $?"
```

The exit status is 0 when every vector passes. The report on standard output
gives the vector count, the passed and failed counts and, for each vector, the
expected and observed findings. `--no-write` leaves the package unchanged.

## 7. TypeScript: `ecl-verify-ts`

From `packages/ecl-ts`, install the locked dependencies, build, and verify the
same bundle:

```
cd packages/ecl-ts
npm ci --ignore-scripts
npm run build
node dist/cli/ecl-verify.js ../../conformance/fixtures/evidence/succeeded.json \
  --trust-policy ../../conformance/fixtures/evidence/trust-policy.json \
  --now 2026-10-01T00:00:00Z
```

The report has the same form and the same verdict. `node
scripts/check-corpus.mjs` then runs `ecl-verify-ts` on every evidence-bundle
and offline-package vector of the corpus and on the sample evidence, and exits
0 when each gives its expected verdict and exit status. `npm test` runs the
package's unit tests. The browser verifier, `web/verifier/index.html` at the
root of the package, runs the same code in a browser, offline. Return to the
root of the package (`cd ../..`) before the next section.

## 8. Go: `ecl-verify-go`

From the root of the package, in `go/crosscheck`:

```
cd go/crosscheck
go run ./cmd/ecl-verify-go ../../conformance/fixtures/evidence/succeeded.json \
  --trust-policy ../../conformance/fixtures/evidence/trust-policy.json \
  --now 2026-10-01T00:00:00Z
```

The verdict is again `verified`, and `tampered.json` again gives `invalid` with
the exit status 1. To run the whole shared corpus with the Go verifier:

```
go run ./cmd/ecl-corpus-check --repo-root ../.. --report ../../go-corpus.json \
  --revision 0000000000000000000000000000000000000000
```

It prints a summary and exits 0 when every vector meets its expectation. The
report file holds each result and names its raw evidence, which the command
writes in the folder `go-corpus-evidence` beside the report. `--revision` names
the source revision that the report records; the zeros stand for an unrecorded
revision. `go test ./...` runs the module's tests.

The implementer report checker verifies such a report against the corpus, its
evidence and the source it names, with no network use:

```
cd ../..
.venv/bin/python scripts/verify_external_implementation_report.py go-corpus.json \
  --evidence-root . --implementation-root go/crosscheck
```

Its exit status is 0 when the report's digests and bindings all verify. An
implementation of your own produces a report of the same form; the external
implementation profile, `conformance/EXTERNAL_IMPLEMENTATION_PROFILE.md`,
states what it holds.

## What next

- `packages/ecl-verify/README.md`, `packages/ecl-ts/README.md` and
  `go/crosscheck/README.md` describe each verifier's options and library use.
- `profiles/OFFLINE-VERIFICATION-1.md` and `profiles/TRUST-POLICY-1.md` define
  what a verifier checks, and `protocols/EBMP-2.md` the evidence and the scope
  table of EBMP2-076.
- `docs/implementer-guide.md` describes how to test your own implementation
  against the conformance suites, and `docs/reviewer-guide.md` the checks an
  assessor makes with this package.

## Windows PowerShell and the first workflow

On Windows create the environment with `py -3 -m venv .venv`, then use
`.venv\Scripts\python.exe -m pip install ./packages/ecl-verify` and
`.venv\Scripts\ecl-verify.exe` instead of `.venv/bin/ecl-verify`. Use a single
line for each command or PowerShell's backtick for continuation; the shell
backslash in the Unix examples is not a PowerShell continuation. Check a
command's exit code with `$LASTEXITCODE`. The Node and Go executable arguments
are the same; use the paths appropriate to the shell.

To generate newly bound teaching evidence, run the
[bounded workflow](../examples/bounded_workflow/README.md). It demonstrates
actual in-memory effects and failure guards, with explicit limits. For the
complete integration and contribution path, use [Start here](start-here.md).

The repository preserves fixture bytes on checkout through `.gitattributes`.
JSON reports are emitted as UTF-8 with LF line endings. For a byte comparison,
capture each process’s stdout as bytes rather than passing it through a shell
text conversion. A shell may re-encode redirected output independently of the
verifier. The package’s checks use the same trust inputs for every verifier.

These are compatibility floors. Use maintained runtimes with current security
patches for deployment. Qualification keeps fixed versions for reproduction;
the public CI also checks a newer-runtime combination.
