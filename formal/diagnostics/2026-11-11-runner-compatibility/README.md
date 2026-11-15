# Current runner compatibility packet

## Distributed evidence paths

This public source contains copies of the recorded evidence with local workspace
paths standardized for portability. File digests and packet inventories identify
these distributed copies. Model inputs, properties, bounds, tool settings, dates,
measurements and outcomes are unchanged. The record of the transformation and
original file digests is `formal/PUBLIC-EVIDENCE-NORMALIZATION.json`. G-14, Inc.
retains the exact original evidence separately. This transformation ran no solver.
References below to original commands, outputs or unchanged retained records
describe the recorded runs; the distributed path strings and associated digests
are the standardized representation described here.

Authors/producers: Robert F. Tilley Jr. and G-14, Inc.

This packet assembles the recorded formal results against the current runner after
process-exit and output-parser repairs. No TLC, Tamarin, Maude or Java process ran
as part of this assembly. The model, theory, configurations, registered checks,
properties, bounds, fairness assumptions, tool pins and original results are
unchanged from `2026-11-11-provenance-refresh`.

The current runner rejects abnormal TLC exits even when output contains the
expected violation banner. It also records Tamarin's failed existence-witness
status and step count accurately. `RUNNER-CHANGES.diff` retains those exact
runner changes. Reclassifying all 70 retained output files with both parsers left
the recorded outcomes and parsed metrics unchanged. That comparison is a parser
regression check, not another execution of the models. The exact per-check
comparison is retained in `OUTPUT-RECLASSIFICATION.json`.

The packet retains 58 TLC checks (seven correct configurations, 35 deliberately
broken configurations and 16 reachability witnesses) and 12 Tamarin checks (one
correct theory and 11 deliberately flawed variants). Every retained check
matched its expected outcome. Counterexamples are the expected results for
negative variants and negated reachability witnesses. The correct theory's
12 lemmas comprise ten universal properties and two existence witnesses; the
correct TLC configurations select 30 safety and four liveness properties within
the recorded finite bounds and fairness assumptions.

`RESULTS.json` is a v3 aggregate. Every per-check dictionary, source invocation,
command, date, setting, output, original runner and model input is retained
unchanged. The new `current_runner` descriptor is separate from the runner that
performed each earlier invocation. `ASSEMBLY.json` records the exact transfer and
the new current-runner identity. `MANIFEST.json` hash-binds this packet; the
hash-bound `formal/current-results.json` selector identifies it explicitly.
The preceding packet and all older packets remain unchanged.

The retained TLC invocations used one worker, `-Xmx1500m` and a 900-second limit
per check. The retained symbolic invocations used one runtime worker, `-M1500m`,
a 120-second limit per check and a ten-second derivation-check limit. Each source
record retains its own dates and settings; there is no new shared invocation date.
`tlc-command-start.json`, `tlc-command-result.json`, `tlc-command.log` and the
wrappers under `invocations/` describe their original invocations. Their archived
workspace paths are provenance, not portable reproduction entry points.

From the source root, check recorded provenance without running formal tools:

```sh
python3 formal/check_recorded_results.py
```

The checker validates the fixed v3 structure, hashes, complete source partition,
retained runners and compatibility with the current registry/model inputs. It
does not authenticate a publisher or establish implementation correctness.
`result-schema.json` describes the structure, and `AGGREGATE-FORMAT.md` specifies
the additional identity and compatibility checks. The PDF build reads recorded
results and does not run formal tools.

To obtain new solver results, enter this packet's directory and use the exact
pinned tools with fresh output paths:

```sh
python3 inputs/formal/run_checks.py --skip-tamarin --tla2tools /path/to/tla2tools-1.7.4.jar --timeout 900 --log-dir /new/tlc-logs --record /new/tlc-results.json
python3 inputs/formal/run_checks.py --skip-tlc --tamarin /path/to/tamarin-prover --maude-dir /path/to/maude-directory --timeout 120 --derivcheck-timeout 10 --log-dir /new/symbolic-logs --record /new/symbolic-results.json
```

These commands create new results; they do not replace the retained invocations.
