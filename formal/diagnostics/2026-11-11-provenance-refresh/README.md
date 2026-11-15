# Current formal provenance refresh

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

This packet refreshes the exact TLC input provenance after one comment in
`formal/tla/ECLCore.tla` changed from "Those three" to "Those four", matching the
four frontiers described there. The executable model text, configurations,
selected properties, bounds, fairness assumptions and runner are unchanged.
All 58 TLC checks were run again on the comment-corrected bytes with the same
900-second per-check limit and one worker. This refresh adds no model coverage.

The 12 Tamarin checks were not rerun: their original receipt, commands, logs,
theory and runner are retained byte for byte from the preceding
`2026-11-11-closing-review` packet. That packet and all older packets remain
unchanged. The two invocation records retain their own dates and settings.
The comment-corrected model SHA-256 is
`48c1b5fa50aee5b4316e1e224376b6932b5a341aeab31cda3d057b2b7f4c1f96`.

This packet retains 70 current checks: 58 TLC checks (seven correct configurations,
35 deliberately broken configurations and 16 reachability witnesses) and 12 Tamarin
checks (one correct theory and 11 deliberately flawed variants). Every check
matched its expected outcome. A counterexample is the expected result for a
negative variant or a negated reachability witness; it is not a passing correct
configuration. The correct theory verified 12 lemmas: ten universal and two
existential. The correct TLC configurations select 30 safety and four liveness
properties within their recorded finite bounds and fairness assumptions.

`RESULTS.json` is a version 3 aggregate, assembled from the unchanged records in
`invocations/`. Each check retains its actual command, dates, inputs, output hash
and runner digest. `check_sources` identifies its one source record; `runners/`
retains both exact runner versions. The current runner and all current model,
theory and configuration inputs are under `inputs/formal/`. `MANIFEST.json`
hash-binds the packet. `result-schema.json` describes the structural format;
identity, completeness, source equality and current-input checks are also required.

The TLC runs used one worker, the requested JVM heap setting `-Xmx1500m` and a 900-second limit
per check. The symbolic runs used one runtime worker, the runtime heap-cap setting `-M1500m`,
a 120-second limit per check, and a ten-second derivation-check limit. There is no
single global invocation timeout. Historical records remain under their original
paths and describe their original source bytes.

To reproduce current checks, use the exact pinned tools identified in
`inputs/formal/run_checks.py` and select fresh output paths:

```sh
python3 inputs/formal/run_checks.py --skip-tamarin --tla2tools /path/to/tla2tools-1.7.4.jar --timeout 900 --log-dir /new/tlc-logs --record /new/tlc-results.json
python3 inputs/formal/run_checks.py --skip-tlc --tamarin /path/to/tamarin-prover --maude-dir /path/to/maude-directory --timeout 120 --derivcheck-timeout 10 --log-dir /new/symbolic-logs --record /new/symbolic-results.json
```

These commands create fresh results. They do not replace the recorded invocations.
The retained invocation wrappers under `invocations/` contain their original
workspace paths and are archived provenance, not portable reproduction entry
points. `tlc-command-start.json`, `tlc-command-result.json` and
`tlc-command.log` retain the refresh command and its completion evidence. The PDF build reads these recorded checks and does not run formal tools.
