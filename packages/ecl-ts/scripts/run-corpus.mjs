#!/usr/bin/env node
/** Replay the complete shared corpus and write its source-bound report and raw results.
 * Robert F. Tilley Jr.; G-14, Inc.
 * Run after npm run build; all four paths/revision options are explicit.
 */
import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { runCorpus } from "../dist/conformance/corpus.js";

try {
  const { values } = parseArgs({ options: {
    "repo-root": { type: "string" }, "source-root": { type: "string" },
    report: { type: "string" }, revision: { type: "string" },
  }, allowPositionals: false });
  if (!values["repo-root"] || !values["source-root"] || !values.report ||
      !/^[0-9a-f]{40}$/.test(values.revision ?? "") || /^0+$/.test(values.revision)) {
    throw new Error("usage: run-corpus.mjs --repo-root DIR --source-root CLEAN_EXPORT --report FRESH_FILE --revision COMMIT");
  }
  const summary = runCorpus(resolve(values["repo-root"]), values.revision,
    resolve(values.report), resolve(values["source-root"]), process.version);
  console.log(JSON.stringify(summary));
  if (summary.decision !== "pass" || summary.counts.met !== summary.vector_count ||
      (summary.counts["not-met"] ?? 0) !== 0 || (summary.counts.unsupported ?? 0) !== 0) process.exitCode = 1;
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 2;
}
