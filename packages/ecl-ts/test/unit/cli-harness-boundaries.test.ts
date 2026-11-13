import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { repoRoot } from "./helpers.js";

// Supply deterministic CLI outputs in a separate process while running the real comparison
// script. These tests exercise the harness's decisions, not the bundle verifier's internals.
const wrapper = `
import childProcess from "node:child_process";
import {syncBuiltinESMExports} from "node:module";
import {readFileSync} from "node:fs";
import {pathToFileURL} from "node:url";
const [script,root,reportPath]=process.argv.slice(2);
const report=JSON.parse(readFileSync(reportPath,"utf8"));
childProcess.spawnSync=(_exe,args)=>{
 let value=report;
 if(args[1].includes("/fixtures/evidence/")){
  const name=args[1].split("/").at(-1).split(".")[0];
  value={verdict:name==="tampered"?"invalid":"verified",effects:[{level:name==="corroborated"?"corroborated":name==="tampered"?"none":"issuer-asserted"}]};
 }
 return {status:value.verdict==="invalid"?1:0,stdout:JSON.stringify(value),stderr:""};
};
syncBuiltinESMExports();process.argv=[process.execPath,script,"--repo-root",root];
await import(pathToFileURL(script));
`;

for (const mode of ["valid", "wrong-primary", "missing-primary", "duplicate-unresolved", "wrong-verdict", "passing-primary", "passing-valid", "duplicate-manifest", "duplicate-corpus"]) {
  test(`CLI corpus harness compares ${mode}`, () => {
    const root = mkdtempSync(join(tmpdir(), "ecl-cli-harness-"));
    try {
      mkdirSync(join(root, "conformance/suites"), { recursive: true });
      const put = (path: string, value: unknown): void => writeFileSync(join(root, path), JSON.stringify(value));
      const vector: Record<string, unknown> = { id: "fixture", path: "bundle.json", stage: "evidence-bundle", expected: "fail", expected_primary_id: "ecl.error.schema-invalid.v1", expected_secondary_ids: [], expected_verdict: "invalid", expected_unresolved_predecessor_ids: ["urn:example:predecessor"], trust_policy_path: "policy.json", evaluated_at: "2026-10-01T00:00:00Z" };
      // The harness confines paths before invoking the stubbed CLI. These files are only
      // existence controls; the stub supplies the deliberate reports under test.
      put("bundle.json", {}); put("policy.json", {});
      mkdirSync(join(root, "conformance/fixtures/evidence"), { recursive: true });
      for (const name of ["succeeded", "denied", "corroborated", "tampered", "trust-policy"]) put(`conformance/fixtures/evidence/${name}.json`, {});
      const report: Record<string, unknown> = { verdict: "invalid", primary: "ecl.error.schema-invalid.v1", unresolved_predecessor_ids: ["urn:example:predecessor"], effects: [] };
      if (mode === "wrong-primary") report["primary"] = "ecl.error.signature-invalid.v1";
      if (mode === "missing-primary") delete report["primary"];
      if (mode === "duplicate-unresolved") report["unresolved_predecessor_ids"] = ["urn:example:predecessor", "urn:example:predecessor"];
      if (mode === "wrong-verdict") report["verdict"] = "verified";
      if (mode === "passing-primary" || mode === "passing-valid") {
        vector["expected"] = "pass"; vector["expected_verdict"] = "verified"; delete vector["expected_primary_id"];
        report["verdict"] = "verified"; report["primary"] = mode === "passing-primary" ? "ecl.error.schema-invalid.v1" : null;
      }
      put("conformance/manifest.json", { vectors: mode === "duplicate-manifest" ? [vector, vector] : [vector] });
      const row = { id: "fixture", capability: "evidence-bundle-verification" };
      put("conformance/shared-corpus.json", { vectors: mode === "duplicate-corpus" ? [row, row] : [row] });
      put("report.json", report); writeFileSync(join(root, "wrapper.mjs"), wrapper);
      const result = spawnSync(process.execPath, [join(root, "wrapper.mjs"), join(repoRoot(), "packages/ecl-ts/scripts/check-corpus.mjs"), root, join(root, "report.json")], { encoding: "utf8" });
      if (mode === "valid" || mode === "passing-valid") assert.equal(result.status, 0, result.stderr + result.stdout);
      else assert.notEqual(result.status, 0, result.stderr + result.stdout);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
}
