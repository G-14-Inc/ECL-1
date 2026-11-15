// Exact source-export names and refusal controls. Robert F. Tilley Jr.; G-14, Inc.
import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { sourceTreeDigest } from "../../src/conformance/corpus.js";
const digest = (v: string | Uint8Array): string => createHash("sha256").update(v).digest("hex");
function fixture(body: (root: string) => void): void {
  const root = fs.mkdtempSync(join(tmpdir(), "ecl-source-names-"));
  try { body(root); } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
for (const name of ["notes 1.txt", "café.txt", "cafe\u0301.txt", "\ue000.txt", "\u{10000}.txt", "a\u2028b\u2029.txt", "\ufffd.txt", "\ufeffname.txt", "CON.txt", "notes.", "notes ", "name:stream.txt"]) {
  test(`source export preserves exact name ${JSON.stringify(name)}`, { skip: process.platform === "win32" && ["CON.txt", "notes.", "notes ", "name:stream.txt"].includes(name) }, (t) => fixture(root => {
    fs.writeFileSync(join(root, name), "x");
    if (!fs.readdirSync(root).includes(name)) { t.skip("host normalizes the requested filename"); return; }
    const entries = [{ path: name, sha256: digest("x"), size_bytes: 1 }];
    assert.deepEqual(sourceTreeDigest(root), { files: 1, digest: digest(JSON.stringify(entries)) });
  }));
}
for (const directory of [false, true]) test(`source export refuses .git ${directory ? "directory" : "file"}`, () => fixture(root => {
  fs.writeFileSync(join(root, "control"), "x");
  if (directory) fs.mkdirSync(join(root, ".git")); else fs.writeFileSync(join(root, ".git"), "gitdir: elsewhere");
  assert.throws(() => sourceTreeDigest(root), /clean export/);
}));
for (const directory of [false, true]) for (const alias of [false, true]) test(`source export refuses invalid UTF-8 directory=${directory}, alias=${alias}`, { skip: process.platform === "win32" }, (t) => fixture(root => {
  fs.writeFileSync(join(root, "control"), "control");
  const raw = Buffer.concat([Buffer.from(root + "/"), Buffer.from([0xff])]);
  try {
    if (directory) { fs.mkdirSync(raw); if (alias) fs.mkdirSync(join(root, "\ufffd")); }
    else { fs.writeFileSync(raw, "different bytes"); if (alias) fs.writeFileSync(join(root, "\ufffd"), "benign alias"); }
  } catch (error) {
    if (["EINVAL", "EILSEQ"].includes((error as NodeJS.ErrnoException).code ?? "")) { t.skip("host refuses invalid-byte filenames"); return; }
    throw error;
  }
  assert.throws(() => sourceTreeDigest(root));
}));
for (const kind of ["backslash", "symlink"]) test(`source export keeps ${kind} refusal`, { skip: process.platform === "win32" }, () => fixture(root => {
  fs.writeFileSync(join(root, "control"), "control");
  if (kind === "backslash") fs.writeFileSync(join(root, "a\\b"), "x");
  else fs.symlinkSync(join(root, "control"), join(root, "link"));
  assert.throws(() => sourceTreeDigest(root));
}));

test("source root boundary excludes ancestors and rejects metadata root", () => fixture(root => {
  const ordinary = join(root, "ordinary"), nested = join(root, ".git", "clean-export");
  for (const path of [ordinary, nested]) { fs.mkdirSync(path, { recursive: true }); fs.writeFileSync(join(path,"control.txt"),"same source bytes\n"); }
  assert.deepEqual(sourceTreeDigest(ordinary), sourceTreeDigest(nested));
  assert.throws(() => sourceTreeDigest(join(root,".git")), /clean export/);
}));
test("source root symlink is refused", { skip: process.platform === "win32" }, () => fixture(root => {
  const source = join(root,"source"), link = join(root,"link");
  fs.mkdirSync(source); fs.writeFileSync(join(source,"control"),"x"); fs.symlinkSync(source,link,"dir");
  assert.throws(() => sourceTreeDigest(link), /symlink/);
}));

test("relative metadata root aliases are refused; clean relative roots preserve identity", () => fixture(root => {
 const prior=process.cwd(), metadata=join(root,".git"), clean=join(root,"clean");
 fs.mkdirSync(join(metadata,"refs"),{recursive:true});fs.writeFileSync(join(metadata,"HEAD"),"x");
 fs.mkdirSync(clean);fs.writeFileSync(join(clean,"control"),"x");const expected=sourceTreeDigest(clean);
 try {
  process.chdir(metadata);
  for(const spelling of [".","refs/..","refs/../."])assert.throws(()=>sourceTreeDigest(spelling),/clean export/);
  process.chdir(clean);assert.deepEqual(sourceTreeDigest("."),expected);
 } finally {process.chdir(prior);}
}));
