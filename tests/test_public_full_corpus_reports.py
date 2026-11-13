"""Public checks must replay and bind both full cross-language reports.

Robert F. Tilley Jr.; G-14, Inc.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path
import pytest
from scripts import check_public
from test_external_report_v3 import bound, row_for

@pytest.mark.parametrize("language", ["typescript", "go"])
def test_public_check_verifies_generated_report(monkeypatch, tmp_path, language):
    root = tmp_path / "repo"; (root / "packages/ecl-ts").mkdir(parents=True)
    (root / "packages/ecl-ts/control.ts").write_text("export const x = 1")
    commands, verified = [], []
    monkeypatch.setattr(check_public, "ROOT", root)
    monkeypatch.setattr(check_public, "run", lambda argv, cwd=None: commands.append(argv))
    monkeypatch.setattr(check_public, "verify_corpus_report", lambda report, implementation_root, **kw: verified.append((report, implementation_root)), raising=False)
    monkeypatch.setattr(sys, "argv", ["check_public.py", "--language", language, "--revision", "a" * 40])
    assert check_public.main() == 0
    assert len(verified) == 1
    report, implementation = verified[0]
    assert report.name == language + ".json"
    if language == "typescript":
        assert any("packages/ecl-ts/scripts/run-corpus.mjs" in command for command in commands)
        assert implementation.name == "typescript-source"
    else:
        assert any("./cmd/ecl-corpus-check" in command for command in commands)
        assert implementation == root / "go/crosscheck"


def test_typescript_export_omits_only_top_level_generated_dirs(tmp_path):
    package = tmp_path / "package"; package.mkdir()
    for name in ["node_modules/dependency", "dist/main.js", "build/test.js", "src/build/meaningful.ts", "src/node_modules/meaningful.ts", "package-lock.json", "LICENSE", ".git"]:
        path = package / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(name)
    target = tmp_path / "export"
    check_public.export_typescript_source(package, target)
    assert sorted(path.relative_to(target).as_posix() for path in target.rglob("*") if path.is_file()) == [".git", "LICENSE", "package-lock.json", "src/build/meaningful.ts", "src/node_modules/meaningful.ts"]


def prepare_report(bound, tmp_path):
    report, bind, check = bound
    path = tmp_path / "evidence/report.json"; path.write_text(json.dumps(report))
    return report, bind, path


def test_public_report_checker_accepts_complete_bound_control(bound, tmp_path):
    _, _, path = prepare_report(bound, tmp_path)
    result = check_public.verify_corpus_report(path, tmp_path / "implementation", root=tmp_path / "corpus")
    assert result["decision"] == "verified-report-integrity" and result["replay_decision"] == "pass"


def test_public_report_checker_refuses_changed_raw_bytes(bound, tmp_path):
    report, _, path = prepare_report(bound, tmp_path)
    raw = tmp_path / "evidence" / report["evidence"][0]["path"]
    raw.write_bytes(raw.read_bytes() + b" ")
    with pytest.raises(subprocess.CalledProcessError):
        check_public.verify_corpus_report(path, tmp_path / "implementation", root=tmp_path / "corpus")


def test_verified_integrity_alone_does_not_mean_replay_pass(bound, tmp_path):
    report, bind, check = bound; row = row_for(report, "observed_effects")
    row["observed_effects"] = None; row["status"] = "not-met"; report["decision"] = "fail"; bind()
    assert check()["decision"] == "verified-report-integrity"
    path = tmp_path / "evidence/report.json"; path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="complete passing replay"):
        check_public.verify_corpus_report(path, tmp_path / "implementation", root=tmp_path / "corpus")


def test_public_check_rejects_verified_but_unsupported_summary(monkeypatch, tmp_path):
    class Result:
        stdout = json.dumps({"decision": "verified-report-integrity", "replay_decision": "pass", "unsupported_optional_vectors": ["not-run"]})
        stderr = ""
        def check_returncode(self): pass
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: Result())
    with pytest.raises(ValueError, match="complete passing replay"):
        check_public.verify_corpus_report(tmp_path / "report.json", tmp_path / "source", root=tmp_path)
