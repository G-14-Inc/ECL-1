"""The ecl-verify package as a reader of the ECL-1 package meets it: the command on the sample
evidence and the offline-package vectors, its exit statuses, its data and its self-containment.

The tests read the files of the ECL-1 package three levels above this folder and nothing else.
"""

from __future__ import annotations

import ast
import importlib
import io
import json
import pkgutil
import re
import sys
from pathlib import Path

import pytest

import ecl_verify
from ecl_verify import cli, resources

ROOT = Path(__file__).resolve().parents[3]
PROJECT = ROOT / "packages" / "ecl-verify"
SOURCE = PROJECT / "src" / "ecl_verify"
SAMPLES = ROOT / "conformance" / "fixtures" / "evidence"
PACKAGES = ROOT / "conformance" / "suites" / "offline-package"
NOW = "2026-10-01T00:00:00Z"
EXIT = {"verified": 0, "invalid": 1, "incomplete": 3, "current-trust-failed": 4}


def verify(path: Path, policy: Path, *extra: str) -> int:
    return cli.main([str(path), "--trust-policy", str(policy), "--now", NOW, *extra])


@pytest.mark.parametrize(
    ("name", "verdict"),
    [
        ("succeeded", "verified"),
        ("denied", "verified"),
        ("corroborated", "verified"),
        ("tampered", "invalid"),
    ],
)
def test_the_samples_get_their_verdicts(
    name: str, verdict: str, capsys: pytest.CaptureFixture[str]
) -> None:
    status = verify(SAMPLES / f"{name}.json", SAMPLES / "trust-policy.json")
    report = capsys.readouterr().out
    assert status == EXIT[verdict]
    assert report.splitlines()[0] == f"verdict: {verdict}"
    assert any(line.startswith("not-established: ") for line in report.splitlines())


def test_the_json_report_is_canonical_and_carries_the_scope(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert verify(SAMPLES / "succeeded.json", SAMPLES / "trust-policy.json", "--json") == 0
    text = capsys.readouterr().out
    report = json.loads(text)
    assert text == json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + (
        "\n"
    )
    assert report["verdict"] == "verified"
    assert "envelope-signatures" in report["scope"]["established"]
    assert "statements-true" in report["scope"]["not_established"]


def test_every_offline_package_vector_gets_its_verdict(
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = json.loads((PACKAGES / "manifest.json").read_bytes())
    vectors = [vector for vector in manifest["vectors"] if "expected_verdict" in vector]
    assert vectors
    for vector in vectors:
        arguments = [
            str(ROOT / vector["path"]),
            "--trust-policy",
            str(ROOT / vector["trust_policy_path"]),
            "--now",
            vector["evaluated_at"],
        ]
        for history in vector.get("trust_policy_history_paths", []):
            arguments += ["--trust-policy-history", str(ROOT / history)]
        if vector.get("require_trusted_time"):
            arguments.append("--require-trusted-time")
        if "register_path" in vector:
            arguments += ["--register", str(ROOT / vector["register_path"])]
        status = cli.main(arguments)
        first = capsys.readouterr().out.splitlines()[0]
        assert (status, first) == (
            EXIT[vector["expected_verdict"]],
            f"verdict: {vector['expected_verdict']}",
        ), vector["id"]


def test_a_malformed_trust_policy_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text("{}", encoding="utf-8")
    assert verify(SAMPLES / "succeeded.json", policy) == 2
    assert "malformed trust policy" in capsys.readouterr().err


def test_an_unreadable_bundle_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert verify(tmp_path / "absent.json", SAMPLES / "trust-policy.json") == 2
    assert capsys.readouterr().err.startswith("error: ")


def test_the_data_are_the_packages_schemas_and_registries() -> None:
    root = resources.data_root()
    assert (root / "schemas").is_dir()
    assert (root / "registries").is_dir()
    for name in ("error-codes", "semantic-rules", "extensions"):
        assert resources.registry_document(name)["entries"], name


def test_the_package_imports_nothing_outside_itself_and_its_dependencies() -> None:
    allowed = {"ecl_verify", "cryptography", "jsonschema", "referencing"}
    for path in sorted(SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            else:
                continue
            for name in names:
                top = name.split(".", 1)[0]
                assert top in allowed or top in sys.stdlib_module_names, f"{path.name}: {name}"


def test_every_module_imports() -> None:
    names = [
        module.name for module in pkgutil.walk_packages(ecl_verify.__path__, prefix="ecl_verify.")
    ]
    assert "ecl_verify.cli" in names
    for name in names:
        importlib.import_module(name)


def test_the_version_is_the_projects() -> None:
    # The project's own lines, read without tomllib, which Python 3.10 lacks.
    text = (PROJECT / "pyproject.toml").read_text(encoding="utf-8")
    project = text.split("[project]\n", 1)[1].split("\n[", 1)[0]
    assert re.search(rf'^version = "{re.escape(ecl_verify.__version__)}"$', project, re.M)
    assert re.search(r'^license = "Apache-2.0"$', project, re.M)
    assert 'ecl-verify = "ecl_verify.cli:main"' in text.split("[project.scripts]\n", 1)[1]


@pytest.mark.parametrize("json_report", [False, True])
def test_reports_preserve_lf_under_windows_text_translation(
    monkeypatch: pytest.MonkeyPatch, json_report: bool
) -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii", newline="\r\n")
    monkeypatch.setattr(sys, "stdout", stream)
    assert (
        verify(
            SAMPLES / "succeeded.json",
            SAMPLES / "trust-policy.json",
            *(["--json"] if json_report else []),
        )
        == 0
    )
    data = raw.getvalue()
    assert data.endswith(b"\n")
    assert b"\r\n" not in data
    if json_report:
        assert json.loads(data)["verdict"] == "verified"


def test_report_output_preserves_unicode_under_a_legacy_text_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii", newline="\r\n")
    monkeypatch.setattr(sys, "stdout", stream)
    cli._write_stdout("verified: 日本語\n")
    assert raw.getvalue() == "verified: 日本語\n".encode()
