"""Run the public package's checks without the private platform or release tooling."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], cwd: Path = ROOT) -> None:
    command = [shutil.which(command[0]) or command[0], *command[1:]]
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)  # noqa: S603 — fixed argv below; no shell or user command


def source_revision(root: Path, declared: str | None = None) -> str:
    """Name the actual checkout's base commit, or an explicitly supplied export revision.

    The corpus report separately hashes the evaluated source tree, including local
    edits. A parent repository's revision is not provenance for an extracted archive.
    """
    value = declared
    if value is None:
        try:
            top = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=root, text=True).strip()
            if Path(top).resolve() != root.resolve():
                raise ValueError("source export has no repository of its own; supply --revision")
            value = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError("source revision is unavailable; supply --revision for an export") from error
    if not re.fullmatch(r"[0-9a-f]{40}", value) or value == "0" * 40:
        raise ValueError("source revision must be a nonzero 40-character lowercase commit identifier")
    return value


def export_typescript_source(package: Path, destination: Path) -> None:
    """Keep the exact package inputs; omit only installed and generated root trees."""
    def ignore(directory: str, names: list[str]) -> list[str]:
        return sorted(set(names) & {"node_modules", "dist", "build"}) if Path(directory) == package else []
    # Preserve links so the report verifier refuses them, rather than dereferencing.
    shutil.copytree(package, destination, symlinks=True, ignore=ignore)


def verify_corpus_report(report: Path, implementation_root: Path, *, root: Path = ROOT) -> dict:
    """Check exact source/raw bindings and require a complete passing local replay."""
    command = [sys.executable, str(Path(__file__).with_name("verify_external_implementation_report.py")),
               str(report), "--root", str(root), "--evidence-root", str(report.parent),
               "--implementation-root", str(implementation_root)]
    print("+ " + " ".join(command), flush=True)
    result = subprocess.run(command, capture_output=True, text=True)
    if result.stdout: print(result.stdout, end="")
    if result.stderr: print(result.stderr, end="", file=sys.stderr)
    result.check_returncode()
    checked = json.loads(result.stdout)
    if (checked.get("decision") != "verified-report-integrity"
            or checked.get("replay_decision") != "pass"
            or checked.get("unsupported_optional_vectors") != []):
        raise ValueError("public check requires a complete passing replay, not report integrity alone")
    return checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("python", "typescript", "go", "all"), default="all")
    parser.add_argument("--revision", help="base source commit for an exported source tree; defaults to this checkout's HEAD")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ecl-public-check-") as folder:
        temp = Path(folder)
        if args.language in ("python", "all"):
            run([sys.executable, "-m", "pytest", "tests", "packages/ecl-verify/tests"])
            report = temp / "python.json"
            try:
                run(
                    [
                        sys.executable,
                        "scripts/run_python_corpus.py",
                        "--report",
                        str(report),
                    ]
                )
            except subprocess.CalledProcessError:
                if report.is_file():
                    failures = [
                        row
                        for row in json.loads(report.read_bytes())["results"]
                        if row["status"] != "met"
                    ]
                    print(json.dumps({"python_corpus_failures": failures}), file=sys.stderr)
                raise
            run(
                [
                    sys.executable,
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "examples/bounded_workflow",
                    "-p",
                    "test_*.py",
                    "-v",
                ]
            )
        if args.language in ("typescript", "all"):
            package = ROOT / "packages/ecl-ts"
            run(["npm", "ci", "--ignore-scripts"], package)
            run(["npm", "run", "build"], package)
            run(["npm", "test"], package)
            run(["node", "packages/ecl-ts/scripts/check-corpus.mjs"])
            source = temp / "typescript-source"
            export_typescript_source(package, source)
            report = temp / "typescript.json"
            run(["node", "packages/ecl-ts/scripts/run-corpus.mjs", "--repo-root", str(ROOT),
                 "--source-root", str(source), "--report", str(report),
                 "--revision", source_revision(ROOT, args.revision)])
            verify_corpus_report(report, source, root=ROOT)
        if args.language in ("go", "all"):
            module = ROOT / "go/crosscheck"
            run(["go", "test", "./..."], module)
            run(
                [
                    "go",
                    "run",
                    "./cmd/ecl-corpus-check",
                    "--repo-root",
                    "../..",
                    "--report",
                    str(temp / "go.json"),
                    "--revision",
                    source_revision(ROOT, args.revision),
                ],
                module,
            )
            verify_corpus_report(temp / "go.json", module, root=ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
