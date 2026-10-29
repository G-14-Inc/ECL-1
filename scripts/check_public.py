"""Run the public package's checks without the private platform or release tooling."""

from __future__ import annotations

import argparse
import json
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("python", "typescript", "go", "all"), default="all")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ecl-public-check-") as folder:
        temp = Path(folder)
        if args.language in ("python", "all"):
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
                    "0" * 40,
                ],
                module,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
