"""Add explicit corpus metadata to an exact replay of the existing Python runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.run_conformance import run  # noqa: E402
from scripts.shared_corpus import OPTIONAL, REQUIRED, build  # noqa: E402


def replay(root: Path) -> dict[str, Any]:
    corpus = build(root)
    report = run(root)
    expected = {row["id"] for row in corpus["vectors"]}
    if {row["id"] for row in report["results"]} != expected or report["vector_count"] != len(
        expected
    ):
        raise ValueError("Python replay does not cover the declared corpus")
    return {
        "schema_version": "ecl_python_corpus_result_v1",
        "candidate_version": report["candidate_version"],
        "corpus_version": corpus["version"],
        "capabilities": [*REQUIRED, *OPTIONAL],
        "corpus_sha256": hashlib.sha256(
            (root / "conformance/shared-corpus.json").read_bytes()
        ).hexdigest(),
        "results": [
            {
                **{key: value for key, value in row.items() if key != "decision"},
                "status": "met" if row["decision"] == "pass" else "not-met",
            }
            for row in report["results"]
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    value = replay(args.root)
    with args.report.open("xb") as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
    return int(any(row["status"] != "met" for row in value["results"]))


if __name__ == "__main__":
    raise SystemExit(main())
