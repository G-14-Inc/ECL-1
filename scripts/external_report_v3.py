"""Compare applicable version 3 observations with the frozen corpus expectations."""
from __future__ import annotations
from collections.abc import Callable
from pathlib import Path
from typing import Any
from scripts.external_report_v2 import TreeReader, _verify_bound_report
from scripts.scope_expectations import effect_identifiers_nonblank, scope_expectation_matches

OBSERVATIONS = {
    "expected_verdict": "observed_verdict",
    "expected_scope": "observed_scope",
    "expected_effects": "observed_effects",
    "expected_unresolved_predecessor_ids": "observed_unresolved_predecessor_ids",
    "expected_canonical_sha256": "observed_canonical_sha256",
}


def observations_match(row: dict[str, Any], vector: dict[str, Any]) -> bool:
    """Require applicable observations; null records an unavailable observation.

    Scope lists and reasons compare exactly; levels compare for every terminal of
    each named action; unresolved predecessors compare as a set. A negative
    canonical vector's digest placeholder is not a digest expectation.
    """
    due = {observed for expected, observed in OBSERVATIONS.items() if expected in vector}
    if row["status"] == "unsupported":
        due = set()
    present = set(row) & set(OBSERVATIONS.values())
    if present != due:
        raise ValueError(f"{row['id']}: observation members differ; missing={sorted(due-present)}, unexpected={sorted(present-due)}")
    if row["status"] == "unsupported":
        return True
    met = True
    for expected, observed in OBSERVATIONS.items():
        if observed not in due:
            continue
        actual, want = row[observed], vector[expected]
        if expected == "expected_canonical_sha256" and vector["expected"] == "fail":
            continue
        if actual is None:
            met = False
        elif expected == "expected_unresolved_predecessor_ids":
            met = met and len(actual) == len(set(actual)) and set(actual) == set(want)
        elif expected == "expected_effects":
            met = met and effect_identifiers_nonblank(actual) and all(
                {item["level"] for item in actual if item["action_id"] == e["action_id"]} == {e["level"]}
                for e in want
            )
        elif expected == "expected_scope":
            met = met and scope_expectation_matches(actual, want)
        else:
            met = met and actual == want
    return met


def verify_v3(
    root: Path, report: dict[str, Any], *, evidence_root: Path | None,
    implementation_root: Path | None, source_tree: TreeReader,
    confined_file: Callable[[Path, str], Path], sha256_file: Callable[[Path], str],
) -> dict[str, Any]:
    return _verify_bound_report(root, report, evidence_root=evidence_root,
        implementation_root=implementation_root, source_tree=source_tree,
        confined_file=confined_file, sha256_file=sha256_file, version=3,
        observation_check=observations_match)
