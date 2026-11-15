#!/usr/bin/env python3
"""Check local review logs and incident scenarios; never run a replay or close a review.

With no arguments, check the repository's disposition-log template and incident scenarios.
Otherwise check the named JSON files. Output is JSON; exit 1 means at least one file failed.
The strict parser's byte, depth and value limits apply. Only the two local schemas are used.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "ecl-verify" / "src"))

from referencing import Registry  # noqa: E402

from ecl_verify.canonical import CanonicalizationError, load_json_strict  # noqa: E402
from ecl_verify.schema import ecl_format_checker  # noqa: E402
from ecl_verify.schema_patterns import schema_validator  # noqa: E402

SCHEMAS = {
    "ecl_review_disposition_log_v1": "ecl-review-disposition-log-v1.schema.json",
    "ecl_incident_scenario_v1": "ecl-incident-scenario-v1.schema.json",
}


def _issue(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _unique(
    rows: list[dict[str, Any]], member: str, path: str, errors: list[dict[str, str]]
) -> dict[str, dict[str, Any]]:
    result = {}
    for index, row in enumerate(rows):
        identifier = row[member]
        if identifier in result:
            errors.append(
                _issue(
                    "duplicate-id",
                    f"{path}/{index}/{member}",
                    "Identifier repeats within this collection.",
                )
            )
        else:
            result[identifier] = row
    return result


def _review_checks(
    value: dict[str, Any], errors: list[dict[str, str]], notices: list[dict[str, str]]
) -> None:
    review = value["review"]
    for period, path in [
        (review, "/review"),
        (review.get("further_review_of_changes"), "/review/further_review_of_changes"),
    ]:
        if period is not None and period["opened"] > period["closes"]:
            errors.append(_issue("date-order", path, "Opening date follows closing date."))
    comments = _unique(value["comments"], "comment_id", "/comments", errors)
    edges = {}
    for index, comment in enumerate(value["comments"]):
        path = f"/comments/{index}"
        disposition = comment["disposition"]
        if disposition["decided"] < comment["received"]:
            errors.append(
                _issue(
                    "date-order",
                    path + "/disposition/decided",
                    "Disposition predates receipt of the comment.",
                )
            )
        if "appeal" in comment and comment["appeal"]["filed"] < comment["received"]:
            errors.append(
                _issue(
                    "date-order", path + "/appeal/filed", "Appeal predates receipt of the comment."
                )
            )
        if disposition["category"] != "duplicate":
            continue
        original = disposition["duplicate_of"]
        if original == comment["comment_id"]:
            errors.append(
                _issue(
                    "duplicate-self-reference",
                    path + "/disposition/duplicate_of",
                    "A comment cannot be its own original.",
                )
            )
        elif original not in comments:
            notices.append(
                _issue(
                    "external-comment-unchecked",
                    path + "/disposition/duplicate_of",
                    "The original is outside this log; its disposition was not checked.",
                )
            )
        else:
            edges[comment["comment_id"]] = original
    # Every node has at most one outgoing edge. An iterative walk bounds stack usage.
    done: set[str] = set()
    for start in edges:
        active: set[str] = set()
        current = start
        while current in edges and current not in done and current not in active:
            active.add(current)
            current = edges[current]
        if current in active:
            errors.append(
                _issue(
                    "duplicate-cycle",
                    "/comments",
                    "Duplicate dispositions form a cycle with no original disposition.",
                )
            )
        done.update(active)


def _scenario_checks(value: dict[str, Any], errors: list[dict[str, str]]) -> None:
    source = value["source"]
    if value["scenario_id"] != f"record-{source['entry']}-{source['key']}":
        errors.append(
            _issue(
                "source-reference",
                "/scenario_id",
                "Scenario identity differs from its source entry/key.",
            )
        )
    if source["url"] != f"https://externalcontrollayer.ai/record-{source['entry']}":
        errors.append(
            _issue("source-reference", "/source/url", "Source URL names a different entry.")
        )
    if not set(value["gaps_exercised"]).issubset(source["gaps_coded"]):
        errors.append(
            _issue(
                "gap-reference",
                "/gaps_exercised",
                "An exercised gap is not among the source's coded gaps.",
            )
        )
    required = {item for step in value["steps"] for item in step.get("requirements", [])}
    if set(value["requirements"]) != required:
        errors.append(
            _issue(
                "requirement-union",
                "/requirements",
                "Scenario requirements differ from the union of step requirements.",
            )
        )

    deployment = value["deployment"]
    collections = {
        name: _unique(
            deployment.get(name, []),
            "subject" if name == "versions" else "id",
            f"/deployment/{name}",
            errors,
        )
        for name in (
            "principals",
            "inputs",
            "action_classes",
            "budgets",
            "windows",
            "detections",
            "controls",
            "versions",
        )
    }
    boundary = deployment.get("claim_boundary", {})
    for name in ("reachable_paths", "negative_boundary_annex"):
        _unique(boundary.get(name, []), "path_id", f"/deployment/claim_boundary/{name}", errors)

    def reference(identifier: str, collection: str, path: str) -> None:
        if identifier not in collections[collection]:
            errors.append(
                _issue(
                    "declaration-reference", path, f"Reference has no declaration in {collection}."
                )
            )

    for index, action in enumerate(deployment["action_classes"]):
        path = f"/deployment/action_classes/{index}"
        if "budget" in action:
            reference(action["budget"], "budgets", path + "/budget")
        for member, identifier in enumerate(action.get("requires_inputs", [])):
            reference(identifier, "inputs", path + f"/requires_inputs/{member}")
        if "statement_check" in action:
            reference(
                action["statement_check"]["reference"],
                "inputs",
                path + "/statement_check/reference",
            )
    for index, principal in enumerate(deployment["principals"]):
        for field, target in (
            ("approves", "action_classes"),
            ("lifts", "detections"),
            ("approves_control_changes", "controls"),
        ):
            for member, identifier in enumerate(principal.get(field, [])):
                reference(identifier, target, f"/deployment/principals/{index}/{field}/{member}")
    for collection in ("windows", "detections", "controls"):
        for index, declaration in enumerate(deployment.get(collection, [])):
            path = f"/deployment/{collection}/{index}"
            for member, identifier in enumerate(declaration.get("classes", [])):
                reference(identifier, "action_classes", path + f"/classes/{member}")
            if collection == "controls" and "detection" in declaration:
                reference(declaration["detection"], "detections", path + "/detection")
            if collection == "windows" and declaration["from"] > declaration["until"]:
                errors.append(_issue("window-order", path, "A window cannot end before it begins."))

    steps = _unique(value["steps"], "step", "/steps", errors)
    positions = {step["step"]: index for index, step in enumerate(value["steps"])}
    positive_effect = False
    for index, step in enumerate(value["steps"]):
        path = f"/steps/{index}"
        kind = step["kind"]
        if kind in ("detection", "lift"):
            reference(step["detection"], "detections", path + "/detection")
        if kind in ("control_change", "control_observed"):
            reference(step["control"], "controls", path + "/control")
        if kind == "outage" and "cached_decision_state" not in deployment:
            errors.append(
                _issue(
                    "outage-declaration",
                    "/deployment/cached_decision_state",
                    "An outage scenario must declare whether cached decision state exists.",
                )
            )
        if kind not in ("propose", "decide"):
            continue
        population = step.get("repeat", 1)
        if kind == "decide":
            target = steps.get(step["target_step"])
            if (
                target is None
                or target["kind"] != "propose"
                or positions[step["target_step"]] >= index
                or target["at"] > step["at"]
            ):
                errors.append(
                    _issue(
                        "target-step",
                        path + "/target_step",
                        "A decision must target an earlier proposal step.",
                    )
                )
                continue
            population = target.get("repeat", 1)
            if "index" in step:
                if step["index"] > population:
                    errors.append(
                        _issue(
                            "proposal-index",
                            path + "/index",
                            "Index exceeds the target's proposal count.",
                        )
                    )
                    continue
                population = 1
        expectation = step["expect"]
        portions = [(population, expectation)]
        if "first" in expectation:
            count = expectation["first"]["count"]
            if population < 2 or count > population:
                errors.append(
                    _issue(
                        "proposal-count",
                        path + "/expect/first/count",
                        "A split needs repeated proposals and cannot exceed their selected count.",
                    )
                )
                continue
            portions = [(count, expectation["first"]), (population - count, expectation["rest"])]
        for count, portion in portions:
            outcome = portion["outcome"]
            allowed = outcome if isinstance(outcome, list) else [outcome]
            committed = portion["effect"] == "committed"
            if count and not any((item == "admit") == committed for item in allowed):
                errors.append(
                    _issue(
                        "outcome-effect",
                        path + "/expect",
                        "No allowed outcome agrees with the expected effect: an admitted proposal commits an effect, and another outcome commits none.",
                    )
                )
            if (
                count
                and "admit" in allowed
                and committed
            ):
                positive_effect = True
    if not positive_effect:
        errors.append(
            _issue(
                "positive-effect",
                "/steps",
                "A scenario must expect at least one admitted action with a committed effect.",
            )
        )


def check_document(value: Any, *, schema_dir: Path = ROOT / "schemas") -> dict[str, Any]:
    """Check a parsed metadata value. File callers should use check_file for strict parsing."""
    errors: list[dict[str, str]] = []
    notices: list[dict[str, str]] = []
    version = value.get("schema_version") if isinstance(value, dict) else None
    filename = SCHEMAS.get(version) if isinstance(version, str) else None
    if filename is None:
        errors.append(
            _issue(
                "metadata-schema",
                "/schema_version",
                "Expected a review disposition log or incident scenario.",
            )
        )
    else:
        schema = load_json_strict(schema_dir / filename)
        validator = schema_validator(
            schema, registry=Registry(), format_checker=ecl_format_checker()
        )
        for error in validator.iter_errors(value):
            path = "/" + "/".join(
                str(part).replace("~", "~0").replace("/", "~1") for part in error.absolute_path
            )
            errors.append(
                _issue("metadata-schema", path, f"Schema {error.validator} check failed.")
            )
            if len(errors) == 100:
                notices.append(
                    _issue("diagnostics-truncated", "/", "Stopped after 100 schema errors.")
                )
                break
        if not errors:
            if version == "ecl_review_disposition_log_v1":
                _review_checks(value, errors, notices)
            else:
                _scenario_checks(value, errors)
    return {"valid": not errors, "errors": errors, "notices": notices}


def check_file(path: Path) -> dict[str, Any]:
    try:
        result = check_document(load_json_strict(path))
    except (OSError, CanonicalizationError) as exc:
        result = {
            "valid": False,
            "errors": [_issue("metadata-input", "/", str(exc))],
            "notices": [],
        }
    return {"file": str(path), **result}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args()
    paths = args.files or [
        ROOT / "governance/review-disposition-log-template.json",
        *sorted((ROOT / "conformance/scenarios").glob("*.json")),
    ]
    results = [check_file(path) for path in paths]
    valid = all(result["valid"] for result in results)
    print(
        json.dumps(
            {"valid": valid, "scope": "repository metadata only", "files": results}, indent=2
        )
    )
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
