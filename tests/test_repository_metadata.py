"""Repository metadata checks preserve adversarial scenarios and review workflow states."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "repository_metadata", ROOT / "scripts/check_repository_metadata.py"
)
assert SPEC and SPEC.loader
metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(metadata)


def review():
    return json.loads((ROOT / "governance/review-disposition-log-template.json").read_text())


def scenario(name="1-knight-2012"):
    return json.loads((ROOT / f"conformance/scenarios/record-{name}.json").read_text())


def step(value, identifier):
    return next(item for item in value["steps"] if item["step"] == identifier)


def duplicate(comment, original):
    comment["disposition"] = {
        "category": "duplicate",
        "response": "Original disposition applies.",
        "duplicate_of": original,
        "decided": "2000-03-15",
        "decided_by": "editors",
    }


def shape_cases():
    cases = []

    def add(name, value, change, valid):
        value = copy.deepcopy(value)
        change(value)
        cases.append((name, value, valid))

    for version in (
        "1.0",
        "1.0.1",
        "1.0.2-review.1",
        "1.0-public-review.1",
        "2.0.0",
        "0.0-example.0",
    ):
        add(
            "draft-version-" + version,
            review(),
            lambda x, v=version: x["review"].update(draft_version=v),
            True,
        )
        value = review()
        value["comments"][0]["disposition"] = {
            "category": "deferred",
            "response": "Scheduled for later review.",
            "deferred_to": version,
            "decided": "2000-03-15",
            "decided_by": "editors",
        }
        cases.append(("deferred-version-" + version, value, True))
    for document in (
        ".",
        "..",
        "../standard/ECL-1_Standard.md",
        "standard/../README.md",
        "standard/./README.md",
        "a/..",
        "a/.",
    ):
        add(
            "path-" + document,
            review(),
            lambda x, d=document: x["comments"][0]["target"].update(document=d),
            False,
        )
    for document in (
        ".github/ISSUE_TEMPLATE/public-review.yml",
        "standard/ECL-1_Standard.md",
        "a/.../file.md",
        "README.md",
    ):
        add(
            "path-" + document,
            review(),
            lambda x, d=document: x["comments"][0]["target"].update(document=d),
            True,
        )
    add(
        "version-trailing-newline",
        review(),
        lambda x: x["review"].update(draft_version="1.0\n"),
        False,
    )
    add(
        "path-trailing-newline",
        review(),
        lambda x: x["comments"][0]["target"].update(document="README.md\n"),
        False,
    )
    for date in ("2026-02-31", "2026-04-31", "1900-02-29", "0000-01-01"):
        add("review-date-" + date, review(), lambda x, d=date: x["review"].update(opened=d), False)
    add("review-leap-date", review(), lambda x: x["review"].update(opened="2000-02-29"), True)
    add("missing-credit", review(), lambda x: x["comments"][0]["submitter"].pop("credit"), False)
    add(
        "missing-category",
        review(),
        lambda x: x["comments"][0]["disposition"].pop("category"),
        False,
    )
    for date in (
        "2026-01-00T00:00:00Z",
        "2026-02-31T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "0000-01-01T00:00:00Z",
    ):
        add("scenario-date-" + date, scenario(), lambda x, d=date: x.update(start_at=d), False)
    add("scenario-leap-date", scenario(), lambda x: x.update(start_at="2000-02-29T00:00:00Z"), True)
    add("step-origin-required", scenario(), lambda x: x["steps"][0].pop("origin"), False)
    add(
        "added-note-required",
        scenario(),
        lambda x: (x["steps"][0].update(origin="added"), x["steps"][0].pop("note")),
        False,
    )
    add("record-note-optional", scenario(), lambda x: x["steps"][0].pop("note"), True)
    add("count-outside-first", scenario(), lambda x: step(x, "s4")["expect"].update(count=1), False)
    add(
        "count-in-rest",
        scenario(),
        lambda x: step(x, "s7")["expect"]["rest"].update(count=1),
        False,
    )
    add(
        "count-above-repeat-ceiling",
        scenario(),
        lambda x: step(x, "s7")["expect"]["first"].update(count=101),
        False,
    )
    add(
        "first-count-required",
        scenario(),
        lambda x: step(x, "s7")["expect"]["first"].pop("count"),
        False,
    )
    add("split-requires-repeat", scenario(), lambda x: step(x, "s7").pop("repeat"), False)
    add(
        "spacing-requires-repeat",
        scenario(),
        lambda x: step(x, "s4").update(spacing_seconds=1),
        False,
    )
    add(
        "nonfirst-decide-count",
        scenario("25-openclaw-2026"),
        lambda x: step(x, "s5")["expect"].update(count=1),
        False,
    )
    return cases


def semantic_cases():
    cases = []

    def add(name, value, change, code):
        value = copy.deepcopy(value)
        change(value)
        cases.append((name, value, code))

    add(
        "duplicate-comment-id",
        review(),
        lambda x: x["comments"][1].update(comment_id=x["comments"][0]["comment_id"]),
        "duplicate-id",
    )
    add(
        "self-duplicate",
        review(),
        lambda x: duplicate(x["comments"][0], "PR1-0001"),
        "duplicate-self-reference",
    )
    add(
        "duplicate-cycle",
        review(),
        lambda x: duplicate(x["comments"][0], "PR1-0002"),
        "duplicate-cycle",
    )
    add(
        "backwards-review-window",
        review(),
        lambda x: x["review"].update(closes="1999-12-31"),
        "date-order",
    )
    add(
        "backwards-further-review",
        review(),
        lambda x: x["review"].update(
            further_review_of_changes={
                "review_id": "PR2",
                "opened": "2000-05-01",
                "closes": "2000-04-01",
            }
        ),
        "date-order",
    )
    add(
        "decision-before-receipt",
        review(),
        lambda x: x["comments"][0]["disposition"].update(decided="2000-01-09"),
        "date-order",
    )
    add(
        "appeal-before-receipt",
        review(),
        lambda x: x["comments"][0].update(appeal={"filed": "2000-01-09", "status": "pending"}),
        "date-order",
    )
    for collection in (
        "principals",
        "inputs",
        "action_classes",
        "budgets",
        "detections",
        "versions",
    ):
        add(
            "duplicate-" + collection,
            scenario(),
            lambda x, c=collection: x["deployment"][c].append(copy.deepcopy(x["deployment"][c][0])),
            "duplicate-id",
        )
    add(
        "duplicate-window",
        scenario("22-replit-2025"),
        lambda x: x["deployment"]["windows"].append(copy.deepcopy(x["deployment"]["windows"][0])),
        "duplicate-id",
    )
    add(
        "duplicate-control",
        scenario("27-openai-hf-2026"),
        lambda x: x["deployment"]["controls"].append(copy.deepcopy(x["deployment"]["controls"][0])),
        "duplicate-id",
    )
    add(
        "duplicate-path",
        scenario("29-openai-dns-2026"),
        lambda x: x["deployment"]["claim_boundary"]["reachable_paths"].append(
            copy.deepcopy(x["deployment"]["claim_boundary"]["reachable_paths"][0])
        ),
        "duplicate-id",
    )
    add("duplicate-step", scenario(), lambda x: x["steps"][1].update(step="s1"), "duplicate-id")
    add(
        "source-identity",
        scenario(),
        lambda x: x.update(scenario_id="record-2-knight-2012"),
        "source-reference",
    )
    add(
        "source-url",
        scenario(),
        lambda x: x["source"].update(url="https://externalcontrollayer.ai/record-2"),
        "source-reference",
    )
    add("uncoded-gap", scenario(), lambda x: x["gaps_exercised"].append("G1"), "gap-reference")
    add(
        "extra-requirement",
        scenario(),
        lambda x: x["requirements"].append("ECL1N-9999"),
        "requirement-union",
    )
    add("missing-requirement", scenario(), lambda x: x["requirements"].pop(), "requirement-union")
    add(
        "unknown-budget",
        scenario(),
        lambda x: x["deployment"]["action_classes"][0].update(budget="missing-budget"),
        "declaration-reference",
    )
    add(
        "unknown-required-input",
        scenario(),
        lambda x: x["deployment"]["action_classes"][0].update(requires_inputs=["missing-input"]),
        "declaration-reference",
    )
    add(
        "unknown-statement-reference",
        scenario("14-chevrolet-2023"),
        lambda x: x["deployment"]["action_classes"][1]["statement_check"].update(
            reference="missing-input"
        ),
        "declaration-reference",
    )
    add(
        "unknown-approval-class",
        scenario(),
        lambda x: x["deployment"]["principals"][1].update(approves=["missing-class"]),
        "declaration-reference",
    )
    add(
        "unknown-lift-permission",
        scenario(),
        lambda x: x["deployment"]["principals"][1].update(lifts=["missing-detection"]),
        "declaration-reference",
    )
    add(
        "unknown-control-permission",
        scenario(),
        lambda x: x["deployment"]["principals"][1].update(
            approves_control_changes=["missing-control"]
        ),
        "declaration-reference",
    )
    add(
        "unknown-window-class",
        scenario("22-replit-2025"),
        lambda x: x["deployment"]["windows"][0].update(classes=["missing-class"]),
        "declaration-reference",
    )
    add(
        "unknown-detection-class",
        scenario(),
        lambda x: x["deployment"]["detections"][0].update(classes=["missing-class"]),
        "declaration-reference",
    )
    add(
        "unknown-control-class",
        scenario("27-openai-hf-2026"),
        lambda x: x["deployment"]["controls"][0].update(classes=["missing-class"]),
        "declaration-reference",
    )
    add(
        "unknown-control-detection",
        scenario("27-openai-hf-2026"),
        lambda x: x["deployment"]["controls"][0].update(detection="missing-detection"),
        "declaration-reference",
    )
    add(
        "window-order",
        scenario("22-replit-2025"),
        lambda x: x["deployment"]["windows"][0].update(until=3599),
        "window-order",
    )
    add(
        "unknown-detection-step",
        scenario(),
        lambda x: next(s for s in x["steps"] if s["kind"] == "detection").update(
            detection="missing-detection"
        ),
        "declaration-reference",
    )
    add(
        "unknown-control-step",
        scenario("27-openai-hf-2026"),
        lambda x: next(s for s in x["steps"] if s["kind"] == "control_change").update(
            control="missing-control"
        ),
        "declaration-reference",
    )
    add(
        "outage-declaration",
        scenario(),
        lambda x: x["deployment"].pop("cached_decision_state"),
        "outage-declaration",
    )
    for name, target in (
        ("missing-target", "s999"),
        ("self-target", "s7"),
        ("later-target", "s9"),
        ("nonproposal-target", "s5"),
    ):
        add(
            name,
            scenario("25-openclaw-2026"),
            lambda x, t=target: step(x, "s7").update(target_step=t),
            "target-step",
        )
    add(
        "decision-before-target-time",
        scenario("25-openclaw-2026"),
        lambda x: step(x, "s7").update(at=0),
        "target-step",
    )
    add(
        "index-out-of-range",
        scenario("25-openclaw-2026"),
        lambda x: step(x, "s5").update(index=31),
        "proposal-index",
    )
    add(
        "proposal-count-too-large",
        scenario(),
        lambda x: step(x, "s7")["expect"]["first"].update(count=31),
        "proposal-count",
    )
    add(
        "decide-count-too-large",
        scenario("25-openclaw-2026"),
        lambda x: step(x, "s7")["expect"]["first"].update(count=31),
        "proposal-count",
    )
    add(
        "indexed-decision-cannot-split",
        scenario("25-openclaw-2026"),
        lambda x: step(x, "s7").update(index=1),
        "proposal-count",
    )
    value = scenario("25-openclaw-2026")
    value["steps"] = [step(value, "s2"), step(value, "s7")]
    value["requirements"] = sorted({r for s in value["steps"] for r in s.get("requirements", [])})
    value["steps"][1]["expect"] = {
        "first": {"count": 30, "outcome": "deny", "effect": "none"},
        "rest": {"outcome": "admit", "effect": "committed"},
    }
    cases.append(("empty-rest-cannot-satisfy-positive", value, "positive-effect"))
    value = scenario("23-postmark-2025")
    for item in value["steps"]:
        if item["kind"] == "propose":
            item["expect"] = {"outcome": "deny", "effect": "none"}
    cases.append(("refuse-everything", value, "positive-effect"))
    return cases


def preserved_cases():
    cases = []
    for path in sorted((ROOT / "conformance/scenarios").glob("*.json")):
        cases.append((path.stem, json.loads(path.read_text())))
    cases.append(("intentional-template", review()))
    value = review()
    value["review"]["status"] = "dispositions-published"
    value["comments"][0]["appeal"] = {"filed": "2000-03-16", "status": "pending"}
    cases.append(("published-disposition-pending-appeal", value))
    value = review()
    value["comments"][0]["appeal"] = {"filed": "2000-03-14", "status": "overturned"}
    value["comments"][0]["disposition"]["decided_by"] = "chair"
    cases.append(("appeal-before-updated-chair-disposition", value))
    value = review()
    duplicate(value["comments"][1], "PR0-0001")
    cases.append(("external-original", value))
    value = review()
    value["comments"][0]["detail_withheld_until_disclosure"] = True
    cases.append(("public-record-with-detail-withheld", value))
    value = review()
    value["comments"][0]["received"] = "1999-12-31"
    cases.append(("comment-carried-from-earlier-window", value))
    value = review()
    value["comments"] = []
    cases.append(("empty-review-log", value))
    value = scenario()
    value["deployment"]["principals"][0].update(halts=True, revokes=True, reviews_changes=True)
    value["deployment"]["principals"][1]["acts_for"] = "urn:example:external:organization"
    cases.append(("adversarial-principal-declarations", value))
    for input_class in ("actor_supplied", "judgment"):
        value = scenario()
        value["deployment"]["inputs"].append(
            {
                "id": "untrusted-reference",
                "class": input_class,
                "source": "An untrusted claim about a source of record.",
                "origin": "system-of-record",
                "content": {"claimed": True},
            }
        )
        cases.append(("untrusted-content-" + input_class, value))
    value = scenario("22-replit-2025")
    value["deployment"]["windows"][0]["classes"] = []
    cases.append(("empty-window-class-set", value))
    value = scenario("22-replit-2025")
    value["deployment"]["windows"][0]["until"] = value["deployment"]["windows"][0]["from"]
    cases.append(("empty-window-interval", value))
    value = scenario()
    value["deployment"]["detections"][0]["classes"] = []
    cases.append(("empty-detection-class-set", value))
    value = scenario("25-openclaw-2026")
    step(value, "s7")["expect"]["first"]["count"] = 30
    cases.append(("empty-rest-permitted", value))
    value = scenario()
    step(value, "s7")["repeat"] = 100
    step(value, "s7")["expect"]["first"]["count"] = 100
    cases.append(("repeat-ceiling-all-first", value))
    value = scenario("23-postmark-2025")
    value["steps"][0]["actor"] = "urn:example:agent:undeclared"
    cases.append(("unknown-actor-remains-testable", value))
    value = scenario()
    value["source"]["credit"] = "An independently worded source attribution."
    value["title"] = "A revised scenario title"
    cases.append(("narrative-variation", value))
    return cases


SHAPE = shape_cases()
SEMANTIC = semantic_cases()
PRESERVED = preserved_cases()


@pytest.mark.parametrize("name,value,valid", SHAPE, ids=[item[0] for item in SHAPE])
def test_metadata_shape(name, value, valid):
    result = metadata.check_document(value)
    schema_errors = [item for item in result["errors"] if item["code"] == "metadata-schema"]
    assert (not schema_errors) is valid, (name, result)


@pytest.mark.parametrize("name,value,code", SEMANTIC, ids=[item[0] for item in SEMANTIC])
def test_metadata_consistency(name, value, code):
    result = metadata.check_document(value)
    codes = [item["code"] for item in result["errors"]]
    assert "metadata-schema" not in codes, (name, result)
    assert not result["valid"] and code in codes, (name, result)


@pytest.mark.parametrize("name,value", PRESERVED, ids=[item[0] for item in PRESERVED])
def test_preserved_metadata(name, value):
    assert metadata.check_document(value)["valid"], (name, metadata.check_document(value))


def test_external_original_reported_without_resolution():
    value = review()
    duplicate(value["comments"][1], "PR0-0001")
    result = metadata.check_document(value)
    assert result["valid"]
    assert [item["code"] for item in result["notices"]] == ["external-comment-unchecked"]


@pytest.mark.parametrize(
    "text",
    ['{"schema_version":"a","schema_version":"b"}', '{"x":NaN}', '{"x":1.0}', '{"x":"\\ud800"}'],
)
def test_strict_input(tmp_path, text):
    path = tmp_path / "invalid.json"
    path.write_text(text)
    result = metadata.check_file(path)
    assert not result["valid"]
    assert result["errors"][0]["code"] == "metadata-input"


def test_cli_default_and_refusal(tmp_path):
    run = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_repository_metadata.py")],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    result = json.loads(run.stdout)
    assert run.returncode == 0, result
    assert result["valid"] and len(result["files"]) == 11
    path = tmp_path / "wrong.json"
    path.write_text('{"schema_version":[]}')
    run = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_repository_metadata.py"), str(path)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    result = json.loads(run.stdout)
    assert run.returncode == 1 and not result["valid"]
    assert result["files"][0]["errors"][0]["code"] == "metadata-schema"


def test_missing_file(tmp_path):
    result = metadata.check_file(tmp_path / "absent.json")
    assert not result["valid"] and result["errors"][0]["code"] == "metadata-input"


def test_long_duplicate_chain_and_cycle():
    value = review()
    original = value["comments"][0]
    value["comments"] = []
    for index in range(1, 1201):
        comment = copy.deepcopy(original)
        comment["comment_id"] = f"PR1-{index:04}"
        if index > 1:
            duplicate(comment, f"PR1-{index - 1:04}")
        value["comments"].append(comment)
    assert metadata.check_document(value)["valid"]
    duplicate(value["comments"][0], "PR1-1200")
    result = metadata.check_document(value)
    assert [error["code"] for error in result["errors"]] == ["duplicate-cycle"]


def test_identifiers_are_unique_per_collection():
    value = scenario()
    old_budget_id = value["deployment"]["budgets"][0]["id"]
    new_budget_id = value["deployment"]["action_classes"][0]["id"]
    value["deployment"]["budgets"][0]["id"] = new_budget_id
    for action in value["deployment"]["action_classes"]:
        if action.get("budget") == old_budget_id:
            action["budget"] = new_budget_id
    assert metadata.check_document(value)["valid"]


def test_schema_diagnostics_are_bounded():
    value = review()
    value["comments"] = [copy.deepcopy(value["comments"][0]) for _ in range(200)]
    for comment in value["comments"]:
        comment["summary"] = ""
    result = metadata.check_document(value)
    assert not result["valid"] and len(result["errors"]) == 100
    assert result["notices"] == [
        {"code": "diagnostics-truncated", "path": "/", "message": "Stopped after 100 schema errors."}
    ]
