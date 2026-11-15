#!/usr/bin/env python3
"""Synthetic MCP release-progress and completion controls (MG1-014/015).

Robert F. Tilley Jr.; G-14, Inc. These unsigned records are test data, not
observations reconstructed from historical gateway executions.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = Path("tests/fixtures/mcp-release-progress-regressions")
SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1"
BINDING = "ecl.ext.mcp-binding.v1"
FORWARD = "ecl.rule.mcp-forward-requires-admit.v1"
RESULT = "ecl.rule.mcp-result-bound.v1"


def load(name: str, *, corpus: bool = False) -> dict:
    directory = "conformance/suites/mcp-gateway" if corpus else "tests/fixtures/mcp-public-review-repairs"
    return json.loads((ROOT / directory / (name + ".json")).read_bytes())


def binding(record: dict) -> dict:
    return next(item["value"] for item in record["terminal"]["extensions"] if item["id"] == BINDING)


def denied(record: dict) -> None:
    event = record["terminal"]["event"]
    event["state"] = "denied"
    event.pop("authority", None)
    event.pop("residual_state", None)


def build() -> dict[str, object]:
    outputs: dict[str, object] = {}
    cases = []

    def add(name: str, record: dict, valid: bool, rules: tuple[str, ...] = ()) -> None:
        path = str(DEST / (name + ".json"))
        outputs[path] = copy.deepcopy(record)
        cases.append({"id": name, "path": path, "valid": valid, "expected_rules": list(rules)})

    early = load("unconsumed-halt-refusal")
    late = load("consumed-halt-refusal")
    add("pre-consumption-control-refusal", early, True)
    add("prepared-final-control-refusal", late, True)
    missing = copy.deepcopy(late)
    missing.pop("prepared")
    add("final-without-prepared-cancelled", missing, False, (FORWARD,))
    denied(missing)
    add("final-without-prepared-denied", missing, False, (FORWARD, RESULT))
    missing.pop("terminal")
    add("final-without-prepared-terminal", missing, False, (FORWARD, RESULT))

    # A discharge is step 4 evidence even when the final step 5 observation is absent.
    discharged = load("obligations-complete-control")
    refused = copy.deepcopy(late)
    for key in ("decision", "decision_request", "prepared", "terminal", "obligation_discharge"):
        refused[key] = copy.deepcopy(discharged[key])
    refused["terminal"]["event"]["state"] = "cancelled"
    refused["terminal"]["event"]["side_effects"] = []
    refused["terminal"]["event"]["residual_state"] = "The gateway did not write the request to the server."
    refused["terminal"]["extensions"] = copy.deepcopy(late["terminal"]["extensions"])
    # Keep the matching request identifier in the returned refusal.
    refused["returned"]["error"]["data"]["ecl"]["request_id"] = refused["decision_request"]["message_id"]
    add("discharged-prepared-final-refusal", refused, True)
    missing = copy.deepcopy(refused)
    missing.pop("prepared")
    denied(missing)
    add("discharged-without-prepared-denied", missing, False, (FORWARD, RESULT))
    # This is an invalid early refusal carrying impossible later discharge evidence.
    missing["release_observations"].pop("final")
    missing["release_observations"]["initial"]["control_state"]["halt"] = True
    add("discharged-before-consumption-denied", missing, False, (FORWARD, RESULT))

    base = load("forward-complete-control")
    add("answered-with-completion", base, True)
    for label, remove_forwarded, remove_terminal in (
        ("both-absent", True, True), ("terminal-only", True, False),
        ("forwarded-only", False, True), ("mismatch", False, False),
    ):
        value = copy.deepcopy(base)
        if remove_forwarded:
            value["forwarded"].pop("forward_completed_at")
        if remove_terminal:
            binding(value).pop("forward_completed_at")
        if label == "mismatch":
            binding(value)["forward_completed_at"] = "2026-09-30T09:00:00.390000Z"
        add("answered-completion-" + label, value, False, (RESULT,))

    recovered = load("recovered-response-control")
    add("recovered-answer-with-completion", recovered, True)
    for server in (True, False):
        prefix = "recovered-answer" if server else "recovered-no-answer"
        for label, remove_forwarded, remove_terminal in (
            ("both-absent", True, True), ("terminal-only", True, False),
            ("forwarded-only", False, True), ("mismatch", False, False),
        ):
            value = copy.deepcopy(recovered)
            if not server:
                value.pop("server_response")
            if remove_forwarded:
                value["forwarded"].pop("forward_completed_at")
            if remove_terminal:
                binding(value).pop("forward_completed_at")
            if label == "mismatch":
                binding(value)["forward_completed_at"] = "2026-09-30T09:00:00.390000Z"
            valid = label == "both-absent"
            add(prefix + "-completion-" + label, value, valid, () if valid else (RESULT,))

    for name in (
        "mcp-valid-recovered-outcome-unknown", "mcp-valid-recovered-not-released",
        "mcp-valid-recovered-unconsumed-admit-denied", "mcp-valid-recorded-admit-denied",
        "mcp-valid-recovered-unverified-decision-denied",
    ):
        add(name.removeprefix("mcp-valid-"), load(name, corpus=True), True)
    add("ordinary-no-answer-unknown", load("forward-failed-complete-control"), True)
    outputs[str(DEST / "manifest.json")] = {
        "schema": SCHEMA,
        "authors_and_producers": ["Robert F. Tilley Jr.", "G-14, Inc."],
        "requirements": ["MG1-010", "MG1-014", "MG1-015", "MG1-016", "MG1-017"],
        "status": "synthetic unsigned regression controls; no historical observation claim",
        "cases": cases,
    }
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = build()
    changed = []
    for relative, value in outputs.items():
        data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        path = ROOT / relative
        if not path.exists() or path.read_bytes() != data:
            changed.append(relative)
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
    print(json.dumps({"cases": len(outputs) - 1, "changed_files": len(changed)}))
    if args.check and changed:
        raise SystemExit("generated MCP release-progress records differ: " + ", ".join(changed))


if __name__ == "__main__":
    main()
