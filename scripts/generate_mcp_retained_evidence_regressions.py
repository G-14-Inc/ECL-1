"""Synthetic MCP completion and retained discharge regressions.

Robert F. Tilley Jr.; G-14, Inc. These records are authored test data.
"""
from pathlib import Path
import copy
import json

import argparse
import hashlib
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT
DEST = Path("tests/fixtures/mcp-retained-evidence-regressions")
RESULT = "ecl.rule.mcp-result-bound.v1"
OBLIGATION = "ecl.rule.mcp-obligations-discharged.v1"
FORWARD = "ecl.rule.mcp-forward-requires-admit.v1"
SCHEMA = "https://externalcontrollayer.ai/ns/schema/binding/mcp-gateway-exchange/1"
RETAINED_CONTROL = {'id': 'clock-intrinsic-proof-failure-control',
 'file': 'clock-intrinsic-proof-failure-control.json',
 'accepted': False,
 'schema_valid': True,
 'direct_accepted': False,
 'finding': '002',
 'rationale': 'Intrinsic obtained-after-checked failure retains earlier obligation refusal '
              'precedence, while the retained discharge itself is inconsistent.',
 'sha256': 'c9871dee8c11bd8902df600a345917a6692de23c217c1d1096029c456473e16f',
 'required_direct_rule': 'ecl.rule.mcp-obligations-discharged.v1'}
outputs = {}
BINDING = "ecl.ext.mcp-binding.v1"

def load(name, group="mcp-public-review-repairs"):
    return json.loads((SOURCE / "tests/fixtures" / group / (name + ".json")).read_bytes())

def binding(value):
    return next(item["value"] for item in value["terminal"]["extensions"] if item["id"] == BINDING)

cases = []
def add(name, value, purpose):
    outputs[str(DEST / (name + ".json"))] = copy.deepcopy(value)
    cases.append({"id": name, "path": str(DEST / (name + ".json")), "purpose": purpose})

answer = load("forward-complete-control")
no_answer = load("forward-failed-complete-control")
recovered = load("recovered-response-control")
for name, value in (("ordinary-answer", answer), ("ordinary-no-answer", no_answer), ("recovered-answer", recovered)):
    add(name + "-control", value, "Existing positive control")
    for label, completed in (("completion-after-terminal", "2026-09-30T09:00:05.000000Z"), ("completion-at-terminal", value["terminal"]["observed_at"]), ("completion-before-forward", "2026-09-30T09:00:00.200000Z")):
        changed = copy.deepcopy(value)
        changed["forwarded"]["forward_completed_at"] = completed
        binding(changed)["forward_completed_at"] = completed
        add(name + "-" + label, changed, "Retained completion chronology and missing-answer distinction")
    absent = copy.deepcopy(value)
    absent["forwarded"].pop("forward_completed_at", None)
    binding(absent).pop("forward_completed_at", None)
    add(name + "-completion-absent", absent, "Live answer requirement versus explicit recovery uncertainty")

# The recovery contract preserves outcomes even when the full response is unavailable.
for state in ("succeeded", "failed", "unknown"):
    value = copy.deepcopy(recovered)
    value.pop("server_response", None)
    value["terminal"]["event"]["state"] = state
    if state == "unknown":
        value["terminal"]["event"]["residual_state"] = "A recorded outcome is unresolved; the original response is unavailable."
        value["terminal"]["event"]["side_effects"] = []
    for absent in (False, True):
        changed = copy.deepcopy(value)
        if absent:
            changed["forwarded"].pop("forward_completed_at", None)
            binding(changed).pop("forward_completed_at", None)
        add("recorded-" + state + ("-completion-absent" if absent else "-completion-retained"), changed, "Known recovery outcome does not invent unavailable clock evidence")

discharged = load("discharged-prepared-final-refusal", "mcp-release-progress-regressions")
no_obligations = load("prepared-final-control-refusal", "mcp-release-progress-regressions")
stale = load("stale-proof-explicit-observation")
for name, value in (("discharged-step5-halt", discharged), ("no-obligations-step5-halt", no_obligations), ("discharged-step5-stale", stale)):
    add(name + "-control", value, "Valid post-discharge refusal, including stale-at-final proof")

for label in ("foreign-obligation", "duplicate-obligation", "proof-after-check", "unsatisfied", "missing-required"):
    value = copy.deepcopy(discharged)
    entries = value["obligation_discharge"]["obligations"]
    if label == "foreign-obligation": entries[0]["obligation_id"] = "urn:example:obligation:not-carried"
    if label == "duplicate-obligation": entries.append(copy.deepcopy(entries[0]))
    if label == "proof-after-check": entries[0]["proof"]["obtained_at"] = "2026-09-30T09:00:00.310000Z"
    if label == "unsatisfied": entries[0]["result"] = "unsatisfied"
    if label == "missing-required": entries.pop()
    add("step5-halt-" + label, value, "Retained discharge intrinsic validity regardless of earlier refusal cause")

value = copy.deepcopy(no_obligations)
value["obligation_discharge"] = copy.deepcopy(discharged["obligation_discharge"])
add("step5-halt-unrequested-discharge", value, "A discharge claims obligations absent from the admitted decision")

value = copy.deepcopy(discharged)
value["returned"]["error"]["code"] = -31011
value["returned"]["error"]["data"]["ecl"]["code"] = "evidence-unavailable"
value["returned"]["error"]["data"]["ecl"]["reason"] = "ecl.error.evidence-unavailable.v1"
for entry in value["terminal"]["extensions"]:
    if entry["id"] == "ecl.ext.outcome-reason.v1": entry["value"]["code"] = "ecl.error.evidence-unavailable.v1"
add("post-consumption-journal-control", value, "Journal failure keeps its explicit refusal precedence")
value["obligation_discharge"]["obligations"][0]["obligation_id"] = "urn:example:obligation:not-carried"
add("post-consumption-journal-foreign-discharge", value, "Journal exception does not make a retained discharge truthful")

# A transport failure does not mean that a JSON-RPC answer arrived.
value = copy.deepcopy(no_answer)
value["returned"]["error"]["message"] = "The transport failed before a complete server response arrived."
value["terminal"]["event"]["residual_state"] = "The stream broke; the effect remains unknown."
add("transport-error-without-answer", value, "A transport error is a forward-failed unknown outcome, not a server answer")
value["forwarded"]["forward_completed_at"] = "2026-09-30T09:00:00.380000Z"
binding(value)["forward_completed_at"] = "2026-09-30T09:00:00.380000Z"
add("transport-error-cannot-claim-answer-time", value, "Transport return alone does not establish MG1-015 answer arrival")

# A JSON-RPC error is an answer and legitimately has a completion observation.
value = copy.deepcopy(answer)
response = {"jsonrpc": "2.0", "id": value["call"]["id"], "error": {"code": -32603, "message": "Server execution failed."}}
value["server_response"] = copy.deepcopy(response)
value["returned"] = copy.deepcopy(response)
value["terminal"]["event"]["state"] = "failed"
binding(value)["response_digest"]["value"] = hashlib.sha256(json.dumps(response, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
add("jsonrpc-error-answer-with-completion", value, "A complete error response differs from a transport failure")
value["forwarded"].pop("forward_completed_at")
binding(value).pop("forward_completed_at")
add("jsonrpc-error-answer-missing-completion", value, "An ordinary error answer also requires completion")

for filename, label in (("mcp-valid-input-required-unknown", "answered-input-required-unknown"), ("mcp-valid-late-answer-inside-window", "answer-after-window-is-informational"), ("mcp-valid-recovered-outcome-unknown", "recovered-outcome-unknown-control")):
    value = json.loads((ROOT / "conformance/suites/mcp-gateway" / (filename + ".json")).read_bytes())
    add(label, value, "Existing accepted unknown-response, late-answer or uncertainty control")

value = copy.deepcopy(discharged)
value["release_observations"].pop("final")
value["returned"]["error"]["code"] = -31011
value["returned"]["error"]["data"]["ecl"]["code"] = "evidence-unavailable"
value["returned"]["error"]["data"]["ecl"]["reason"] = "ecl.error.evidence-unavailable.v1"
for entry in value["terminal"]["extensions"]:
    if entry["id"] == "ecl.ext.outcome-reason.v1": entry["value"]["code"] = "ecl.error.evidence-unavailable.v1"
add("discharged-journal-before-final-control", value, "A failed journal before the final observation retains valid discharge")
value["obligation_discharge"]["obligations"][0]["proof"]["obtained_at"] = "2026-09-30T09:00:00.310000Z"
add("discharged-journal-before-final-intrinsic-error", value, "An absent final observation does not hide intrinsic proof ordering")

value = copy.deepcopy(stale)
value["obligation_discharge"]["obligations"][0]["proof"]["obtained_at"] = "2026-09-30T09:00:00.310000Z"
add("stale-refusal-retains-intrinsic-error", value, "A correct stale-proof refusal cannot erase another retained-record contradiction")

value = copy.deepcopy(discharged)
value["obligation_discharge"]["obligations"][0]["checked_at"] = "2026-09-30T09:00:00.310000Z"
add("halt-refusal-check-after-final", value, "Step 4 check must precede a reliable Step 5 observation even when halt prevents release")
value["release_observations"]["final"]["clock_regressed"] = True
add("halt-refusal-unreliable-final-control", value, "An explicitly failed clock comparison cannot establish check-to-final ordering")
value["obligation_discharge"]["obligations"][0]["proof"]["obtained_at"] = "2026-09-30T09:00:00.320000Z"
add("halt-refusal-unreliable-final-intrinsic-error", value, "Failed final clock comparison does not excuse acquisition after check")

# Intrinsic validity applies even when no reliable final observation survives.
intrinsic_negatives = set()
for name, base in (("halt", discharged), ("unreliable-final", outputs[str(DEST / "halt-refusal-unreliable-final-control.json")]), ("journal-before-final", outputs[str(DEST / "discharged-journal-before-final-control.json")])):
    for label in ("expired-before-check", "expires-at-check", "fresh-after-check", "no-expiry"):
        value = copy.deepcopy(base)
        entry = value["obligation_discharge"]["obligations"][0]
        if label == "no-expiry": entry.pop("fresh_until", None)
        else: entry["fresh_until"] = {"expired-before-check":"2026-09-30T08:00:00.000000Z", "expires-at-check":entry["checked_at"], "fresh-after-check":"2026-09-30T09:00:01.000000Z"}[label]
        name_id = name + "-" + label
        add(name_id, value, "A satisfied proof must be fresh when checked; an absent bound asserts no expiry")
        if label in ("expired-before-check", "expires-at-check"): intrinsic_negatives.add(name_id)

value = copy.deepcopy(outputs[str(DEST / "discharged-journal-before-final-intrinsic-error.json")])
value["returned"]["error"]["code"] = -31010
value["returned"]["error"]["data"]["ecl"].update(code="obligation-unproven", reason="ecl.error.obligation-unproven.v1")
for entry in value["terminal"]["extensions"]:
    if entry["id"] == "ecl.ext.outcome-reason.v1": entry["value"]["code"] = "ecl.error.obligation-unproven.v1"
add("intrinsic-failure-before-final-obligation-refusal", value, "Intrinsic proof failure establishes refusal precedence without a final clock observation")
intrinsic_negatives.add("intrinsic-failure-before-final-obligation-refusal")

unanswered_negatives = set()
for name in ("ordinary-no-answer-control", "recovered-outcome-unknown-control", "recorded-unknown-completion-absent", "recorded-succeeded-completion-absent"):
    base = outputs[str(DEST / (name + ".json"))]
    for label in ("digest-only", "time-only", "digest-and-time"):
        value = copy.deepcopy(base)
        if label != "time-only": binding(value)["response_digest"] = {"algorithm":"ecl.digest.sha-256.v1", "value":"0"*64}
        if label != "digest-only":
            value["forwarded"]["forward_completed_at"] = value["terminal"]["observed_at"]
            binding(value)["forward_completed_at"] = value["terminal"]["observed_at"]
        name_id = name + "-" + label
        add(name_id, value, "An unanswered exchange cannot invent answer evidence; recorded outcomes preserve historical evidence")
        if not name.startswith("recorded-"): unanswered_negatives.add(name_id)

result_negatives = {
    "ordinary-answer-completion-after-terminal", "ordinary-no-answer-completion-after-terminal",
    "ordinary-no-answer-completion-at-terminal", "recovered-answer-completion-after-terminal",
    "ordinary-answer-completion-absent", "transport-error-cannot-claim-answer-time",
    "jsonrpc-error-answer-missing-completion",
}
obligation_negatives = {
    "step5-halt-foreign-obligation", "step5-halt-duplicate-obligation", "step5-halt-proof-after-check",
    "step5-halt-missing-required", "step5-halt-unrequested-discharge",
    "post-consumption-journal-foreign-discharge", "discharged-journal-before-final-intrinsic-error",
    "stale-refusal-retains-intrinsic-error", "halt-refusal-check-after-final",
    "halt-refusal-unreliable-final-intrinsic-error",
}
for case in cases:
    rules = []
    if case["id"] in result_negatives | unanswered_negatives | {"ordinary-no-answer-completion-before-forward"}: rules.append(RESULT)
    if case["id"].endswith("completion-before-forward"): rules.append(FORWARD)
    if case["id"] in obligation_negatives | intrinsic_negatives: rules.append(OBLIGATION)
    case["schema_valid"] = case["id"] != "step5-halt-unsatisfied"
    case["accepted"] = case["schema_valid"] and not rules
    case["expected_rules"] = sorted(rules) if case["schema_valid"] else ["ecl.error.schema-invalid.v1"]
outputs[str(DEST / "manifest.json")] = {
    "schema": SCHEMA,
    "authors_and_producers": ["Robert F. Tilley Jr.", "G-14, Inc."],
    "requirements": ["MG1-010", "MG1-013", "MG1-014", "MG1-015", "MG1-016", "MG1-017"],
    "status": "Synthetic unsigned record regressions; no historical execution claim.",
    "cases": cases,
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    changed = []
    consistency = Path("tests/fixtures/mcp-record-consistency/manifest.json")
    retained = json.loads((ROOT / consistency).read_bytes())
    rows = [row for row in retained["cases"] if row["id"] == "clock-intrinsic-proof-failure-control"]
    if len(rows) != 1:
        raise ValueError("the retained refusal-precedence control must be unique")
    row = rows[0]
    payload = ROOT / consistency.parent / RETAINED_CONTROL["file"]
    if hashlib.sha256(payload.read_bytes()).hexdigest() != RETAINED_CONTROL["sha256"]:
        raise ValueError("the exact retained refusal-precedence payload changed")
    row.clear()
    row.update(copy.deepcopy(RETAINED_CONTROL))
    outputs[str(consistency)] = retained
    for relative, value in outputs.items():
        data = (json.dumps(value, sort_keys=relative != str(consistency), indent=2) + "\n").encode()
        path = ROOT / relative
        if not path.exists() or path.read_bytes() != data:
            changed.append(relative)
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
    print(json.dumps({"cases": len(cases), "changed_files": changed}))
    if args.check and changed: raise SystemExit(1)

if __name__ == "__main__": main()
