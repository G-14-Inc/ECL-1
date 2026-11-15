"""Targeted public-review schema-unit witnesses, with explicit evaluation stages.

The two partial MCP journal controls exercise structural schema branches only;
their protocol stage does not assert successful MCP binding validation or dispatch.
All records are synthetic. Robert F. Tilley Jr.; G-14, Inc.
"""
from pathlib import Path
import argparse
import copy
import json

ROOT = Path(__file__).resolve().parents[1]
SUITE = Path("conformance/suites/repair-coverage")
NS = "https://externalcontrollayer.ai/ns/schema/"
SCHEMA_INVALID = "ecl.error.schema-invalid.v1"


def build(root=ROOT):
    files, vectors = {}, []
    def read(path): return json.loads((root / path).read_bytes())
    def add(name, value, schema, stage, requirements, units, *, primary=None, secondary=()):
        identifier = "repair-coverage-" + name
        path = SUITE / (identifier + ".json")
        files[path] = copy.deepcopy(value)
        row = {"id": identifier, "path": path.as_posix(), "schema": NS + schema,
               "stage": stage, "requirement_ids": requirements, "covers": [NS + schema + unit for unit in units],
               "expected": "fail" if primary else "pass", "expected_secondary_ids": list(secondary),
               "source": {"kind": "mutation", "generator": "scripts/generate_repair_coverage_vectors.py",
                          "mutation": "Synthetic " + stage + "-stage unit witness: " + name + ". The protocol stage checks structural schema acceptance, not MCP binding or dispatch."}}
        if primary:
            row.update(expected_primary_id=primary, negates=requirements)
        vectors.append(row)

    safe = read(Path("conformance/suites/strict-failure/strict-failure-valid-profile.json"))
    safe["dependencies"] = [next(copy.deepcopy(d) for d in safe["dependencies"] if d["class"] == "advisory")]
    unit = "#/properties/dependencies/items/allOf/0/if#if[0]"
    add("advisory-control", safe, "safe-state-profile/1", "safe-state-profile", ["TS1-031"], [unit])
    bad = copy.deepcopy(safe); bad["dependencies"][0].update(supplies_required_proof=True, loss_disposition="fail_closed")
    add("advisory-required-proof", bad, "safe-state-profile/1", "safe-state-profile", ["TS1-031"], [unit], primary=SCHEMA_INVALID, secondary=["ecl.rule.dependency-classification-consistent.v1"])

    for kind, source, branch, member in [("assessment", "assessment-valid-l1-class-a", 2, "claim_decision"), ("claim", "claim-valid-l1-class-a-disclosed", 4, None)]:
        schema = "assessment-package/1" if kind == "assessment" else "conformance-claim/1"
        base = read(Path("conformance/suites/document-coverage") / (source + ".json"))
        unit = f"#/allOf/{branch}/if#if[0]"
        add(kind + "-l1-control", base, schema, "document", ["ECL1N-0077"], [unit])
        # Retain the other conditional-conformance fields so only the L1 prohibition fails.
        if kind == "claim":
            base = read(Path("conformance/suites/document-coverage/claim-valid-conditional-l3-class-c.json"))
            base["level"] = 1
        else:
            base[member]["status"] = "conditional_conformance"
        add(kind + "-conditional-l1", base, schema, "document", ["ECL1N-0077"], [unit], primary=SCHEMA_INVALID)

    base = read(Path("conformance/suites/aarm-binding/aarm-valid-allow-released.json"))
    unit = "#/properties/terminal/properties/event/properties/state/enum#enum"
    add("aarm-terminal-control", base, "binding/aarm-exchange/1", "binding", ["AB1-007"], [unit])
    bad = copy.deepcopy(base); bad["terminal"]["event"]["state"] = "released"
    add("aarm-nonterminal-state", bad, "binding/aarm-exchange/1", "binding", ["AB1-007"], [unit], primary=SCHEMA_INVALID)

    schema = "binding/mcp-gateway-exchange/1"
    base = read(Path("tests/fixtures/mcp-public-review-repairs/forward-complete-control.json"))
    state = "#/$defs/releaseObservation/properties/control_state"
    control_units = [state + "/if#if[0]", state + "/if/properties/status/enum#enum", state + "/properties/status/enum#enum", "#/allOf/0/if#if[0]"]
    add("mcp-complete-control", base, schema, "binding", ["MG1-014"], control_units)
    bad = copy.deepcopy(base); bad["release_observations"]["initial"]["control_state"].pop("fresh_until")
    add("mcp-control-without-freshness", bad, schema, "binding", ["MG1-014"], control_units[:2], primary=SCHEMA_INVALID)
    bad = copy.deepcopy(base); bad["release_observations"]["initial"]["control_state"]["status"] = "unknown"
    add("mcp-control-status-enum", bad, schema, "binding", ["MG1-014"], [control_units[2]], primary=SCHEMA_INVALID)
    bad = copy.deepcopy(base); bad.pop("prepared"); bad.pop("released")
    add("mcp-forward-without-preparation", bad, schema, "binding", ["MG1-014"], [control_units[3]], primary=SCHEMA_INVALID)

    prepared = read(Path("conformance/suites/mcp-gateway/mcp-valid-recovered-not-released.json"))
    units = ["#/allOf/1/if#if[0]"]
    add("mcp-prepared-control", prepared, schema, "binding", ["MG1-014", "MG1-016"], units)
    bad = copy.deepcopy(prepared); bad.pop("release_guard_milliseconds")
    add("mcp-prepared-without-guard", bad, schema, "binding", ["MG1-014"], units, primary=SCHEMA_INVALID)

    # Halt after release but before dispatch legitimately retains preparation,
    # release and final control evidence without a forwarded attempt. Use the
    # binding stage so the complete exchange, not merely its shape, is checked.
    journal_source = "tests/fixtures/mcp-public-review-repairs/halt-after-release-before-dispatch.json"
    journal = read(Path(journal_source))
    units = ["#/allOf/2/if#if[0]"]
    start = len(vectors)
    add("mcp-release-journal-shape", journal, schema, "binding", ["MG1-014"], units)
    bad = copy.deepcopy(journal); bad.pop("release_guard_milliseconds")
    add("mcp-release-journal-without-guard", bad, schema, "binding", ["MG1-014"], ["#/allOf/1/if#if[0]"], primary=SCHEMA_INVALID)
    bad = copy.deepcopy(journal); bad["release_observations"].pop("final")
    add("mcp-release-journal-without-final", bad, schema, "binding", ["MG1-014"], [units[0]], primary=SCHEMA_INVALID)
    for row in vectors[start:]:
        row["source"].update(base_vector=journal_source, mutation=(
            "Retain a valid halt-after-release-before-dispatch exchange; " +
            ("remove only its release guard." if row["id"].endswith("without-guard") else
             "remove only its final control observation." if row["id"].endswith("without-final") else
             "preserve its preparation, release journal and final observation.") +
            " Binding-stage check; no dispatch or recovery outcome is fabricated."
        ))

    # Extract an actual modify response from a valid synthetic exchange. Its
    # existing digest commits to that exchange's modifications. These two
    # protocol-stage records test the extension's required digest, not a full
    # exchange, signature, or release decision.
    source = "conformance/suites/acs-binding/acs-valid-modify-new-request.json"
    response = read(Path(source))["response"]
    unit = NS + "extension/acs-decision/1#/allOf/0/if#if[0]"
    add("acs-modify-digest-control", response, "dcmp/2", "protocol", ["AC1-008", "AC1-010"], [])
    vectors[-1]["covers"] = [unit]
    vectors[-1]["source"].update(base_vector="acs-valid-modify-new-request", mutation="Extract the original deny response carrying the modify decision and its modifications digest; protocol-stage extension-schema control only.")
    bad = copy.deepcopy(response)
    next(item for item in bad["extensions"] if item["id"] == "ecl.ext.acs-decision.v1")["value"].pop("modifications_digest")
    add("acs-modify-without-digest", bad, "dcmp/2", "protocol", ["AC1-008", "AC1-010"], [], primary="ecl.rule.extension-value-valid.v1")
    vectors[-1]["covers"] = [unit]
    vectors[-1]["source"].update(base_vector="acs-valid-modify-new-request", mutation="Extract the original deny response and remove only the modify decision's required modifications digest; protocol-stage extension-schema refusal only.")

    # Failed signed routes may retain request params and their digest together,
    # or neither before submission. A decided exchange always retains its result.
    # These binding-stage witnesses retain the direct-record regression inputs.
    source = "tests/fixtures/acs-record-completeness/cases.json"
    cases = {case["case"]: case for case in read(Path(source))["cases"]}
    failed_unit = "#/properties/guardian/allOf/2/if#if[0]"
    decided_unit = "#/properties/guardian/allOf/0/if#if[0]"
    for case_name, name, unit, requirements in [
        ("acs-signed-failed-timeout", "acs-failed-signed-paired-control", failed_unit, ["AC1-004", "AC1-006", "AC1-010"]),
        ("acs-signed-failed-before-submission", "acs-failed-signed-before-submission-control", failed_unit, ["AC1-004", "AC1-006", "AC1-010"]),
        ("acs-signed-failed-no-params", "acs-failed-signed-without-params", failed_unit, ["AC1-004", "AC1-010"]),
        ("acs-signed-failed-no-params-digest", "acs-failed-signed-without-digest", failed_unit, ["AC1-004", "AC1-010"]),
        ("acs-signed-control", "acs-decided-result-control", decided_unit, ["AC1-004", "AC1-010"]),
        ("acs-prior-result-only-deletion", "acs-decided-without-result", decided_unit, ["AC1-010"]),
        ("acs-missing-result-and-dependencies-direct", "acs-decided-without-result-and-dependencies", decided_unit, ["AC1-010"]),
    ]:
        case = cases[case_name]
        expected = case["expected_public_rules"]
        assert expected in ([], [SCHEMA_INVALID]), case_name
        add(name, case["record"], "binding/acs-exchange/1", "binding", requirements, [unit],
            primary=SCHEMA_INVALID if expected else None)
        vectors[-1]["source"]["mutation"] = (
            "Retain the synthetic " + case_name + " record from " + source +
            "; validate its schema and, when schema-valid, its ACS binding rules."
        )

    source = "profiles/examples/claims/framework-mapping.json"
    mapping = read(Path(source))
    mapping["obligations"][0]["support_class"] = "supporting_evidence_only"
    unit = "#/$defs/obligation/allOf/1/if#if[0]"
    add("mapping-supporting-evidence-control", mapping, "mapping-packet/1", "document", ["ECL1N-0125"], [unit])
    vectors[-1]["source"]["mutation"] = "Classify the first obligation in profiles/examples/claims/framework-mapping.json as supporting_evidence_only, retaining its explicit ECL surfaces and evidence. Synthetic document-schema control only."
    for member, name in [("ecl_surfaces", "surface"), ("evidence", "evidence")]:
        bad = copy.deepcopy(mapping); bad["obligations"][0][member] = []
        add("mapping-supporting-without-" + name, bad, "mapping-packet/1", "document", ["ECL1N-0125"], [unit], primary=SCHEMA_INVALID)
        vectors[-1]["source"]["mutation"] = "Classify the first obligation in profiles/examples/claims/framework-mapping.json as supporting_evidence_only, then remove only its " + member + ". Synthetic document-schema refusal only."

    files[SUITE / "manifest.json"] = {"schema_version": "ecl_conformance_vector_manifest_v3", "candidate_version": "1.0", "suite": "ecl-1-public-review-repair-coverage", "vectors": vectors}
    return {path: (json.dumps(value, indent=2, sort_keys=True) + "\n").encode() for path, value in files.items()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for path, content in build().items():
        target = ROOT / path
        if args.check:
            if not target.is_file() or target.read_bytes() != content:
                raise SystemExit("stale coverage fixture: " + str(path))
        else:
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(content)
