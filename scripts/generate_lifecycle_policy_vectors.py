"""Reproduce lifecycle policy declarations and retention-duration syntax controls."""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/ecl-verify/src"))
from coverage_denominator import attribution_for, schema_units

SCHEMA = "https://externalcontrollayer.ai/ns/schema/lifecycle-policy/1"
ERROR = "ecl.error.schema-invalid.v1"
SUITE = Path("conformance/suites/lifecycle-policy-contract")
GENERATOR = "scripts/generate_lifecycle_policy_vectors.py"
BASE = "conformance/suites/document-coverage/lifecycle-valid-policy.json"


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def build(root=ROOT):
    base = json.loads((root / BASE).read_bytes())
    outputs, rows = {}, []

    def add(name, value, valid, requirement):
        identifier = "lifecycle-policy-contract-" + name
        path = SUITE / (identifier + ".json")
        outputs[path] = encoded(value)
        row = {
            "id": identifier, "path": path.as_posix(), "stage": "document", "schema": SCHEMA,
            "source": {"kind": "mutation", "generator": GENERATOR, "base_vector": BASE, "mutation": name},
            "expected": "pass" if valid else "fail", "expected_secondary_ids": [],
            "requirement_ids": [requirement], "covers": [SCHEMA + "##root"],
        }
        if not valid:
            row.update(expected_primary_id=ERROR, negates=[requirement])
        rows.append(row)

    add("complete-policy-control", base, True, "EL1-002")
    value = copy.deepcopy(base)
    value.pop("policy_requirements")
    add("missing-five-area-declarations", value, False, "EL1-002")
    for area in ["supersession", "revocation", "residency", "encryption", "access"]:
        value = copy.deepcopy(base)
        value["policy_requirements"].pop(area)
        add("missing-" + area, value, False, "EL1-002")
        value = copy.deepcopy(base)
        value["policy_requirements"][area] = ""
        add("empty-" + area, value, False, "EL1-002")
    for label, invalid in [
        ("whitespace", " \t\r\n"), ("unicode-whitespace", "\u00a0\u2028\ufeff"),
        ("null", None), ("boolean", False), ("number", 0), ("array", []), ("object", {}),
    ]:
        value = copy.deepcopy(base)
        value["policy_requirements"]["access"] = invalid
        add("access-" + label, value, False, "EL1-002")
    for label, invalid in [("absent-map", None), ("array-map", []), ("string-map", "policy"), ("empty-map", {})]:
        value = copy.deepcopy(base)
        value["policy_requirements"] = invalid
        add(label, value, False, "EL1-002")
    value = copy.deepcopy(base)
    value["policy_requirements"]["additional_area"] = "A field not defined by this representation."
    add("unknown-policy-area", value, False, "EL1-002")
    value = copy.deepcopy(base)
    value["policy_requirements"]["supersession"] = (
        "For immutable receipt records, supersession does not apply: these records have no preferred-successor process."
    )
    add("scoped-inapplicability-control", value, True, "EL1-002")

    # Author-selected expectations exercise component order, calendar units, zero,
    # lexical boundaries and types. They are independent of the schema's regex.
    valid_durations = {
        "year": "P1Y", "zero-days": "P0D", "zero-seconds": "PT0S", "zero-years": "P0Y",
        "calendar-month": "P1M", "thirty-days": "P30D", "hour": "PT1H", "sixty-minutes": "PT60M",
        "ninety-seconds": "PT90S", "combined": "P1Y2M3DT4H5M6.125S", "fractional-second": "PT0.000000001S",
        "leading-zeros": "P0001Y02M003DT04H05M006.0S", "large-integer": "P9999999999999999999999999999D",
        "day-seconds": "P1DT1S", "year-hours": "P1YT1H", "month-minutes": "P1MT1M", "year-days": "P1Y2D",
    }
    invalid_durations = {
        "word": "Pending", "empty-period": "P", "empty-time": "PT", "trailing-time-year": "P1YT",
        "trailing-time-day": "P1DT", "repeated-year": "P1Y2Y", "reordered-date": "P1D1Y",
        "reordered-time": "PT1S1M", "weeks": "P1W", "fractional-year": "P1.5Y", "fractional-day": "P1.5D",
        "fractional-hour": "PT1.5H", "fractional-minute": "PT1.5M", "missing-integer-seconds": "PT.5S",
        "missing-fraction-seconds": "PT5.S", "negative-component": "P-1D", "negative-sign": "-P1D",
        "positive-sign": "+P1D", "signed-seconds": "PT+1S", "exponent": "P1e3D", "trailing-newline": "P1D\n",
        "trailing-crlf": "P1D\r\n", "trailing-line-separator": "P1D\u2028", "trailing-paragraph-separator": "P1D\u2029",
        "leading-space": " P1D", "trailing-space": "P1D ", "lowercase": "p1d", "fullwidth-digit": "P１D",
        "arabic-digit": "P١D", "empty-string": "", "null": None, "boolean": True, "number": 1,
    }
    for valid, values in [(True, valid_durations), (False, invalid_durations)]:
        for label, duration in values.items():
            value = copy.deepcopy(base)
            value["retention_rules"][0]["duration"] = duration
            add("duration-" + label, value, valid, "EL1-007")

    units = schema_units(SCHEMA, json.loads((root / "schemas/ecl-lifecycle-policy-v1.schema.json").read_bytes()))
    attribution = attribution_for(root)
    for row in rows:
        value = json.loads(outputs[Path(row["path"])])
        for unit in units:
            if unit["id"] in row["covers"] and not attribution.witnesses(unit, row, value):
                raise ValueError("unsupported coverage attribution: " + row["id"] + " " + unit["id"])
    missing = [unit["id"] + ":" + verdict for unit in units for verdict in ["pass", "fail"]
               if not any(row["expected"] == verdict and unit["id"] in row["covers"] for row in rows)]
    if missing:
        raise ValueError("missing lifecycle schema-unit coverage: " + str(missing))
    outputs[SUITE / "manifest.json"] = encoded({
        "schema_version": "ecl_conformance_vector_manifest_v3", "candidate_version": "1.0",
        "suite": "ecl-1-v1.0-lifecycle-policy-contract", "vectors": sorted(rows, key=lambda row: row["id"]),
    })
    return outputs, {"vectors": len(rows), "schema_units": len(units), "new_schema_units": 0,
                     "missing_two_sided_attribution": missing}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs, receipt = build(args.root)
    for path, data in outputs.items():
        target = args.root / path
        if args.check:
            if not target.is_file() or target.read_bytes() != data:
                raise SystemExit("stale lifecycle policy control: " + str(path))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    print(json.dumps({**receipt, "check": args.check}))


if __name__ == "__main__":
    main()
