"""Generate docs/gap-coverage.md, the public annex on control gaps G1 to G13, from data.

`registries/gap-coverage.json` holds, for each gap of the Control Gap Classification, a one-sentence
definition, the ECL-1 requirements and checklist items that address it, the requirements of the
binding profiles that address it for an implementation that claims them, the machine checks that
refuse an artifact showing it, the Control Gap Record entries that showed it, and what is left
open. The levels and summaries come from the compiled registry and Section 11.3 of the standard,
so a level change in the standard makes the annex stale; the machine checks of a binding profile
are the registered rules that cite the profile requirements listed. `--check`, which
`make spec-check` runs, fails when the annex is stale or the data names a requirement, checklist
item, rule or suite that does not exist or a suite that SUITES does not describe, or lists a
binding-profile requirement among the core requirements or the reverse. `--record PATH` re-derives each gap's record entries from a copy of
the record's source file (the `codes` list of each entry) before writing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import spec_index

ROOT = Path(__file__).resolve().parents[1]
DATA = Path("registries/gap-coverage.json")
OUTPUT = Path("docs/gap-coverage.md")
GAPS = tuple(f"G{number}" for number in range(1, 14))
# The binding profiles: a requirement whose source is one of these applies only to an
# implementation that claims that profile.
PROFILES = "profiles/"
# What each conformance suite that a gap may name checks, as the annex says it.
SUITES = {
    "evidence-bundle": "verifies signed evidence bundles offline under the verifier's own trust "
    "policy",
    "key-roles": "refuses a trust policy in which one key holds two component roles, and does "
    "not count a decision request or decision response signed by a key without that role",
}


class GapCoverageError(ValueError):
    """The gap data and the repository disagree."""


def read_data(root: Path) -> dict[str, Any]:
    value = json.loads((root / DATA).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != "ecl_gap_coverage_v1":
        raise GapCoverageError(f"{DATA} is not an ecl_gap_coverage_v1 document")
    return value


def active_rules(root: Path) -> dict[str, str]:
    value = spec_index.read_json(root / "registries/semantic-rules.json")
    return {
        entry["id"]: entry["description"]
        for entry in value["entries"]
        if entry["status"] == "active"
    }


def rules_citing(root: Path, identifiers: list[str]) -> list[str]:
    """The active rules that cite one of `identifiers` as a requirement, in registry order."""
    value = spec_index.read_json(root / "registries/semantic-rules.json")
    wanted = set(identifiers)
    return [
        entry["id"]
        for entry in value["entries"]
        if entry["status"] == "active" and wanted & set(entry["attributes"].get("requirements", []))
    ]


def profile_of(requirement: spec_index.Requirement) -> str | None:
    """The binding profile a requirement belongs to, named by its file, or None for the core."""
    path = requirement.source_path
    if not path.startswith(PROFILES):
        return None
    return Path(path).stem


def suite_size(root: Path, name: str) -> int:
    path = root / "conformance/suites" / name / "manifest.json"
    if not path.is_file():
        raise GapCoverageError(f"no conformance suite named {name}")
    return len(spec_index.read_json(path)["vectors"])


def validate(root: Path, value: dict[str, Any]) -> None:
    gaps = value["gaps"]
    problems: list[str] = []
    if [gap["id"] for gap in gaps] != list(GAPS):
        problems.append("the data must list G1 to G13 once each, in order")
    requirements = {item.identifier: item for item in spec_index.requirements(root)}
    compiled = set(requirements)
    items = {item.identifier for item in spec_index.checklist(root)}
    rules = active_rules(root)
    entries = value["record"]["entries"]
    digest = value["record"].get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        problems.append("record source-file digest must be a lowercase SHA-256 value")
    if not entries or any(
        not isinstance(title, str) or not title.strip() or "\n" in title or "\r" in title
        for title in entries.values()
    ):
        problems.append("record entries must have nonempty single-line titles")
    for gap in gaps:
        name = gap["id"]
        problems += [
            f"{name} has no {key}"
            for key in ("label", "definition", "open")
            if not str(gap.get(key, "")).strip()
        ]
        if not gap["requirements"]:
            problems.append(f"{name} names no requirement")
        for key in ("requirements", "profile_requirements", "checklist", "machine_checks", "record_entries"):
            listed = gap.get(key, [])
            if len(listed) != len(set(listed)):
                problems.append(f"{name} repeats an entry in {key}")
        problems += [
            f"{name} names a requirement that is not compiled: {identifier}"
            for identifier in [*gap["requirements"], *gap.get("profile_requirements", [])]
            if identifier not in compiled
        ]
        problems += [
            f"{name} lists a binding-profile requirement among its core requirements: {identifier}"
            for identifier in gap["requirements"]
            if identifier in compiled and profile_of(requirements[identifier]) is not None
        ]
        problems += [
            f"{name} lists a requirement that is not a binding-profile requirement: {identifier}"
            for identifier in gap.get("profile_requirements", [])
            if identifier in compiled and profile_of(requirements[identifier]) is None
        ]
        problems += [
            f"{name} names a checklist item that does not exist: {identifier}"
            for identifier in gap["checklist"]
            if identifier not in items
        ]
        for check in gap["machine_checks"]:
            if check.startswith("suite:"):
                try:
                    suite_size(root, check.removeprefix("suite:"))
                except GapCoverageError as error:
                    problems.append(f"{name}: {error}")
                if check.removeprefix("suite:") not in SUITES:
                    problems.append(f"{name} names a suite the annex cannot describe: {check}")
            elif check not in rules:
                problems.append(f"{name} names a rule that is not active: {check}")
            elif check not in rules_citing(root, gap["requirements"]):
                problems.append(f"{name} rule {check} does not cite a listed core requirement")
        problems += [
            f"{name} names a record entry that the data does not list: {number}"
            for number in gap["record_entries"]
            if str(number) not in entries
        ]
    if problems:
        raise GapCoverageError("\n".join(problems))


def record_title(raw: str) -> str:
    """Decode a single-line title in the record's fixed-layout YAML subset.

    Single-quoted scalars escape a quote by doubling it; double-quoted titles use JSON
    escapes. Block scalars and multiline titles are outside this importer's declared subset.
    """
    value = raw.strip()
    if value.startswith("'"):
        if not re.fullmatch(r"'(?:[^']|'')*'", value):
            raise GapCoverageError("invalid single-quoted record title")
        value = value[1:-1].replace("''", "'")
    elif value.startswith('"'):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as error:
            raise GapCoverageError("invalid JSON-style double-quoted record title") from error
    elif value.startswith(("|", ">", "[", "{", "&", "*", "!")) or re.search(r"(?:^|\s)#|:\s", value):
        raise GapCoverageError("record title with YAML control syntax must be quoted")
    if not isinstance(value, str) or not value.strip() or "\n" in value or "\r" in value:
        raise GapCoverageError("record title must be a nonempty single-line scalar")
    return value


def record_codes_bytes(data: bytes) -> tuple[dict[str, str], dict[str, list[int]]]:
    """Each entry's short title, and the entries whose `codes` list names each gap.

    The record is YAML; this reads only the fields it needs, by their fixed layout: an entry opens
    with `- n: N` at column 0, its fields are indented two spaces, and each item of its `codes`
    and `not_coded` lists is `    - code: Gn`. Only `codes` items count.
    """
    shorts: dict[str, str] = {}
    coded: dict[str, list[int]] = {}
    number: int | None = None
    numbers: set[int] = set()
    block = ""
    for line in data.decode("utf-8").splitlines():
        entry = re.match(r"^- n: ([0-9]+)\s*$", line)
        if entry:
            number, block = int(entry.group(1)), ""
            if number <= 0 or number in numbers:
                raise GapCoverageError("record entry numbers must be positive and unique")
            numbers.add(number)
            continue
        if number is None:
            continue
        field = re.match(r"^  ([a-z_]+):(.*)$", line)
        if field:
            block = field.group(1)
            if block == "short":
                if str(number) in shorts:
                    raise GapCoverageError(f"record entry {number} repeats its short title")
                shorts[str(number)] = record_title(field.group(2))
            continue
        code = re.match(r"^    - code: (G[0-9]+)\s*$", line)
        if block == "codes" and line.startswith("    - code:") and not code:
            raise GapCoverageError(f"record entry {number} has an invalid gap-code line")
        if code and block == "codes":
            identifier = code.group(1)
            if identifier not in GAPS:
                raise GapCoverageError(f"record entry {number} names an unknown gap: {identifier}")
            assigned = coded.setdefault(identifier, [])
            if number in assigned:
                raise GapCoverageError(f"record entry {number} repeats gap {identifier}")
            assigned.append(number)
    if not numbers or set(shorts) != {str(number) for number in numbers}:
        raise GapCoverageError("each record entry must have one short title")
    return shorts, coded


def record_codes(path: Path) -> tuple[dict[str, str], dict[str, list[int]]]:
    """Read the record's fixed-layout YAML subset, without a YAML dependency."""
    return record_codes_bytes(path.read_bytes())


def refresh_record(root: Path, path: Path) -> dict[str, Any]:
    value = read_data(root)
    data = path.read_bytes()
    shorts, coded = record_codes_bytes(data)
    value["record"]["entries"] = dict(sorted(shorts.items(), key=lambda pair: int(pair[0])))
    value["record"]["sha256"] = hashlib.sha256(data).hexdigest()
    for gap in value["gaps"]:
        gap["record_entries"] = sorted(coded.get(gap["id"], []))
    validate(root, value)
    (root / DATA).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", "utf-8")
    return value


def link_label(value: str) -> str:
    """Keep a record title literal inside a Markdown link label."""
    return value.replace("\\", "\\\\").replace("[", r"\[").replace("]", r"\]")


def level_name(level: int) -> str:
    return f"L{level}"


def sentence_part(description: str) -> str:
    """A rule's registry description as the rest of a sentence: its first letter in lower case,
    unless it begins an acronym such as AARM, and without its final period."""
    text = description.rstrip(".")
    first = text[0] if text[1:2].isupper() else text[0].lower()
    return first + text[1:]


def series(names: list[str]) -> str:
    """`names` as an English series: "G5", "G5 and G6", "G5, G6 and G8"."""
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def render(root: Path = ROOT) -> str:
    value = read_data(root)
    validate(root, value)
    requirements = {item.identifier: item for item in spec_index.requirements(root)}
    items = {item.identifier: item for item in spec_index.checklist(root)}
    rules = active_rules(root)
    classification, record = value["classification"], value["record"]
    gaps = value["gaps"]
    adapted = [gap["id"] for gap in gaps if gap["adapted"]]
    lines = [
        "# Control-gap coverage in ECL-1",
        "",
        "This annex shows, for each of the 13 control gaps of the Control Gap Classification, "
        "which requirements of ECL-1 address it and at which conformance level, which "
        "requirements of the binding profiles address it for an implementation that claims them, "
        "how an assessor and a machine check test it, which entries of the Control Gap Record "
        "showed it, and what the text leaves open. It describes "
        f"{spec_index.source_build_label(root)}. It is not a conformance claim or an assessment.",
        "",
        # CC BY 4.0 section 3(a)(1): the licensor, a link to the material, the license and its
        # URI, and whether the material was adapted (review finding S16).
        f"Gap definitions are from the {classification['name']}, version "
        f"{classification['version']}, {classification['licensor']}, {classification['url']}, "
        f"licensed under {classification['license']} ({classification['license_url']})."
        + (
            f" The definitions of {series(adapted)} are adapted: their two sentences are joined "
            "into one, or the first sentence is kept."
            if adapted
            else ""
        )
        + " Incident entries are "
        f"from the {record['name']}, version {record['version']}, {record['licensor']}, "
        f"{record['url']}, licensed under {record['license']} ({record['license_url']}); an entry "
        "is listed under a gap when the record codes that gap for it.",
        "",
        "This file is generated from `registries/gap-coverage.json` and the compiled "
        "requirement registry, and is not edited by hand.",
        "",
        "Requirement tables show opening excerpts that can omit later clauses, conditions, "
        "lists and tables. Each requirement ID links to the complete requirement in the "
        "generated HTML document; checklist IDs link to their complete source tables.",
        "",
        "## Summary",
        "",
        "| Gap | Requirements | Lowest level | Profile requirements | Checklist items | "
        "Core rules | Core suites (vectors) | Profile rules | Record entries |",
        "| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for gap in gaps:
        lowest = min(requirements[identifier].level for identifier in gap["requirements"])
        suites = [check.removeprefix("suite:") for check in gap["machine_checks"] if check.startswith("suite:")]
        core_rules = [check for check in gap["machine_checks"] if not check.startswith("suite:")]
        profile_rules = rules_citing(root, gap.get("profile_requirements", []))
        suite_count = f"{len(suites)} ({sum(suite_size(root, name) for name in suites)})" if suites else "0 (0)"
        lines.append(
            f"| [{gap['id']} {gap['label']}](#{gap['id'].lower()}-"
            f"{re.sub(r'[^a-z0-9]+', '-', gap['label'].lower()).strip('-')}) | "
            f"{len(gap['requirements'])} | {level_name(lowest)} | "
            f"{len(gap.get('profile_requirements', []))} | {len(gap['checklist'])} | "
            f"{len(core_rules)} | {suite_count} | {len(profile_rules)} | {len(gap['record_entries'])} |"
        )
    core_ids = {identifier for gap in gaps for identifier in gap["requirements"]}
    profile_ids = {identifier for gap in gaps for identifier in gap.get("profile_requirements", [])}
    checklist_ids = {identifier for gap in gaps for identifier in gap["checklist"]}
    record_ids = {number for gap in gaps for number in gap["record_entries"]}
    core_rule_ids = {check for gap in gaps for check in gap["machine_checks"] if not check.startswith("suite:")}
    profile_rule_ids = {check for gap in gaps for check in rules_citing(root, gap.get("profile_requirements", []))}
    suite_ids = {check.removeprefix("suite:") for gap in gaps for check in gap["machine_checks"] if check.startswith("suite:")}
    suite_vectors = {vector["id"] for name in suite_ids for vector in spec_index.read_json(root / "conformance/suites" / name / "manifest.json")["vectors"]}
    profile_total = sum(profile_of(item) is not None for item in requirements.values())
    lines += [
        "",
        "These counts describe listed associations, not test results or conformance percentages. "
        "A requirement, rule, suite or record can occur in more than one gap; the rows are not "
        "disjoint coverage and must not be added. Suite vector counts include both positive and "
        "negative cases, and do not state how many passed a run.",
        "",
        f"Across G1–G13 the unique listed identifiers comprise {len(core_ids)} of "
        f"{len(requirements) - profile_total} core and companion-protocol requirements, "
        f"{len(profile_ids)} of {profile_total} profile requirements "
        f"({len(requirements)} compiled requirements in total), and {len(checklist_ids)} of "
        f"{len(items)} Section 11.3 checklist items. The mappings list {len(core_rule_ids)} core "
        f"rule identifiers and {len(profile_rule_ids)} profile rule identifiers "
        f"({len(core_rule_ids | profile_rule_ids)} unique across both lists, of {len(rules)} active "
        f"semantic rules), plus {len(suite_ids)} named suites containing {len(suite_vectors)} "
        f"unique vector identifiers. They refer to {len(record_ids)} of the "
        f"{len(record['entries'])} record entries in the retained source extract.",
        "",
        "The record's source-file digest in `registries/gap-coverage.json` identifies the external "
        "YAML bytes used for its last import. Those bytes are not included here, so that digest "
        "is not rechecked by ordinary generation. An explicit `--record` refresh parses and hashes "
        "one read of the supplied file before replacing the retained extract.",
    ]
    for gap in gaps:
        rows = sorted(
            (requirements[identifier] for identifier in gap["requirements"]),
            key=lambda item: (item.level, item.identifier),
        )
        lines += [
            "",
            f"## {gap['id']} {gap['label']}",
            "",
            f"Definition: {gap['definition']}",
            "",
            "| Requirement | Level | Opening excerpt |",
            "| --- | --- | --- |",
        ]
        lines += [
            f"| {spec_index.requirement_link(item)} | {level_name(item.level)} | {spec_index.summary(item.statement)} |"
            for item in rows
        ]
        profiled = sorted(
            (requirements[identifier] for identifier in gap.get("profile_requirements", [])),
            key=lambda item: (str(profile_of(item)), item.identifier),
        )
        if profiled:
            lines += [
                "",
                "Binding profiles. These requirements apply only to an implementation that "
                "claims the profile:",
                "",
                "| Requirement | Profile | Opening excerpt |",
                "| --- | --- | --- |",
            ]
            lines += [
                f"| {spec_index.requirement_link(item)} | {profile_of(item)} | {spec_index.summary(item.statement)} |"
                for item in profiled
            ]
        listed = sorted(
            (items[identifier] for identifier in gap["checklist"]),
            key=lambda item: (item.level, item.identifier),
        )
        lines += [
            "",
            "Checklist items: "
            + ", ".join(f"{spec_index.checklist_link(item, root)} ({level_name(item.level)})" for item in listed)
            + ".",
            "",
        ]
        checks = []
        for check in gap["machine_checks"]:
            if check.startswith("suite:"):
                name = check.removeprefix("suite:")
                checks.append(
                    f"- The `{name}` conformance suite ({suite_size(root, name)} vectors), which "
                    f"{SUITES[name]}."
                )
            else:
                checks.append(f"- `{check}`: {sentence_part(rules[check])}.")
        profile_checks = [
            (f"- `{rule}`: the same check described above also applies to the binding records."
             if rule in gap["machine_checks"]
             else f"- `{rule}`: {sentence_part(rules[rule])}.")
            for rule in rules_citing(root, gap.get("profile_requirements", []))
        ]
        if checks:
            lines += ["Machine checks:", "", *checks]
        elif profile_checks:
            lines.append(
                "Machine checks: none for the core requirements. An assessor checks them, as "
                "described under what is left open."
            )
        else:
            lines.append(
                "Machine checks: none. An assessor checks this gap, as described under what is "
                "left open."
            )
        if profile_checks:
            lines += [
                "",
                "Machine checks of the binding profiles, applied to the records they define:",
                "",
                *profile_checks,
            ]
        entries = [
            f"[Record {number}: {link_label(record['entries'][str(number)])}]"
            f"({record['entry_url'].format(n=number)})"
            for number in gap["record_entries"]
        ]
        lines += [
            "",
            f"Record entries that showed this gap ({len(entries)}): "
            + (", ".join(entries) if entries else "none")
            + ".",
            "",
            f"Left open: {gap['open']}",
        ]
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--record", type=Path, help="the record's source file, to refresh entries")
    args = parser.parse_args(argv)
    try:
        if args.record is not None:
            if args.check:
                raise GapCoverageError("--record refreshes the data and needs --write")
            refresh_record(args.root, args.record)
        content = render(args.root)
        target = args.root / OUTPUT
        if args.check:
            if not target.is_file() or target.read_bytes() != content.encode("utf-8"):
                raise GapCoverageError(f"{OUTPUT} is stale; run tools/gap_coverage.py --write")
            print("gap coverage: check passed")
        else:
            target.write_bytes(content.encode("utf-8"))
            print(f"gap coverage: wrote {OUTPUT}")
    except (OSError, KeyError, ValueError) as error:
        print(f"gap coverage: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
