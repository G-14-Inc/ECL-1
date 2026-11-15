"""Derive everything an L1 claim answers and write docs/l1-minimum.md.

The path starts from every requirement of the core standard whose minimum level is L1 (see
spec_index for how the level is read, and Section 6.1 of the standard for the rule). It then
follows what the obligations on the path name, an obligation being a requirement with a MUST-class
keyword: an obligation that names a companion protocol or profile (for example `DCMP-2`, or `ECL
Integrity Envelope 1`) brings in every requirement of that document that applies at L1, and an
obligation that cites another requirement by ID brings in that requirement. A recommendation or a
permission on the path brings nothing in, because it binds no claim. It repeats until nothing new
is named. A companion that no obligation on the path names is not on the path. The L1 checklist
items are the rows of Section 11.3 whose minimum level is L1.

`--write` regenerates the document; `--check` fails when it is stale, which `make spec-check` runs.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import spec_index
from spec_index import ChecklistItem, Requirement

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = Path("docs/l1-minimum.md")
ID_PATTERN = re.compile(r"\b[A-Z][A-Z0-9]{1,11}-[0-9]{3,5}\b")
# Other names under which the core and the companions cite a document, besides its set name.
ALIASES = {
    "protocols/INTEGRITY-ENVELOPE-1.md": ("ECL Integrity Envelope 1", "ECL-IE-1"),
}
KINDS = ("obligation", "recommendation", "permission")


@dataclass(frozen=True)
class Entry:
    requirement: Requirement
    reason: str


@dataclass(frozen=True)
class L1Path:
    """The derived path: its requirements in order of discovery and why each document is on it."""

    entries: tuple[Entry, ...]
    documents: dict[str, list[str]]
    checklist: tuple[ChecklistItem, ...]


def name_patterns(root: Path) -> dict[str, list[re.Pattern[str]]]:
    """For each companion document, the patterns that find a citation of it by name."""
    patterns: dict[str, list[re.Pattern[str]]] = {}
    for path, name in spec_index.documents(root).items():
        if path == spec_index.STANDARD:
            continue
        names = (name, *ALIASES.get(path, ()))
        patterns[path] = [
            re.compile(r"(?<![A-Za-z0-9-])" + re.escape(item) + r"(?![A-Za-z0-9])")
            for item in names
        ]
    return patterns


def derive(root: Path = ROOT) -> L1Path:
    every = spec_index.requirements(root)
    by_id = {item.identifier: item for item in every}
    by_document: dict[str, list[Requirement]] = {}
    for item in every:
        by_document.setdefault(item.source_path, []).append(item)
    patterns = name_patterns(root)
    reasons: dict[str, str] = {}
    documents: dict[str, list[str]] = {}
    queue: list[Requirement] = []

    def add(item: Requirement, reason: str) -> None:
        if item.level == 1 and item.identifier not in reasons:
            reasons[item.identifier] = reason
            queue.append(item)

    for item in by_document.get(spec_index.STANDARD, []):
        add(item, "core requirement at L1")
    while queue:
        item = queue.pop(0)
        if item.kind != "obligation":
            # Only a MUST-class requirement binds a claim, so only it brings others in.
            continue
        for path, found in patterns.items():
            if path == item.source_path or not any(pattern.search(item.text) for pattern in found):
                continue
            documents.setdefault(path, []).append(item.identifier)
            for member in by_document.get(path, []):
                add(member, f"in {spec_index.documents(root)[path]}, named by {item.identifier}")
        for cited in ID_PATTERN.findall(item.text):
            if cited in by_id and cited != item.identifier:
                add(by_id[cited], f"cited by {item.identifier}")
    order = {item.identifier: index for index, item in enumerate(every)}
    entries = tuple(
        Entry(by_id[identifier], reason)
        for identifier, reason in sorted(reasons.items(), key=lambda pair: order[pair[0]])
    )
    items = tuple(item for item in spec_index.checklist(root) if item.level == 1)
    return L1Path(entries, documents, items)


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def section(heading: str) -> str:
    match = re.match(r"^(?:\d+(?:\.\d+)*\.?)\s", heading)
    return heading.split(" ", 1)[0].rstrip(".") if match else heading


def render(root: Path = ROOT) -> str:
    path = derive(root)
    titles = spec_index.documents(root)
    order = list(titles)
    grouped: dict[str, list[Entry]] = {}
    for entry in path.entries:
        grouped.setdefault(entry.requirement.source_path, []).append(entry)
    documents = [name for name in order if name in grouped]
    absent = [name for name in order if name not in grouped]
    total = len(path.entries)
    kinds = Counter(entry.requirement.kind for entry in path.entries)
    conditional = sum(entry.requirement.conditional for entry in path.entries)
    lines = [
        "# Minimum path to an L1 claim",
        "",
        f"{spec_index.source_build_label(root)}. This document is generated from the "
        "compiled requirement registry (`registries/requirements-compiled.json`) and the "
        "checklist in Section 11.3 of the standard, and is not edited by hand.",
        "",
        f"An `L1` claim answers {plural(total, 'requirement')} across "
        f"{plural(len(documents), 'document')} and {plural(len(path.checklist), 'checklist item')}. "
        f"Of the requirements, {kinds['obligation']} are obligations (MUST), "
        f"{kinds['recommendation']} are recommendations (SHOULD only) and {kinds['permission']} "
        f"are permissions (MAY only). {conditional} are marked conditional by an opening-text "
        "heuristic: they open with a condition, "
        "either a choice that "
        "only some deployments make, such as federation or an AI bill of materials, or an event "
        "that every deployment handles when it happens, such as a key compromise. The list sizes "
        "the first implementation and the first assessment. It is not a conformance claim.",
        "",
        "## How the path is derived",
        "",
        "- Every requirement of the core standard whose minimum level is `L1` is on the path. The "
        "minimum level is the `Min Level` cell of an FR row, or the level qualifier that opens a "
        'requirement ("For `L2` and above", "`L2`:" and similar); a requirement without one '
        "applies at every level (standard, Section 6.1).",
        "- An obligation on the path, a requirement with a MUST-class keyword, that names a "
        "companion protocol or profile brings in every requirement of that document that applies "
        "at `L1`. An obligation on the path that cites another requirement by its ID brings in "
        "that requirement. A recommendation or permission on the path brings nothing in, because "
        "it binds no claim. Dependency discovery uses the complete compiled text, including "
        "explicitly attributed continuation paragraphs and tables. This repeats until nothing new is named.",
        "- A companion that no obligation on the path names is not on the path. A claim that "
        "declares a profile, or uses a function that a protocol governs, adds those requirements.",
        "- The generator marks a requirement conditional when its text opens with a condition "
        'such as "When", "If" or "This model".',
        "",
        "The conditional count reflects this opening-text heuristic, not a complete count of "
        "applicability conditions. Read each complete requirement to determine whether it "
        "binds the claim. Kind is determined from the full compiled requirement; an opening "
        "excerpt can omit a later obligation, prohibition, qualification, list or table.",
        "",
        "Requirement IDs link to their complete text in the generated HTML documents. "
        "Checklist IDs link to their complete source tables, including assessor methods and "
        "pass criteria. The excerpts below are navigation aids.",
        "",
        "## Size by document",
        "",
        "| Document | On the path because | Requirements | Obligations | Recommendations "
        "| Permissions | Conditional |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name in documents:
        rows = grouped[name]
        counts = Counter(entry.requirement.kind for entry in rows)
        because = (
            "it is the core standard"
            if name == spec_index.STANDARD
            else "named by " + ", ".join(path.documents[name])
            if name in path.documents
            else "requirements on the path cite "
            + ", ".join(entry.requirement.identifier for entry in rows)
        )
        lines.append(
            f"| {titles[name]} | {because} | {len(rows)} | "
            + " | ".join(str(counts[kind]) for kind in KINDS)
            + f" | {sum(entry.requirement.conditional for entry in rows)} |"
        )
    lines.append(
        f"| Total | | {total} | "
        + " | ".join(str(kinds[kind]) for kind in KINDS)
        + f" | {conditional} |"
    )
    lines += [
        "",
        "Not on the path: " + ", ".join(titles[name] for name in absent) + ".",
        "",
        "## Checklist items for an L1 claim",
        "",
        "| Domain | Items |",
        "| --- | ---: |",
    ]
    domains = Counter(item.domain for item in path.checklist)
    lines += [f"| `{domain}` | {count} |" for domain, count in domains.items()]
    lines += [
        "",
        "| Item | Related | Applicability | Control question excerpt |",
        "| --- | --- | --- | --- |",
    ]
    lines += [
        f"| {spec_index.checklist_link(item, root)} | {item.related} | {item.applicability} | "
        f"{spec_index.summary(item.question, 200)} |"
        for item in path.checklist
    ]
    lines += ["", "## Requirements by document", ""]
    for name in documents:
        rows = grouped[name]
        lines += [
            f"### {titles[name]} (`{name}`)",
            "",
            "| ID | Section | Kind | Opening excerpt |",
            "| --- | --- | --- | --- |",
        ]
        for entry in rows:
            item = entry.requirement
            kind = item.kind + (", conditional" if item.conditional else "")
            lines.append(
                f"| {spec_index.requirement_link(item)} | {section(item.source_heading)} | {kind} | "
                f"{spec_index.summary(item.statement)} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    try:
        content = render(args.root)
        target = args.root / OUTPUT
        if args.check:
            if not target.is_file() or target.read_bytes() != content.encode("utf-8"):
                print(f"L1 path: {OUTPUT} is stale; run tools/l1_path.py --write", file=sys.stderr)
                return 1
            print("L1 path: check passed")
        else:
            target.write_bytes(content.encode("utf-8"))
            print(f"L1 path: wrote {OUTPUT}")
    except (OSError, KeyError, ValueError) as error:
        print(f"L1 path: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
