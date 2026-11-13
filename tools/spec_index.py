"""Read the compiled requirements and the conformance checklist the way the derived documents do.

The compiled registry (`registries/requirements-compiled.json`) gives each requirement its source,
heading, text and normative keywords. Two facts the generated documents need are not fields of the
registry, so they are read from the text by fixed rules:

- the minimum conformance level: the `Min Level` cell of an FR row, or a level qualifier that opens
  the requirement ("For `L2` and above", "For `L3` and `L4` claims", "For `L4`", "`L2` and above",
  "`L2`:", "A claim at `L3` or `L4`"); any other requirement applies at every level. Section 6.1 of
  the standard states this rule, for the core and for the companion documents alike;
- whether it is conditional: the text opens with a condition ("When", "If", "Where", "For
  federated", "Federated", "This model", "Sector profiles", "Model-routing"), so that it binds only
  a deployment in that condition.

The checklist is read from the tables of Section 11.3 of the standard.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STANDARD = "standard/ECL-1_Standard.md"
REGISTRY = "registries/requirements-compiled.json"
VERSION_SET = "release/VERSION_SET.json"
LEVEL_PATTERNS = (
    re.compile(r"^For `L([1-4])` and above\b"),
    re.compile(r"^For `L([1-4])` and `L[1-4]` claims\b"),
    re.compile(r"^For `L([1-4])`(?: claims)?[,\s]"),
    re.compile(r"^`L([1-4])` and above\b"),
    re.compile(r"^`L([1-4])`:"),
    re.compile(r"^A claim at `L([1-4])` or `L[1-4]`"),
)
FR_ROW = re.compile(r"^\|\s*(FR-[0-9]{3})\s*\|\s*L([1-4])\s*\|\s*(.*?)\s*\|")
CONDITIONS = (
    "When ",
    "If ",
    "Where ",
    "For federated ",
    "Federated ",
    "This model ",
    "Sector profiles ",
    "Model-routing",
)
CHECKLIST_ROW = re.compile(r"^\|\s*([A-Z]{2}-[0-9]{2})\s*\|\s*L([1-4])\s*\|")
OBLIGATIONS = frozenset({"MUST", "MUST_NOT", "SHALL", "SHALL_NOT", "REQUIRED"})
RECOMMENDATIONS = frozenset({"SHOULD", "SHOULD_NOT", "RECOMMENDED", "NOT_RECOMMENDED"})


@dataclass(frozen=True)
class Requirement:
    """One compiled requirement and the facts the generated documents derive from it."""

    identifier: str
    source_path: str
    source_heading: str
    text: str
    forces: tuple[str, ...]
    text_sha256: str

    @property
    def prefix(self) -> str:
        return self.identifier.split("-", 1)[0]

    @property
    def statement(self) -> str:
        """The requirement sentence: for an FR table row, its requirement cell."""
        row = FR_ROW.match(self.text)
        return row.group(3) if row else self.text

    @property
    def level(self) -> int:
        """The minimum conformance level at which the requirement applies."""
        row = FR_ROW.match(self.text)
        if row:
            return int(row.group(2))
        for pattern in LEVEL_PATTERNS:
            found = pattern.match(self.text)
            if found:
                return int(found.group(1))
        return 1

    @property
    def conditional(self) -> bool:
        return self.statement.startswith(CONDITIONS)

    @property
    def kind(self) -> str:
        """`obligation` with any MUST-class keyword, else `recommendation`, else `permission`."""
        forces = set(self.forces)
        if forces & OBLIGATIONS:
            return "obligation"
        if forces & RECOMMENDATIONS:
            return "recommendation"
        return "permission"


@dataclass(frozen=True)
class ChecklistItem:
    """One row of the Section 11.3 checklist tables."""

    identifier: str
    level: int
    related: str
    applicability: str
    question: str

    @property
    def domain(self) -> str:
        return self.identifier.split("-", 1)[0]


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def requirements(root: Path) -> list[Requirement]:
    """The compiled requirements, in registry order."""
    registry = read_json(root / REGISTRY)
    return [
        Requirement(
            identifier=row["requirement_id"],
            source_path=row["source_path"],
            source_heading=row["source_heading"],
            text=row["text"],
            forces=tuple(row["normative_forces"]),
            text_sha256=row["text_sha256"],
        )
        for row in registry["requirements"]
    ]



def requirement_link(item: Requirement) -> str:
    """Link an excerpt to the complete requirement in the generated HTML source."""
    document = Path(item.source_path).stem.lower() + ".html"
    return f"[{item.identifier}](../render/{document}#{item.identifier})"


def checklist_link(item: ChecklistItem, root: Path) -> str:
    """Link to the complete checklist table containing this item's identifier."""
    heading = ""
    for line in (root / STANDARD).read_text(encoding="utf-8").splitlines():
        if line.startswith("#### "):
            heading = line[5:].strip()
        if CHECKLIST_ROW.match(line) and cells(line)[0] == item.identifier:
            fragment = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
            return f"[{item.identifier}](../{STANDARD}#{fragment})"
    raise ValueError(f"no checklist table for {item.identifier}")

def candidate_version(root: Path) -> str:
    return str(read_json(root / REGISTRY)["candidate_version"])


def source_build_label(root: Path) -> str:
    """The current source draft identity, separate from the protocol version."""
    value = read_json(root / "release/BUILD_DESCRIPTOR.json")
    return f"{value['designation']}; source build `{value['source_version']}`, prepared `{value['review_date']}`; local candidate"


def cells(row: str) -> list[str]:
    """The cells of a Markdown table row; a backslash-escaped bar stays inside its cell."""
    parts = re.split(r"(?<!\\)\|", row.strip())
    return [part.strip() for part in parts[1:-1]]


def checklist(root: Path) -> list[ChecklistItem]:
    """Every checklist item in Section 11.3, in document order."""
    items: list[ChecklistItem] = []
    inside = False
    for line in (root / STANDARD).read_text(encoding="utf-8").splitlines():
        if line.startswith("### 11.3 "):
            inside = True
            continue
        if inside and line.startswith("### "):
            break
        if inside and CHECKLIST_ROW.match(line):
            row = cells(line)
            items.append(
                ChecklistItem(
                    identifier=row[0],
                    level=int(row[1][1:]),
                    related=row[2],
                    applicability=row[3],
                    question=row[4],
                )
            )
    if not items:
        raise ValueError("no checklist items found in Section 11.3")
    return items


def documents(root: Path) -> dict[str, str]:
    """Each normative document by path: the core standard, then the companions in set order."""
    value = read_json(root / VERSION_SET)
    titles = {value["standard"]["path"]: "ECL-1 core standard"}
    for companion in value["companions"]:
        titles[companion["path"]] = str(companion["name"])
    return titles


def summary(text: str, limit: int = 160) -> str:
    """The first sentence of a requirement, shortened at a word boundary to at most `limit`."""
    flat = re.sub(r"\s+", " ", text).strip()
    flat = re.sub("\\s*[\u2013\u2014]\\s*", "; ", flat)
    sentence = flat
    for end in re.finditer(r"(?<=\.)\s(?=[A-Z`*(])", flat):
        # A period after a bare number ends a list marker ("1."), not a sentence.
        if re.search(r"(?:^|\s)\d+\.$", flat[: end.start()]):
            continue
        sentence = flat[: end.start()]
        break
    if len(sentence) > limit:
        cut = sentence[: limit + 1].rsplit(" ", 1)[0].rstrip(",;:")
        if cut.count("`") % 2:
            cut = cut[: cut.rfind("`")].rstrip()
        sentence = cut + "…"
    return sentence.replace("|", "\\|")
