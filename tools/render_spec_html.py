"""Deterministic static Markdown rendering; declarations stay in their source documents."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from collections.abc import Sequence
from html.parser import HTMLParser
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from markdown_it import MarkdownIt
from markdown_it.token import Token
from mdit_py_plugins.footnote import footnote_plugin

ROOT = Path(__file__).resolve().parents[1]
ID_PATTERN = re.compile(r"\b[A-Z][A-Z0-9]{1,11}-[0-9]{3,5}\b")


# The public change log, rendered when the tree holds it. CHANGES.md is the platform's internal
# record and is never rendered: the rendered set is public, and its index links only public pages.
PUBLIC_CHANGE_LOG = "CHANGELOG.md"


def sources(root: Path) -> list[Path]:
    result = [root / "standard/ECL-1_Standard.md", root / "standard/ISSUES.md"]
    if (root / PUBLIC_CHANGE_LOG).is_file():
        result.append(root / PUBLIC_CHANGE_LOG)
    result += sorted((root / "protocols").glob("*.md"))
    result += sorted((root / "profiles").glob("*.md"))
    return sorted(p for p in result if p.name != "README.md")


def slug(path: Path) -> str:
    return path.stem.lower() + ".html"


def text_of(token: Token) -> str:
    """The plain text of an inline token; a line break inside a paragraph reads as a space."""
    return "".join(
        " " if child.type in {"softbreak", "hardbreak"} else child.content
        for child in token.children or []
        if child.type in {"text", "code_inline", "softbreak", "hardbreak"}
    )


def heading_id(text: str, seen: set[str]) -> str:
    base = re.sub(r"[^a-z0-9_ -]", "", text.lower()).strip().replace(" ", "-") or "section"
    result = base
    number = 1
    while result in seen:
        result = f"{base}-{number}"
        number += 1
    seen.add(result)
    return result


def inline_html(content: str) -> Token:
    token = Token("html_inline", "", 0)
    token.content = content
    return token


def requirement_links(
    token: Token, definitions: dict[str, int], destinations: dict[str, str], anchored: set[str]
) -> None:
    children = token.children or []
    # Remove an existing bold pair only for an exact requirement-ID token. The
    # anchor itself then wraps the bold ID, rather than nesting bold elements.
    for index in range(1, len(children) - 1):
        child = children[index]
        if (
            child.type == "text"
            and child.content in definitions
            and token.map is not None
            and token.map[0] <= definitions[child.content] - 1 < token.map[1]
            and children[index - 1].type == "strong_open"
            and children[index + 1].type == "strong_close"
        ):
            children[index - 1] = inline_html("")
            children[index + 1] = inline_html("")
    rewritten: list[Token] = []
    link_depth = 0
    for child in children:
        if child.type == "link_open":
            link_depth += 1
        elif child.type == "link_close":
            link_depth -= 1
        if child.type != "text" or link_depth:
            rewritten.append(child)
            continue
        cursor = 0
        for match in ID_PATTERN.finditer(child.content):
            rid = match.group()
            if rid not in destinations:
                continue
            rewritten.append(inline_html(html.escape(child.content[cursor : match.start()])))
            definition = definitions.get(rid)
            if (
                definition is not None
                and token.map is not None
                and token.map[0] <= definition - 1 < token.map[1]
                and rid not in anchored
            ):
                anchored.add(rid)
                content = (
                    f'<span id="{rid}"><strong>{rid}</strong></span>'
                    f'<a class="requirement-link" href="#{rid}" aria-label="Link to {rid}">§</a>'
                )
            else:
                content = f'<a href="{html.escape(destinations[rid], quote=True)}">{rid}</a>'
            rewritten.append(inline_html(content))
            cursor = match.end()
        if cursor:
            rewritten.append(inline_html(html.escape(child.content[cursor:])))
        else:
            rewritten.append(child)
    token.children = rewritten


def page(title: str, body: str, record: str = "") -> bytes:
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<title>{html.escape(title)}</title>\n<link rel="stylesheet" href="style.css">\n'
        '</head>\n<body>\n<a class="skip" href="#main">Skip to content</a>\n'
        '<nav aria-label="Documents"><a href="index.html">Document index</a></nav>\n'
        f'<main id="main">\n{body}{record}</main>\n</body>\n</html>\n'
    ).encode()


# Every rendered page carries the same explicit source-candidate identity.
STATUS = "release/BUILD_DESCRIPTOR.json"
RIGHTS = "Text: CC BY 4.0. Schemas, tests and code: Apache-2.0. Patent pledge: PATENTS.md."


def digest_of(root: Path, relative: str) -> str:
    path = root / relative
    if not path.is_file():
        raise ValueError(f"missing declared source: {relative}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_descriptor(root: Path) -> dict[str, Any]:
    from datetime import date

    value = json.loads((root / STATUS).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("source build descriptor must be an object")
    required = {
        "schema_version": "ecl_source_build_descriptor_v1",
        "status": "public-review-local-candidate",
    }
    if any(value.get(key) != expected for key, expected in required.items()):
        raise ValueError("source build descriptor has no supported explicit review status")
    for key in ("designation", "source_version", "review_date"):
        text = value.get(key)
        if not isinstance(text, str) or not text.strip() or text.strip().lower() in {"absent", "unknown", "tbd", "todo"}:
            raise ValueError(f"unresolved source build descriptor: {key}")
    if date.fromisoformat(value["review_date"]).isoformat() != value["review_date"]:
        raise ValueError("review_date must be an exact ISO date")
    if any(value.get(key) is not False for key in ("publication_authorized", "release_authorized", "signing_authorized")):
        raise ValueError("a local public-review descriptor cannot assert publication, signing or release")
    if value.get("authors_and_producers") != ["Robert F. Tilley Jr.", "G-14, Inc."]:
        raise ValueError("source build descriptor must retain the authors and producers")
    return value


def release_status(root: Path) -> str:
    value = build_descriptor(root)
    return f"{value['designation']}; source {value['source_version']}; review date {value['review_date']}; local candidate"


def source_record(root: Path, relative: str | None) -> str:
    """The identification that standard/README.md requires of every rendered form."""
    rows = []
    if relative is not None:
        rows.append(
            (
                "Source",
                f"<code>{html.escape(relative)}</code>, SHA-256 <code>{digest_of(root, relative)}</code>",
            )
        )
    rows += [
        ("Release status", html.escape(release_status(root))),
        ("Rights", html.escape(RIGHTS)),
    ]
    items = "".join(f"<dt>{name}</dt><dd>{value}</dd>\n" for name, value in rows)
    return (
        f'<aside class="source-record" aria-label="Source record">\n<dl>\n{items}</dl>\n</aside>\n'
    )


def render_document(
    source: str,
    definitions: dict[str, int],
    destinations: dict[str, str],
    source_names: dict[str, str],
    source_path: str,
    record: str = "",
) -> tuple[bytes, str, str]:
    parser = MarkdownIt("commonmark", {"html": False}).enable("table").use(footnote_plugin)
    environment: dict[str, Any] = {}
    tokens = parser.parse(source, environment)
    headings = [
        (index, int(t.tag[1:])) for index, t in enumerate(tokens) if t.type == "heading_open"
    ]
    if sum(level == 1 for _, level in headings) != 1 or not headings or headings[0][1] != 1:
        raise ValueError(f"{source_path}: exactly one leading h1 is required")
    if any(after[1] > before[1] + 1 for before, after in pairwise(headings)):
        raise ValueError(f"{source_path}: heading levels skip")
    title = text_of(tokens[headings[0][0] + 1])
    seen = {"main"}
    for index, _ in headings:
        tokens[index].attrSet("id", heading_id(text_of(tokens[index + 1]), seen))
    description = ""
    anchored: set[str] = set()
    for index, token in enumerate(tokens):
        # A wide table is a horizontal scroll region in the static render. Make that region
        # keyboard focusable so a person who does not use a pointer can reach and scroll it.
        if token.type == "table_open":
            token.attrSet("tabindex", "0")
        if token.type == "th_open":
            token.attrSet("scope", "col")
        if token.type == "paragraph_open" and token.level == 0 and not description:
            description = text_of(tokens[index + 1])
        if token.type != "inline":
            continue
        for child in token.children or []:
            if child.type not in {"link_open", "image"}:
                continue
            attr = "href" if child.type == "link_open" else "src"
            uri = str(child.attrGet(attr) or "")
            split = urlsplit(uri)
            if not split.scheme and split.path:
                target = str(PurePosixPath(source_path).parent / unquote(split.path))
                # Normalize ../ lexically without reading or exposing host paths.
                parts: list[str] = []
                for part in PurePosixPath(target).parts:
                    if part == "..":
                        if not parts:
                            raise ValueError(f"{source_path}: link escapes repository")
                        parts.pop()
                    elif part != ".":
                        parts.append(part)
                normalized = "/".join(parts)
                if normalized in source_names:
                    child.attrSet(
                        attr,
                        source_names[normalized] + ("#" + split.fragment if split.fragment else ""),
                    )
                else:
                    # Other repository artifacts remain available beside render/.
                    child.attrSet(
                        attr, "../" + normalized + ("#" + split.fragment if split.fragment else "")
                    )
        requirement_links(token, definitions, destinations, anchored)
    if set(definitions) != anchored:
        raise ValueError(
            f"{source_path}: missing requirement anchors: {sorted(set(definitions) - anchored)}"
        )
    rendered = parser.renderer.render(tokens, parser.options, environment)
    return page(title, rendered, record), title, description


def contrast(foreground: str, background: str = "ffffff") -> float:
    def luminance(color: str) -> float:
        values = [int(color[i : i + 2], 16) / 255 for i in (0, 2, 4)]
        linear = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in values]
        return sum(v * weight for v, weight in zip(linear, (0.2126, 0.7152, 0.0722), strict=True))

    a, b = sorted((luminance(foreground), luminance(background)))
    return (b + 0.05) / (a + 0.05)


def stylesheet() -> bytes:
    ratios = "; ".join(
        f"#{color}/#ffffff {contrast(color):.2f}:1" for color in ("1a1a1a", "0b57d0", "6b3fa0")
    )
    return (
        f"/* Computed WCAG contrast: {ratios}. All exceed 4.5:1. */\n"
        "html { background: #ffffff; color: #1a1a1a; font-family: system-ui, sans-serif; line-height: 1.6; }\n"
        "body { margin: 0 auto; padding: 1.5rem; max-width: 70ch; }\n"
        "a { color: #0b57d0; text-decoration: underline; overflow-wrap: anywhere; }\n"
        "a:visited { color: #6b3fa0; }\n"
        ":focus-visible { outline: 3px solid #0b57d0; outline-offset: 3px; }\n"
        ".skip { position: absolute; left: -10000px; }\n.skip:focus { position: static; }\n"
        "h1, h2, h3, h4, h5, h6 { line-height: 1.25; margin-top: 2rem; }\n"
        "table { display: block; overflow-x: auto; border-collapse: collapse; }\n"
        "th, td { border: 1px solid #1a1a1a; padding: 0.5rem; vertical-align: top; }\n"
        "th { text-align: left; }\npre { overflow-x: auto; padding: 0.5rem; border: 1px solid #1a1a1a; }\n"
        "code { overflow-wrap: anywhere; }\n.requirement-link { margin-left: 0.35em; }\n"
        ".source-record { margin-top: 3rem; border-top: 1px solid #1a1a1a; font-size: 0.9em; }\n"
        ".source-record dt { font-weight: bold; }\n.source-record dd { margin: 0 0 0.5rem 0; }\n"
    ).encode()


def render_all(root: Path) -> dict[str, bytes]:
    descriptor = build_descriptor(root)
    paths = sources(root)
    source_names = {p.relative_to(root).as_posix(): slug(p) for p in paths}
    if len(set(source_names.values())) != len(paths):
        raise ValueError("colliding render filenames")
    registry = json.loads(
        (root / "registries/requirements-compiled.json").read_text(encoding="utf-8")
    )
    rows = registry["requirements"]
    destinations = {
        row["requirement_id"]: source_names[row["source_path"]] + "#" + row["requirement_id"]
        for row in rows
    }
    outputs: dict[str, bytes] = {"style.css": stylesheet()}
    groups: dict[str, list[str]] = {"Core": [], "Protocols": [], "Profiles": [], "Records": []}
    for path in paths:
        relative = path.relative_to(root).as_posix()
        definitions = {
            row["requirement_id"]: row["source_line"]
            for row in rows
            if row["source_path"] == relative
        }
        body, title, description = render_document(
            path.read_text(encoding="utf-8"),
            definitions,
            destinations,
            source_names,
            relative,
            source_record(root, relative),
        )
        outputs[slug(path)] = body
        group = {"protocols": "Protocols", "profiles": "Profiles"}.get(
            path.parent.name, "Core" if path.name == "ECL-1_Standard.md" else "Records"
        )
        groups[group].append(
            f'<li><a href="{slug(path)}">{html.escape(title)}</a>: {html.escape(description)}</li>'
        )
    index = (
        f"<h1>{html.escape(descriptor['designation'])} document index</h1>\n"
        "<p>Author: Robert F. Tilley Jr. Producer and maintainer: G-14, Inc.</p>\n"
    )
    for group, entries in groups.items():
        index += f"<h2>{group}</h2>\n<ul>\n" + "\n".join(entries) + "\n</ul>\n"
    outputs["index.html"] = page(
        descriptor["designation"] + " document index", index, source_record(root, None)
    )
    validate_outputs(root, outputs)
    return dict(sorted(outputs.items()))


class Document(HTMLParser):
    def __init__(self, data: bytes) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.links: list[str] = []
        self.headings: list[int] = []
        self.feed(data.decode("utf-8"))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        identifier = values.get("id")
        if identifier:
            if identifier in self.ids:
                raise ValueError(f"duplicate HTML id: {identifier}")
            self.ids.add(identifier)
        if tag in {"script", "iframe"} or any(name.startswith("on") for name in values):
            raise ValueError("active HTML is forbidden")
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.headings.append(int(tag[1]))
        if tag == "th" and values.get("scope") != "col":
            raise ValueError("table header lacks column scope")
        if tag == "table" and values.get("tabindex") != "0":
            raise ValueError("scrollable table is not keyboard focusable")
        for name in ("href", "src"):
            uri = values.get(name)
            if uri:
                if urlsplit(uri).scheme.lower() in {"javascript", "data", "vbscript"}:
                    raise ValueError("active URI is forbidden")
                self.links.append(uri)


def validate_outputs(root: Path, outputs: dict[str, bytes]) -> None:
    documents = {name: Document(data) for name, data in outputs.items() if name.endswith(".html")}
    for name, document in documents.items():
        if document.headings.count(1) != 1 or any(
            b > a + 1 for a, b in pairwise(document.headings)
        ):
            raise ValueError(f"{name}: invalid heading hierarchy")
        for uri in document.links:
            split = urlsplit(uri)
            if split.scheme or split.netloc:
                continue
            target = unquote(split.path) or name
            if target in documents:
                if split.fragment and unquote(split.fragment) not in documents[target].ids:
                    raise ValueError(f"{name}: unresolved anchor {uri}")
            elif target not in outputs:
                artifact = (root / "render" / target).resolve()
                if not artifact.is_relative_to(root.resolve()) or not artifact.is_file():
                    raise ValueError(f"{name}: unresolved artifact {uri}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        outputs = render_all(args.root)
        directory = args.root / "render"
        if directory.is_symlink() or any((directory / name).is_symlink() for name in outputs):
            raise ValueError("render output cannot be a symlink")
        if args.check:
            actual = (
                {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}
                if directory.is_dir()
                else {}
            )
            if actual != outputs:
                raise ValueError("render is stale or contains undeclared output")
        else:
            directory.mkdir(exist_ok=True)
            for name, data in outputs.items():
                (directory / name).write_bytes(data)
        print(
            f"HTML render: {len(outputs) - 1} pages; {'check passed' if args.check else 'generated'}"
        )
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f"HTML render refused: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
