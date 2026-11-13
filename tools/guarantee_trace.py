"""Trace every compiled requirement to the elements of the ECL-1 guarantee.

The guarantee section of the standard names seven elements. TRACE below records, for each
requirement of the compiled registry, the elements it serves, by the letters of CODES; a range
rule covers a run of IDs that serve the same elements. A requirement that serves no element is
listed in UNTRACED with the decision taken about it and the reason. `--write` regenerates
`registries/guarantee-trace.json`; `--check`, which `make spec-check` runs, fails when the registry
is stale, when a compiled requirement has no trace and no recorded decision, when a rule names a
requirement that is not compiled, or when an element's name is missing from the guarantee section.

Adding a requirement to the standard therefore means adding its trace here.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import spec_index

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = Path("registries/guarantee-trace.json")
GUARANTEE_HEADING = "## The ECL-1 Guarantee (Informative)"


@dataclass(frozen=True)
class Element:
    code: str
    identifier: str
    name: str
    statement: str
    anchors: tuple[str, ...]


ELEMENTS = (
    Element(
        "M",
        "mediation",
        "Mediation without bypass",
        "Every in-scope consequential action crosses the Enforcement Boundary before its effect, "
        "no undisclosed path goes around it, and the governed AI system can neither rewrite, "
        "disable nor bypass enforcement.",
        ("ECL1N-0028", "ECL1N-0033", "ECL1N-0141"),
    ),
    Element(
        "D",
        "independent-decision",
        "A decision the governed AI system cannot change",
        "Policy outside the governed AI system decides. Inputs whose asserted values the system "
        "can produce or overwrite without independent validation, or whose authenticity or "
        "transition checks it can modify or bypass, and judgments about meaning or risk, can "
        "only make an outcome stricter and are never the basis of an admit. An independently "
        "validated state transition does not by itself make the resulting authoritative "
        "observation actor-supplied. The control plane is independent of the governed AI system.",
        ("FR-001", "ECL1N-0040", "ECL1N-0179", "ECL1N-0180"),
    ),
    Element(
        "F",
        "fail-closed",
        "Failure ends closed",
        "Missing proof, integrity failure, policy ambiguity and the loss of a required "
        "dependency end in denial, restricted mode or halt.",
        ("FR-003", "ECL1N-0043", "ECL1N-0146"),
    ),
    Element(
        "A",
        "bounded-authority",
        "Bounded, revocable authority",
        "Authority is typed, transaction-bound, time-bounded and revocable, and each delegation "
        "hop preserves or narrows it.",
        ("ECL1N-0031", "ECL1N-0035", "ECL1N-0042"),
    ),
    Element(
        "E",
        "verifiable-evidence",
        "Evidence a third party can check",
        "Each decision and action leaves tamper-evident evidence, including the inputs the "
        "decision rested on; from L2 it is independently verifiable outside the primary control "
        "plane.",
        ("ECL1N-0037", "ECL1N-0047", "ECL1N-0181", "FR-108"),
    ),
    Element(
        "S",
        "declared-scope",
        "Declared scope and claim boundary",
        "A claim states which actions and paths are in scope, which are excluded, its level, "
        "independence class and assessment, so that no reader takes it to cover more.",
        ("ECL1N-0009", "ECL1N-0010", "ECL1N-0078"),
    ),
    Element(
        "O",
        "sustaining-operations",
        "Operations that keep it true",
        "Revocation within a declared timing case, an emergency control plane, detections that "
        "act on decisions, verification of the controls and reviewed changes keep the other "
        "elements true over time.",
        ("FR-004", "ECL1N-0053", "ECL1N-0097", "ECL1N-0167"),
    ),
)
CODES = {element.code: element for element in ELEMENTS}


def span(prefix: str, first: int, last: int, codes: str, width: int = 3) -> dict[str, str]:
    """The trace `codes` for every ID from prefix-first to prefix-last."""
    return {f"{prefix}-{number:0{width}d}": codes for number in range(first, last + 1)}


def core(entries: str) -> dict[str, str]:
    """ECL1N traces written as 'number:codes' pairs separated by spaces."""
    result: dict[str, str] = {}
    for pair in entries.split():
        number, codes = pair.split(":")
        result[f"ECL1N-{int(number):04d}"] = codes
    return result


# The elements each requirement serves. The analysis behind these choices is recorded with the
# owner's decisions; each line can be checked against the requirement's text.
TRACE: dict[str, str] = {
    # Core standard: scope and claim boundary (Section 2), references (Section 3).
    **core(
        "1:S 2:S 3:S 4:S 5:S 6:S 7:SM 8:SM 9:S 10:S 11:S 12:S 13:E 14:E 15:SM 16:S 17:S 18:DM "
        "19:S 20:S 21:S 22:ES 23:S 24:S 25:S 26:S 27:S 163:MS"
    ),
    # Core standard: architecture and the runtime control invariant (Section 5).
    **core(
        "28:M 29:F 31:A 32:MDE 33:M 34:D 35:A 36:M 37:E 38:SM 39:SM 40:DE 41:D 42:A 43:MFO 44:M "
        "45:MS 46:DM 47:E 48:E 49:E 50:E 51:E 52:OE 53:OA 54:O 55:DEO 56:SD 57:DE 58:ES 59:EF "
        "60:DA 141:MD 145:E 164:D 165:D 166:OD 167:OF 168:OF 169:O 170:OD 171:EO 172:AS 173:A "
        "174:D 175:D 176:DO 177:DF 178:D 179:D 180:D 181:DE 182:DF"
    ),
    # RC-6: what holds at the release boundary, recovery after a failure, and what a verifier
    # reports (Sections 5.4.1, 5.4.2 and 5.6; an outside evaluation of October 2026).
    **core("185:MS 186:MAFOE 187:FMA 188:AFE 189:EA 190:ES 194:ES"),
    # Core standard: equivalence, profiles and interoperability baselines (Section 6).
    **core("61:MDFE 62:MDFE 63:S 183:S 64:MDFE 65:MD 66:S 67:A 68:S 69:ES 70:ED 30:S 137:S"),
    # Core standard: conformance levels, claims and assessment (Sections 7 and 11).
    **core(
        "71:S 72:S 73:S 74:S 75:SD 76:SD 77:S 78:S 79:S 80:SE 81:S 82:S 83:S 84:S 85:S 86:S 87:S "
        "142:DS 143:DS 144:DS 147:S 148:S 149:S 150:S 151:SMFO 152:SO 129:S 130:S 131:S 132:S "
        "133:S 134:S 135:S 136:S 138:E 139:E 140:S 153:S 154:SMFEO"
    ),
    # Core standard: deployment models, timing and fallback states (Section 8).
    **core(
        "89:MFEDS 90:MS 92:AEO 94:FO 95:SF 96:EOD 97:O 98:O 99:O 100:OE 101:F 102:F 103:F 104:F "
        "105:F 146:F 106:OM 107:DA 108:AE 184:AE"
    ),
    # RC-6: the scope of a restriction that a loss of required proof brings, the dependency model
    # that sets it, and when a restriction ends (Section 8.8).
    **core("191:F 192:FS 193:FO"),
    # Core standard: threat model, security and key custody (Section 9), positioning (Section 10).
    **core(
        "109:DMS 110:FDOE 111:MD 112:A 113:E 114:E 115:E 116:O 117:E 118:FDE 119:E 120:E "
        "155:E 156:ED 157:ED 158:E 159:EO 160:E 161:E 162:E 121:S 122:S 123:S 124:S 125:S 126:S "
        "127:S 128:S"
    ),
    # Core standard: functional requirements (Section 6.2).
    "ECL1N-0195": "E",
    "ECL1N-0196": "E",
    "ECL1N-0197": "E",
    "ECL1N-0198": "E",
    "ECL1N-0199": "E",
    "FR-001": "D",
    "FR-002": "D",
    "FR-003": "F",
    "FR-004": "OF",
    "FR-005": "S",
    "FR-006": "SM",
    "FR-007": "S",
    "FR-008": "F",
    "FR-101": "MS",
    "FR-102": "DAE",
    "FR-103": "DAE",
    "FR-104": "A",
    "FR-105": "A",
    "FR-106": "A",
    "FR-107": "E",
    "FR-108": "E",
    "FR-109": "D",
    "FR-110": "FO",
    "FR-111": "OF",
    "FR-112": "O",
    "FR-113": "E",
    "FR-201": "M",
    "FR-202": "DM",
    "FR-203": "AE",
    "FR-204": "O",
    "FR-205": "O",
    "FR-301": "MF",
    "FR-302": "DM",
    "FR-303": "O",
    "FR-304": "E",
    "FR-305": "FEO",
    # DCMP-2: decisions that bind the exact request and its authority, and fail closed.
    "DCMP2-001": "DE",
    "DCMP2-002": "FE",
    "DCMP2-003": "F",
    **span("DCMP2", 4, 5, "E"),
    "DCMP2-006": "DA",
    "DCMP2-007": "DE",
    "DCMP2-008": "DE",
    **span("DCMP2", 9, 10, "A"),
    "DCMP2-011": "E",
    "DCMP2-012": "AF",
    "DCMP2-013": "A",
    "DCMP2-014": "F",
    "DCMP2-015": "A",
    "DCMP2-016": "DE",
    "DCMP2-017": "FM",
    **span("DCMP2", 18, 19, "F"),
    "DCMP2-020": "DE",
    "DCMP2-021": "DE",
    "DCMP2-022": "OA",
    "DCMP2-023": "E",
    "DCMP2-024": "AE",
    "DCMP2-025": "OF",
    **span("DCMP2", 26, 31, "E"),
    "DCMP2-032": "AE",
    **span("DCMP2", 33, 34, "E"),
    "DCMP2-035": "D",
    "DCMP2-036": "DE",
    "DCMP2-037": "E",
    "DCMP2-038": "F",
    "DCMP2-039": "E",
    **span("DCMP2", 40, 41, "F"),
    "DCMP2-042": "DE",
    "DCMP2-043": "E",
    **span("DCMP2", 44, 50, "AE"),
    "DCMP2-051": "MF",
    "DCMP2-052": "DAF",
    "DCMP2-053": "D",
    # RC-5 round 4: the governed AI system's statements in a request are actor_supplied inputs and
    # a declared budget debit is never negative (review finding R2-S3).
    "DCMP2-054": "D",
    "DCMP2-055": "D",
    # Version 1.0, second fix round: a continuation after a challenge is a new request, evaluated
    # afresh, and an approval stands only for what the approver was shown.
    **span("DCMP2", 56, 57, "DE"),
    # EBMP-2: evidence of each decision, authority use and effect.
    **span("EBMP2", 1, 6, "E"),
    "EBMP2-007": "EA",
    **span("EBMP2", 8, 9, "AE"),
    **span("EBMP2", 10, 13, "E"),
    "EBMP2-014": "EA",
    "EBMP2-015": "E",
    "EBMP2-016": "DE",
    "EBMP2-017": "DA",
    "EBMP2-018": "D",
    "EBMP2-019": "E",
    "EBMP2-020": "FE",
    "EBMP2-021": "OE",
    **span("EBMP2", 22, 33, "E"),
    "EBMP2-035": "AE",
    **span("EBMP2", 36, 46, "E"),
    "EBMP2-047": "EA",
    "EBMP2-048": "E",
    **span("EBMP2", 49, 50, "EA"),
    "EBMP2-051": "EF",
    **span("EBMP2", 52, 53, "EA"),
    "EBMP2-054": "E",
    "EBMP2-055": "EM",
    **span("EBMP2", 56, 62, "E"),
    "EBMP2-063": "DO",
    "EBMP2-064": "OD",
    # Execution states that only move forward, one identifier per attempt, the verification profile.
    **span("EBMP2", 65, 67, "E"),
    # One primary finding for a bundle with several defects, whatever the order of its envelopes.
    "EBMP2-068": "EF",
    # A native adapter binding: the native record stays authoritative, and a binding that does not
    # account for its source and derived objects is refused.
    "EBMP2-069": "EF",
    # RC-6, evaluation edition 2: a release records the discharge of the obligations its decision
    # left to Enforcement; the release time is observed at the release boundary and a late forward
    # is recorded and refused; use counts, single-use consumption and the MCP call bind authority;
    # the report states what its verdict establishes and what it does not.
    "EBMP2-070": "EF",
    **span("EBMP2", 71, 75, "EA"),
    "EBMP2-076": "ES",
    # Version 1.0, second fix round: every object of a bundle, observations included, is a node of
    # the causal graph with its workflow, trace and attempt checked; a continuation after a
    # challenge verifies as one history with the request it continues.
    **span("EBMP2", 77, 78, "E"),
    # INTEGRITY-ENVELOPE-1: signatures a third party can check; resource limits fail closed.
    **span("IE1", 1, 11, "E"),
    **span("IE1", 12, 15, "ED"),
    **span("IE1", 16, 27, "E"),
    **span("IE1", 28, 30, "FE"),
    **span("IE1", 31, 36, "E"),
    # The order of the strict-input checks: one refusal, one finding, before anything is read.
    "IE1-037": "FE",
    # One reading of a schema's patterns and formats, so every validator refuses the same input.
    "IE1-038": "FE",
    # Envelope verification: the role each message type needs, and steps that name one error.
    "IE1-039": "DE",
    "IE1-040": "FE",
    # TIMING-SAFE-STATE-1: time evidence, declared timing, fail behavior and precedence.
    **span("TS1", 1, 5, "E"),
    **span("TS1", 6, 8, "S"),
    **span("TS1", 9, 11, "FO"),
    "TS1-012": "O",
    "TS1-013": "FO",
    "TS1-014": "O",
    **span("TS1", 15, 20, "F"),
    "TS1-021": "E",
    **span("TS1", 22, 23, "EF"),
    "TS1-024": "E",
    **span("TS1", 25, 26, "FO"),
    "TS1-027": "F",
    "TS1-028": "O",
    "TS1-029": "E",
    "TS1-030": "ES",
    **span("TS1", 31, 33, "F"),
    **span("TS1", 34, 36, "O"),
    # DISTRIBUTED-WORKFLOW-1: causal evidence, delegation and stale work.
    **span("DW1", 1, 9, "E"),
    "DW1-010": "EF",
    "DW1-011": "A",
    **span("DW1", 12, 13, "E"),
    "DW1-014": "ED",
    "DW1-015": "DA",
    **span("DW1", 16, 17, "DO"),
    "DW1-018": "A",
    "DW1-019": "F",
    **span("DW1", 20, 22, "E"),
    "DW1-023": "MA",
    "DW1-024": "E",
    "DW1-025": "DE",
    "DW1-026": "DA",
    "DW1-027": "MD",
    **span("DW1", 28, 30, "E"),
    # EVIDENCE-LIFECYCLE-1: evidence stays verifiable through retention, export and redaction.
    **span("EL1", 1, 27, "E"),
    # EXTENSION-REGISTRY-1: extensions cannot silently change a decision or its evidence.
    **span("XR1", 1, 5, "ED"),
    "XR1-006": "F",
    "XR1-007": "E",
    "XR1-008": "D",
    **span("XR1", 9, 10, "F"),
    **span("XR1", 11, 15, "E"),
    "XR1-016": "AD",
    "XR1-017": "E",
    **span("XR1", 18, 19, "S"),
    **span("XR1", 20, 22, "E"),
    "XR1-023": "FE",
    # Profiles.
    **span("TP1", 1, 8, "E"),
    # One key, one role: a requester's key cannot sign the decision it asked for (ECL1N-0157).
    **span("TP1", 9, 10, "DE"),
    "DHB1-001": "DE",
    "DHB1-002": "DA",
    "DHB1-003": "F",
    "DHB1-004": "DF",
    "DHB1-005": "E",
    **span("DHB1", 6, 7, "F"),
    "DHB1-008": "FE",
    "TE1-001": "M",
    "TE1-002": "MA",
    "TE1-003": "A",
    "TE1-004": "E",
    "TE1-005": "OA",
    "TE1-006": "AE",
    "TE1-007": "E",
    "TE1-008": "AM",
    "TE1-009": "AE",
    "TE1-010": "A",
    "TE1-011": "E",
    "TE1-012": "O",
    "TE1-013": "S",
    "AZB1-001": "DA",
    "AZB1-002": "DF",
    "AZB1-003": "F",
    **span("AZB1", 4, 5, "DF"),
    "AZB1-006": "S",
    "AZB1-007": "AO",
    "AZB1-008": "S",
    **span("SF1", 1, 3, "F"),
    "SF1-004": "FS",
    # The deployment, not the document, classifies the dependencies that supply required proof.
    "SF1-005": "FS",
    # Binding profiles (RC-5). A bound tool never releases an action by itself (M, D), its
    # outcomes map no less strictly and its failures end closed (D, F), its own records are
    # bound to and ranked below the ECL evidence (E), and the authority it carries stays within
    # the ECL authorization (A).
    # AARM-BINDING-1.
    "AB1-001": "SD",
    "AB1-002": "MDE",
    "AB1-003": "DF",
    "AB1-004": "DAE",
    "AB1-005": "F",
    "AB1-006": "DE",
    **span("AB1", 7, 9, "E"),
    "AB1-010": "MS",
    "AB1-011": "E",
    "AB1-012": "AM",
    "AB1-013": "DE",
    # ACS-BINDING-1.
    "AC1-001": "SM",
    "AC1-002": "MDS",
    "AC1-003": "MDA",
    "AC1-004": "DF",
    "AC1-005": "DAEF",
    "AC1-006": "FM",
    "AC1-007": "FE",
    **span("AC1", 8, 10, "E"),
    "AC1-011": "M",
    "AC1-012": "DE",
    # MCP-GATEWAY-1.
    "MG1-001": "MS",
    "MG1-002": "MF",
    "MG1-003": "DS",
    "MG1-004": "DEF",
    "MG1-005": "MA",
    **span("MG1", 6, 7, "F"),
    "MG1-008": "ODF",
    "MG1-009": "MA",
    "MG1-010": "E",
    "MG1-011": "DF",
    "MG1-012": "E",
    # The release path (an outside evaluation of October 2026): obligations that the decision
    # leaves to Enforcement are proven before the release (D, F); authority is checked at the
    # release boundary, after every step that can block (A, F); the times recorded are those
    # observed (A, E); the journal makes each event durable before its step and recovery claims
    # only what it shows (E); and a journal that cannot record ends closed (F, E).
    "MG1-013": "DF",
    "MG1-014": "AF",
    "MG1-015": "AE",
    "MG1-016": "E",
    "MG1-017": "FE",
    # OTEL-EVIDENCE-EXPORT-1: an export is a copy of the evidence and never a dependency of the
    # decision or of release.
    "OE1-001": "E",
    "OE1-002": "DEO",
    **span("OE1", 3, 4, "E"),
    "OE1-005": "AE",
    **span("OE1", 6, 10, "E"),
    # OAUTH-AUTHORITY-1: a token expresses exactly one admit and no more authority.
    **span("OA1", 1, 3, "A"),
    "OA1-004": "AM",
    **span("OA1", 5, 6, "A"),
    "OA1-007": "AF",
    "OA1-008": "AFO",
    "OA1-009": "DA",
    "OA1-010": "E",
    "OA1-011": "FE",
}

# Requirements that serve no element of the guarantee, the decision taken about each, and why.
UNTRACED: dict[str, dict[str, str]] = {
    "ECL1N-0088": {
        "decision": "keep",
        "reason": "It governs how the editor changes the standard: a 12-month deprecation window "
        "that gives implementers and claimants stable ground. It binds no deployment, so it "
        "serves no element of a deployment's guarantee.",
        "proposal": "Move the commitment to the governance documents in a later revision.",
    },
    "ECL1N-0091": {
        "decision": "keep",
        "reason": "It advises when to choose the centralized deployment model; it is selection "
        "guidance, not a control.",
        "proposal": "Make it informative, together with the deployment-profile schema and the "
        "reference deployment model, which encode it as conditions on a centralized deployment.",
    },
    "ECL1N-0093": {
        "decision": "keep",
        "reason": "It advises when to choose the sovereign deployment model for residency, "
        "regulatory or mission reasons; it is selection guidance, not a control.",
        "proposal": "Make it informative, together with the deployment-profile schema and the "
        "reference deployment model, which encode it as conditions on a sovereign deployment.",
    },
    "EBMP2-034": {
        "decision": "keep",
        "reason": "It limits evidence collection to the declared purpose and data classes. It "
        "bounds the evidence obligations for privacy rather than serving an element of the "
        "guarantee.",
    },
}


class TraceError(ValueError):
    """The trace and the compiled registry disagree."""


def guarantee_text(root: Path) -> str:
    text = (root / spec_index.STANDARD).read_text(encoding="utf-8")
    start = text.find(GUARANTEE_HEADING)
    if start < 0:
        raise TraceError("the standard has no guarantee section")
    end = text.find("\n## ", start + len(GUARANTEE_HEADING))
    return text[start : end if end >= 0 else len(text)]


def build(root: Path = ROOT) -> dict[str, Any]:
    requirements = spec_index.requirements(root)
    compiled = {item.identifier for item in requirements}
    problems = [
        f"a trace rule names a requirement that is not compiled: {identifier}"
        for identifier in sorted(set(TRACE) - compiled)
    ]
    problems += [
        f"an untraced entry names a requirement that is not compiled: {identifier}"
        for identifier in sorted(set(UNTRACED) - compiled)
    ]
    problems += [
        f"{identifier} is both traced and untraced"
        for identifier in sorted(set(TRACE) & set(UNTRACED))
    ]
    problems += [
        f"unknown element code in the trace of {identifier}: {codes}"
        for identifier, codes in sorted(TRACE.items())
        if not codes or set(codes) - set(CODES) or len(set(codes)) != len(codes)
    ]
    section = guarantee_text(root)
    problems += [
        f"the guarantee section does not name the element {element.name!r}"
        for element in ELEMENTS
        if f"**{element.name}.**" not in section
    ]
    problems += [
        f"{identifier} has no trace and no recorded decision"
        for identifier in sorted(compiled - set(TRACE) - set(UNTRACED))
    ]
    for element in ELEMENTS:
        problems += [
            f"the anchor {anchor} of {element.identifier} does not serve it"
            for anchor in element.anchors
            if element.code not in TRACE.get(anchor, "")
        ]
    if problems:
        raise TraceError("\n".join(problems))
    order = [element.code for element in ELEMENTS]
    rows = []
    for item in requirements:
        codes = TRACE.get(item.identifier, "")
        rows.append(
            {
                "requirement_id": item.identifier,
                "source_path": item.source_path,
                "text_sha256": item.text_sha256,
                "elements": [CODES[code].identifier for code in sorted(codes, key=order.index)],
            }
        )
    by_element = {
        element.identifier: [
            row["requirement_id"] for row in rows if element.identifier in row["elements"]
        ]
        for element in ELEMENTS
    }
    return {
        "schema_version": "ecl_guarantee_trace_v1",
        "candidate_version": spec_index.candidate_version(root),
        "generator": "tools/guarantee_trace.py",
        "source": spec_index.REGISTRY,
        "elements": [
            {
                "id": element.identifier,
                "name": element.name,
                "statement": element.statement,
                "anchors": list(element.anchors),
                "requirement_count": len(by_element[element.identifier]),
            }
            for element in ELEMENTS
        ],
        "counts": {
            "requirements": len(rows),
            "traced": sum(bool(row["elements"]) for row in rows),
            "untraced": sum(not row["elements"] for row in rows),
        },
        "untraced": [
            {"requirement_id": identifier, **UNTRACED[identifier]}
            for identifier in sorted(UNTRACED)
        ],
        "requirements": rows,
    }


def encode(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    try:
        value = build(args.root)
        content = encode(value)
        target = args.root / OUTPUT
        if args.check:
            if not target.is_file() or target.read_bytes() != content.encode("utf-8"):
                raise TraceError(f"{OUTPUT} is stale; run tools/guarantee_trace.py --write")
        else:
            target.write_bytes(content.encode("utf-8"))
    except (OSError, KeyError, ValueError) as error:
        print(f"guarantee trace: {error}", file=sys.stderr)
        return 1
    counts = value["counts"]
    print(
        f"guarantee trace: {counts['traced']} of {counts['requirements']} requirements traced, "
        f"{counts['untraced']} untraced with a recorded decision; "
        + ("check passed" if args.check else f"wrote {OUTPUT}")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
