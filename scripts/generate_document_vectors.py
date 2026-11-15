"""Generate the deterministic document-coverage suite.

ECL1N-0058 asks for a positive and a negative case for every schema branch. The claim and assessment
documents are the action register, the conformance claim, the assessment package, the mapping packet,
the deployment profile, the evidence lifecycle policy, the offline verification package and the work
intent. The runner evaluates them at its `document` stage: strict parsing, then the schema that the
vector names, then the registered rules that apply to the document. These include the action
register declarations rule (ECL1N-0178), the deployment timing rule (ECL1N-0100), and the
extension and context rules that apply to work intent.

Each passing vector is a published example from `profiles/examples/`, or an authored document where
the repository publishes none, changed where a branch needs another value. Each failing vector
changes one passing vector in one place, so that a single schema unit (an enum or a conditional arm)
is the reason it is refused, and claims that unit in `covers`. `scripts/coverage_denominator.py`
accepts a claim only when changing that unit alone changes the vector's result, so a claim here
cannot outrun its artifact. Each failing vector negates the requirement whose document content the
refused unit carries; the mapping is listed case by case below.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

SUITE = Path("conformance/suites/document-coverage")
SUITE_ID = "ecl-1-v1.0-document-coverage"
GENERATOR = "scripts/generate_document_vectors.py"
STAGE = "document"
SCHEMA_INVALID = "ecl.error.schema-invalid.v1"
REGISTER_RULE = "ecl.rule.register-declarations-consistent.v1"
NAMESPACE = "https://externalcontrollayer.ai/ns/schema/"
REGISTER = NAMESPACE + "action-register/1"
CLAIM = NAMESPACE + "conformance-claim/1"
PACKAGE = NAMESPACE + "assessment-package/1"
MAPPING = NAMESPACE + "mapping-packet/1"
DEPLOYMENT = NAMESPACE + "deployment-profile/1"
LIFECYCLE = NAMESPACE + "lifecycle-policy/1"
OFFLINE = NAMESPACE + "offline-verification-package/1"
INTENT = NAMESPACE + "work-intent/1"

EXAMPLES = Path("profiles/examples")
REGISTER_EXAMPLE = EXAMPLES / "claims/action-register.json"
CLAIM_EXAMPLE = EXAMPLES / "claims/public-assessment-only-claim.json"
PACKAGE_EXAMPLE = EXAMPLES / "claims/assessment-package.json"
MAPPING_EXAMPLE = EXAMPLES / "claims/framework-mapping.json"
CENTRALIZED = EXAMPLES / "deployment/centralized-hosted-local-gate.json"
FEDERATED = EXAMPLES / "deployment/federated-local-gate.json"
SOVEREIGN = EXAMPLES / "deployment/sovereign-self-managed-local-gate.json"
OFFLINE_EDGE = EXAMPLES / "deployment/offline-edge-local-gate.json"
AIR_GAPPED = EXAMPLES / "deployment/air-gapped-local-gate.json"
UNCHANGED = "copy the published example without change"


def unit(schema: str, pointer: str, kind: str, index: int = 0) -> str:
    """The coverage-denominator identifier of a schema unit."""
    if kind == "root":
        return schema + "##root"
    if kind == "enum":
        return f"{schema}#{pointer}/enum#enum"
    return f"{schema}#{pointer}/{kind}#{kind}[{index}]"


# Action register.
AR_ROOT = unit(REGISTER, "", "root")
AR_CLASSIFICATION = unit(REGISTER, "/$defs/actionEntry/properties/classification", "enum")
AR_DIMENSION = unit(REGISTER, "/$defs/actionEntry/properties/consequence_dimensions/items", "enum")
AR_ENFORCEMENT = unit(REGISTER, "/$defs/actionEntry/properties/enforcement_class", "enum")
AR_CONSEQUENTIAL = unit(REGISTER, "/$defs/actionEntry/allOf/0", "if")
AR_CONSEQUENTIAL_PREDICATE = unit(
    REGISTER, "/$defs/actionEntry/allOf/0/if/properties/classification", "enum"
)
AR_INTERCEPTION = unit(REGISTER, "/$defs/capabilityPath/properties/interception_result", "enum")
AR_INPUT_CLASS = unit(REGISTER, "/$defs/decisionInputDeclaration/properties/class", "enum")
# ECL1N-0177: a threshold names what it compares by a pointer into the action's parameters or by a
# measure that the deployment defines (review finding R3-P5).
AR_THRESHOLD_PARAMETER = unit(REGISTER, "/$defs/approvalThreshold", "oneOf", 0)
AR_THRESHOLD_MEASURE = unit(REGISTER, "/$defs/approvalThreshold", "oneOf", 1)
# Conformance claim.
CC_ROOT = unit(CLAIM, "", "root")
CC_BOUNDARY = unit(CLAIM, "/properties/boundary_class", "enum")
CC_RESPONSIBILITY = unit(CLAIM, "/properties/responsibilities/items", "enum")
CC_STATUS = unit(CLAIM, "/properties/status", "enum")
CC_CLASS = unit(CLAIM, "/$defs/independence/properties/class", "enum")
CC_SUPPORT = unit(CLAIM, "/$defs/mappingClaim/properties/support_class", "enum")
CC_VALIDATION = unit(CLAIM, "/$defs/mappingClaim/properties/validation_state", "enum")
CC_CONDITIONAL = unit(CLAIM, "/allOf/0", "if")
CC_LEVEL_4 = unit(CLAIM, "/allOf/1", "if")
CC_LEVEL_2 = unit(CLAIM, "/allOf/2", "if")
CC_LEVEL_2_CLASS = unit(CLAIM, "/allOf/2/then/properties/independence/properties/class", "enum")
CC_CLASS_A = unit(CLAIM, "/allOf/3", "if")
# Assessment package.
AP_ROOT = unit(PACKAGE, "", "root")
AP_BOUNDARY = unit(PACKAGE, "/properties/boundary_class", "enum")
AP_ROLE = unit(PACKAGE, "/$defs/artifact/properties/role", "enum")
AP_RESULT = unit(PACKAGE, "/$defs/checklistItem/properties/result", "enum")
AP_EVIDENCED = unit(PACKAGE, "/$defs/checklistItem/allOf/0", "if")
AP_EVIDENCED_PREDICATE = unit(PACKAGE, "/$defs/checklistItem/allOf/0/if/properties/result", "enum")
AP_NOT_APPLICABLE = unit(PACKAGE, "/$defs/checklistItem/allOf/1", "if")
AP_STATUS = unit(PACKAGE, "/$defs/claimDecision/properties/status", "enum")
AP_DISPOSITION = unit(PACKAGE, "/$defs/finding/properties/disposition", "enum")
AP_SEVERITY = unit(PACKAGE, "/$defs/finding/properties/severity", "enum")
AP_CLASS = unit(PACKAGE, "/$defs/independence/properties/class", "enum")
AP_PROCUREMENT = unit(PACKAGE, "/$defs/procurementDecision/properties/decision", "enum")
AP_TREATMENT = unit(PACKAGE, "/$defs/residualRisk/properties/treatment", "enum")
AP_LEVEL_2 = unit(PACKAGE, "/allOf/0", "if")
AP_LEVEL_2_CLASS = unit(PACKAGE, "/allOf/0/then/properties/independence/properties/class", "enum")
AP_LEVEL_4 = unit(PACKAGE, "/allOf/1", "if")
# Mapping packet.
MP_ROOT = unit(MAPPING, "", "root")
MP_VALIDATION = unit(MAPPING, "/properties/validation_state", "enum")
MP_SUPPORT = unit(MAPPING, "/$defs/obligation/properties/support_class", "enum")
MP_OBLIGATION_VALIDATION = unit(MAPPING, "/$defs/obligation/properties/validation_state", "enum")
MP_DIRECT = unit(MAPPING, "/$defs/obligation/allOf/0", "if")
# Deployment profile.
DP_ROOT = unit(DEPLOYMENT, "", "root")
DP_SURFACE = unit(DEPLOYMENT, "/properties/delivery_surfaces/items", "enum")
DP_MODEL = unit(DEPLOYMENT, "/properties/model", "enum")
DP_LOCATION = unit(DEPLOYMENT, "/properties/release_path/properties/enforcement_location", "enum")
DP_NETWORK_LOSS = unit(
    DEPLOYMENT, "/properties/release_path/properties/network_loss_disposition", "enum"
)
DP_EXPIRES_TO = unit(DEPLOYMENT, "/$defs/degradedMode/properties/expires_to", "enum")
DP_DEPENDENCY_CLASS = unit(DEPLOYMENT, "/$defs/dependency/properties/class", "enum")
DP_FAILURE = unit(DEPLOYMENT, "/$defs/dependency/properties/failure_disposition", "enum")
DP_FEDERATED_FIELD = unit(DEPLOYMENT, "/$defs/federatedFields/items", "enum")
DP_RESTRICTED_ACTION = unit(
    DEPLOYMENT, "/$defs/restrictedMode/properties/allowed_actions/items", "enum"
)
DP_TIMING = unit(DEPLOYMENT, "/$defs/timingCase/allOf/0", "if")
DP_STALE = unit(
    DEPLOYMENT, "/$defs/topologyControls/properties/offline/properties/stale_transition", "enum"
)
DP_CENTRALIZED, DP_FEDERATED, DP_SOVEREIGN, DP_OFFLINE, DP_AIR_GAPPED = (
    unit(DEPLOYMENT, f"/allOf/{index}", "if") for index in range(5)
)
# Lifecycle policy, offline verification package and work intent.
LP_ROOT = unit(LIFECYCLE, "", "root")
OV_ROOT = unit(OFFLINE, "", "root")
OV_ROLE = unit(OFFLINE, "/properties/artifacts/items/properties/role", "enum")
WI_ROOT = unit(INTENT, "", "root")
WI_KIND = unit(INTENT, "/properties/exact_targets/items/properties/kind", "enum")


@dataclass(frozen=True)
class Case:
    """One vector. A case with `negates` fails with `primary`, schema invalidity unless it names a
    registered rule; the others pass."""

    identifier: str
    value: Any
    schema: str
    base: Path | str | None
    change: str
    covers: tuple[str, ...]
    requirements: tuple[str, ...]
    negates: tuple[str, ...] = ()
    primary: str = SCHEMA_INVALID


def read(root: Path, path: Path) -> dict[str, Any]:
    value = json.loads((root / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: not an object")
    return value


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def digest(fill: str) -> dict[str, str]:
    if len(fill) != 2 or any(char not in "0123456789abcdef" for char in fill):
        raise ValueError("a synthetic SHA-256 placeholder uses one hexadecimal byte")
    return {"algorithm": "ecl.digest.sha-256.v1", "value": fill * 32}


def reference(uri: str, fill: str) -> dict[str, Any]:
    return {"uri": uri, "version": "1", "digest": digest(fill)}


def changed(value: dict[str, Any], *edits: tuple[tuple[str | int, ...], Any]) -> dict[str, Any]:
    """A copy with each (path, new) edit applied; a new value of `None` deletes the member."""
    result = copy.deepcopy(value)
    for path, new in edits:
        container: Any = result
        for key in path[:-1]:
            container = container[key]
        if new is None:
            del container[path[-1]]
        else:
            container[path[-1]] = copy.deepcopy(new)
    return result


def path(name: str) -> str:
    return (SUITE / (name + ".json")).as_posix()


def passing(
    name: str,
    value: dict[str, Any],
    schema: str,
    base: Path | str | None,
    change: str,
    covers: tuple[str, ...],
    requirements: tuple[str, ...],
) -> Case:
    return Case(name, value, schema, base, change, covers, requirements)


def refusal(
    name: str,
    value: dict[str, Any],
    schema: str,
    base: str,
    change: str,
    covers: tuple[str, ...],
    negates: tuple[str, ...],
) -> Case:
    return Case(name, value, schema, base, change, covers, negates, negates)


def rule_refusal(
    name: str,
    value: dict[str, Any],
    base: str,
    change: str,
    negates: tuple[str, ...],
) -> Case:
    """A register that its schema accepts and `ecl.rule.register-declarations-consistent.v1`
    refuses (ECL1N-0178); a verifier refuses it as a usage error (DCMP2-053)."""
    return Case(name, value, REGISTER, base, change, (), negates, negates, REGISTER_RULE)


def register_rule_cases(example: dict[str, Any], base: str) -> list[Case]:
    """ECL1N-0178 and DCMP2-053: the register declarations that its schema cannot check. The
    published example declares a payee-mandate check computed from the payee allow-list and the
    principal's mandate (`derived_from`)."""
    entry = example["entries"][0]
    inputs = entry["decision_inputs"]
    names = [item["input"] for item in inputs]
    check = names.index("urn:example:input:payee-mandate-check")
    anomaly = names.index("urn:example:input:transfer-anomaly-score")
    balance = names.index("urn:example:input:account-balance")
    # Review finding R2-S2 (attack a26): a second entry for the action class that declares the
    # anomaly score verifiable, so that a verifier would have to choose a declaration.
    second = copy.deepcopy(entry)
    second["decision_inputs"][anomaly]["class"] = "verifiable"
    repeated = [*inputs, copy.deepcopy(inputs[anomaly])]
    variant = copy.deepcopy(inputs[anomaly])
    variant["input"] = variant["input"].replace("urn:", "URN:", 1)
    return [
        rule_refusal(
            "register-invalid-action-class-declared-twice",
            changed(example, (("entries",), [second, entry])),
            base,
            "declare the action class a second time, with the anomaly score verifiable",
            ("DCMP2-053", "ECL1N-0178"),
        ),
        rule_refusal(
            "register-invalid-input-declared-twice",
            changed(example, (("entries", 0, "decision_inputs"), repeated)),
            base,
            "declare the anomaly score a second time for the action class",
            ("DCMP2-053", "ECL1N-0178"),
        ),
        rule_refusal(
            "register-invalid-input-declared-twice-urn-case",
            changed(example, (("entries", 0, "decision_inputs"), [*inputs, variant])),
            base,
            "declare the anomaly score again under URN:, which names the same URN",
            ("DCMP2-053", "ECL1N-0178"),
        ),
        rule_refusal(
            "register-invalid-derived-from-undeclared-input",
            changed(
                example,
                (
                    ("entries", 0, "decision_inputs", check, "derived_from"),
                    [names[0], "urn:example:input:vendor-rating"],
                ),
            ),
            base,
            "compute the payee-mandate check from a vendor rating that the register does not declare",
            ("ECL1N-0178",),
        ),
        rule_refusal(
            "register-invalid-verifiable-derived-from-judgment",
            changed(
                example,
                (
                    ("entries", 0, "decision_inputs", check, "derived_from"),
                    [names[0], names[anomaly]],
                ),
            ),
            base,
            "compute the verifiable payee-mandate check from the anomaly score",
            ("ECL1N-0178",),
        ),
        rule_refusal(
            "register-invalid-derivation-cycle",
            changed(
                example,
                (
                    ("entries", 0, "decision_inputs", balance, "derived_from"),
                    [names[check]],
                ),
                (
                    ("entries", 0, "decision_inputs", check, "derived_from"),
                    [names[0], names[balance]],
                ),
            ),
            base,
            "compute the account balance from the payee-mandate check and the check from the balance",
            ("ECL1N-0178",),
        ),
    ]


def register_cases(root: Path) -> list[Case]:
    # ECL1N-0007: the register states each class's classification decision, its consequences, its
    # affected resources and its enforcement class, and any human-approval threshold (ECL1N-0177).
    # ECL1N-0039: it documents each exercised interception point. ECL1N-0178: it declares each
    # decision input of a consequential class, with its class, required flag, source, maximum age,
    # deadline and the inputs it is computed from.
    example = read(root, REGISTER_EXAMPLE)
    entry = example["entries"][0]
    pending = changed(
        entry,
        (("action_class_id",), "ecl.action.payment-refund.v1"),
        (("classification",), "consequential_pending_review"),
        (("enforcement_class",), "soft"),
        (("rationale",), "Refund reversal is under review; it is mediated as consequential."),
        (("capability_paths", 0, "path_id"), "urn:example:ecl:path:payments-refund"),
        (("capability_paths", 0, "interception_result"), "soft_mediated"),
        (("consequence_coupling",), None),
        (("human_approval_threshold",), None),
    )
    confined = {
        "action_class_id": "ecl.action.draft-summary.v1",
        "classification": "non_consequential",
        "rationale": "A draft summary stays in the isolated execution context (ECL1N-0005).",
        "consequence_dimensions": [],
        "affected_resources": [],
        "actor_subject_classes": entry["actor_subject_classes"],
        "data_classes": [],
        "enforcement_class": "soft",
        "capability_paths": [],
        "evidence_profile": "ecl.evidence.summary.v1",
    }
    widened = changed(example, (("entries",), [entry, pending, confined]))
    base = path("register-valid-published-example")
    anomaly = [item["input"] for item in entry["decision_inputs"]].index(
        "urn:example:input:transfer-anomaly-score"
    )
    names = ("ECL1N-0007",)
    return [
        passing(
            "register-valid-published-example",
            example,
            REGISTER,
            REGISTER_EXAMPLE,
            UNCHANGED,
            (
                AR_ROOT,
                AR_CLASSIFICATION,
                AR_DIMENSION,
                AR_ENFORCEMENT,
                AR_CONSEQUENTIAL,
                AR_CONSEQUENTIAL_PREDICATE,
                AR_INTERCEPTION,
                AR_INPUT_CLASS,
                AR_THRESHOLD_PARAMETER,
                AR_THRESHOLD_MEASURE,
            ),
            ("ECL1N-0007", "ECL1N-0039", "ECL1N-0178"),
        ),
        passing(
            "register-valid-pending-review-and-confined-entries",
            widened,
            REGISTER,
            REGISTER_EXAMPLE,
            "add a soft-mediated entry pending review and a confined non-consequential entry",
            (AR_ROOT, AR_CLASSIFICATION, AR_ENFORCEMENT, AR_CONSEQUENTIAL, AR_INTERCEPTION),
            ("ECL1N-0007", "ECL1N-0039"),
        ),
        refusal(
            "register-invalid-classification-outside-enum",
            changed(example, (("entries", 0, "classification"), "deferred")),
            REGISTER,
            base,
            "set the classification decision to a value the schema does not define",
            (AR_ROOT, AR_CLASSIFICATION),
            names,
        ),
        refusal(
            "register-invalid-consequence-dimension-outside-enum",
            changed(
                example,
                (
                    ("entries", 0, "consequence_dimensions"),
                    [*entry["consequence_dimensions"], "reputational"],
                ),
            ),
            REGISTER,
            base,
            "add a consequence dimension that the classification rules do not define",
            (AR_ROOT, AR_DIMENSION),
            names,
        ),
        refusal(
            "register-invalid-enforcement-class-outside-enum",
            changed(example, (("entries", 0, "enforcement_class"), "advisory")),
            REGISTER,
            base,
            "set the enforcement class to a value other than soft or hard",
            (AR_ROOT, AR_ENFORCEMENT),
            names,
        ),
        refusal(
            "register-invalid-consequential-without-affected-resources",
            changed(example, (("entries", 0, "affected_resources"), [])),
            REGISTER,
            base,
            "remove the affected resources of a consequential entry",
            (AR_ROOT, AR_CONSEQUENTIAL, AR_CONSEQUENTIAL_PREDICATE),
            names,
        ),
        refusal(
            "register-invalid-interception-result-outside-enum",
            changed(
                example,
                (("entries", 0, "capability_paths", 0, "interception_result"), "partly_mediated"),
            ),
            REGISTER,
            base,
            "set an exercised interception result to a value the schema does not define",
            (AR_ROOT, AR_INTERCEPTION),
            ("ECL1N-0039",),
        ),
        refusal(
            "register-invalid-decision-input-class-outside-enum",
            # The anomaly score, from which no declared input is computed, so that only the schema
            # refuses the register.
            changed(example, (("entries", 0, "decision_inputs", anomaly, "class"), "trusted")),
            REGISTER,
            base,
            "set a decision input's class to a value the core standard does not define",
            (AR_ROOT, AR_INPUT_CLASS),
            ("ECL1N-0178",),
        ),
        refusal(
            "register-invalid-consequential-without-decision-inputs",
            changed(example, (("entries", 0, "decision_inputs"), None)),
            REGISTER,
            base,
            "remove the decision inputs of a consequential entry",
            (AR_ROOT, AR_CONSEQUENTIAL, AR_CONSEQUENTIAL_PREDICATE),
            ("ECL1N-0178",),
        ),
        refusal(
            "register-invalid-decision-input-without-maximum-age",
            changed(example, (("entries", 0, "decision_inputs", 2, "maximum_age_seconds"), None)),
            REGISTER,
            base,
            "remove the maximum age of a declared decision input",
            (AR_ROOT,),
            ("ECL1N-0178",),
        ),
        refusal(
            "register-invalid-approval-threshold-without-approvers",
            changed(example, (("entries", 0, "human_approval_threshold", 0, "approvers"), None)),
            REGISTER,
            base,
            "remove the number of approvers from a human-approval threshold",
            (AR_ROOT,),
            names,
        ),
        # A threshold that names neither a parameter nor a measure; each alternative of the
        # threshold's oneOf is witnessed by the threshold that loses what the other names.
        refusal(
            "register-invalid-approval-threshold-without-parameter",
            changed(example, (("entries", 0, "human_approval_threshold", 0, "parameter"), None)),
            REGISTER,
            base,
            "remove the parameter that the first human-approval threshold compares, leaving it "
            "neither a parameter nor a measure",
            (AR_ROOT, AR_THRESHOLD_MEASURE),
            names,
        ),
        refusal(
            "register-invalid-approval-threshold-without-measure",
            changed(example, (("entries", 0, "human_approval_threshold", 1, "measure"), None)),
            REGISTER,
            base,
            "remove the measure that the second human-approval threshold compares, leaving it "
            "neither a parameter nor a measure",
            (AR_ROOT, AR_THRESHOLD_PARAMETER),
            names,
        ),
        refusal(
            "register-invalid-approval-threshold-parameter-and-measure",
            changed(
                example,
                (
                    ("entries", 0, "human_approval_threshold", 0, "measure"),
                    "urn:example:ecl:measure:payment-amount",
                ),
            ),
            REGISTER,
            base,
            "name both a parameter and a measure in one human-approval threshold",
            (AR_ROOT,),
            names,
        ),
        refusal(
            "register-invalid-approval-threshold-parameter-not-a-pointer",
            changed(
                example, (("entries", 0, "human_approval_threshold", 0, "parameter"), "amount")
            ),
            REGISTER,
            base,
            "name the threshold's parameter without the leading solidus of a JSON Pointer",
            (AR_ROOT,),
            names,
        ),
        *register_rule_cases(example, base),
    ]


def claim_cases(root: Path) -> list[Case]:
    # ECL1N-0073: the boundary class. ECL1N-0078: the claim status and the achieved independence
    # class. ECL1N-0076: Class A is disclosed and never represented as the class a higher level
    # needs. ECL1N-0077: no conditional conformance at L4, and a conditional claim names its
    # conditions and its end. ECL1N-0124 and ECL1N-0125: a mapping claim's support class and
    # validation state.
    example = read(root, CLAIM_EXAMPLE)
    condition = {
        "condition_id": "urn:example:ecl:condition:drill-archive-index",
        "finding_reference": {"uri": "urn:example:ecl:finding:noncritical-drill-index", "version": "1"},
        "remediation": "Complete the archive index for the retained negative-test and drill reports.",
        "owner": "urn:example:ecl:owner:assurance",
        "deadline": "2026-12-27T12:00:00Z",
        "operating_limit": "No new action class enters the boundary until the condition closes.",
    }
    conditional = changed(
        example,
        (("level",), 3),
        (("status",), "conditional_conformance"),
        (("independence", "class"), "C"),
        (("conditions",), [condition]),
        (("limitations",), [
            "Fictional L3 Class C conditional-conformance document-shape test; not an actual deployment claim, assessment or certification.",
            "The fictional general interoperability scope uses Ed25519 and does not enable ML-DSA-65. Its one noncritical condition concerns report indexing; required negative-test evidence is assumed present for this shape test.",
        ]),
    )
    full = changed(
        example,
        (("level",), 4),
        (("status",), "full_conformance"),
        (("independence", "class"), "C"),
        (("limitations",), [
            "Fictional L4 Class C full-conformance document-shape test; not an actual deployment claim, assessment or certification.",
            "The fictional general interoperability scope uses Ed25519 and does not enable ML-DSA-65; no open provider-qualification finding is asserted in this variant.",
        ]),
    )
    disclosed = changed(
        example,
        (("level",), 1),
        (("independence", "class"), "A"),
        (
            ("independence", "same_operator_disclosure"),
            "The control plane uses same-operator separated controls; no separately administered"
            " or externally independent trust domain is asserted.",
        ),
    )
    base = path("claim-valid-published-example")
    return [
        passing(
            "claim-valid-published-example",
            example,
            CLAIM,
            CLAIM_EXAMPLE,
            UNCHANGED,
            (
                CC_ROOT,
                CC_BOUNDARY,
                CC_RESPONSIBILITY,
                CC_STATUS,
                CC_CLASS,
                CC_SUPPORT,
                CC_VALIDATION,
                CC_LEVEL_2,
                CC_LEVEL_2_CLASS,
            ),
            ("ECL1N-0073", "ECL1N-0076", "ECL1N-0078", "ECL1N-0124", "ECL1N-0125"),
        ),
        passing(
            "claim-valid-conditional-l3-class-c",
            conditional,
            CLAIM,
            CLAIM_EXAMPLE,
            "claim conditional conformance at L3 with Class C and one condition",
            (CC_ROOT, CC_STATUS, CC_CLASS, CC_CONDITIONAL, CC_LEVEL_2, CC_LEVEL_2_CLASS),
            ("ECL1N-0076", "ECL1N-0077", "ECL1N-0078"),
        ),
        passing(
            "claim-valid-full-l4-class-c",
            full,
            CLAIM,
            CLAIM_EXAMPLE,
            "claim full conformance at L4 with Class C",
            (CC_ROOT, CC_STATUS, CC_CLASS, CC_LEVEL_4, CC_LEVEL_2, CC_LEVEL_2_CLASS),
            ("ECL1N-0076", "ECL1N-0077", "ECL1N-0078"),
        ),
        passing(
            "claim-valid-l1-class-a-disclosed",
            disclosed,
            CLAIM,
            CLAIM_EXAMPLE,
            "claim L1 with Class A and its same-operator disclosure",
            (CC_ROOT, CC_CLASS, CC_CLASS_A),
            ("ECL1N-0076", "ECL1N-0078"),
        ),
        refusal(
            "claim-invalid-boundary-class-outside-enum",
            changed(example, (("boundary_class",), "partial-mediation")),
            CLAIM,
            base,
            "declare a boundary class the standard does not define",
            (CC_ROOT, CC_BOUNDARY),
            ("ECL1N-0073",),
        ),
        refusal(
            "claim-invalid-status-outside-enum",
            changed(example, (("status",), "provisional")),
            CLAIM,
            base,
            "state a claim status the standard does not define",
            (CC_ROOT, CC_STATUS),
            ("ECL1N-0078",),
        ),
        refusal(
            "claim-invalid-independence-class-outside-enum",
            changed(disclosed, (("independence", "class"), "D")),
            CLAIM,
            path("claim-valid-l1-class-a-disclosed"),
            "state an independence class the standard does not define",
            (CC_ROOT, CC_CLASS),
            ("ECL1N-0078",),
        ),
        refusal(
            "claim-invalid-mapping-support-class-outside-enum",
            changed(example, (("mapping_claims", 0, "support_class"), "full_support")),
            CLAIM,
            base,
            "classify a mapped obligation outside the three mapping claim classes",
            (CC_ROOT, CC_SUPPORT),
            ("ECL1N-0124",),
        ),
        refusal(
            "claim-invalid-mapping-validation-state-outside-enum",
            changed(example, (("mapping_claims", 0, "validation_state"), "framework_certified")),
            CLAIM,
            base,
            "state a mapping validation state the standard does not define",
            (CC_ROOT, CC_VALIDATION),
            ("ECL1N-0125",),
        ),
        refusal(
            "claim-invalid-conditional-without-conditions",
            changed(conditional, (("conditions",), None)),
            CLAIM,
            path("claim-valid-conditional-l3-class-c"),
            "remove the conditions of a conditional claim",
            (CC_ROOT, CC_CONDITIONAL),
            ("ECL1N-0077",),
        ),
        refusal(
            "claim-invalid-conditional-at-l4",
            changed(conditional, (("level",), 4)),
            CLAIM,
            path("claim-valid-conditional-l3-class-c"),
            "raise a conditional claim to L4",
            (CC_ROOT, CC_LEVEL_4),
            ("ECL1N-0077",),
        ),
        refusal(
            "claim-invalid-class-a-at-l2",
            changed(disclosed, (("level",), 2)),
            CLAIM,
            path("claim-valid-l1-class-a-disclosed"),
            "raise a Class A claim to L2",
            (CC_ROOT, CC_LEVEL_2, CC_LEVEL_2_CLASS),
            ("ECL1N-0076",),
        ),
        refusal(
            "claim-invalid-class-a-without-disclosure",
            changed(disclosed, (("independence", "same_operator_disclosure"), None)),
            CLAIM,
            path("claim-valid-l1-class-a-disclosed"),
            "remove the same-operator disclosure of a Class A claim",
            (CC_ROOT, CC_CLASS_A),
            ("ECL1N-0076",),
        ),
    ]


def package_cases(root: Path) -> list[Case]:
    # ECL1N-0133: the boundary class of the submission. ECL1N-0130: Pass, Fail or Not Applicable.
    # ECL1N-0129: evidence links for each applicable item. ECL1N-0153: Not Applicable only with
    # evidence that the predicate is false. ECL1N-0147: the severities. ECL1N-0081: checklist
    # results, severities, claim status and procurement decision are kept apart. ECL1N-0080: the
    # artifact references and the structured findings, risk and independence record. ECL1N-0076
    # and ECL1N-0077 as for the claim.
    example = read(root, PACKAGE_EXAMPLE)
    not_applicable_item = {
        "item_id": "urn:example:ecl:checklist:fleet-staged-rollout",
        "requirement_ids": ["FR-205"],
        "minimum_level": 3,
        "result": "not_applicable",
        "evidence": [],
        "applicability_false_evidence": ["urn:example:ecl:evidence:claimed-level-below-l3"],
        "notes": "The claimed level is below the item's minimum level (ECL1N-0153).",
    }
    not_applicable = changed(
        example, (("checklist",), [*example["checklist"], not_applicable_item])
    )
    level_4 = changed(example, (("level",), 4), (("independence", "class"), "C"))
    level_1 = changed(example, (("level",), 1), (("independence", "class"), "A"))
    base = path("assessment-valid-published-example")
    return [
        passing(
            "assessment-valid-published-example",
            example,
            PACKAGE,
            PACKAGE_EXAMPLE,
            UNCHANGED,
            (
                AP_ROOT,
                AP_BOUNDARY,
                AP_ROLE,
                AP_RESULT,
                AP_EVIDENCED,
                AP_EVIDENCED_PREDICATE,
                AP_STATUS,
                AP_DISPOSITION,
                AP_SEVERITY,
                AP_CLASS,
                AP_PROCUREMENT,
                AP_TREATMENT,
                AP_LEVEL_2,
                AP_LEVEL_2_CLASS,
            ),
            (
                "ECL1N-0076",
                "ECL1N-0080",
                "ECL1N-0081",
                "ECL1N-0129",
                "ECL1N-0130",
                "ECL1N-0133",
                "ECL1N-0147",
            ),
        ),
        passing(
            "assessment-valid-not-applicable-item",
            not_applicable,
            PACKAGE,
            PACKAGE_EXAMPLE,
            "add an item marked not applicable with evidence that its predicate is false",
            (AP_ROOT, AP_RESULT, AP_NOT_APPLICABLE),
            ("ECL1N-0130", "ECL1N-0153"),
        ),
        passing(
            "assessment-valid-l4-class-c",
            level_4,
            PACKAGE,
            PACKAGE_EXAMPLE,
            "assess at L4 with Class C",
            (AP_ROOT, AP_CLASS, AP_LEVEL_4, AP_LEVEL_2, AP_LEVEL_2_CLASS),
            ("ECL1N-0076", "ECL1N-0077"),
        ),
        passing(
            "assessment-valid-l1-class-a",
            level_1,
            PACKAGE,
            PACKAGE_EXAMPLE,
            "assess at L1 with Class A",
            (AP_ROOT, AP_CLASS),
            ("ECL1N-0080",),
        ),
        refusal(
            "assessment-invalid-boundary-class-outside-enum",
            changed(example, (("boundary_class",), "partial-mediation")),
            PACKAGE,
            base,
            "record a claim boundary class the standard does not define",
            (AP_ROOT, AP_BOUNDARY),
            ("ECL1N-0133",),
        ),
        refusal(
            "assessment-invalid-artifact-role-outside-enum",
            changed(example, (("artifact_manifest", 0, "role"), "screenshot")),
            PACKAGE,
            base,
            "give an artifact of the manifest a role the schema does not define",
            (AP_ROOT, AP_ROLE),
            ("ECL1N-0080",),
        ),
        refusal(
            "assessment-invalid-checklist-result-outside-enum",
            changed(example, (("checklist", 0, "result"), "partial")),
            PACKAGE,
            base,
            "mark a checklist item other than Pass, Fail or Not Applicable",
            (AP_ROOT, AP_RESULT),
            ("ECL1N-0130",),
        ),
        refusal(
            "assessment-invalid-result-without-evidence",
            changed(example, (("checklist", 0, "evidence"), [])),
            PACKAGE,
            base,
            "remove the evidence links of a passed item",
            (AP_ROOT, AP_EVIDENCED, AP_EVIDENCED_PREDICATE),
            ("ECL1N-0129",),
        ),
        refusal(
            "assessment-invalid-not-applicable-without-predicate-evidence",
            changed(not_applicable, (("checklist", 2, "applicability_false_evidence"), None)),
            PACKAGE,
            path("assessment-valid-not-applicable-item"),
            "remove the evidence that the not-applicable item's predicate is false",
            (AP_ROOT, AP_NOT_APPLICABLE),
            ("ECL1N-0153",),
        ),
        refusal(
            "assessment-invalid-claim-status-outside-enum",
            changed(example, (("claim_decision", "status"), "provisional")),
            PACKAGE,
            base,
            "record a claim status the standard does not define",
            (AP_ROOT, AP_STATUS),
            ("ECL1N-0081",),
        ),
        refusal(
            "assessment-invalid-finding-disposition-outside-enum",
            changed(
                example,
                (
                    ("findings",),
                    [
                        *example["findings"],
                        {
                            **example["findings"][0],
                            "finding_id": "urn:example:ecl:finding:unregistered-disposition",
                            "disposition": "waived",
                            "title": "A finding with an unregistered disposition",
                        },
                    ],
                ),
            ),
            PACKAGE,
            base,
            "add an unregistered-disposition finding while retaining the failed checklist's active finding",
            (AP_ROOT, AP_DISPOSITION),
            ("ECL1N-0080",),
        ),
        refusal(
            "assessment-invalid-finding-severity-outside-enum",
            changed(
                example,
                (
                    ("findings",),
                    [
                        *example["findings"],
                        {
                            **example["findings"][0],
                            "finding_id": "urn:example:ecl:finding:unregistered-severity",
                            "severity": "high",
                            "title": "A finding with an unregistered severity",
                        },
                    ],
                ),
            ),
            PACKAGE,
            base,
            "add an unregistered-severity finding while retaining the failed checklist's valid finding",
            (AP_ROOT, AP_SEVERITY),
            ("ECL1N-0147",),
        ),
        refusal(
            "assessment-invalid-independence-class-outside-enum",
            changed(level_1, (("independence", "class"), "D")),
            PACKAGE,
            path("assessment-valid-l1-class-a"),
            "record an independence class the standard does not define",
            (AP_ROOT, AP_CLASS),
            ("ECL1N-0080",),
        ),
        refusal(
            "assessment-invalid-procurement-decision-outside-enum",
            changed(example, (("procurement_decision", "decision"), "approved")),
            PACKAGE,
            base,
            "record a procurement decision the schema does not define",
            (AP_ROOT, AP_PROCUREMENT),
            ("ECL1N-0081",),
        ),
        refusal(
            "assessment-invalid-risk-treatment-outside-enum",
            changed(example, (("residual_risks", 0, "treatment"), "ignore")),
            PACKAGE,
            base,
            "record a residual-risk treatment the schema does not define",
            (AP_ROOT, AP_TREATMENT),
            ("ECL1N-0080",),
        ),
        refusal(
            "assessment-invalid-class-a-at-l2",
            changed(level_1, (("level",), 2)),
            PACKAGE,
            path("assessment-valid-l1-class-a"),
            "raise a Class A assessment to L2",
            (AP_ROOT, AP_LEVEL_2, AP_LEVEL_2_CLASS),
            ("ECL1N-0076",),
        ),
        refusal(
            "assessment-invalid-conditional-at-l4",
            changed(level_4, (("claim_decision", "status"), "conditional_conformance")),
            PACKAGE,
            path("assessment-valid-l4-class-c"),
            "decide conditional conformance at L4",
            (AP_ROOT, AP_LEVEL_4),
            ("ECL1N-0077",),
        ),
    ]


def mapping_cases(root: Path) -> list[Case]:
    # ECL1N-0124: each mapped obligation's class. ECL1N-0125: the validation state and the ECL
    # surface relied on.
    example = read(root, MAPPING_EXAMPLE)
    base = path("mapping-valid-published-example")
    return [
        passing(
            "mapping-valid-published-example",
            example,
            MAPPING,
            MAPPING_EXAMPLE,
            UNCHANGED,
            (MP_ROOT, MP_VALIDATION, MP_SUPPORT, MP_OBLIGATION_VALIDATION, MP_DIRECT),
            ("ECL1N-0124", "ECL1N-0125"),
        ),
        refusal(
            "mapping-invalid-validation-state-outside-enum",
            changed(example, (("validation_state",), "framework_certified")),
            MAPPING,
            base,
            "state a packet validation state the standard does not define",
            (MP_ROOT, MP_VALIDATION),
            ("ECL1N-0125",),
        ),
        refusal(
            "mapping-invalid-obligation-support-class-outside-enum",
            changed(example, (("obligations", 1, "support_class"), "partial_support")),
            MAPPING,
            base,
            "classify an obligation outside the three mapping claim classes",
            (MP_ROOT, MP_SUPPORT),
            ("ECL1N-0124",),
        ),
        refusal(
            "mapping-invalid-obligation-validation-state-outside-enum",
            changed(example, (("obligations", 0, "validation_state"), "certified")),
            MAPPING,
            base,
            "state an obligation validation state the standard does not define",
            (MP_ROOT, MP_OBLIGATION_VALIDATION),
            ("ECL1N-0125",),
        ),
        refusal(
            "mapping-invalid-direct-support-without-surface",
            changed(example, (("obligations", 0, "ecl_surfaces"), [])),
            MAPPING,
            base,
            "remove the ECL surface of an obligation claimed as direct runtime support",
            (MP_ROOT, MP_DIRECT),
            ("ECL1N-0125",),
        ),
    ]


def deployment_cases(root: Path) -> list[Case]:
    # ECL1N-0009: the deployment topology in scope. TS1-011: a local gate. FR-008: the defined
    # degraded-mode behavior on disconnection and its expiry. TS1-019: degraded mode states how it
    # expires into restricted mode or halt. TS1-010: the dependency classes. TS1-013: the states a
    # dependency failure causes.
    # TS1-020: the operations restricted mode keeps. ECL1N-0098: a non-default timing case states
    # its rationale. ECL1N-0108: the federated authority context. ECL1N-0092, ECL1N-0094 and
    # ECL1N-0096: what the federated, offline and air-gapped models define.
    centralized = read(root, CENTRALIZED)
    federated = read(root, FEDERATED)
    sovereign = read(root, SOVEREIGN)
    offline = read(root, OFFLINE_EDGE)
    air_gapped = read(root, AIR_GAPPED)
    stricter = changed(
        offline,
        (("timing_case", "uses_default_baseline"), False),
        (("timing_case", "connected_revocation_seconds"), 60),
        (
            ("timing_case", "variance_rationale"),
            "A sector rule requires faster revocation than the default for the claimed level.",
        ),
        (
            ("timing_case", "control_assumptions"),
            ["The trusted time source remains available during disconnection."],
        ),
        (
            ("timing_case", "residual_risk"),
            "The connected revocation bound is 60 seconds; offline staleness remains bounded at 3600 seconds and evidence export at 14400 seconds. Physical disconnection still prevents connected revocation delivery.",
        ),
    )
    common = (
        DP_ROOT,
        DP_SURFACE,
        DP_MODEL,
        DP_LOCATION,
        DP_NETWORK_LOSS,
        DP_EXPIRES_TO,
        DP_DEPENDENCY_CLASS,
        DP_FAILURE,
        DP_RESTRICTED_ACTION,
    )
    requirements = (
        "ECL1N-0009",
        "FR-008",
        "TS1-010",
        "TS1-011",
        "TS1-013",
        "TS1-019",
        "TS1-020",
    )
    central = path("deployment-valid-centralized-example")
    surfaces = centralized["delivery_surfaces"]
    restricted = centralized["fallback"]["restricted"]["allowed_actions"]
    fields = federated["topology_controls"]["federated"]["authority_context_fields"]
    return [
        passing(
            "deployment-valid-centralized-example",
            centralized,
            DEPLOYMENT,
            CENTRALIZED,
            UNCHANGED,
            (*common, DP_CENTRALIZED),
            requirements,
        ),
        passing(
            "deployment-valid-federated-example",
            federated,
            DEPLOYMENT,
            FEDERATED,
            UNCHANGED,
            (*common, DP_FEDERATED, DP_FEDERATED_FIELD),
            (*requirements, "ECL1N-0092", "ECL1N-0108"),
        ),
        passing(
            "deployment-valid-sovereign-example",
            sovereign,
            DEPLOYMENT,
            SOVEREIGN,
            UNCHANGED,
            (*common, DP_SOVEREIGN),
            requirements,
        ),
        passing(
            "deployment-valid-offline-edge-example",
            offline,
            DEPLOYMENT,
            OFFLINE_EDGE,
            UNCHANGED,
            (*common, DP_OFFLINE, DP_STALE),
            (*requirements, "ECL1N-0094"),
        ),
        passing(
            "deployment-valid-air-gapped-example",
            air_gapped,
            DEPLOYMENT,
            AIR_GAPPED,
            UNCHANGED,
            (*common, DP_AIR_GAPPED),
            (*requirements, "ECL1N-0096"),
        ),
        passing(
            "deployment-valid-stricter-timing-case",
            stricter,
            DEPLOYMENT,
            OFFLINE_EDGE,
            "declare a stricter timing case with its rationale, assumptions and residual risk",
            (DP_ROOT, DP_TIMING, DP_OFFLINE, DP_STALE),
            ("ECL1N-0094", "ECL1N-0098"),
        ),
        refusal(
            "deployment-invalid-model-outside-enum",
            changed(centralized, (("model",), "hybrid-mesh")),
            DEPLOYMENT,
            central,
            "declare a deployment model the standard does not define",
            (DP_ROOT, DP_MODEL),
            ("ECL1N-0009",),
        ),
        refusal(
            "deployment-invalid-delivery-surface-outside-enum",
            changed(centralized, (("delivery_surfaces",), [*surfaces, "cloud_console"])),
            DEPLOYMENT,
            central,
            "add a delivery surface the schema does not define",
            (DP_ROOT, DP_SURFACE),
            ("ECL1N-0009",),
        ),
        refusal(
            "deployment-invalid-enforcement-location-outside-enum",
            changed(centralized, (("release_path", "enforcement_location"), "remote_service")),
            DEPLOYMENT,
            central,
            "place enforcement in a remote service instead of a local gate",
            (DP_ROOT, DP_LOCATION),
            ("TS1-011",),
        ),
        refusal(
            "deployment-invalid-network-loss-disposition-outside-enum",
            changed(
                centralized,
                (("release_path", "network_loss_disposition"), "continue_last_decision"),
            ),
            DEPLOYMENT,
            central,
            "let disconnection continue on the last decision instead of restricting or halting",
            (DP_ROOT, DP_NETWORK_LOSS),
            ("FR-008",),
        ),
        refusal(
            "deployment-invalid-degraded-expiry-outside-enum",
            changed(centralized, (("fallback", "degraded", "expires_to"), "ordinary")),
            DEPLOYMENT,
            central,
            "let degraded mode expire into ordinary operation",
            (DP_ROOT, DP_EXPIRES_TO),
            ("TS1-019",),
        ),
        refusal(
            "deployment-invalid-dependency-class-outside-enum",
            changed(centralized, (("dependencies", 0, "class"), "best_effort")),
            DEPLOYMENT,
            central,
            "declare a dependency class the timing profile does not define",
            (DP_ROOT, DP_DEPENDENCY_CLASS),
            ("TS1-010",),
        ),
        refusal(
            "deployment-invalid-dependency-failure-outside-enum",
            changed(centralized, (("dependencies", 0, "failure_disposition"), "allow")),
            DEPLOYMENT,
            central,
            "let a dependency failure allow actions",
            (DP_ROOT, DP_FAILURE),
            ("TS1-013",),
        ),
        refusal(
            "deployment-invalid-restricted-action-outside-enum",
            changed(
                centralized,
                (
                    ("fallback", "restricted", "allowed_actions"),
                    [*restricted, "new_customer_payment"],
                ),
            ),
            DEPLOYMENT,
            central,
            "keep a new consequential action available in restricted mode",
            (DP_ROOT, DP_RESTRICTED_ACTION),
            ("TS1-020",),
        ),
        refusal(
            "deployment-invalid-federated-field-outside-enum",
            changed(
                federated,
                (
                    ("topology_controls", "federated", "authority_context_fields"),
                    [*fields[:-1], "tenant_name"],
                ),
            ),
            DEPLOYMENT,
            path("deployment-valid-federated-example"),
            "replace an exchanged authority-context field with one the profile does not define",
            (DP_ROOT, DP_FEDERATED_FIELD),
            ("ECL1N-0108",),
        ),
        refusal(
            "deployment-invalid-nondefault-timing-without-rationale",
            changed(stricter, (("timing_case", "variance_rationale"), None)),
            DEPLOYMENT,
            path("deployment-valid-stricter-timing-case"),
            "remove the rationale of a non-default timing case",
            (DP_ROOT, DP_TIMING),
            ("ECL1N-0098",),
        ),
        refusal(
            "deployment-invalid-stale-transition-outside-enum",
            changed(offline, (("topology_controls", "offline", "stale_transition"), "continue")),
            DEPLOYMENT,
            path("deployment-valid-offline-edge-example"),
            "let stale offline control state continue instead of restricting or halting",
            (DP_ROOT, DP_STALE),
            ("ECL1N-0094",),
        ),
        refusal(
            "deployment-invalid-centralized-without-controls",
            changed(centralized, (("topology_controls", "centralized"), None)),
            DEPLOYMENT,
            central,
            "remove the controls of the centralized model",
            (DP_ROOT, DP_CENTRALIZED),
            ("ECL1N-0009",),
        ),
        refusal(
            "deployment-invalid-federated-without-controls",
            changed(federated, (("topology_controls", "federated"), None)),
            DEPLOYMENT,
            path("deployment-valid-federated-example"),
            "remove the controls of the federated model",
            (DP_ROOT, DP_FEDERATED),
            ("ECL1N-0092",),
        ),
        refusal(
            "deployment-invalid-sovereign-without-controls",
            changed(sovereign, (("topology_controls", "sovereign"), None)),
            DEPLOYMENT,
            path("deployment-valid-sovereign-example"),
            "remove the controls of the sovereign model",
            (DP_ROOT, DP_SOVEREIGN),
            ("ECL1N-0009",),
        ),
        refusal(
            "deployment-invalid-offline-without-controls",
            changed(offline, (("topology_controls", "offline"), None)),
            DEPLOYMENT,
            path("deployment-valid-offline-edge-example"),
            "remove the controls of the offline-edge model",
            (DP_ROOT, DP_OFFLINE),
            ("ECL1N-0094",),
        ),
        refusal(
            "deployment-invalid-air-gapped-without-controls",
            changed(air_gapped, (("topology_controls", "air_gapped"), None)),
            DEPLOYMENT,
            path("deployment-valid-air-gapped-example"),
            "remove the controls of the air-gapped model",
            (DP_ROOT, DP_AIR_GAPPED),
            ("ECL1N-0096",),
        ),
    ]


def lifecycle_policy() -> dict[str, Any]:
    """An evidence lifecycle policy; the repository publishes no example of one."""
    return {
        "policy_id": "urn:example:ecl:lifecycle-policy:payments-evidence",
        "version": "1",
        "digest": digest("e1"),
        "effective_at": "2026-07-27T00:00:00Z",
        "retention_rules": [
            {
                "evidence_class": "standard action evidence",
                "start_event": "terminal outcome recorded",
                "duration": "P1Y",
                "shortening_authority_class": "records owner with legal approval",
            }
        ],
        "policy_requirements": {
            "supersession": "For standard action evidence, preserve the predecessor and its validity interval; identify the preferred successor under urn:example:policy:supersession:1.",
            "revocation": "For standard action evidence, record revoked purpose, scope, effective time, reason and authority under urn:example:policy:revocation:1.",
            "residency": "For standard action evidence, permitted storage and export regions are defined by urn:example:policy:residency:1.",
            "encryption": "For standard action evidence, protect stored copies and transfers under urn:example:policy:encryption:1.",
            "access": "For standard action evidence, authorized custodians and access review are defined by urn:example:policy:access:1.",
        },
        "hold_precedence": "legal_hold_over_scheduled_destruction",
        "export": {
            "custody_manifest_required": True,
            "receipt_event_required": True,
            "offline_material_required": True,
        },
        "redaction": {
            "derivative_identity_required": True,
            "sealed_source_binding_required": True,
            "manifest_required": True,
        },
        "destruction": {
            "proof_required": True,
            "observation_boundary_required": True,
            "minimum_lifecycle_proof_retained": True,
        },
    }


def offline_package() -> dict[str, Any]:
    """An offline verification package manifest; the repository publishes no example of one."""

    def artifact(name: str, media_type: str, role: str, size: int, fill: str) -> dict[str, Any]:
        return {
            "path": name,
            "media_type": media_type,
            "role": role,
            "size_bytes": size,
            "digest": digest(fill),
        }

    return {
        "package_id": "urn:example:ecl:offline-package:payments-2026-07",
        "package_version": "1.0-rc.1",
        "created_at": "2026-07-27T12:00:00Z",
        "expires_at": "2027-07-27T12:00:00Z",
        "verification_time_policy": "ecl.time.issued-at.v1",
        "trust_policy": reference("urn:example:ecl:trust-policy:payments", "f1"),
        "revocation_snapshot": reference("urn:example:ecl:revocations:payments", "f2"),
        "registry_snapshots": [reference("urn:example:ecl:registry-snapshot:1.0", "f3")],
        "time_evidence": [reference("urn:example:ecl:time-evidence:payments", "f4")],
        "artifacts": [
            artifact("evidence/bundle.json", "application/json", "payload", 4096, "f5"),
            artifact("trust/trust-policy.json", "application/json", "trust_policy", 2048, "f1"),
            artifact(
                "trust/revocations.json", "application/json", "revocation_snapshot", 512, "f2"
            ),
            artifact(
                "registries/catalog.json", "application/json", "registry_snapshot", 8192, "f3"
            ),
            artifact("time/attestations.json", "application/json", "time_evidence", 1024, "f4"),
        ],
        "deterministic_assembly": {
            "entry_order": "utf8-bytewise-path",
            "timestamp_policy": "zip-epoch-1980-01-01T00:00:00Z",
            "permissions_policy": "regular-files-0644-no-directory-entries",
            "path_encoding_policy": "utf8-nfc-posix-relative",
            "storage_policy": "zip-stored",
            "container_profile": "ecl.zip.store.v1",
        },
    }


def work_intent() -> dict[str, Any]:
    """A distributed work intent; the repository publishes no example of one."""
    return {
        "protocol": "ECL-WI-1",
        "schema_version": "1.0-rc.1",
        "intent_id": "urn:example:ecl:intent:schema-migration-7",
        "agent": {
            "id": "urn:example:agent:migration-planner",
            "type": "ecl.principal.workload.v1",
            "trust_domain": "urn:example:trust-domain:engineering",
        },
        "workflow": {
            "workflow_id": "urn:example:workflow:schema-migration",
            "root_trace_id": "urn:example:trace:schema-migration",
            "attempt": 1,
            "sequence": 1,
            "causal_predecessors": [],
        },
        "issued_at": "2026-07-27T12:00:00Z",
        "expires_at": "2026-07-27T13:00:00Z",
        "exact_targets": [
            {"kind": "migration", "identifier": "db/migrations/0007_add_index.sql"},
            {"kind": "schema", "identifier": "accounts", "digest": digest("d1")},
        ],
        "semantic_topics": ["account lookup performance"],
        "dependency_epochs": {"policy": "42", "trust": "11", "source": "a1b2c3"},
        "declared_outputs": ["db/migrations/0007_add_index.sql"],
    }


def record_cases() -> list[Case]:
    # EL1-002: the policy identifies all ten applicable lifecycle policy areas. EL1-025:
    # legal hold takes precedence over scheduled destruction. XR1-015: an offline package binds
    # its registry snapshot. EBMP2-033: it includes the revocation state. IE1-021: it carries each
    # artifact verification needs, by role. DW1-016: a work intent binds its epochs. DW1-015: an
    # intent is not authority. DW1-014: exact, typed targets let conflicts be held and reconciled.
    policy = lifecycle_policy()
    package = offline_package()
    intent = work_intent()
    granted = changed(
        intent,
        (
            ("authorization",),
            {
                "authorization_id": "urn:example:ecl:authority:self-asserted",
                "valid_until": "2026-07-27T13:00:00Z",
            },
        ),
    )
    return [
        passing(
            "lifecycle-valid-policy",
            policy,
            LIFECYCLE,
            None,
            "an evidence lifecycle policy for one evidence class",
            (LP_ROOT,),
            ("EL1-002", "EL1-025"),
        ),
        refusal(
            "lifecycle-invalid-destruction-over-legal-hold",
            changed(policy, (("hold_precedence",), "scheduled_destruction_over_legal_hold")),
            LIFECYCLE,
            path("lifecycle-valid-policy"),
            "let scheduled destruction take precedence over a legal hold",
            (LP_ROOT,),
            ("EL1-025",),
        ),
        refusal(
            "lifecycle-invalid-without-destruction-rules",
            changed(policy, (("destruction",), None)),
            LIFECYCLE,
            path("lifecycle-valid-policy"),
            "remove the destruction requirements of the policy",
            (LP_ROOT,),
            ("EL1-002",),
        ),
        passing(
            "offline-package-valid",
            package,
            OFFLINE,
            None,
            "an offline verification package for one evidence bundle",
            (OV_ROOT, OV_ROLE),
            ("EBMP2-033", "IE1-021", "XR1-015"),
        ),
        refusal(
            "offline-package-invalid-artifact-role-outside-enum",
            changed(package, (("artifacts", 0, "role"), "screenshot")),
            OFFLINE,
            path("offline-package-valid"),
            "give a packaged artifact a role that verification does not define",
            (OV_ROOT, OV_ROLE),
            ("IE1-021",),
        ),
        refusal(
            "offline-package-invalid-without-registry-snapshot",
            changed(package, (("registry_snapshots",), None)),
            OFFLINE,
            path("offline-package-valid"),
            "remove the registry snapshot the verifier uses",
            (OV_ROOT,),
            ("XR1-015",),
        ),
        refusal(
            "offline-package-invalid-without-revocation-snapshot",
            changed(package, (("revocation_snapshot",), None)),
            OFFLINE,
            path("offline-package-valid"),
            "remove the revocation state from the package",
            (OV_ROOT,),
            ("EBMP2-033",),
        ),
        passing(
            "work-intent-valid",
            intent,
            INTENT,
            None,
            "a work intent for one schema migration",
            (WI_ROOT, WI_KIND),
            ("DW1-014", "DW1-015", "DW1-016"),
        ),
        refusal(
            "work-intent-invalid-target-kind-outside-enum",
            changed(intent, (("exact_targets", 0, "kind"), "directory")),
            INTENT,
            path("work-intent-valid"),
            "name an exact target by a kind the schema does not define",
            (WI_ROOT, WI_KIND),
            ("DW1-014",),
        ),
        refusal(
            "work-intent-invalid-carries-authority",
            granted,
            INTENT,
            path("work-intent-valid"),
            "add an authorization to the intent",
            (WI_ROOT,),
            ("DW1-015",),
        ),
        refusal(
            "work-intent-invalid-without-dependency-epochs",
            changed(intent, (("dependency_epochs",), {})),
            INTENT,
            path("work-intent-valid"),
            "remove the dependency epochs the intent binds",
            (WI_ROOT,),
            ("DW1-016",),
        ),
    ]


def build(root: Path = ROOT) -> dict[Path, bytes]:
    cases = [
        *register_cases(root),
        *claim_cases(root),
        *package_cases(root),
        *mapping_cases(root),
        *deployment_cases(root),
        *record_cases(),
    ]
    artifacts: dict[Path, bytes] = {}
    vectors: list[dict[str, Any]] = []
    for case in cases:
        relative = SUITE / (case.identifier + ".json")
        if relative in artifacts:
            raise ValueError(f"duplicate document vector: {case.identifier}")
        artifacts[relative] = json_bytes(case.value)
        source: dict[str, str] = {"kind": "authored", "generator": GENERATOR}
        if case.base is not None:
            base = case.base.as_posix() if isinstance(case.base, Path) else case.base
            source = {
                "kind": "mutation",
                "generator": GENERATOR,
                "base_vector": base,
                "mutation": case.change,
            }
        row: dict[str, Any] = {
            "id": case.identifier,
            "path": relative.as_posix(),
            "stage": STAGE,
            "schema": case.schema,
            "source": source,
            "expected": "fail" if case.negates else "pass",
            "expected_secondary_ids": [],
            "requirement_ids": sorted(set(case.requirements)),
            "covers": sorted(set(case.covers)),
        }
        if case.negates:
            row["expected_primary_id"] = case.primary
            row["negates"] = sorted(set(case.negates))
        vectors.append(row)
    manifest = {
        "schema_version": "ecl_conformance_vector_manifest_v3",
        "suite": SUITE_ID,
        "candidate_version": "1.0",
        "vectors": sorted(vectors, key=lambda item: item["id"]),
    }
    artifacts[SUITE / "manifest.json"] = json_bytes(manifest)
    return artifacts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        expected = build(args.root)
        for relative, content in expected.items():
            target = args.root / relative
            if args.check:
                if not target.is_file() or target.read_bytes() != content:
                    raise ValueError(f"document vector is stale: {relative}")
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        present = {item.relative_to(args.root) for item in (args.root / SUITE).glob("*.json")}
        extra = sorted(item.as_posix() for item in present - set(expected))
        if extra:
            raise ValueError(f"document suite holds files the generator does not make: {extra}")
    except (OSError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print("document vectors: check passed" if args.check else "document vectors: generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
