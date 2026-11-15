"""Named declarations retain their identity at the Python helper boundary.

Robert F. Tilley Jr.; G-14, Inc.
"""
from dataclasses import replace
from types import MappingProxyType

import pytest

from ecl_verify.claims import (
    AIBOM_REQUIRED_FIELDS, CONSEQUENTIAL_FLAGS, SIX_RESPONSIBILITIES,
    ActionRegisterEntry, AssessmentOutcome, AssessmentPackage,
    AssessorIndependence, ChecklistItem, ClaimBoundary, ClaimError,
    EquivalenceDossier, MappingPacket, PublicClaim, ReferenceUse, SectorProfileInvocation,
    SupplierDeliverables, TraceBoundary, VersionTransition,
    classify_action, validate_aibom,
)


STAMP = "2026-11-10T00:00:00Z"
ENTRY = ActionRegisterEntry("act", "consequential", "Changes a resource",
    ("resource",), ("actor",), ("data",), "hard", None, ("ab",))
BOUNDARY = ClaimBoundary("soi", "full-system-mediation", 1, (ENTRY,),
    frozenset({"ab"}), frozenset({"ab"}), frozenset(), "local gate",
    SIX_RESPONSIBILITIES, ("gate",), "A")
TRACE = TraceBoundary("trace", ("ab", "cd"), {"cd": "ab"},
    frozenset({"model"}), frozenset({"model"}), True)
CLAIM = PublicClaim("soi", 1, "full_conformance", "full-system-mediation", "A",
    "1", ("DCMP-2:2",), (), STAMP, (), class_a_disclosure="Same-operator controls")
OUTCOME = AssessmentOutcome({"item": "pass"}, {}, "full_conformance", "award")
EQUIVALENCE = EquivalenceDossier("FR-001", "Alternative", "Property", "Difference",
    "Expiry", True, True, True, True, "decision", None, 2, False)
MAPPING = MappingPacket("packet", "1", "Framework", "2026", {"duty": "out_of_scope"},
    {"duty": ()}, {"duty": "External obligation"}, ("Boundary",), "draft", STAMP)
INDEPENDENCE = AssessorIndependence(1, "assessor", False, False, False, False, False)
PACKAGE = AssessmentPackage(1, STAMP, STAMP, False, {"artifact": "a" * 64},
    (ChecklistItem("item", "pass", 1, ("evidence",)),), "soi", "full-system-mediation",
    "negative", "matrix", None, None, None, None, INDEPENDENCE)
SUPPLIER_NAMES = (
    "public_claim checklist requirement_evidence_matrix fr_checklist_matrix "
    "soi_diagram trust_boundary_diagram action_register negative_boundary_annex "
    "declared_timing_case privilege_matrix dcmp_request dcmp_response ebmp_bundle "
    "redacted_ebmp_bundle revocation_drill emergency_drill incident_response "
    "change_management"
).split()
SUPPLIER = SupplierDeliverables(1, {name: "artifact:" + name for name in SUPPLIER_NAMES}, False, False)


def test_capability_path_string_cannot_be_split_to_satisfy_reconciliation():
    # One malformed "ab" declaration previously covered the unrelated paths a and b.
    malformed = replace(BOUNDARY, action_register=(replace(ENTRY, capability_paths="ab"),),
        included_effect_paths=frozenset({"a", "b"}), reachable_effect_paths=frozenset({"a", "b"}))
    with pytest.raises(ClaimError):
        malformed.validate()
    with pytest.raises(ClaimError, match="not reconciled"):
        replace(malformed, action_register=(ENTRY,)).validate()
    replace(malformed, action_register=(replace(ENTRY, capability_paths=("a", "b")),)).validate()
    BOUNDARY.validate()


@pytest.mark.parametrize("field,value", [
    ("action_class_id", " "), ("rationale", "\t"), ("classification", []),
    ("enforcement_class", {}), ("affected_resources", "resource"),
    ("identities", ["actor"]), ("data_classes", (True,)), ("capability_paths", (" ",)),
    ("budget_dimensions", "USD"), ("witness_posture", " "),
    ("capability_freeze_scope", True), ("irreversibility_class", ""),
    ("commit_mode", 1), ("quorum_rule", " "),
    ("human_approval_threshold", "approval"), ("human_approval_threshold", ("approval",)),
])
def test_action_declaration_shapes_are_not_coerced(field, value):
    with pytest.raises(ClaimError): replace(ENTRY, **{field: value}).validate()


@pytest.mark.parametrize("field,value", [
    ("soi_id", " "), ("deployment_topology", True), ("claim_class", []),
    ("action_register", "entry"), ("action_register", ({},)),
    ("included_effect_paths", {"ab"}), ("reachable_effect_paths", "ab"),
    ("negative_boundary_paths", frozenset({" "})),
    ("responsibilities", set(SIX_RESPONSIBILITIES)), ("trust_boundaries", "gate"),
    ("trust_boundaries", (" ",)),
])
def test_boundary_declared_containers_have_named_members(field, value):
    with pytest.raises(ClaimError): replace(BOUNDARY, **{field: value}).validate()


@pytest.mark.parametrize("field,value", [
    ("root_trace_id", " "), ("external_action_ids", "abcd"),
    ("external_action_ids", (True,)), ("child_parent_links", ("cd",)),
    ("child_parent_links", {True: "ab"}), ("child_parent_links", {"cd": []}),
    ("capable_model_ids", {"model"}), ("declared_soi_model_ids", frozenset({" "})),
])
def test_trace_declarations_are_not_split_or_truthiness_only(field, value):
    with pytest.raises(ClaimError): replace(TRACE, **{field: value}).validate()


@pytest.mark.parametrize("field,value", [
    ("soi_id", " "), ("core_version", "\t"), ("status", []),
    ("boundary_class", {}), ("independence_class", []),
    ("companion_versions", "DCMP-2:2"), ("companion_versions", (True,)),
    ("profile_versions", "profile"), ("profile_versions", (" ",)),
    ("limitations", "limitation"), ("limitations", (False,)),
    ("class_a_disclosure", " "), ("framework_name", " "),
    ("mapping_packet_id", True), ("obligation_slice", ""),
    ("residual_gap", "\t"),
])
def test_public_claim_fields_require_named_declarations(field, value):
    with pytest.raises(ClaimError): replace(CLAIM, **{field: value}).validate()


@pytest.mark.parametrize("field,value", [
    ("checklist_results", ("item",)), ("checklist_results", {"": "pass"}),
    ("checklist_results", {" ": "pass"}), ("checklist_results", {True: "pass"}),
    ("checklist_results", {"item": []}),
    ("finding_severities", ("finding",)), ("finding_severities", {"": "minor"}),
    ("finding_severities", {" ": "minor"}), ("finding_severities", {True: "minor"}),
    ("finding_severities", {"finding": []}),
    ("claim_status", []), ("procurement_decision", {}),
    ("checklist_findings", ()),
])
def test_assessment_mapping_domains_raise_claim_error(field, value):
    with pytest.raises(ClaimError): replace(OUTCOME, **{field: value}).validate()


def test_failed_item_links_preserve_distinct_identifiers_and_minor_caveats():
    outcome = AssessmentOutcome({"item": "fail"}, {"finding": "minor", "general": "observation"},
        "full_conformance", "award", {"item": "finding"})
    outcome.validate()
    for results, severities, links in (
        ({" ": "fail"}, {"finding": "minor"}, {" ": "finding"}),
        ({"item": "fail"}, {" ": "minor"}, {"item": " "}),
        ({"item": "fail"}, {"finding": "minor"}, {"item": True}),
    ):
        with pytest.raises(ClaimError):
            replace(outcome, checklist_results=results, finding_severities=severities,
                checklist_findings=links).validate()


@pytest.mark.parametrize("field,value", [
    ("replaced_requirement_id", " "), ("alternative", True), ("preserved_property", ""),
    ("residual_difference", []), ("expiry_conditions", "\t"),
    ("assessor_decision_id", " "), ("independent_validation_id", " "),
])
def test_equivalence_requires_actual_text_not_truthiness(field, value):
    with pytest.raises(ClaimError): replace(EQUIVALENCE, **{field: value}).validate()


@pytest.mark.parametrize("field,value", [
    ("packet_id", " "), ("version", True), ("framework", ""), ("framework_edition", []),
    ("obligation_classes", ["duty"]), ("obligation_classes", {"duty": []}),
    ("ecl_surfaces", ()), ("residual_obligations", []),
    ("assumptions", "Boundary"), ("assumptions", (" ",)), ("validation_state", []),
    ("ecl_surfaces", {"duty": (), " ": ()}),
    ("residual_obligations", {"duty": "External obligation", "extra": True}),
])
def test_mapping_shape_is_checked_before_mapping_operations(field, value):
    with pytest.raises(ClaimError): replace(MAPPING, **{field: value}).validate()


@pytest.mark.parametrize("field,value", [
    ("artifact_hashes", ["artifact"]), ("artifact_hashes", {" ": "a" * 64}),
    ("soi_boundary_id", " "), ("boundary_class", []),
    ("negative_boundary_annex_id", True), ("fr_coverage_matrix_id", " "),
    ("structured_claim_decision_id", " "), ("findings_id", True),
    ("residual_risk_id", ""), ("independence_disclosure_id", []),
    ("assessor_independence", {}),
])
def test_assessment_package_named_inputs_precede_operations(field, value):
    with pytest.raises(ClaimError): replace(PACKAGE, **{field: value}).validate()


@pytest.mark.parametrize("artifact_ids", [
    list(SUPPLIER.artifact_ids),
    {**SUPPLIER.artifact_ids, "public_claim": " "},
    {**SUPPLIER.artifact_ids, "public_claim": True},
    {**SUPPLIER.artifact_ids, " ": "extra"},
])
def test_supplier_artifact_references_are_named_text(artifact_ids):
    with pytest.raises(ClaimError): replace(SUPPLIER, artifact_ids=artifact_ids).validate()


@pytest.mark.parametrize("value", [
    list(AIBOM_REQUIRED_FIELDS),
    {key: " " for key in AIBOM_REQUIRED_FIELDS},
    {key: True for key in AIBOM_REQUIRED_FIELDS},
])
def test_aibom_metadata_are_named_text(value):
    with pytest.raises(ClaimError): validate_aibom(value)


@pytest.mark.parametrize("declaration", [
    ReferenceUse(" ", False), ReferenceUse("reference", True, version=" "),
    ReferenceUse("reference", True, date=True), ReferenceUse("reference", False, immutable_digest=[]),
    replace(INDEPENDENCE, assessor_id=" "),
    replace(INDEPENDENCE, published_sector_exception=" "),
    VersionTransition(True, 0, True, " "),
])
def test_reference_and_exception_text_cannot_be_blank(declaration):
    with pytest.raises(ClaimError): declaration.validate()


@pytest.mark.parametrize("changes", [
    {"sector": []}, {"applicable_standard": " "}, {"applicable_standard": True},
    {"reference": {}},
])
def test_invoked_sector_has_a_named_standard_and_reference(changes):
    invocation = SectorProfileInvocation("industrial-control", "IEC 62443", True,
        ReferenceUse("IEC 62443", True, version="edition"))
    with pytest.raises(ClaimError): replace(invocation, **changes).validate()


def test_action_flags_require_mapping_before_lookup():
    with pytest.raises(ClaimError): classify_action(list(CONSEQUENTIAL_FLAGS))


def test_valid_optional_empty_collections_and_mapping_implementations_remain_supported():
    for declaration in (ENTRY, BOUNDARY, TRACE, CLAIM, OUTCOME, EQUIVALENCE, MAPPING, PACKAGE, SUPPLIER,
        replace(ENTRY, classification="non_consequential", capability_paths=(), budget_dimensions=(),
                affected_resources=(), identities=(), data_classes=(), human_approval_threshold=()),
        replace(ENTRY, human_approval_threshold=(MappingProxyType({"parameter": "/amount", "unit": "USD", "value": "1", "approvers": 1}),)),
        replace(CLAIM, level=2, independence_class="B", class_a_disclosure=None),
        replace(TRACE, child_parent_links=MappingProxyType({"cd": "ab"})),
        replace(OUTCOME, checklist_results=MappingProxyType({"item": "pass"}),
                finding_severities=MappingProxyType({}), checklist_findings=MappingProxyType({})),
        replace(MAPPING, obligation_classes=MappingProxyType(MAPPING.obligation_classes),
                ecl_surfaces=MappingProxyType(MAPPING.ecl_surfaces), residual_obligations=MappingProxyType(MAPPING.residual_obligations)),
        replace(PACKAGE, artifact_hashes=MappingProxyType(PACKAGE.artifact_hashes)),
        replace(SUPPLIER, artifact_ids=MappingProxyType({**SUPPLIER.artifact_ids, "additional": "extra"})),
        ReferenceUse("reference", False), ReferenceUse("reference", True, version="1"),
        SectorProfileInvocation("industrial-control", "IEC 62443", True,
            ReferenceUse("IEC 62443", True, version="edition")),
        SectorProfileInvocation("other", "", False, ReferenceUse("background", False)),
        VersionTransition(False, 0, False, None),
        replace(INDEPENDENCE, level=2, material_affiliate_or_reseller=True,
                direct_implementation_within_24_months=False, published_sector_exception="Sector authority's published exception"),
    ):
        declaration.validate()
    validate_aibom(MappingProxyType({key: "declared:" + key for key in AIBOM_REQUIRED_FIELDS}))
    assert classify_action(MappingProxyType(dict.fromkeys(CONSEQUENTIAL_FLAGS, False)),
        fully_confined_to_isolated_context=True) == "non_consequential"
