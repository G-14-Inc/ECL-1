"""The public verifier can read evidence without exposing its producer APIs."""

from __future__ import annotations

import ast
import importlib
import importlib.util
from pathlib import Path

import pytest

import ecl_verify

PRIVATE_APIS = {
    "integrity": ("time_attestation", "Countersignature", "add_countersignature"),
    "offline": ("deterministic_zip",),
    "decision_basis_checks": (
        "DecisionBasisError",
        "entry",
        "decision_basis",
        "with_decision_basis",
    ),
    "extensions": ("ExtensionRegistryLedger",),
    "safe_state": ("BufferedEvidence", "EvidenceBuffer"),
    "bindings.aarm": ("mapped_outcome", "receipt_extension"),
    "bindings.acs": (
        "mapped_outcome",
        "failure_outcome",
        "decision_extension",
        "effective_parameters",
    ),
    "bindings.common": ("encode_content", "with_extension", "modification_request"),
    "bindings.jose": ("TokenSigner", "algorithm_for", "public_jwk", "sign"),
    "bindings.mcp": (
        "ToolMapping",
        "RequestContext",
        "binding_value",
        "decision_request",
        "refusal",
        "decision_refusal",
        "returned_for",
        "storable",
        "terminal_state",
    ),
    "bindings.oauth": ("authorization_details_entry", "token_claims", "issue", "dpop_proof"),
    "bindings.otel": ("attributes", "log_record", "logs_data", "Exporter", "main"),
}


@pytest.mark.parametrize("name", ["signing", "decision_basis"])
def test_private_producer_modules_are_absent(name: str) -> None:
    assert importlib.util.find_spec("ecl_verify." + name) is None


@pytest.mark.parametrize(("name", "producers"), PRIVATE_APIS.items())
def test_producer_apis_are_absent(name: str, producers: tuple[str, ...]) -> None:
    module = importlib.import_module("ecl_verify." + name)
    assert not set(producers) & set(vars(module))


def test_no_public_module_depends_on_private_keys_or_the_private_library() -> None:
    package = Path(ecl_verify.__file__).parent
    for path in package.rglob("*.py"):
        parsed = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
                assert not any("PrivateKey" in alias.name for alias in node.names), path
            else:
                continue
            assert not any(module.startswith("ecl_reference") for module in modules), path


def test_the_mapping_reader_has_no_producer_serialization_api() -> None:
    from ecl_verify.bindings.mcp import _ToolMapping

    assert not hasattr(_ToolMapping, "as_record")
