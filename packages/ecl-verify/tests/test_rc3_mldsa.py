from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import sys
import unittest
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

# The pinned cryptography release has the ML-DSA API; another may not have the module, or not this
# class. Without it these tests skip with this reason, and ECL_FAIL_ON_SKIP=1, which CI sets, makes
# the skip a failure.
try:
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
except ImportError:
    pytest.skip(
        "the installed cryptography has no ML-DSA API, so these tests did not run; install the "
        "locked development environment (make sync); ECL_FAIL_ON_SKIP=1 makes this skip a failure",
        allow_module_level=True,
    )


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "ecl-verify" / "src"))

from ecl_verify.canonical import canonicalize, load_json_strict  # noqa: E402
from ecl_verify.integrity import (  # noqa: E402
    IntegrityError,
    MlDsa65ProviderEvidence,
    VerificationContext,
    VerificationKey,
    load_mldsa65_public_key,
    mldsa65_provider_identity,
    signing_input,
    verify_envelope,
    verify_mldsa65_external_mu,
)


FIXTURE = (
    ROOT
    / "conformance"
    / "vectors"
    / "integrity"
    / "mldsa65-nist-acvp-sigver-tc123.json"
)
# NIST's list of potential updates (errata) of FIPS 204 as last updated on 2026-07-31, reviewed
# for RC-5: none of its entries changes which signatures verify.
ERRATA_DIGEST = "5bc93ce63bc647e6d1d456cb2d3a171426c15aca4a7a0e0edd40d08b7a34c793"
# The ACVP-Server commit of 2026-07-20 whose files the fixture's digests name; NIST replaced
# both files on 2026-07-31 (commit a7f283cdc87d), and case 9/123 differs there.
ACVP_COMMIT = "2972def23bf9f3680c2c531561ed9bdd0f1086ad"


class Rc3MlDsaTests(unittest.TestCase):
    def fixture(self) -> dict:
        value = load_json_strict(FIXTURE)
        assert isinstance(value, dict)
        return value

    def test_provider_and_nist_acvp_case_are_source_locked(self) -> None:
        fixture = self.fixture()
        provider_version, backend_version = mldsa65_provider_identity()
        self.assertEqual("50.0.2", provider_version)
        self.assertIn("OpenSSL", backend_version)
        source = fixture["source"]
        self.assertEqual(ACVP_COMMIT, source["revision"])
        evidence = MlDsa65ProviderEvidence(
            provider_package="cryptography",
            provider_version=provider_version,
            backend_version=backend_version,
            fips_204_reference="https://doi.org/10.6028/NIST.FIPS.204",
            active_errata_reference=(
                "https://csrc.nist.gov/files/pubs/fips/204/final/docs/"
                "fips-204-potential-updates.xlsx"
            ),
            active_errata_digest=ERRATA_DIGEST,
            acvp_prompt_reference=(
                f"{source['repository']}/blob/{ACVP_COMMIT}/{source['path']}"
            ),
            acvp_prompt_digest=source["prompt_sha256"],
            acvp_expected_results_reference=(
                f"{source['repository']}/blob/{ACVP_COMMIT}/"
                f"{source['expected_results_path']}"
            ),
            acvp_expected_results_digest=source["expected_results_sha256"],
            acvp_group_id=source["source_group_id"],
            acvp_test_case_id=source["source_test_case_id"],
            public_key_bytes=len(bytes.fromhex(fixture["public_key_hex"])),
            signature_bytes=len(bytes.fromhex(fixture["signature_hex"])),
            external_mu_bytes=len(bytes.fromhex(fixture["mu_hex"])),
        )
        evidence.validate()
        self.assertEqual(
            "50.0.2", importlib.metadata.version(evidence.provider_package)
        )

    def test_nist_acvp_mldsa65_external_mu_verifies_and_mutation_fails(
        self,
    ) -> None:
        fixture = self.fixture()
        public_key = load_mldsa65_public_key(
            bytes.fromhex(fixture["public_key_hex"])
        )
        signature = bytes.fromhex(fixture["signature_hex"])
        mu = bytes.fromhex(fixture["mu_hex"])
        verify_mldsa65_external_mu(
            public_key=public_key,
            signature=signature,
            mu=mu,
        )
        mutated = bytearray(signature)
        mutated[0] ^= 1
        with self.assertRaises(InvalidSignature):
            verify_mldsa65_external_mu(
                public_key=public_key,
                signature=bytes(mutated),
                mu=mu,
            )

    def test_mldsa65_verifies_exact_ecl_dsse_message_with_empty_context(
        self,
    ) -> None:
        payload = load_json_strict(
            ROOT
            / "conformance"
            / "vectors"
            / "dcmp-2"
            / "valid-decision-request.json"
        )
        assert isinstance(payload, dict)
        payload_type = "application/vnd.ecl.dcmp+json"
        key_id = "urn:example:key:mldsa65-1"
        policy = payload["integrity_policy"]
        policy["accepted_suites"] = ["ecl.sig.ml-dsa-65.v1"]
        policy["eligible_key_ids"] = [key_id]
        policy["required_key_ids"] = [key_id]
        private_key = MLDSA65PrivateKey.from_seed_bytes(bytes(range(32)))
        payload_bytes = canonicalize(payload)
        message = signing_input(payload_type, payload_bytes)
        signature = private_key.sign(message, b"")
        envelope = {
            "envelope_version": "ECL-IE-1",
            "payload_type": payload_type,
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "payload_digest": {
                "algorithm": "ecl.digest.sha-256.v1",
                "value": hashlib.sha256(payload_bytes).hexdigest(),
            },
            "signatures": [
                {
                    "key_id": key_id,
                    "suite_id": "ecl.sig.ml-dsa-65.v1",
                    "signature": base64.b64encode(signature).decode("ascii"),
                }
            ],
        }
        trust = policy["trust_policy"]
        context = VerificationContext(
            trust_policy_id=trust["id"],
            trust_policy_version=trust["version"],
            trust_policy_digest=trust["digest"]["value"],
            trust_policy_epoch=trust["epoch"],
            evaluated_at=payload["issued_at"],
            verification_time_policy=policy["verification_time_policy"],
            revocation_policy=policy["revocation_policy"],
            allowed_suites=("ecl.sig.ml-dsa-65.v1",),
        )
        keyring = {
            key_id: VerificationKey(
                key_id=key_id,
                suite_id="ecl.sig.ml-dsa-65.v1",
                public_key=private_key.public_key(),
                trust_policy_ids=(trust["id"],),
                purposes=(payload_type,),
            )
        }
        result = verify_envelope(envelope, keyring, context)
        self.assertEqual((key_id,), result.valid_key_ids)

        wrong_context_signature = private_key.sign(message, b"wrong-context")
        envelope["signatures"][0]["signature"] = base64.b64encode(
            wrong_context_signature
        ).decode("ascii")
        with self.assertRaisesRegex(
            IntegrityError,
            "required signatures are missing or invalid",
        ):
            verify_envelope(envelope, keyring, context)
