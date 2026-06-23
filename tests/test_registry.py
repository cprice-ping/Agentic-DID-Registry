"""
Integration tests for the Agent Identity Registry.

Runs entirely in-process using FastAPI's TestClient — no real HTTP server needed.
Uses a temporary SQLite database and a fresh registry keypair per test session.
"""
import json
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def configure_test_env(tmp_path_factory):
    """Point the app at a temporary DB and key file for the whole test session."""
    tmp = tmp_path_factory.mktemp("registry")
    os.environ["REGISTRY_DOMAIN"] = "test.example.com"
    os.environ["REGISTRY_KEY_PATH"] = str(tmp / "registry.key.pem")
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp / 'registry.db'}"
    yield
    # Cleanup handled automatically by tmp_path_factory


@pytest.fixture(scope="session")
def client(configure_test_env):
    """Create a TestClient for the full FastAPI app."""
    # Import after env vars are set
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def sample_charter() -> dict:
    return {
        "name": "napa-node-01",
        "capabilities": ["observe", "publish"],
        "scope": "Napa Valley environmental monitoring — watershed, weather, AQI",
        "intent": "Collect domain sensor data, reason locally, publish observations",
        "operator": "did:web:test.example.com",
    }


@pytest.fixture()
def agent_keypair() -> tuple[dict, object]:
    """Return (public_key_jwk, private_key) for use in registration tests."""
    from app.crypto import generate_ed25519_keypair
    private_key, public_key_jwk = generate_ed25519_keypair()
    return public_key_jwk, private_key


# ── Registry DID document ─────────────────────────────────────────────────────

class TestRegistryDIDDocument:
    def test_returns_200(self, client):
        resp = client.get("/.well-known/did.json")
        assert resp.status_code == 200

    def test_content_type_is_json(self, client):
        resp = client.get("/.well-known/did.json")
        assert "application/json" in resp.headers["content-type"]

    def test_has_required_did_fields(self, client):
        doc = client.get("/.well-known/did.json").json()
        assert doc["id"] == "did:web:test.example.com"
        assert "@context" in doc
        assert "verificationMethod" in doc
        assert len(doc["verificationMethod"]) == 1
        vm = doc["verificationMethod"][0]
        assert vm["type"] == "JsonWebKey2020"
        assert vm["publicKeyJwk"]["kty"] == "OKP"
        assert vm["publicKeyJwk"]["crv"] == "Ed25519"

    def test_did_id_matches_domain(self, client):
        doc = client.get("/.well-known/did.json").json()
        assert "test.example.com" in doc["id"]


# ── Agent registration ────────────────────────────────────────────────────────

class TestAgentRegistration:
    def test_register_returns_201(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        resp = client.post("/agents", json={
            "agent_id": "napanode01",
            "public_key_jwk": pub_jwk,
            "charter": sample_charter,
        })
        assert resp.status_code == 201

    def test_register_returns_did(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        resp = client.post("/agents", json={
            "agent_id": "napanode02",
            "public_key_jwk": pub_jwk,
            "charter": sample_charter,
        })
        data = resp.json()
        assert data["did"] == "did:web:test.example.com:agents:napanode02"

    def test_register_returns_charter_vc(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        resp = client.post("/agents", json={
            "agent_id": "napanode03",
            "public_key_jwk": pub_jwk,
            "charter": sample_charter,
        })
        data = resp.json()
        vc = data["charter_vc"]
        assert "VerifiableCredential" in vc["type"]
        assert "AgentCharterCredential" in vc["type"]
        assert vc["issuer"] == "did:web:test.example.com"
        subject = vc["credentialSubject"]
        assert subject["id"] == "did:web:test.example.com:agents:napanode03"
        assert subject["capabilities"] == ["observe", "publish"]
        assert "proof" in vc

    def test_duplicate_agent_id_returns_409(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        client.post("/agents", json={
            "agent_id": "duptest",
            "public_key_jwk": pub_jwk,
            "charter": sample_charter,
        })
        resp = client.post("/agents", json={
            "agent_id": "duptest",
            "public_key_jwk": pub_jwk,
            "charter": sample_charter,
        })
        assert resp.status_code == 409

    def test_invalid_agent_id_rejected(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        resp = client.post("/agents", json={
            "agent_id": "UPPERCASE-INVALID!",
            "public_key_jwk": pub_jwk,
            "charter": sample_charter,
        })
        assert resp.status_code == 422


# ── DID document resolution ───────────────────────────────────────────────────

class TestAgentDIDDocument:
    @pytest.fixture(autouse=True)
    def register(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        client.post("/agents", json={
            "agent_id": "diddoctest",
            "public_key_jwk": pub_jwk,
            "charter": sample_charter,
        })

    def test_did_document_returns_200(self, client):
        resp = client.get("/agents/diddoctest/did.json")
        assert resp.status_code == 200

    def test_did_document_has_correct_id(self, client):
        doc = client.get("/agents/diddoctest/did.json").json()
        assert doc["id"] == "did:web:test.example.com:agents:diddoctest"

    def test_did_document_has_controller(self, client):
        doc = client.get("/agents/diddoctest/did.json").json()
        assert doc["controller"] == "did:web:test.example.com"

    def test_did_document_has_public_key(self, client):
        doc = client.get("/agents/diddoctest/did.json").json()
        vm = doc["verificationMethod"][0]
        assert vm["publicKeyJwk"]["kty"] == "OKP"

    def test_unknown_agent_returns_404(self, client):
        resp = client.get("/agents/doesnotexist/did.json")
        assert resp.status_code == 404


# ── Charter retrieval ─────────────────────────────────────────────────────────

class TestCharterRetrieval:
    @pytest.fixture(autouse=True)
    def register(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        client.post("/agents", json={
            "agent_id": "chartertest",
            "public_key_jwk": pub_jwk,
            "charter": sample_charter,
        })

    def test_charter_returns_200(self, client):
        resp = client.get("/agents/chartertest/charter")
        assert resp.status_code == 200

    def test_charter_is_valid_vc(self, client):
        vc = client.get("/agents/chartertest/charter").json()
        assert "VerifiableCredential" in vc["type"]
        assert "proof" in vc
        assert vc["proof"]["cryptosuite"] == "eddsa-jcs-2022"

    def test_charter_signature_verifies(self, client):
        """The registry's signature on the charter VC must be cryptographically valid."""
        from app.crypto import verify_document_proof

        vc = client.get("/agents/chartertest/charter").json()
        registry_doc = client.get("/.well-known/did.json").json()
        vm_id = vc["proof"]["verificationMethod"]
        pub_key_jwk = next(
            vm["publicKeyJwk"]
            for vm in registry_doc["verificationMethod"]
            if vm["id"] == vm_id
        )
        assert verify_document_proof(vc, pub_key_jwk), "Charter VC signature is invalid"

    def test_unknown_agent_returns_404(self, client):
        assert client.get("/agents/nobody/charter").status_code == 404


# ── Key rotation ──────────────────────────────────────────────────────────────

class TestKeyRotation:
    @pytest.fixture(autouse=True)
    def register(self, client, sample_charter):
        from app.crypto import generate_ed25519_keypair
        self.orig_key, orig_jwk = generate_ed25519_keypair()
        client.post("/agents", json={
            "agent_id": "rotatetest",
            "public_key_jwk": orig_jwk,
            "charter": sample_charter,
        })

    def test_rotate_returns_200(self, client):
        from app.crypto import generate_ed25519_keypair
        _, new_jwk = generate_ed25519_keypair()
        resp = client.post("/agents/rotatetest/rotate", json={"new_public_key_jwk": new_jwk})
        assert resp.status_code == 200

    def test_rotate_updates_did_document_key(self, client):
        from app.crypto import generate_ed25519_keypair
        _, new_jwk = generate_ed25519_keypair()
        client.post("/agents/rotatetest/rotate", json={"new_public_key_jwk": new_jwk})
        doc = client.get("/agents/rotatetest/did.json").json()
        assert doc["verificationMethod"][0]["publicKeyJwk"]["x"] == new_jwk["x"]

    def test_rotate_reissues_charter_vc(self, client):
        from app.crypto import generate_ed25519_keypair, verify_document_proof
        _, new_jwk = generate_ed25519_keypair()
        data = client.post(
            "/agents/rotatetest/rotate", json={"new_public_key_jwk": new_jwk}
        ).json()
        registry_doc = client.get("/.well-known/did.json").json()
        vm_id = data["charter_vc"]["proof"]["verificationMethod"]
        pub_key_jwk = next(
            vm["publicKeyJwk"]
            for vm in registry_doc["verificationMethod"]
            if vm["id"] == vm_id
        )
        assert verify_document_proof(data["charter_vc"], pub_key_jwk)


# ── Revocation ────────────────────────────────────────────────────────────────

class TestRevocation:
    @pytest.fixture(autouse=True)
    def register(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        client.post("/agents", json={
            "agent_id": "revoketest",
            "public_key_jwk": pub_jwk,
            "charter": sample_charter,
        })

    def test_revoke_returns_200(self, client):
        resp = client.delete("/agents/revoketest")
        assert resp.status_code == 200

    def test_revoked_did_document_is_tombstone(self, client):
        client.delete("/agents/revoketest")
        doc = client.get("/agents/revoketest/did.json").json()
        assert doc.get("deactivated") is True

    def test_revoked_charter_returns_410(self, client):
        client.delete("/agents/revoketest")
        resp = client.get("/agents/revoketest/charter")
        assert resp.status_code == 410

    def test_double_revoke_returns_410(self, client):
        client.delete("/agents/revoketest")
        resp = client.delete("/agents/revoketest")
        assert resp.status_code == 410


# ── Crypto unit tests ─────────────────────────────────────────────────────────

class TestCrypto:
    def test_sign_and_verify_roundtrip(self):
        from app.crypto import generate_ed25519_keypair, sign_document, verify_document_proof
        private_key, pub_jwk = generate_ed25519_keypair()
        doc = {"hello": "world", "number": 42}
        signed = sign_document(doc, private_key, "did:web:test.example.com#key-1")
        assert "proof" in signed
        assert verify_document_proof(signed, pub_jwk)

    def test_tampered_document_fails_verification(self):
        from app.crypto import generate_ed25519_keypair, sign_document, verify_document_proof
        private_key, pub_jwk = generate_ed25519_keypair()
        signed = sign_document({"hello": "world"}, private_key, "did:web:test#key-1")
        tampered = {**signed, "hello": "tampered"}
        assert not verify_document_proof(tampered, pub_jwk)

    def test_wrong_key_fails_verification(self):
        from app.crypto import generate_ed25519_keypair, sign_document, verify_document_proof
        private_key, _ = generate_ed25519_keypair()
        _, other_pub_jwk = generate_ed25519_keypair()
        signed = sign_document({"hello": "world"}, private_key, "did:web:test#key-1")
        assert not verify_document_proof(signed, other_pub_jwk)


# ── DID helpers unit tests ────────────────────────────────────────────────────

class TestDIDHelpers:
    def test_make_agent_did(self):
        from app.did import make_agent_did
        assert make_agent_did("example.com", "node01") == "did:web:example.com:agents:node01"

    def test_did_to_url_root(self):
        from app.did import did_to_url
        assert did_to_url("did:web:example.com") == "https://example.com/.well-known/did.json"

    def test_did_to_url_path(self):
        from app.did import did_to_url
        url = did_to_url("did:web:example.com:agents:node01")
        assert url == "https://example.com/agents/node01/did.json"


# ── Verifiable Presentation tests ─────────────────────────────────────────────

class TestVerifiablePresentation:
    """
    Tests for present() — structure and cryptographic correctness.

    Sets up an agent directly through the registry API and saves the key/VC
    where the RegistryClient expects them, without any HTTP transport trickery.
    """

    @pytest.fixture()
    def agent_setup(self, client, tmp_path, sample_charter):
        """Register an agent, manually persist key + VC, return (rc, did, pub_jwk, registry_did_doc)."""
        import re
        import uuid
        from app.crypto import generate_ed25519_keypair, private_key_to_pem
        from registry_client import RegistryClient

        private_key, pub_jwk = generate_ed25519_keypair()
        agent_id = f"vptest{uuid.uuid4().hex[:6]}"
        resp = client.post("/agents", json={
            "agent_id": agent_id,
            "public_key_jwk": pub_jwk,
            "charter": sample_charter,
        })
        assert resp.status_code == 201
        data = resp.json()
        did = data["did"]
        charter_vc = data["charter_vc"]

        rc = RegistryClient(
            registry_url="http://testserver",
            keys_dir=tmp_path / "keys",
            charters_dir=tmp_path / "charters",
        )

        slug = re.sub(r"[^a-zA-Z0-9_\-]", "_", did)
        key_path = tmp_path / "keys" / f"{slug}.pem"
        charter_file = tmp_path / "charters" / f"{slug}.json"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        charter_file.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(private_key_to_pem(private_key))
        key_path.chmod(0o600)
        charter_file.write_text(json.dumps(charter_vc, indent=2))

        registry_did_doc = client.get("/.well-known/did.json").json()
        return rc, did, pub_jwk, charter_vc, registry_did_doc

    def test_present_returns_vp(self, agent_setup):
        rc, did, *_ = agent_setup
        vp = rc.present(did)
        assert "VerifiablePresentation" in vp["type"]
        assert vp["holder"] == did
        assert len(vp["verifiableCredential"]) == 1
        assert "proof" in vp

    def test_present_proof_purpose_is_authentication(self, agent_setup):
        rc, did, *_ = agent_setup
        vp = rc.present(did)
        assert vp["proof"]["proofPurpose"] == "authentication"
        assert vp["proof"]["verificationMethod"] == f"{did}#key-1"

    def test_present_includes_challenge(self, agent_setup):
        rc, did, *_ = agent_setup
        vp = rc.present(did, challenge="nonce-123")
        assert vp.get("challenge") == "nonce-123"

    def test_holder_signature_verifies(self, agent_setup):
        """VP proof must verify against the agent's own public key."""
        from app.crypto import verify_document_proof
        rc, did, agent_pub_jwk, _, _ = agent_setup
        vp = rc.present(did)
        assert verify_document_proof(vp, agent_pub_jwk)

    def test_charter_vc_inside_vp_verifies(self, agent_setup):
        """Registry's signature on the VC embedded in the VP must be valid."""
        from app.crypto import verify_document_proof
        rc, did, _, _, registry_did_doc = agent_setup
        vp = rc.present(did)
        charter_vc = vp["verifiableCredential"][0]
        vm_id = charter_vc["proof"]["verificationMethod"]
        reg_pub_jwk = next(
            vm["publicKeyJwk"]
            for vm in registry_did_doc["verificationMethod"]
            if vm["id"] == vm_id
        )
        assert verify_document_proof(charter_vc, reg_pub_jwk)

    def test_tampered_vp_fails(self, agent_setup):
        """Modifying the VP after signing must invalidate the holder's proof."""
        from app.crypto import verify_document_proof
        rc, did, agent_pub_jwk, _, _ = agent_setup
        vp = rc.present(did)
        tampered = {**vp, "holder": "did:web:evil.example.com:agents:fake"}
        assert not verify_document_proof(tampered, agent_pub_jwk)

