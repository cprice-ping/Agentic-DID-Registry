"""
Integration tests for the Agent Identity Registry.

Runs entirely in-process using FastAPI's TestClient — no real HTTP server needed.
Uses a temporary SQLite database, a fresh registry keypair, and a fresh operator
keypair (the enrollment trust root) per test session.
"""
import base64
import gzip
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

# ── Operator (enrollment) trust root, shared across the session ──────────────

_OPERATOR: dict = {}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_json(obj: dict) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode())


def make_voucher(
    agent_id: str,
    capabilities=None,
    operator=None,
    purpose: str = "enroll",
    ttl: int = 3600,
    aud=None,
    jti=None,
    sign_key=None,
) -> str:
    """Mint an operator-signed enrollment/revocation voucher for tests."""
    key = sign_key or _OPERATOR["key"]
    now = int(datetime.now(timezone.utc).timestamp())
    payload: dict = {
        "iss": "test-operator",
        "aud": aud if aud is not None else _OPERATOR["registry_did"],
        "sub": agent_id,
        "iat": now,
        "exp": now + ttl,
        "jti": jti or str(uuid.uuid4()),
        "purpose": purpose,
    }
    if purpose == "enroll":
        if capabilities is not None:
            payload["capabilities"] = capabilities
        if operator is not None:
            payload["operator"] = operator
    header = {"alg": "EdDSA", "typ": "enrollment-voucher+jwt", "kid": _OPERATOR["kid"]}
    h = _b64url_json(header)
    p = _b64url_json(payload)
    sig = _b64url(key.sign(f"{h}.{p}".encode()))
    return f"{h}.{p}.{sig}"


def register(client, agent_id, public_key_jwk, charter, capabilities="auto", **voucher_kw):
    """POST /agents with an enrollment voucher whose grant covers the charter."""
    caps = charter.get("capabilities") if capabilities == "auto" else capabilities
    voucher = make_voucher(agent_id, capabilities=caps, **voucher_kw)
    return client.post(
        "/agents",
        json={"agent_id": agent_id, "public_key_jwk": public_key_jwk, "charter": charter},
        headers={"Authorization": f"Bearer {voucher}"},
    )


def _decode_status_bit(encoded_list: str, index: int) -> int:
    """Decode a multibase('u')+gzip Bitstring Status List and read bit *index*."""
    assert encoded_list.startswith("u")
    raw = encoded_list[1:]
    pad = 4 - len(raw) % 4
    if pad != 4:
        raw += "=" * pad
    bits = gzip.decompress(base64.urlsafe_b64decode(raw))
    return (bits[index // 8] >> (7 - (index % 8))) & 1


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def configure_test_env(tmp_path_factory):
    """Point the app at a temporary DB, key file, and operator JWKS."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    tmp = tmp_path_factory.mktemp("registry")
    os.environ["REGISTRY_DOMAIN"] = "test.example.com"
    os.environ["REGISTRY_KEY_PATH"] = str(tmp / "registry.key.pem")
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp / 'registry.db'}"

    # Operator trust root — registry trusts this public key for enrollment.
    op_key = Ed25519PrivateKey.generate()
    raw = op_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = _b64url(hashlib.sha256(raw).digest())[:16]
    jwks_path = tmp / "operator_jwks.json"
    jwks_path.write_text(
        json.dumps({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw), "kid": kid}]})
    )
    os.environ["OPERATOR_JWKS_PATH"] = str(jwks_path)

    _OPERATOR["key"] = op_key
    _OPERATOR["kid"] = kid
    _OPERATOR["registry_did"] = "did:web:test.example.com"
    yield


@pytest.fixture(scope="session")
def client(configure_test_env):
    """Create a TestClient for the full FastAPI app."""
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
        resp = register(client, "napanode01", pub_jwk, sample_charter)
        assert resp.status_code == 201

    def test_register_returns_did(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        resp = register(client, "napanode02", pub_jwk, sample_charter)
        data = resp.json()
        assert data["did"] == "did:web:test.example.com:agents:napanode02"

    def test_register_returns_charter_vc(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        resp = register(client, "napanode03", pub_jwk, sample_charter)
        data = resp.json()
        vc = data["charter_vc"]
        assert "VerifiableCredential" in vc["type"]
        assert "AgentCharterCredential" in vc["type"]
        assert vc["issuer"] == "did:web:test.example.com"
        subject = vc["credentialSubject"]
        assert subject["id"] == "did:web:test.example.com:agents:napanode03"
        assert subject["capabilities"] == ["observe", "publish"]
        assert "proof" in vc

    def test_charter_context_uses_registry_domain(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        vc = register(client, "ctxtest", pub_jwk, sample_charter).json()["charter_vc"]
        assert "https://test.example.com/contexts/agent-charter/v1" in vc["@context"]
        assert all("cpricedomain.net" not in c for c in vc["@context"])

    def test_charter_has_validity_and_status(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        vc = register(client, "napaexpiry", pub_jwk, sample_charter).json()["charter_vc"]
        assert "validFrom" in vc and "validUntil" in vc
        status = vc["credentialStatus"]
        assert status["type"] == "BitstringStatusListEntry"
        assert status["statusListCredential"].endswith("/status/list")

    def test_duplicate_agent_id_returns_409(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        register(client, "duptest", pub_jwk, sample_charter)
        resp = register(client, "duptest", pub_jwk, sample_charter)
        assert resp.status_code == 409

    def test_invalid_agent_id_rejected(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        resp = client.post(
            "/agents",
            json={
                "agent_id": "UPPERCASE-INVALID!",
                "public_key_jwk": pub_jwk,
                "charter": sample_charter,
            },
            headers={"Authorization": f"Bearer {make_voucher('UPPERCASE-INVALID!')}"},
        )
        assert resp.status_code == 422


# ── Enrollment voucher auth ───────────────────────────────────────────────────

class TestEnrollmentVoucher:
    def test_missing_voucher_rejected(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        resp = client.post(
            "/agents",
            json={"agent_id": "novoucher", "public_key_jwk": pub_jwk, "charter": sample_charter},
        )
        assert resp.status_code == 401

    def test_tampered_voucher_rejected(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        voucher = make_voucher("tampered", capabilities=["observe", "publish"])
        h, p, s = voucher.split(".")
        bad = f"{h}.{p}.{s[:-4]}AAAA"  # corrupt signature
        resp = client.post(
            "/agents",
            json={"agent_id": "tampered", "public_key_jwk": pub_jwk, "charter": sample_charter},
            headers={"Authorization": f"Bearer {bad}"},
        )
        assert resp.status_code == 403

    def test_wrong_audience_rejected(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        resp = register(
            client, "wrongaud", pub_jwk, sample_charter, aud="did:web:other.example.com"
        )
        assert resp.status_code == 403

    def test_untrusted_operator_rejected(self, client, sample_charter, agent_keypair):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        pub_jwk, _ = agent_keypair
        rogue = Ed25519PrivateKey.generate()
        resp = register(client, "rogueop", pub_jwk, sample_charter, sign_key=rogue)
        assert resp.status_code == 403

    def test_agent_id_mismatch_rejected(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        voucher = make_voucher("authorized-id", capabilities=["observe", "publish"])
        resp = client.post(
            "/agents",
            json={"agent_id": "different-id", "public_key_jwk": pub_jwk, "charter": sample_charter},
            headers={"Authorization": f"Bearer {voucher}"},
        )
        assert resp.status_code == 403

    def test_capability_outside_grant_rejected(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        # Voucher grants only "observe"; charter asks for observe+publish.
        resp = register(client, "overclaim", pub_jwk, sample_charter, capabilities=["observe"])
        assert resp.status_code == 403

    def test_voucher_clamps_operator(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        charter = {**sample_charter, "operator": "did:web:agent-asserted.example.com"}
        resp = register(
            client, "clampop", pub_jwk, charter,
            operator="did:web:trusted-operator.example.com",
        )
        assert resp.status_code == 201
        subject = resp.json()["charter_vc"]["credentialSubject"]
        assert subject["operator"] == "did:web:trusted-operator.example.com"

    def test_voucher_single_use(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        voucher = make_voucher("singleuse", capabilities=["observe", "publish"])
        body = {"agent_id": "singleuse", "public_key_jwk": pub_jwk, "charter": sample_charter}
        headers = {"Authorization": f"Bearer {voucher}"}
        first = client.post("/agents", json=body, headers=headers)
        assert first.status_code == 201
        second = client.post("/agents", json=body, headers=headers)
        assert second.status_code == 409
        assert "already been used" in second.json()["detail"]


# ── DID document resolution ───────────────────────────────────────────────────

class TestAgentDIDDocument:
    @pytest.fixture(autouse=True)
    def register(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        register(client, "diddoctest", pub_jwk, sample_charter)

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
        register(client, "chartertest", pub_jwk, sample_charter)

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

    def test_ldp_vc_proofvalue_is_base58btc(self, client):
        """eddsa-jcs-2022 mandates multibase base58btc ('z'), not base64url ('u')."""
        vc = client.get("/agents/chartertest/charter").json()
        assert vc["proof"]["proofValue"].startswith("z")

    def test_ldp_vc_proof_is_spec_shaped(self, client):
        """
        Independently reconstruct the eddsa-jcs-2022 hash and verify the signature
        — proving the wire format matches the spec (base58btc proofValue + the
        document @context folded into the proofConfig), not just self-consistency.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from app.crypto import b58btc_decode, jcs

        vc = client.get("/agents/chartertest/charter").json()
        registry_doc = client.get("/.well-known/did.json").json()
        vm_id = vc["proof"]["verificationMethod"]
        pub_x = next(
            vm["publicKeyJwk"]["x"]
            for vm in registry_doc["verificationMethod"]
            if vm["id"] == vm_id
        )

        def _dec(s):
            pad = 4 - len(s) % 4
            return base64.urlsafe_b64decode(s + ("=" * pad if pad != 4 else ""))

        pub = Ed25519PublicKey.from_public_bytes(_dec(pub_x))
        signature = b58btc_decode(vc["proof"]["proofValue"][1:])  # strip 'z'

        proof_options = {k: v for k, v in vc["proof"].items() if k != "proofValue"}
        doc = {k: v for k, v in vc.items() if k != "proof"}
        proof_config = {"@context": doc["@context"], **proof_options}
        hash_data = (
            hashlib.sha256(jcs(proof_config)).digest()
            + hashlib.sha256(jcs(doc)).digest()
        )
        pub.verify(signature, hash_data)  # raises InvalidSignature if wrong

    def test_unknown_agent_returns_404(self, client):
        assert client.get("/agents/nobody/charter").status_code == 404


# ── Charter decision attributes (PIP projection) ──────────────────────────────

class TestCharterAttributes:
    @pytest.fixture(autouse=True)
    def register(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        register(client, "attrtest", pub_jwk, sample_charter)

    def test_attributes_returns_declared_context(self, client):
        a = client.get("/agents/attrtest/attributes").json()
        assert a["subject"] == "did:web:test.example.com:agents:attrtest"
        assert a["agent_id"] == "attrtest"
        assert a["issuer"] == "did:web:test.example.com"
        assert a["status"] == "active"
        assert a["capabilities"] == ["observe", "publish"]
        assert a["intent"]  # declared intent present
        assert "validUntil" in a

    def test_unknown_agent_returns_404(self, client):
        assert client.get("/agents/nobody/attributes").status_code == 404

    def test_resolve_by_did_returns_same_attributes(self, client):
        did = "did:web:test.example.com:agents:attrtest"
        by_id = client.get("/agents/attrtest/attributes").json()
        by_did = client.get("/resolve", params={"subject": did}).json()
        assert by_did == by_id
        assert by_did["subject"] == did
        assert by_did["capabilities"] == ["observe", "publish"]

    def test_resolve_foreign_did_rejected(self, client):
        resp = client.get(
            "/resolve", params={"subject": "did:web:other.example.com:agents:attrtest"}
        )
        assert resp.status_code == 400

    def test_resolve_unknown_agent_404(self, client):
        resp = client.get(
            "/resolve", params={"subject": "did:web:test.example.com:agents:ghost"}
        )
        assert resp.status_code == 404

    def test_revoked_agent_fails_closed(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        register(client, "attrrevoke", pub_jwk, sample_charter)
        voucher = make_voucher("attrrevoke", purpose="revoke")
        client.delete(
            "/agents/attrrevoke", headers={"Authorization": f"Bearer {voucher}"}
        )
        # 200 (not 410) with an explicit status + empty capabilities → policy denies
        resp = client.get("/agents/attrrevoke/attributes")
        assert resp.status_code == 200
        a = resp.json()
        assert a["status"] == "revoked"
        assert a["capabilities"] == []
        assert a["revokedAt"] is not None


# ── Presentation verification (POST /verify, wallet-less) ─────────────────────

class TestPresentationVerification:
    @pytest.fixture()
    def presented(self, client, sample_charter):
        """Register an agent and return a make_vp() that signs a VP with its key."""
        from app.crypto import generate_ed25519_keypair, sign_document
        priv, jwk = generate_ed25519_keypair()
        aid = f"verify{uuid.uuid4().hex[:8]}"
        data = register(client, aid, jwk, sample_charter).json()
        did, charter_vc = data["did"], data["charter_vc"]

        def make_vp(challenge=None):
            vp = {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": did,
                "verifiableCredential": [charter_vc],
            }
            if challenge:
                vp["challenge"] = challenge
            return sign_document(vp, priv, f"{did}#key-1", proof_purpose="authentication")

        return aid, did, priv, charter_vc, make_vp

    def test_valid_presentation(self, client, presented):
        _, did, _, _, make_vp = presented
        r = client.post("/verify", json={"presentation": make_vp()}).json()
        assert r["valid"] is True
        assert r["holder_signature_valid"] and r["charter_signature_valid"]
        assert r["status"] == "active"
        assert r["holder"] == did
        assert r["claims"]["capabilities"] == ["observe", "publish"]

    def test_challenge_enforced(self, client, presented):
        *_, make_vp = presented
        vp = make_vp(challenge="nonce-1")
        ok = client.post("/verify", json={"presentation": vp, "challenge": "nonce-1"}).json()
        assert ok["valid"] is True
        bad = client.post("/verify", json={"presentation": vp, "challenge": "nonce-2"}).json()
        assert bad["valid"] is False
        assert "Challenge" in bad["error"]

    def test_tampered_presentation_rejected(self, client, presented):
        *_, make_vp = presented
        tampered = {**make_vp(), "holder": "did:web:test.example.com:agents:impostor"}
        r = client.post("/verify", json={"presentation": tampered}).json()
        assert r["valid"] is False
        # holder swapped to an unknown agent → caught as unknown holder
        assert "Unknown holder" in r["error"]

    def test_tampered_credential_rejected(self, client, presented):
        """Mutating the VP body after signing invalidates the holder signature."""
        from app.crypto import generate_ed25519_keypair
        _, did, priv, charter_vc, make_vp = presented
        vp = make_vp()
        vp["verifiableCredential"][0]["credentialSubject"]["capabilities"] = ["admin"]
        r = client.post("/verify", json={"presentation": vp}).json()
        assert r["valid"] is False
        assert r["holder_signature_valid"] is False

    def test_unknown_holder(self, client):
        from app.crypto import generate_ed25519_keypair, sign_document
        priv, _ = generate_ed25519_keypair()
        did = "did:web:test.example.com:agents:ghostagent"
        vp = sign_document(
            {"@context": ["https://www.w3.org/ns/credentials/v2"],
             "type": ["VerifiablePresentation"], "holder": did,
             "verifiableCredential": [{"x": 1}]},
            priv, f"{did}#key-1", proof_purpose="authentication",
        )
        r = client.post("/verify", json={"presentation": vp}).json()
        assert r["valid"] is False
        assert "Unknown holder" in r["error"]

    def test_revoked_holder_fails_closed_but_sigs_still_valid(self, client, presented):
        aid, did, _, _, make_vp = presented
        vp = make_vp()
        voucher = make_voucher(aid, purpose="revoke")
        client.delete(f"/agents/{aid}", headers={"Authorization": f"Bearer {voucher}"})
        r = client.post("/verify", json={"presentation": vp}).json()
        assert r["valid"] is False
        assert r["status"] == "revoked"
        # the signatures themselves remain cryptographically valid
        assert r["holder_signature_valid"] is True
        assert r["charter_signature_valid"] is True


# ── Bitstring Status List ─────────────────────────────────────────────────────

class TestStatusList:
    def test_status_list_is_signed_credential(self, client):
        from app.crypto import verify_document_proof
        vc = client.get("/status/list").json()
        assert "BitstringStatusListCredential" in vc["type"]
        assert vc["credentialSubject"]["encodedList"].startswith("u")
        registry_doc = client.get("/.well-known/did.json").json()
        pub = registry_doc["verificationMethod"][0]["publicKeyJwk"]
        assert verify_document_proof(vc, pub)

    def test_revocation_flips_status_bit(self, client, sample_charter, agent_keypair):
        pub_jwk, _ = agent_keypair
        vc = register(client, "statusrevoke", pub_jwk, sample_charter).json()["charter_vc"]
        index = int(vc["credentialStatus"]["statusListIndex"])

        before = client.get("/status/list").json()["credentialSubject"]["encodedList"]
        assert _decode_status_bit(before, index) == 0

        voucher = make_voucher("statusrevoke", purpose="revoke")
        client.delete("/agents/statusrevoke", headers={"Authorization": f"Bearer {voucher}"})

        after = client.get("/status/list").json()["credentialSubject"]["encodedList"]
        assert _decode_status_bit(after, index) == 1


# ── Key rotation ──────────────────────────────────────────────────────────────

class TestKeyRotation:
    @pytest.fixture()
    def agent(self, client, sample_charter):
        """Register a fresh, isolated agent and return (agent_id, did, current_key)."""
        from app.crypto import generate_ed25519_keypair
        key, jwk = generate_ed25519_keypair()
        agent_id = f"rotate{uuid.uuid4().hex[:8]}"
        resp = register(client, agent_id, jwk, sample_charter)
        assert resp.status_code == 201
        return agent_id, resp.json()["did"], key

    @staticmethod
    def _rotation_body(did, new_jwk, sign_key):
        from app.crypto import sign_document
        signed = sign_document(
            {"did": did, "new_public_key_jwk": new_jwk},
            sign_key,
            f"{did}#key-1",
            proof_purpose="authentication",
        )
        return {"new_public_key_jwk": new_jwk, "proof": signed["proof"]}

    def test_rotate_returns_200(self, client, agent):
        from app.crypto import generate_ed25519_keypair
        agent_id, did, key = agent
        _, new_jwk = generate_ed25519_keypair()
        resp = client.post(f"/agents/{agent_id}/rotate", json=self._rotation_body(did, new_jwk, key))
        assert resp.status_code == 200

    def test_rotate_without_valid_proof_rejected(self, client, agent):
        from app.crypto import generate_ed25519_keypair
        agent_id, did, _ = agent
        wrong_key, _ = generate_ed25519_keypair()  # not the current key
        _, new_jwk = generate_ed25519_keypair()
        resp = client.post(
            f"/agents/{agent_id}/rotate",
            json=self._rotation_body(did, new_jwk, wrong_key),
        )
        assert resp.status_code == 403

    def test_rotate_missing_proof_is_422(self, client, agent):
        from app.crypto import generate_ed25519_keypair
        agent_id, _, _ = agent
        _, new_jwk = generate_ed25519_keypair()
        resp = client.post(f"/agents/{agent_id}/rotate", json={"new_public_key_jwk": new_jwk})
        assert resp.status_code == 422

    def test_rotate_updates_did_document_key(self, client, agent):
        from app.crypto import generate_ed25519_keypair
        agent_id, did, key = agent
        _, new_jwk = generate_ed25519_keypair()
        client.post(f"/agents/{agent_id}/rotate", json=self._rotation_body(did, new_jwk, key))
        doc = client.get(f"/agents/{agent_id}/did.json").json()
        assert doc["verificationMethod"][0]["publicKeyJwk"]["x"] == new_jwk["x"]

    def test_rotate_reissues_charter_vc(self, client, agent):
        from app.crypto import generate_ed25519_keypair, verify_document_proof
        agent_id, did, key = agent
        _, new_jwk = generate_ed25519_keypair()
        data = client.post(
            f"/agents/{agent_id}/rotate", json=self._rotation_body(did, new_jwk, key)
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
        register(client, "revoketest", pub_jwk, sample_charter)

    def _revoke(self, client, agent_id="revoketest", **kw):
        voucher = make_voucher(agent_id, purpose="revoke", **kw)
        return client.delete(
            f"/agents/{agent_id}", headers={"Authorization": f"Bearer {voucher}"}
        )

    def test_revoke_without_voucher_rejected(self, client):
        assert client.delete("/agents/revoketest").status_code == 401

    def test_revoke_with_enroll_voucher_rejected(self, client):
        voucher = make_voucher("revoketest", purpose="enroll", capabilities=["observe"])
        resp = client.delete(
            "/agents/revoketest", headers={"Authorization": f"Bearer {voucher}"}
        )
        assert resp.status_code == 403

    def test_revoke_returns_200(self, client):
        assert self._revoke(client).status_code == 200

    def test_revoked_did_document_is_tombstone(self, client):
        self._revoke(client)
        doc = client.get("/agents/revoketest/did.json").json()
        assert doc.get("deactivated") is True

    def test_revoked_charter_returns_410(self, client):
        self._revoke(client)
        resp = client.get("/agents/revoketest/charter")
        assert resp.status_code == 410

    def test_double_revoke_returns_410(self, client):
        self._revoke(client)
        resp = self._revoke(client)
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

    def test_base58btc_roundtrip(self):
        import os
        from app.crypto import b58btc_encode, b58btc_decode
        for data in (b"", b"\x00", b"\x00\x00\x01\x02", os.urandom(64)):
            assert b58btc_decode(b58btc_encode(data)) == data

    def test_signed_doc_uses_z_multibase(self):
        from app.crypto import generate_ed25519_keypair, sign_document
        priv, _ = generate_ed25519_keypair()
        signed = sign_document({"@context": ["x"], "a": 1}, priv, "did:web:test#key-1")
        assert signed["proof"]["proofValue"].startswith("z")


# ── Voucher unit tests ────────────────────────────────────────────────────────

class TestVoucherModule:
    def _keys(self):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        raw = _OPERATOR["key"].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {_OPERATOR["kid"]: {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw), "kid": _OPERATOR["kid"]}}

    def test_valid_voucher_grant(self):
        from app.voucher import verify_voucher
        v = make_voucher("unit01", capabilities=["observe"], operator="did:web:op")
        grant = verify_voucher(v, self._keys(), expected_audience=_OPERATOR["registry_did"])
        assert grant.agent_id == "unit01"
        assert grant.capabilities == ["observe"]
        assert grant.operator == "did:web:op"
        assert grant.purpose == "enroll"

    def test_no_trusted_keys_rejects(self):
        from app.voucher import verify_voucher, VoucherError
        v = make_voucher("unit02")
        with pytest.raises(VoucherError):
            verify_voucher(v, {}, expected_audience=_OPERATOR["registry_did"])

    def test_expired_voucher_rejected(self):
        from app.voucher import verify_voucher, VoucherError
        v = make_voucher("unit03", ttl=-10)
        with pytest.raises(VoucherError):
            verify_voucher(v, self._keys(), expected_audience=_OPERATOR["registry_did"])


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
        from app.crypto import generate_ed25519_keypair, private_key_to_pem
        from registry_client import RegistryClient

        private_key, pub_jwk = generate_ed25519_keypair()
        agent_id = f"vptest{uuid.uuid4().hex[:6]}"
        resp = register(client, agent_id, pub_jwk, sample_charter)
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


# ── JWT format tests ──────────────────────────────────────────────────────────

class TestJWTFormats:
    """
    Tests for vc+jwt and vc+sd-jwt charter formats and JWT VP / KB-JWT presentation.
    """

    @pytest.fixture(autouse=True, scope="class")
    def register(self, client):  # noqa: PT004 (class-scope instance method, pytest <10)
        from app.crypto import generate_ed25519_keypair
        _, pub_jwk = generate_ed25519_keypair()
        charter = {
            "name": "napa-node-01",
            "capabilities": ["observe", "publish"],
            "scope": "Napa Valley environmental monitoring",
            "intent": "Collect domain sensor data",
            "operator": "did:web:test.example.com",
        }
        resp = register(client, "jwttest", pub_jwk, charter)
        assert resp.status_code == 201

    # ── /charter?format=jwt_vc ───────────────────────────────────────────────

    def test_jwt_vc_returns_compact_jwt(self, client):
        resp = client.get("/agents/jwttest/charter?format=jwt_vc")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/vc+jwt")
        parts = resp.text.split(".")
        assert len(parts) == 3, "JWT must be header.payload.signature"

    def test_jwt_vc_header_alg_is_eddsa(self, client):
        resp = client.get("/agents/jwttest/charter?format=jwt_vc")
        header_b64 = resp.text.split(".")[0]
        pad = 4 - len(header_b64) % 4
        header = json.loads(base64.urlsafe_b64decode(header_b64 + ("=" * pad if pad != 4 else "")))
        assert header["alg"] == "EdDSA"
        assert header["typ"] == "vc+jwt"

    def test_jwt_vc_payload_claims(self, client):
        resp = client.get("/agents/jwttest/charter?format=jwt_vc")
        payload_b64 = resp.text.split(".")[1]
        pad = 4 - len(payload_b64) % 4
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + ("=" * pad if pad != 4 else "")))
        assert payload["iss"] == "did:web:test.example.com"
        assert payload["sub"] == "did:web:test.example.com:agents:jwttest"
        assert "vc" in payload
        assert "AgentCharterCredential" in payload["vc"]["type"]
        assert "cnf" in payload  # agent public key bound to credential
        assert payload["cnf"]["jwk"]["kty"] == "OKP"
        assert "exp" in payload  # credential is time-bounded
        assert payload["vc"]["credentialStatus"]["type"] == "BitstringStatusListEntry"

    def test_jwt_vc_signature_verifies(self, client):
        """Ed25519 signature on the VC-JWT must verify against the registry key."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        jwt_str = client.get("/agents/jwttest/charter?format=jwt_vc").text
        header_b64, payload_b64, sig_b64 = jwt_str.split(".")

        def _dec(s):
            pad = 4 - len(s) % 4
            return base64.urlsafe_b64decode(s + ("=" * pad if pad != 4 else ""))

        registry_doc = client.get("/.well-known/did.json").json()
        pub_x = registry_doc["verificationMethod"][0]["publicKeyJwk"]["x"]
        pub_key = Ed25519PublicKey.from_public_bytes(_dec(pub_x))
        pub_key.verify(_dec(sig_b64), f"{header_b64}.{payload_b64}".encode())
        # raises cryptography.exceptions.InvalidSignature on failure

    # ── /charter?format=sd_jwt_vc ────────────────────────────────────────────

    def test_sd_jwt_vc_returns_tilde_separated(self, client):
        resp = client.get("/agents/jwttest/charter?format=sd_jwt_vc")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/vc+sd-jwt")
        assert "~" in resp.text, "SD-JWT must contain ~ separators"

    def test_sd_jwt_vc_has_disclosures(self, client):
        resp = client.get("/agents/jwttest/charter?format=sd_jwt_vc")
        parts = resp.text.split("~")
        disclosures = [p for p in parts[1:] if p]
        assert len(disclosures) > 0, "SD-JWT must have at least one disclosure"

    def test_sd_jwt_vc_jwt_header(self, client):
        resp = client.get("/agents/jwttest/charter?format=sd_jwt_vc")
        jwt_part = resp.text.split("~")[0]
        header_b64 = jwt_part.split(".")[0]
        pad = 4 - len(header_b64) % 4
        header = json.loads(base64.urlsafe_b64decode(header_b64 + ("=" * pad if pad != 4 else "")))
        assert header["alg"] == "EdDSA"
        assert header["typ"] == "vc+sd-jwt"

    def test_sd_jwt_vc_payload_has_sd_digests(self, client):
        resp = client.get("/agents/jwttest/charter?format=sd_jwt_vc")
        jwt_part = resp.text.split("~")[0]
        payload_b64 = jwt_part.split(".")[1]
        pad = 4 - len(payload_b64) % 4
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + ("=" * pad if pad != 4 else "")))
        assert "_sd" in payload
        assert len(payload["_sd"]) > 0
        assert payload["_sd_alg"] == "sha-256"
        assert "vct" in payload
        assert payload["sub"] == "did:web:test.example.com:agents:jwttest"

    def test_sd_jwt_vc_disclosure_decodes_to_claim(self, client):
        """Each disclosure must decode to [salt, claim_name, claim_value]."""
        resp = client.get("/agents/jwttest/charter?format=sd_jwt_vc")
        parts = resp.text.split("~")
        jwt_part = parts[0]
        disclosures = [p for p in parts[1:] if p]

        payload_b64 = jwt_part.split(".")[1]
        pad = 4 - len(payload_b64) % 4
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + ("=" * pad if pad != 4 else "")))
        sd_digests = set(payload["_sd"])

        for disc_b64 in disclosures:
            pad = 4 - len(disc_b64) % 4
            decoded = json.loads(base64.urlsafe_b64decode(disc_b64 + ("=" * pad if pad != 4 else "")))
            assert len(decoded) == 3, "Disclosure must be [salt, name, value]"
            digest = base64.urlsafe_b64encode(
                hashlib.sha256(disc_b64.encode()).digest()
            ).rstrip(b"=").decode()
            assert digest in sd_digests, f"Disclosure digest {digest!r} not found in _sd"

    # ── JWT VP (present_jwt) ──────────────────────────────────────────────────

    def test_make_jwt_vp_structure(self):
        """make_jwt_vp produces a valid three-part JWT with expected claims."""
        from app.crypto import generate_ed25519_keypair
        from app.jwt_vc import issue_vc_jwt, make_jwt_vp

        priv, pub_jwk = generate_ed25519_keypair()
        agent_did = "did:web:test.example.com:agents:jwttest"
        issuer_did = "did:web:test.example.com"
        vc_jwt = issue_vc_jwt(agent_did, {"name": "t"}, issuer_did, priv, f"{issuer_did}#key-1")
        vp_jwt = make_jwt_vp(agent_did, vc_jwt, priv, f"{agent_did}#key-1", "https://verifier.example", "nonce-abc")

        parts = vp_jwt.split(".")
        assert len(parts) == 3
        payload_b64 = parts[1]
        pad = 4 - len(payload_b64) % 4
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + ("=" * pad if pad != 4 else "")))
        assert payload["iss"] == agent_did
        assert payload["aud"] == "https://verifier.example"
        assert payload["nonce"] == "nonce-abc"
        assert "vp" in payload
        assert vc_jwt in payload["vp"]["verifiableCredential"]

    # ── KB-JWT (present_sd_jwt) ───────────────────────────────────────────────

    def test_attach_key_binding_appends_kb_jwt(self):
        """attach_key_binding must append a kb+jwt after the last ~."""
        from app.crypto import generate_ed25519_keypair
        from app.jwt_vc import issue_sd_jwt_vc, attach_key_binding

        priv, pub_jwk = generate_ed25519_keypair()
        agent_did = "did:web:test.example.com:agents:jwttest"
        issuer_did = "did:web:test.example.com"
        sd_jwt = issue_sd_jwt_vc(
            agent_did, {"name": "t", "capabilities": ["observe"]},
            issuer_did, priv, f"{issuer_did}#key-1", pub_jwk,
        )
        presentation = attach_key_binding(
            sd_jwt, priv, f"{agent_did}#key-1", "https://verifier.example", "nonce-xyz"
        )
        parts = presentation.split("~")
        kb_jwt = parts[-1]
        assert kb_jwt, "KB-JWT must be non-empty"
        header_b64 = kb_jwt.split(".")[0]
        pad = 4 - len(header_b64) % 4
        header = json.loads(base64.urlsafe_b64decode(header_b64 + ("=" * pad if pad != 4 else "")))
        assert header["typ"] == "kb+jwt"
        assert header["alg"] == "EdDSA"
