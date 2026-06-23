"""
Cryptographic primitives for the Agent Identity Registry.

Key format : Ed25519 (OKP / RFC 8037)
VC signing  : Data Integrity Proof, eddsa-jcs-2022 cryptosuite
              (sha256(JCS(proofOptions)) ‖ sha256(JCS(document)), signed with Ed25519)
Multibase   : 'u' prefix = base64url (RFC 4648 §5, no padding)
"""
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)


# ── Base64url helpers ────────────────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ── Key generation & serialisation ──────────────────────────────────────────

def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, dict]:
    """Return (private_key, public_key_jwk)."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, public_key_to_jwk(private_key.public_key())


def public_key_to_jwk(public_key: Ed25519PublicKey, key_id: str = "key-1") -> dict:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw), "kid": key_id}


def load_or_create_private_key(path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from *path* (PEM/PKCS8), or generate and save one."""
    if path.exists():
        return load_pem_private_key(path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    path.chmod(0o600)
    return key


def private_key_to_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def load_private_key_from_pem(pem: bytes) -> Ed25519PrivateKey:
    return load_pem_private_key(pem, password=None)


# ── Low-level signing ────────────────────────────────────────────────────────

def sign_bytes(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def verify_bytes(public_key_jwk: dict, data: bytes, signature: bytes) -> bool:
    try:
        raw = b64url_decode(public_key_jwk["x"])
        public_key = Ed25519PublicKey.from_public_bytes(raw)
        public_key.verify(signature, data)
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


# ── JSON Canonicalization (RFC 8785, simplified) ─────────────────────────────

def jcs(obj: dict) -> bytes:
    """
    Simplified JCS (JSON Canonicalization Scheme, RFC 8785).
    Sufficient for the well-typed payloads produced by this registry.
    Handles nested dicts/lists, strings, numbers, booleans, and None.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ── Data Integrity Proof (eddsa-jcs-2022) ────────────────────────────────────

def sign_document(
    doc: dict,
    private_key: Ed25519PrivateKey,
    verification_method: str,
    proof_purpose: str = "assertionMethod",
) -> dict:
    """
    Add a Data Integrity Proof to *doc* using the eddsa-jcs-2022 cryptosuite.

    Signing input: sha256(JCS(proofOptions)) ‖ sha256(JCS(doc_without_proof))
    proofValue  : multibase base64url ('u' prefix)
    """
    proof_options: dict = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }

    hash_input = (
        hashlib.sha256(jcs(proof_options)).digest()
        + hashlib.sha256(jcs(doc)).digest()
    )
    signature = sign_bytes(private_key, hash_input)
    proof_value = "u" + b64url_encode(signature)

    return {**doc, "proof": {**proof_options, "proofValue": proof_value}}


def verify_document_proof(doc: dict, public_key_jwk: dict) -> bool:
    """
    Verify a Data Integrity Proof (eddsa-jcs-2022) on *doc*.
    Returns True only if the signature is valid.
    """
    proof = doc.get("proof")
    if not proof:
        return False

    proof_value = proof.get("proofValue", "")
    if not proof_value.startswith("u"):
        return False  # only base64url multibase supported

    try:
        signature = b64url_decode(proof_value[1:])
    except Exception:
        return False

    proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
    doc_without_proof = {k: v for k, v in doc.items() if k != "proof"}

    hash_input = (
        hashlib.sha256(jcs(proof_options)).digest()
        + hashlib.sha256(jcs(doc_without_proof)).digest()
    )
    return verify_bytes(public_key_jwk, hash_input, signature)
