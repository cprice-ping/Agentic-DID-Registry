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
    Byte-identical to RFC 8785 for the string/array/object payloads this registry
    signs (no floats); not a full RFC 8785 implementation.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ── Multibase base58btc ('z') — the proofValue encoding eddsa-jcs-2022 mandates ─

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


def b58btc_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def b58btc_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58_INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def decode_multibase(value: str) -> "bytes | None":
    """Decode a multibase proofValue: 'z' = base58btc (spec), 'u' = base64url (legacy)."""
    try:
        if value.startswith("z"):
            return b58btc_decode(value[1:])
        if value.startswith("u"):
            return b64url_decode(value[1:])
    except Exception:
        return None
    return None


# ── Data Integrity Proof (eddsa-jcs-2022) ────────────────────────────────────

def _proof_config(proof_options: dict, doc: dict) -> dict:
    """
    The proof configuration hashed by eddsa-jcs-2022 carries the document's
    @context when present, per the W3C vc-di-eddsa cryptosuite. (JCS sorts keys,
    so insertion order is irrelevant.)
    """
    if "@context" in doc:
        return {"@context": doc["@context"], **proof_options}
    return dict(proof_options)


def sign_document(
    doc: dict,
    private_key: Ed25519PrivateKey,
    verification_method: str,
    proof_purpose: str = "assertionMethod",
) -> dict:
    """
    Add a Data Integrity Proof to *doc* using the eddsa-jcs-2022 cryptosuite.

    Signing input: sha256(JCS(proofConfig)) ‖ sha256(JCS(doc_without_proof)),
    where proofConfig is the proof options plus the document @context.
    proofValue  : multibase base58btc ('z' prefix), per spec.
    """
    proof_options: dict = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }

    hash_input = (
        hashlib.sha256(jcs(_proof_config(proof_options, doc))).digest()
        + hashlib.sha256(jcs(doc)).digest()
    )
    signature = sign_bytes(private_key, hash_input)
    proof_value = "z" + b58btc_encode(signature)

    return {**doc, "proof": {**proof_options, "proofValue": proof_value}}


def verify_document_proof(doc: dict, public_key_jwk: dict) -> bool:
    """
    Verify a Data Integrity Proof (eddsa-jcs-2022) on *doc*.
    Accepts base58btc ('z', spec) and base64url ('u', legacy) proofValues.
    """
    proof = doc.get("proof")
    if not proof:
        return False

    signature = decode_multibase(proof.get("proofValue", ""))
    if signature is None:
        return False

    proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
    doc_without_proof = {k: v for k, v in doc.items() if k != "proof"}

    hash_input = (
        hashlib.sha256(jcs(_proof_config(proof_options, doc_without_proof))).digest()
        + hashlib.sha256(jcs(doc_without_proof)).digest()
    )
    return verify_bytes(public_key_jwk, hash_input, signature)
