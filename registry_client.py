"""
Agent Identity Registry — client library.

Consuming projects import this module and use the module-level ``registry``
instance (configured via AGENT_REGISTRY_URL env var) or construct their own
``RegistryClient``.

Usage
-----
    from registry_client import registry

    # One-time at agent setup
    did = registry.provision({
        "name": "napa-node-01",
        "capabilities": ["observe", "publish"],
        "scope": "Napa Valley environmental monitoring — watershed, weather, AQI",
        "intent": "Collect domain sensor data, reason locally, publish observations",
        "operator": "did:web:cpricedomain.net",
    })

    # Verify another agent's charter (cached with TTL)
    charter = registry.verify("did:web:cpricedomain.net:agents:napanode01")
    if charter and "observe" in charter.get("capabilities", []):
        ...

    # Sign a record before publishing
    signed = registry.sign(record, did=did)

Key storage
-----------
  Private key : ~/.agent/keys/{did_slug}.pem  (mode 0600)
  Charter VC  : ~/.agent/charters/{did_slug}.json
"""
import base64
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
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

DEFAULT_KEYS_DIR = Path.home() / ".agent" / "keys"
DEFAULT_CHARTERS_DIR = Path.home() / ".agent" / "charters"
VERIFY_CACHE_TTL = 300  # seconds


# ── Base64url helpers ────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ── Key helpers ───────────────────────────────────────────────────────────────

def _generate_keypair() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _public_key_to_jwk(public_key: Ed25519PublicKey) -> dict:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url_encode(raw)}


def _save_private_key(key: Ed25519PrivateKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    path.write_bytes(pem)
    path.chmod(0o600)


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    return load_pem_private_key(path.read_bytes(), password=None)


# ── Signing / verification (same algorithm as registry) ──────────────────────

def _jcs(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _make_proof(
    private_key: Ed25519PrivateKey,
    doc: dict,
    verification_method: str,
    proof_purpose: str,
) -> dict:
    proof_options: dict = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }
    hash_input = (
        hashlib.sha256(_jcs(proof_options)).digest()
        + hashlib.sha256(_jcs(doc)).digest()
    )
    signature = private_key.sign(hash_input)
    return {**proof_options, "proofValue": "u" + _b64url_encode(signature)}


def _verify_proof(doc: dict, public_key_jwk: dict) -> bool:
    """Verify a Data Integrity Proof (eddsa-jcs-2022) on *doc*."""
    proof = doc.get("proof")
    if not proof:
        return False
    proof_value = proof.get("proofValue", "")
    if not proof_value.startswith("u"):
        return False
    try:
        signature = _b64url_decode(proof_value[1:])
        proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
        doc_without_proof = {k: v for k, v in doc.items() if k != "proof"}
        hash_input = (
            hashlib.sha256(_jcs(proof_options)).digest()
            + hashlib.sha256(_jcs(doc_without_proof)).digest()
        )
        raw = _b64url_decode(public_key_jwk["x"])
        pub = Ed25519PublicKey.from_public_bytes(raw)
        pub.verify(signature, hash_input)
        return True
    except Exception:
        return False


# ── RegistryClient ────────────────────────────────────────────────────────────

class RegistryClient:
    """
    Client for the Agent Identity Registry.

    Parameters
    ----------
    registry_url:  Base URL of the registry, e.g. ``https://cpricedomain.net``.
    keys_dir:      Directory for local private keys (default ~/.agent/keys/).
    charters_dir:  Directory for local charter VCs (default ~/.agent/charters/).
    http_timeout:  HTTP request timeout in seconds.
    """

    def __init__(
        self,
        registry_url: str,
        keys_dir: Optional[Path] = None,
        charters_dir: Optional[Path] = None,
        http_timeout: float = 10.0,
    ) -> None:
        self._registry_url = registry_url.rstrip("/")
        self._keys_dir = keys_dir or DEFAULT_KEYS_DIR
        self._charters_dir = charters_dir or DEFAULT_CHARTERS_DIR
        self._http_timeout = http_timeout
        # did → (expires_at: float, charter_claims: dict)
        self._verify_cache: dict[str, tuple[float, dict]] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def provision(self, charter: dict) -> str:
        """
        Generate a local Ed25519 keypair, register with the registry, and return
        the minted DID.

        The private key is stored at ``~/.agent/keys/{did_slug}.pem`` (mode 0600).
        The signed charter VC is stored at ``~/.agent/charters/{did_slug}.json``.

        Raises
        ------
        ValueError
            If the charter has no ``name`` (or ``agent_id``) to derive an ID from,
            or if the agent_id is already registered.
        httpx.HTTPStatusError
            On unexpected HTTP errors from the registry.
        """
        agent_id = self._derive_agent_id(charter)
        private_key = _generate_keypair()
        public_key_jwk = _public_key_to_jwk(private_key.public_key())

        # Strip internal client-only key before sending to registry
        charter_claims = {k: v for k, v in charter.items() if k != "agent_id"}

        payload = {
            "agent_id": agent_id,
            "public_key_jwk": public_key_jwk,
            "charter": charter_claims,
        }

        with httpx.Client(timeout=self._http_timeout) as client:
            response = client.post(f"{self._registry_url}/agents", json=payload)

        if response.status_code == 409:
            raise ValueError(f"Agent '{agent_id}' is already registered.")
        response.raise_for_status()

        data = response.json()
        did: str = data["did"]
        charter_vc: dict = data["charter_vc"]

        # Persist key and VC locally
        _save_private_key(private_key, self._key_path(did))
        charter_path = self._charter_path(did)
        charter_path.parent.mkdir(parents=True, exist_ok=True)
        charter_path.write_text(json.dumps(charter_vc, indent=2))

        return did

    def verify(self, did: str) -> Optional[dict]:
        """
        Resolve *did* from the registry and return its charter credential subject
        claims.

        - Verifies the registry's signature on the VC before returning.
        - Returns ``None`` if the DID is unknown, revoked, or the signature fails.
        - Results are cached for ``VERIFY_CACHE_TTL`` seconds (default 300 s).

        Example
        -------
        ::

            charter = registry.verify("did:web:cpricedomain.net:agents:napanode01")
            if charter and "observe" in charter.get("capabilities", []):
                # trust the record
        """
        # Cache hit
        cached = self._verify_cache.get(did)
        if cached:
            expires_at, claims = cached
            if time.monotonic() < expires_at:
                return claims

        agent_id = self._did_to_agent_id(did)
        if not agent_id:
            return None

        try:
            with httpx.Client(timeout=self._http_timeout) as client:
                charter_resp = client.get(
                    f"{self._registry_url}/agents/{agent_id}/charter"
                )
                if charter_resp.status_code in (404, 410):
                    return None
                charter_resp.raise_for_status()
                vc = charter_resp.json()

                registry_did_resp = client.get(
                    f"{self._registry_url}/.well-known/did.json"
                )
                registry_did_resp.raise_for_status()
                registry_did_doc = registry_did_resp.json()
        except httpx.HTTPError:
            return None

        # Locate the registry's verification key referenced in the proof
        vm_id = vc.get("proof", {}).get("verificationMethod", "")
        registry_pub_key_jwk = self._extract_verification_key(registry_did_doc, vm_id)
        if not registry_pub_key_jwk:
            return None

        if not _verify_proof(vc, registry_pub_key_jwk):
            return None

        claims = vc.get("credentialSubject", {})
        self._verify_cache[did] = (time.monotonic() + VERIFY_CACHE_TTL, claims)
        return claims

    def sign(self, record: dict, did: str) -> dict:
        """
        Sign *record* with the agent's local private key.

        Returns a copy of *record* with a ``proof`` property appended.

        Raises
        ------
        FileNotFoundError
            If no local private key exists for *did* (agent not provisioned on
            this machine).
        """
        key_path = self._key_path(did)
        if not key_path.exists():
            raise FileNotFoundError(
                f"No private key found for DID {did!r}. "
                f"Expected: {key_path}. "
                "Run registry.provision() on this machine first."
            )
        private_key = _load_private_key(key_path)
        proof = _make_proof(
            private_key,
            record,
            verification_method=f"{did}#key-1",
            proof_purpose="authentication",
        )
        return {**record, "proof": proof}

    def present(self, did: str, challenge: Optional[str] = None) -> dict:
        """
        Create a Verifiable Presentation (VP) wrapping the agent's charter VC.

        The VP is signed with the agent's own private key, proving that the
        presenter controls the DID in the credential.  Any third party can verify
        both signatures independently:

        1. Agent signature on the VP  → proves the presenter controls the DID
        2. Registry signature on the VC inside the VP → proves the charter was
           issued by the trusted registry

        Parameters
        ----------
        did:       The agent DID to present on behalf of.
        challenge: Optional nonce from the verifier (replay protection).

        Raises
        ------
        FileNotFoundError
            If the private key or charter VC are not found locally.
        """
        key_path = self._key_path(did)
        charter_path = self._charter_path(did)
        if not key_path.exists():
            raise FileNotFoundError(
                f"No private key for {did!r}. Run registry.provision() first."
            )
        if not charter_path.exists():
            raise FileNotFoundError(
                f"No charter VC for {did!r}. Run registry.provision() first."
            )

        charter_vc = json.loads(charter_path.read_text())
        vp: dict = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": did,
            "verifiableCredential": [charter_vc],
        }
        if challenge:
            vp["challenge"] = challenge

        private_key = _load_private_key(key_path)
        proof = _make_proof(
            private_key,
            vp,
            verification_method=f"{did}#key-1",
            proof_purpose="authentication",
        )
        return {**vp, "proof": proof}

    def invalidate_cache(self, did: Optional[str] = None) -> None:
        """Invalidate the verify cache for *did*, or clear it entirely."""
        if did:
            self._verify_cache.pop(did, None)
        else:
            self._verify_cache.clear()

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _derive_agent_id(charter: dict) -> str:
        """
        Derive a URL-safe agent_id from charter fields.
        Uses ``agent_id`` if present, otherwise normalises ``name``.
        """
        explicit = charter.get("agent_id", "").strip()
        if explicit:
            # Validate that it's already URL-safe
            if not re.match(r"^[a-z0-9][a-z0-9\-]{0,62}$", explicit):
                raise ValueError(
                    f"agent_id {explicit!r} must be lowercase alphanumeric + hyphens."
                )
            return explicit

        name = charter.get("name", "")
        agent_id = re.sub(r"[^a-z0-9]+", "", name.lower())
        if not agent_id:
            raise ValueError(
                "Charter must include 'name' (or 'agent_id') to derive an agent ID."
            )
        return agent_id

    @staticmethod
    def _did_to_agent_id(did: str) -> Optional[str]:
        """Extract agent_id from a did:web DID managed by this registry."""
        # Expected: did:web:{domain}:agents:{agent_id}
        parts = did.split(":")
        if (
            len(parts) == 5
            and parts[0] == "did"
            and parts[1] == "web"
            and parts[3] == "agents"
        ):
            return parts[4]
        return None

    def _key_path(self, did: str) -> Path:
        slug = re.sub(r"[^a-zA-Z0-9_\-]", "_", did)
        return self._keys_dir / f"{slug}.pem"

    def _charter_path(self, did: str) -> Path:
        slug = re.sub(r"[^a-zA-Z0-9_\-]", "_", did)
        return self._charters_dir / f"{slug}.json"

    @staticmethod
    def _extract_verification_key(did_doc: dict, vm_id: str) -> Optional[dict]:
        """Return the publicKeyJwk for the verification method matching *vm_id*."""
        for vm in did_doc.get("verificationMethod", []):
            if not vm_id or vm.get("id") == vm_id:
                return vm.get("publicKeyJwk")
        return None


# ── Standalone presentation verifier ─────────────────────────────────────────

class PresentationVerificationResult:
    """Result of verify_presentation()."""

    def __init__(
        self,
        valid: bool,
        holder_did: str,
        charter: Optional[dict],
        holder_signature_valid: bool,
        charter_signature_valid: bool,
        error: Optional[str] = None,
    ) -> None:
        self.valid = valid
        self.holder_did = holder_did
        self.charter = charter
        self.holder_signature_valid = holder_signature_valid
        self.charter_signature_valid = charter_signature_valid
        self.error = error

    def __repr__(self) -> str:
        return (
            f"PresentationVerificationResult("
            f"valid={self.valid}, "
            f"holder={self.holder_did!r}, "
            f"holder_sig={self.holder_signature_valid}, "
            f"charter_sig={self.charter_signature_valid}"
            f"{',' + repr(self.error) if self.error else ''})"
        )


def verify_presentation(
    vp: dict,
    registry_url: str,
    challenge: Optional[str] = None,
    http_timeout: float = 10.0,
) -> PresentationVerificationResult:
    """
    Verify a Verifiable Presentation end-to-end.

    Two independent checks:
    1. Holder signature on the VP — proves the presenter controls the DID
    2. Registry signature on the charter VC inside the VP — proves the charter
       was issued by the trusted registry

    Optionally checks that the VP's challenge matches the expected value.

    Parameters
    ----------
    vp:           The Verifiable Presentation dict (as returned by ``present()``).
    registry_url: Base URL of the registry, used to fetch DID documents.
    challenge:    If provided, must match ``vp["challenge"]`` exactly.

    Returns
    -------
    PresentationVerificationResult with ``.valid`` True only if both
    signatures check out (and the challenge matches if supplied).
    """
    holder_did: str = vp.get("holder", "")
    holder_sig_ok = False
    charter_sig_ok = False

    def _fail(msg: str) -> PresentationVerificationResult:
        return PresentationVerificationResult(
            valid=False,
            holder_did=holder_did,
            charter=None,
            holder_signature_valid=holder_sig_ok,
            charter_signature_valid=charter_sig_ok,
            error=msg,
        )

    # Optional challenge check
    if challenge is not None and vp.get("challenge") != challenge:
        return _fail(
            f"Challenge mismatch: expected {challenge!r}, got {vp.get('challenge')!r}"
        )

    if not holder_did:
        return _fail("VP missing 'holder' field.")

    vcs = vp.get("verifiableCredential", [])
    if not vcs:
        return _fail("VP contains no verifiableCredential.")

    # ── 1. Verify holder's signature on the VP ────────────────────────────────
    # Fetch the agent's DID document from the registry to get its public key.
    # In a did:web world this would be a direct HTTPS fetch to the resolution URL;
    # we fetch from the registry API which serves the same document.
    try:
        parts = holder_did.split(":")
        if len(parts) != 5 or parts[3] != "agents":
            return _fail(f"Unsupported DID format for holder: {holder_did!r}")
        agent_id = parts[4]
        base = registry_url.rstrip("/")

        with httpx.Client(timeout=http_timeout) as client:
            agent_did_resp = client.get(f"{base}/agents/{agent_id}/did.json")
            if agent_did_resp.status_code == 404:
                return _fail(f"Agent DID not found in registry: {holder_did!r}")
            agent_did_resp.raise_for_status()
            agent_did_doc = agent_did_resp.json()

            if agent_did_doc.get("deactivated"):
                return _fail(f"Agent DID has been revoked: {holder_did!r}")

            # Fetch registry DID document for charter VC verification
            registry_did_resp = client.get(f"{base}/.well-known/did.json")
            registry_did_resp.raise_for_status()
            registry_did_doc = registry_did_resp.json()

    except httpx.HTTPError as exc:
        return _fail(f"HTTP error fetching DID documents: {exc}")

    # Locate holder's public key
    vp_proof_vm = vp.get("proof", {}).get("verificationMethod", "")
    agent_pub_key_jwk = _extract_vm_key(agent_did_doc, vp_proof_vm)
    if not agent_pub_key_jwk:
        return _fail(
            f"Could not find verification key {vp_proof_vm!r} in agent DID document."
        )

    holder_sig_ok = _verify_proof(vp, agent_pub_key_jwk)
    if not holder_sig_ok:
        return _fail("Holder signature on VP is invalid.")

    # ── 2. Verify registry's signature on the charter VC ─────────────────────
    charter_vc = vcs[0]
    vc_proof_vm = charter_vc.get("proof", {}).get("verificationMethod", "")
    registry_pub_key_jwk = _extract_vm_key(registry_did_doc, vc_proof_vm)
    if not registry_pub_key_jwk:
        return _fail(
            f"Could not find verification key {vc_proof_vm!r} in registry DID document."
        )

    charter_sig_ok = _verify_proof(charter_vc, registry_pub_key_jwk)
    if not charter_sig_ok:
        return _fail("Registry signature on charter VC is invalid.")

    charter = charter_vc.get("credentialSubject", {})
    return PresentationVerificationResult(
        valid=True,
        holder_did=holder_did,
        charter=charter,
        holder_signature_valid=True,
        charter_signature_valid=True,
    )


def _extract_vm_key(did_doc: dict, vm_id: str) -> Optional[dict]:
    """Extract publicKeyJwk from a DID document by verification method id."""
    for vm in did_doc.get("verificationMethod", []):
        if not vm_id or vm.get("id") == vm_id:
            return vm.get("publicKeyJwk")
    return None


# ── Module-level convenience instance ────────────────────────────────────────

_REGISTRY_URL = os.environ.get("AGENT_REGISTRY_URL", "https://cpricedomain.net")
registry = RegistryClient(registry_url=_REGISTRY_URL)
