"""
JWT-secured VC formats for Neo / OID4VC interoperability.

Formats
-------
vc+jwt      W3C VC Data Model v2, JWT-secured (JOSE envelope, EdDSA signature)
vc+sd-jwt   SD-JWT-VC (draft-ietf-oauth-selective-disclosure-jwt) — all charter
            claims are individually selectively-disclosable

Both are signed with the registry's Ed25519 key and carry a `cnf.jwk` binding
the credential to the agent's public key, enabling Key Binding JWTs at
presentation time.

JWT VP      OID4VP-compatible Verifiable Presentation (jwt+vp) — wraps a vc+jwt
            and is signed by the agent's own key.

KB-JWT      Key Binding JWT (kb+jwt) — appended to an SD-JWT-VC presentation;
            signed by the agent's key, binds nonce + audience to the credential.
"""
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import REGISTRY_BASE_URL


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _make_jwt(
    payload: dict,
    private_key: Ed25519PrivateKey,
    kid: str,
    typ: str,
) -> str:
    """Produce a compact JWS (header.payload.signature) with EdDSA."""
    header = {"alg": "EdDSA", "typ": typ, "kid": kid}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = _b64url(private_key.sign(signing_input))
    return f"{h}.{p}.{sig}"


def _clean_jwk(jwk: dict) -> dict:
    """Strip non-standard fields (kid) from a JWK for embedding in cnf."""
    return {k: v for k, v in jwk.items() if k not in ("kid",)}


# ── VC-JWT issuance ───────────────────────────────────────────────────────────

def issue_vc_jwt(
    agent_did: str,
    charter: dict,
    issuer_did: str,
    private_key: Ed25519PrivateKey,
    verification_method: str,
    agent_public_key_jwk: Optional[dict] = None,
    ttl_days: int = 0,
    credential_status: Optional[dict] = None,
) -> str:
    """
    Issue a W3C VC Data Model v2 JWT-secured charter credential (vc+jwt).

    JWT claim mapping (per VC Data Model v2 §JWT):
      iss  ← issuer DID
      sub  ← credentialSubject.id (agent DID)
      iat  ← validFrom
      jti  ← VC id
      vc   ← credential object (without issuer/id/validFrom — in JWT claims)

    The agent's public key is included as cnf.jwk so the verifier can
    enforce Key Binding at presentation time.
    """
    now = int(datetime.now(timezone.utc).timestamp())
    jti = f"{issuer_did}/credentials/{agent_did.split(':')[-1]}"

    # credentialSubject carries charter claims; 'id' is at JWT 'sub' level
    credential_subject = {k: v for k, v in charter.items() if k != "id"}

    vc: dict = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            f"{REGISTRY_BASE_URL}/contexts/agent-charter/v1",
        ],
        "type": ["VerifiableCredential", "AgentCharterCredential"],
        "credentialSubject": credential_subject,
    }
    if credential_status is not None:
        vc["credentialStatus"] = credential_status

    payload: dict = {
        "iss": issuer_did,
        "sub": agent_did,
        "iat": now,
        "jti": jti,
        "vc": vc,
    }

    if ttl_days > 0:
        payload["exp"] = now + ttl_days * 86400
    if agent_public_key_jwk:
        payload["cnf"] = {"jwk": _clean_jwk(agent_public_key_jwk)}

    return _make_jwt(payload, private_key, kid=verification_method, typ="vc+jwt")


# ── SD-JWT-VC issuance ────────────────────────────────────────────────────────

#: Charter claims offered as individually selectable disclosures
_SD_CLAIMS = ["name", "capabilities", "scope", "intent", "operator"]


def issue_sd_jwt_vc(
    agent_did: str,
    charter: dict,
    issuer_did: str,
    private_key: Ed25519PrivateKey,
    verification_method: str,
    agent_public_key_jwk: Optional[dict] = None,
    selectively_disclosable: Optional[list[str]] = None,
    ttl_days: int = 0,
    credential_status: Optional[dict] = None,
) -> str:
    """
    Issue an SD-JWT-VC (vc+sd-jwt).

    Each charter claim is individually selectively-disclosable.  The holder
    can strip any disclosure before presenting — the verifier only sees what
    the holder chooses to reveal.

    Returned format:  <signed-JWT>~<Disc1>~<Disc2>~...~
    (trailing ~ signals no Key Binding JWT — that is added at presentation time)

    Disclosure format (per SD-JWT spec §4):
      base64url( JSON( [salt, claim_name, claim_value] ) )

    The digest in the JWT payload is:  base64url( SHA-256(disclosure_b64) )
    """
    if selectively_disclosable is None:
        selectively_disclosable = _SD_CLAIMS

    now = int(datetime.now(timezone.utc).timestamp())

    disclosures: list[str] = []
    sd_digests: list[str] = []

    for key in selectively_disclosable:
        if key in charter:
            salt = _b64url(os.urandom(16))
            disc_json = json.dumps([salt, key, charter[key]], separators=(",", ":"))
            disc_b64 = _b64url(disc_json.encode("utf-8"))
            digest = _b64url(hashlib.sha256(disc_b64.encode()).digest())
            disclosures.append(disc_b64)
            sd_digests.append(digest)

    payload: dict = {
        "iss": issuer_did,
        "sub": agent_did,
        "iat": now,
        # vct identifies the credential type — must be a URI per SD-JWT-VC spec
        "vct": f"{REGISTRY_BASE_URL}/credentials/AgentCharterCredential",
        "_sd_alg": "sha-256",
        "_sd": sorted(sd_digests),  # sorted for deterministic serialisation
    }

    if ttl_days > 0:
        payload["exp"] = now + ttl_days * 86400
    # Revocation reference.  SD-JWT-VC's native form is IETF token-status-list;
    # here we reference the same W3C Bitstring Status List the JSON-LD/JWT VCs use
    # so there is a single source of revocation truth.  (Full token-status-list
    # encoding is a follow-up — see README.)
    if credential_status is not None:
        payload["status"] = {"status_list": credential_status}
    if agent_public_key_jwk:
        payload["cnf"] = {"jwk": _clean_jwk(agent_public_key_jwk)}

    jwt_str = _make_jwt(payload, private_key, kid=verification_method, typ="vc+sd-jwt")
    # SD-JWT = <JWT>~<Disclosure>...~  (trailing ~ = holder has no KB-JWT yet)
    return "~".join([jwt_str] + disclosures) + "~"


# ── JWT VP (OID4VP presentation) ──────────────────────────────────────────────

def make_jwt_vp(
    holder_did: str,
    vc_jwt: str,
    holder_private_key: Ed25519PrivateKey,
    verification_method: str,
    audience: str,
    nonce: str,
) -> str:
    """
    Create an OID4VP-compatible JWT Verifiable Presentation (jwt+vp).

    Wraps a vc+jwt inside a VP JWT signed by the holder's own key.
    The verifier checks:
      1. The VP JWT signature (holder controls the DID)
      2. The VC-JWT signature inside (registry issued the charter)

    JWT claim mapping (per W3C VP Data Model §JWT + OID4VP §6):
      iss   ← holder DID
      aud   ← verifier's client_id / redirect_uri
      nonce ← challenge from the verifier's presentation request
      iat   ← current time
      vp    ← VP object containing the vc+jwt
    """
    now = int(datetime.now(timezone.utc).timestamp())
    payload: dict = {
        "iss": holder_did,
        "aud": audience,
        "nonce": nonce,
        "iat": now,
        "vp": {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [vc_jwt],
        },
    }
    return _make_jwt(payload, holder_private_key, kid=verification_method, typ="jwt+vp")


# ── Key Binding JWT (SD-JWT presentation) ─────────────────────────────────────

def make_key_binding_jwt(
    holder_private_key: Ed25519PrivateKey,
    verification_method: str,
    sd_jwt_without_kb: str,
    audience: str,
    nonce: str,
) -> str:
    """
    Create a Key Binding JWT (kb+jwt) to append to an SD-JWT-VC presentation.

    The KB-JWT proves the presenter controls the key in the credential's
    cnf.jwk claim.  The verifier checks:
      1. KB-JWT signature matches cnf.jwk in the SD-JWT
      2. nonce matches the verifier's challenge
      3. sd_hash covers the exact SD-JWT being presented

    Per SD-JWT spec §6.3.
    """
    # sd_hash = base64url(SHA-256(SD-JWT-without-KB))
    # The SD-JWT string passed here must NOT have a trailing KB-JWT
    sd_jwt_bytes = sd_jwt_without_kb.encode("ascii")
    sd_hash = _b64url(hashlib.sha256(sd_jwt_bytes).digest())

    now = int(datetime.now(timezone.utc).timestamp())
    payload: dict = {
        "aud": audience,
        "nonce": nonce,
        "iat": now,
        "sd_hash": sd_hash,
    }
    return _make_jwt(payload, holder_private_key, kid=verification_method, typ="kb+jwt")


def attach_key_binding(
    sd_jwt_with_disclosures: str,
    holder_private_key: Ed25519PrivateKey,
    verification_method: str,
    audience: str,
    nonce: str,
) -> str:
    """
    Take a stored SD-JWT-VC (trailing ~, no KB-JWT) and append a KB-JWT.

    Returns the presentation-ready string:
      <JWT>~<Disc1>~...~<KB-JWT>
    """
    # Strip the trailing empty element from the issuer's ~-terminated string
    sd_jwt_no_kb = sd_jwt_with_disclosures.rstrip("~")
    kb_jwt = make_key_binding_jwt(
        holder_private_key, verification_method, sd_jwt_no_kb + "~", audience, nonce
    )
    return sd_jwt_no_kb + "~" + kb_jwt
