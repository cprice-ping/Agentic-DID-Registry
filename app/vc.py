"""
Verifiable Credential issuance for agent charters.

VC format : W3C VC Data Model v2 (JSON-LD)
Proof     : Data Integrity Proof, eddsa-jcs-2022 (see app/crypto.py)
Issuer    : the registry (did:web:{domain})
Subject   : the agent (did:web:{domain}:agents:{id})
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.crypto import sign_document


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_charter_vc(
    agent_did: str,
    charter: dict,
    issuer_did: str,
    ttl_days: int = 0,
    credential_status: Optional[dict] = None,
) -> dict:
    """
    Assemble an unsigned W3C VC Data Model v2 charter credential.

    *charter* should contain the credential subject claims:
      name, capabilities, scope, intent, operator
    The 'id' claim is set to *agent_did* — callers must not include it.

    *ttl_days* > 0 adds a ``validUntil`` so the credential expires.
    *credential_status* attaches a Bitstring Status List entry for revocation.
    """
    now = datetime.now(timezone.utc)
    # Derive a stable VC id from the agent DID
    vc_id = f"{issuer_did}/credentials/{agent_did.split(':')[-1]}"
    vc: dict = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://cpricedomain.net/contexts/agent-charter/v1",
        ],
        "id": vc_id,
        "type": ["VerifiableCredential", "AgentCharterCredential"],
        "issuer": issuer_did,
        "validFrom": _iso(now),
        "credentialSubject": {
            "id": agent_did,
            **charter,
        },
    }
    if ttl_days > 0:
        vc["validUntil"] = _iso(now + timedelta(days=ttl_days))
    if credential_status is not None:
        vc["credentialStatus"] = credential_status
    return vc


def issue_charter_vc(
    agent_did: str,
    charter: dict,
    issuer_did: str,
    registry_private_key: Ed25519PrivateKey,
    verification_method: str,
    ttl_days: int = 0,
    credential_status: Optional[dict] = None,
) -> dict:
    """Build and cryptographically sign a charter VC."""
    unsigned = build_charter_vc(
        agent_did, charter, issuer_did, ttl_days, credential_status
    )
    return sign_document(unsigned, registry_private_key, verification_method)
