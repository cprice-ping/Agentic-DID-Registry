"""
Verifiable Credential issuance for agent charters.

VC format : W3C VC Data Model v2 (JSON-LD)
Proof     : Data Integrity Proof, eddsa-jcs-2022 (see app/crypto.py)
Issuer    : the registry (did:web:{domain})
Subject   : the agent (did:web:{domain}:agents:{id})
"""
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.crypto import sign_document


def build_charter_vc(
    agent_did: str,
    charter: dict,
    issuer_did: str,
) -> dict:
    """
    Assemble an unsigned W3C VC Data Model v2 charter credential.

    *charter* should contain the credential subject claims:
      name, capabilities, scope, intent, operator
    The 'id' claim is set to *agent_did* — callers must not include it.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Derive a stable VC id from the agent DID
    vc_id = f"{issuer_did}/credentials/{agent_did.split(':')[-1]}"
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://cpricedomain.net/contexts/agent-charter/v1",
        ],
        "id": vc_id,
        "type": ["VerifiableCredential", "AgentCharterCredential"],
        "issuer": issuer_did,
        "validFrom": now,
        "credentialSubject": {
            "id": agent_did,
            **charter,
        },
    }


def issue_charter_vc(
    agent_did: str,
    charter: dict,
    issuer_did: str,
    registry_private_key: Ed25519PrivateKey,
    verification_method: str,
) -> dict:
    """Build and cryptographically sign a charter VC."""
    unsigned = build_charter_vc(agent_did, charter, issuer_did)
    return sign_document(unsigned, registry_private_key, verification_method)
