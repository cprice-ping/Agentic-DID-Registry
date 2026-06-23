"""
DID document construction for did:web identities.

Resolution mapping (did:web spec):
  did:web:example.com                → https://example.com/.well-known/did.json
  did:web:example.com:agents:node01  → https://example.com/agents/node01/did.json
"""
from urllib.parse import unquote


def make_registry_did(domain: str) -> str:
    return f"did:web:{domain}"


def make_agent_did(domain: str, agent_id: str) -> str:
    return f"did:web:{domain}:agents:{agent_id}"


def did_to_url(did: str) -> str:
    """Convert a did:web identifier to its HTTPS resolution URL."""
    remainder = did[len("did:web:"):]
    parts = remainder.split(":")
    host = unquote(parts[0])
    if len(parts) == 1:
        return f"https://{host}/.well-known/did.json"
    path = "/".join(parts[1:])
    return f"https://{host}/{path}/did.json"


def make_registry_did_document(did: str, public_key_jwk: dict) -> dict:
    """DID document for the registry itself (served at /.well-known/did.json)."""
    key_id = f"{did}#key-1"
    # Strip kid — it's implicit from the fragment
    jwk = {k: v for k, v in public_key_jwk.items() if k != "kid"}
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }


def make_agent_did_document(
    did: str,
    public_key_jwk: dict,
    controller_did: str,
) -> dict:
    """DID document for an agent (served at /agents/{id}/did.json)."""
    key_id = f"{did}#key-1"
    jwk = {k: v for k, v in public_key_jwk.items() if k != "kid"}
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "controller": controller_did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }


def make_tombstone(did: str) -> dict:
    """
    Revocation tombstone — returned when a DID document is requested for a
    revoked agent.  Per did:web spec, the document still resolves but signals
    deactivation via the 'deactivated' property.
    """
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "deactivated": True,
    }
