from pydantic import BaseModel, Field


class AgentRegistrationRequest(BaseModel):
    agent_id: str = Field(
        ...,
        description="URL-safe slug, e.g. 'napanode01'. Used in the DID path.",
        pattern=r"^[a-z0-9][a-z0-9\-]{0,62}$",
    )
    public_key_jwk: dict = Field(
        ..., description="Agent's Ed25519 public key as a JWK (kty=OKP, crv=Ed25519)."
    )
    charter: dict = Field(
        ...,
        description=(
            "Charter claims for the VC credentialSubject. "
            "Expected keys: name, capabilities, scope, intent, operator."
        ),
    )


class AgentRegistrationResponse(BaseModel):
    did: str
    did_document: dict
    charter_vc: dict


class KeyRotationRequest(BaseModel):
    new_public_key_jwk: dict = Field(
        ..., description="Replacement Ed25519 public key as a JWK."
    )
    proof: dict = Field(
        ...,
        description=(
            "Data Integrity proof over {did, new_public_key_jwk}, signed with the "
            "agent's CURRENT private key. Proves possession of the key being "
            "rotated out — no operator voucher needed for self-rotation."
        ),
    )


class KeyRotationResponse(BaseModel):
    did: str
    did_document: dict
    charter_vc: dict
