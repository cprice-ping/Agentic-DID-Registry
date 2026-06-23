import json
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Column, Field, SQLModel, Text


class Agent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    # URL-safe slug used in the DID path, e.g. "napanode01"
    agent_id: str = Field(unique=True, index=True)

    # Full did:web identifier, e.g. "did:web:cpricedomain.net:agents:napanode01"
    did: str = Field(unique=True, index=True)

    # Agent's public key, stored as JSON-serialised JWK
    public_key_jwk: str = Field(sa_column=Column(Text))

    # Signed W3C charter VC, stored as JSON string
    charter_vc: str = Field(sa_column=Column(Text))

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    revoked_at: Optional[datetime] = Field(default=None)

    # ── Convenience deserialisers ────────────────────────────────────────────

    def get_public_key_jwk(self) -> dict:
        return json.loads(self.public_key_jwk)

    def get_charter_vc(self) -> dict:
        return json.loads(self.charter_vc)
