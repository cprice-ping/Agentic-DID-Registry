"""
Agent Identity Registry — FastAPI application.

Endpoints
---------
GET  /.well-known/did.json          Registry DID document (did:web resolution)
POST /agents                        Register an agent
GET  /agents/{agent_id}/did.json    Agent DID document (did:web resolution)
GET  /agents/{agent_id}/charter     Agent charter as a signed W3C VC
POST /agents/{agent_id}/rotate      Key rotation
DELETE /agents/{agent_id}           Revocation
"""
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from sqlmodel import Session, select

from app.config import REGISTRY_DOMAIN, REGISTRY_KEY_PATH
from app.crypto import load_or_create_private_key, public_key_to_jwk
from app.database import create_db_and_tables, get_session
from app.did import (
    make_agent_did,
    make_agent_did_document,
    make_registry_did,
    make_registry_did_document,
    make_tombstone,
)
from app.models import Agent
from app.schemas import (
    AgentRegistrationRequest,
    AgentRegistrationResponse,
    KeyRotationRequest,
    KeyRotationResponse,
)
from app.vc import issue_charter_vc

# ── Registry singleton state (initialised at startup) ────────────────────────

_registry_private_key = None
_registry_did: str = ""
_registry_public_key_jwk: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _registry_private_key, _registry_did, _registry_public_key_jwk

    create_db_and_tables()
    _registry_private_key = load_or_create_private_key(REGISTRY_KEY_PATH)
    _registry_did = make_registry_did(REGISTRY_DOMAIN)
    _registry_public_key_jwk = public_key_to_jwk(
        _registry_private_key.public_key(), key_id="key-1"
    )
    yield


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Agent Identity Registry",
    description=(
        "Mints and manages did:web identities for autonomous agents. "
        "Issues W3C Verifiable Credential charters. "
        "Private keys never leave the agent."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

SessionDep = Annotated[Session, Depends(get_session)]


# ── Registry DID document ────────────────────────────────────────────────────

@app.get(
    "/.well-known/did.json",
    response_class=Response,
    summary="Registry DID document",
    tags=["Registry"],
)
def get_registry_did_document() -> Response:
    """Serve the registry's own DID document — the trust anchor for all agent charters."""
    doc = make_registry_did_document(_registry_did, _registry_public_key_jwk)
    return Response(content=json.dumps(doc, indent=2), media_type="application/json")


# ── Agent registration ────────────────────────────────────────────────────────

@app.post(
    "/agents",
    response_model=AgentRegistrationResponse,
    status_code=201,
    summary="Register a new agent",
    tags=["Agents"],
)
def register_agent(req: AgentRegistrationRequest, session: SessionDep) -> AgentRegistrationResponse:
    """
    Register an agent's public key and charter with the registry.

    The agent generates its own keypair locally and submits only the **public** key.
    The registry:
    1. Mints a did:web DID for the agent
    2. Issues a signed charter VC (W3C VC Data Model v2)
    3. Returns the DID, DID document, and charter VC

    Private keys never reach the registry.
    """
    existing = session.exec(select(Agent).where(Agent.agent_id == req.agent_id)).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Agent '{req.agent_id}' is already registered.",
        )

    agent_did = make_agent_did(REGISTRY_DOMAIN, req.agent_id)
    verification_method = f"{_registry_did}#key-1"

    charter_vc = issue_charter_vc(
        agent_did=agent_did,
        charter=req.charter,
        issuer_did=_registry_did,
        registry_private_key=_registry_private_key,
        verification_method=verification_method,
    )
    did_doc = make_agent_did_document(
        agent_did, req.public_key_jwk, controller_did=_registry_did
    )

    agent = Agent(
        agent_id=req.agent_id,
        did=agent_did,
        public_key_jwk=json.dumps(req.public_key_jwk),
        charter_vc=json.dumps(charter_vc),
    )
    session.add(agent)
    session.commit()

    return AgentRegistrationResponse(
        did=agent_did,
        did_document=did_doc,
        charter_vc=charter_vc,
    )


# ── DID document resolution ───────────────────────────────────────────────────

@app.get(
    "/agents/{agent_id}/did.json",
    response_class=Response,
    summary="Agent DID document",
    tags=["Agents"],
)
def get_agent_did_document(agent_id: str, session: SessionDep) -> Response:
    """
    Serve the agent's DID document — the did:web resolution endpoint.

    Returns a tombstone (deactivated=true) for revoked agents so that resolvers
    receive a valid but deactivated document rather than a 404.
    """
    agent = session.exec(select(Agent).where(Agent.agent_id == agent_id)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    if agent.revoked_at:
        doc = make_tombstone(agent.did)
    else:
        doc = make_agent_did_document(
            agent.did, agent.get_public_key_jwk(), controller_did=_registry_did
        )

    return Response(content=json.dumps(doc, indent=2), media_type="application/json")


# ── Charter retrieval ─────────────────────────────────────────────────────────

@app.get(
    "/agents/{agent_id}/charter",
    response_class=Response,
    summary="Agent charter VC",
    tags=["Agents"],
)
def get_agent_charter(
    agent_id: str,
    session: SessionDep,
    format: Literal["ldp_vc", "jwt_vc", "sd_jwt_vc"] = Query(
        default="ldp_vc",
        description=(
            "ldp_vc   — JSON-LD with Data Integrity Proof (default)\n"
            "jwt_vc   — W3C VC Data Model v2, JWT-secured (vc+jwt)\n"
            "sd_jwt_vc — SD-JWT-VC with selective disclosure (vc+sd-jwt)"
        ),
    ),
) -> Response:
    """
    Return the agent's signed charter credential.

    Use **?format=jwt_vc** or **?format=sd_jwt_vc** for Neo / OID4VC flows.
    The default (ldp_vc) is the JSON-LD + Data Integrity Proof form used by
    the registry's own verify / present pipeline.
    """
    agent = session.exec(select(Agent).where(Agent.agent_id == agent_id)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    if agent.revoked_at:
        raise HTTPException(status_code=410, detail="Agent has been revoked.")

    if format == "ldp_vc":
        return Response(content=agent.charter_vc, media_type="application/json")

    # Extract charter claims from the stored ldp_vc for re-issuance
    stored_vc = agent.get_charter_vc()
    charter = {
        k: v
        for k, v in stored_vc.get("credentialSubject", {}).items()
        if k != "id"
    }
    verification_method = f"{_registry_did}#key-1"

    if format == "jwt_vc":
        from app.jwt_vc import issue_vc_jwt
        jwt_str = issue_vc_jwt(
            agent_did=agent.did,
            charter=charter,
            issuer_did=_registry_did,
            private_key=_registry_private_key,
            verification_method=verification_method,
            agent_public_key_jwk=agent.get_public_key_jwk(),
        )
        return Response(content=jwt_str, media_type="application/vc+jwt")

    # format == "sd_jwt_vc"
    from app.jwt_vc import issue_sd_jwt_vc
    sd_jwt_str = issue_sd_jwt_vc(
        agent_did=agent.did,
        charter=charter,
        issuer_did=_registry_did,
        private_key=_registry_private_key,
        verification_method=verification_method,
        agent_public_key_jwk=agent.get_public_key_jwk(),
    )
    return Response(content=sd_jwt_str, media_type="application/vc+sd-jwt")


# ── Key rotation ──────────────────────────────────────────────────────────────

@app.post(
    "/agents/{agent_id}/rotate",
    response_model=KeyRotationResponse,
    summary="Rotate agent key",
    tags=["Agents"],
)
def rotate_agent_key(
    agent_id: str, req: KeyRotationRequest, session: SessionDep
) -> KeyRotationResponse:
    """
    Replace the agent's public key and re-issue a fresh charter VC signed against
    the new key binding.  The DID and charter claims are preserved; only the key
    and VC issuance timestamp change.
    """
    agent = session.exec(select(Agent).where(Agent.agent_id == agent_id)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    if agent.revoked_at:
        raise HTTPException(status_code=410, detail="Agent has been revoked.")

    # Preserve existing charter claims, re-issue with the same subject
    old_vc = agent.get_charter_vc()
    charter = {
        k: v
        for k, v in old_vc.get("credentialSubject", {}).items()
        if k != "id"
    }

    verification_method = f"{_registry_did}#key-1"
    new_charter_vc = issue_charter_vc(
        agent_did=agent.did,
        charter=charter,
        issuer_did=_registry_did,
        registry_private_key=_registry_private_key,
        verification_method=verification_method,
    )

    agent.public_key_jwk = json.dumps(req.new_public_key_jwk)
    agent.charter_vc = json.dumps(new_charter_vc)
    session.add(agent)
    session.commit()

    did_doc = make_agent_did_document(
        agent.did, req.new_public_key_jwk, controller_did=_registry_did
    )
    return KeyRotationResponse(
        did=agent.did,
        did_document=did_doc,
        charter_vc=new_charter_vc,
    )


# ── Revocation ────────────────────────────────────────────────────────────────

@app.delete(
    "/agents/{agent_id}",
    summary="Revoke an agent",
    tags=["Agents"],
)
def revoke_agent(agent_id: str, session: SessionDep) -> dict:
    """
    Revoke an agent.  The DID document endpoint will subsequently return a
    tombstone; the charter endpoint will return 410 Gone.
    """
    agent = session.exec(select(Agent).where(Agent.agent_id == agent_id)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    if agent.revoked_at:
        raise HTTPException(status_code=410, detail="Agent is already revoked.")

    agent.revoked_at = datetime.now(timezone.utc)
    session.add(agent)
    session.commit()

    return make_tombstone(agent.did)
