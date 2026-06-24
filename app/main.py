"""
Agent Identity Registry — FastAPI application.

Endpoints
---------
GET  /.well-known/did.json          Registry DID document (did:web resolution)
POST /agents                        Register an agent (operator voucher required)
GET  /agents/{agent_id}/did.json    Agent DID document (did:web resolution)
GET  /agents/{agent_id}/charter     Agent charter as a signed W3C VC
POST /agents/{agent_id}/rotate      Key rotation (agent self-proof)
DELETE /agents/{agent_id}           Revocation (operator voucher required)
GET  /status/list                   Bitstring Status List credential (revocation)

Auth model
----------
Enrollment can't authenticate itself, so the registry trusts an out-of-band
**operator-signed voucher** (see app/voucher.py) on POST /agents and DELETE.
The voucher pins the agent_id and bounds the capabilities the charter may claim —
it is both the authentication and the vetting.  Key rotation is authenticated by
the agent itself, with a proof-of-possession signed by the key being retired.
"""
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from sqlmodel import Session, select

from app.config import (
    CHARTER_TTL_DAYS,
    OPERATOR_JWKS_PATH,
    REGISTRY_BASE_URL,
    REGISTRY_DOMAIN,
    REGISTRY_KEY_PATH,
    REQUIRE_ENROLLMENT_VOUCHER,
)
from app.crypto import (
    load_or_create_private_key,
    public_key_to_jwk,
    sign_document,
    verify_document_proof,
)
from app.database import create_db_and_tables, get_session
from app.did import (
    make_agent_did,
    make_agent_did_document,
    make_registry_did,
    make_registry_did_document,
    make_tombstone,
)
from app.models import Agent, ConsumedVoucher
from app.schemas import (
    AgentRegistrationRequest,
    AgentRegistrationResponse,
    KeyRotationRequest,
    KeyRotationResponse,
)
from app.status_list import (
    build_encoded_list,
    credential_status_entry,
    status_list_credential,
)
from app.vc import issue_charter_vc
from app.voucher import VoucherError, VoucherGrant, load_operator_keys, verify_voucher

# ── Registry singleton state (initialised at startup) ────────────────────────

_registry_private_key = None
_registry_did: str = ""
_registry_public_key_jwk: dict = {}
_operator_keys: dict = {}

STATUS_LIST_URL = f"{REGISTRY_BASE_URL}/status/list"


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _registry_private_key, _registry_did, _registry_public_key_jwk, _operator_keys

    create_db_and_tables()
    _registry_private_key = load_or_create_private_key(REGISTRY_KEY_PATH)
    _registry_did = make_registry_did(REGISTRY_DOMAIN)
    _registry_public_key_jwk = public_key_to_jwk(
        _registry_private_key.public_key(), key_id="key-1"
    )
    _operator_keys = load_operator_keys(OPERATOR_JWKS_PATH)
    yield


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Agent Identity Registry",
    description=(
        "Mints and manages did:web identities for autonomous agents. "
        "Issues W3C Verifiable Credential charters. "
        "Private keys never leave the agent."
    ),
    version="0.2.0",
    lifespan=lifespan,
)

SessionDep = Annotated[Session, Depends(get_session)]


# ── Enrollment auth helpers ───────────────────────────────────────────────────

def _bearer_voucher(authorization: Optional[str]) -> str:
    """Extract the voucher from an Authorization: Bearer header."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing enrollment voucher. Send 'Authorization: Bearer <voucher>'.",
        )
    return authorization[7:].strip()


def _verify_grant(
    authorization: Optional[str],
    expected_agent_id: str,
    expected_purpose: str,
    session: Session,
) -> Optional[VoucherGrant]:
    """
    Verify an operator voucher for *expected_agent_id* and *expected_purpose*.

    Returns the grant, or None when voucher checks are disabled for local dev.
    Raises HTTPException(401/403/409) on any failure.
    """
    if not REQUIRE_ENROLLMENT_VOUCHER:
        return None

    token = _bearer_voucher(authorization)
    try:
        grant = verify_voucher(token, _operator_keys, expected_audience=_registry_did)
    except VoucherError as exc:
        raise HTTPException(status_code=403, detail=f"Voucher rejected: {exc}")

    if grant.agent_id != expected_agent_id:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Voucher authorizes agent_id {grant.agent_id!r}, "
                f"not {expected_agent_id!r}."
            ),
        )
    if grant.purpose != expected_purpose:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Voucher purpose is {grant.purpose!r}, expected {expected_purpose!r}."
            ),
        )
    if session.get(ConsumedVoucher, grant.jti):
        raise HTTPException(status_code=409, detail="Voucher has already been used.")
    return grant


def _consume(grant: Optional[VoucherGrant], session: Session) -> None:
    if grant is not None:
        session.add(ConsumedVoucher(jti=grant.jti, agent_id=grant.agent_id))


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


# ── Bitstring Status List ─────────────────────────────────────────────────────

@app.get(
    "/status/list",
    response_class=Response,
    summary="Bitstring Status List credential",
    tags=["Registry"],
)
def get_status_list(session: SessionDep) -> Response:
    """
    Serve the signed Bitstring Status List credential.

    The bitstring is derived live from the Agent table (bit set ⇔ revoked) so it
    can never drift from the source of truth.  Offline verifiers of jwt_vc /
    sd_jwt_vc charters check their bit here to learn revocation status.
    """
    revoked = session.exec(
        select(Agent.status_index).where(Agent.revoked_at.is_not(None))
    ).all()
    encoded = build_encoded_list([i for i in revoked if i is not None])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    unsigned = status_list_credential(
        issuer_did=_registry_did,
        list_url=STATUS_LIST_URL,
        encoded_list=encoded,
        valid_from=now,
    )
    signed = sign_document(
        unsigned, _registry_private_key, f"{_registry_did}#key-1"
    )
    return Response(content=json.dumps(signed, indent=2), media_type="application/json")


# ── Agent registration ────────────────────────────────────────────────────────

@app.post(
    "/agents",
    response_model=AgentRegistrationResponse,
    status_code=201,
    summary="Register a new agent",
    tags=["Agents"],
)
def register_agent(
    req: AgentRegistrationRequest,
    session: SessionDep,
    authorization: Annotated[Optional[str], Header()] = None,
) -> AgentRegistrationResponse:
    """
    Register an agent's public key and charter with the registry.

    Requires an operator-signed enrollment voucher (Authorization: Bearer).  The
    voucher pins the agent_id and bounds the capabilities — the registry clamps
    the submitted charter to the grant, so it never signs claims the operator did
    not authorize.

    The agent generates its own keypair locally and submits only the **public** key.
    Private keys never reach the registry.
    """
    grant = _verify_grant(authorization, req.agent_id, "enroll", session)

    existing = session.exec(select(Agent).where(Agent.agent_id == req.agent_id)).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Agent '{req.agent_id}' is already registered.",
        )

    charter = dict(req.charter)
    # ── Clamp the charter to the voucher grant ────────────────────────────────
    if grant is not None:
        requested_caps = charter.get("capabilities", []) or []
        if grant.capabilities is not None:
            allowed = set(grant.capabilities)
            extra = [c for c in requested_caps if c not in allowed]
            if extra:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Charter requests capabilities {extra} not authorized by "
                        f"the voucher (allowed: {sorted(allowed)})."
                    ),
                )
        if grant.operator is not None:
            charter["operator"] = grant.operator

    agent_did = make_agent_did(REGISTRY_DOMAIN, req.agent_id)
    verification_method = f"{_registry_did}#key-1"

    # Insert first to obtain the status-list index (the row id), then issue the
    # charter carrying that index, then persist the charter.
    agent = Agent(
        agent_id=req.agent_id,
        did=agent_did,
        public_key_jwk=json.dumps(req.public_key_jwk),
        charter_vc="",
    )
    session.add(agent)
    session.flush()  # assigns agent.id
    agent.status_index = agent.id

    credential_status = credential_status_entry(STATUS_LIST_URL, agent.status_index)
    charter_vc = issue_charter_vc(
        agent_did=agent_did,
        charter=charter,
        issuer_did=_registry_did,
        registry_private_key=_registry_private_key,
        verification_method=verification_method,
        ttl_days=CHARTER_TTL_DAYS,
        credential_status=credential_status,
    )
    agent.charter_vc = json.dumps(charter_vc)
    session.add(agent)

    did_doc = make_agent_did_document(
        agent_did, req.public_key_jwk, controller_did=_registry_did
    )

    _consume(grant, session)
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
    credential_status = (
        credential_status_entry(STATUS_LIST_URL, agent.status_index)
        if agent.status_index is not None
        else None
    )

    if format == "jwt_vc":
        from app.jwt_vc import issue_vc_jwt
        jwt_str = issue_vc_jwt(
            agent_did=agent.did,
            charter=charter,
            issuer_did=_registry_did,
            private_key=_registry_private_key,
            verification_method=verification_method,
            agent_public_key_jwk=agent.get_public_key_jwk(),
            ttl_days=CHARTER_TTL_DAYS,
            credential_status=credential_status,
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
        ttl_days=CHARTER_TTL_DAYS,
        credential_status=credential_status,
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
    Replace the agent's public key and re-issue a fresh charter VC.

    Authenticated by the agent itself: the request carries a proof over
    {did, new_public_key_jwk} signed with the key being retired.  Only the holder
    of the current private key can rotate — no operator voucher required.
    """
    agent = session.exec(select(Agent).where(Agent.agent_id == agent_id)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    if agent.revoked_at:
        raise HTTPException(status_code=410, detail="Agent has been revoked.")

    # ── Proof of possession of the CURRENT key ────────────────────────────────
    signed_doc = {
        "did": agent.did,
        "new_public_key_jwk": req.new_public_key_jwk,
        "proof": req.proof,
    }
    if not verify_document_proof(signed_doc, agent.get_public_key_jwk()):
        raise HTTPException(
            status_code=403,
            detail="Rotation proof is invalid — must be signed by the current key.",
        )

    # Preserve existing charter claims, re-issue with the same subject
    old_vc = agent.get_charter_vc()
    charter = {
        k: v
        for k, v in old_vc.get("credentialSubject", {}).items()
        if k != "id"
    }

    verification_method = f"{_registry_did}#key-1"
    credential_status = (
        credential_status_entry(STATUS_LIST_URL, agent.status_index)
        if agent.status_index is not None
        else None
    )
    new_charter_vc = issue_charter_vc(
        agent_did=agent.did,
        charter=charter,
        issuer_did=_registry_did,
        registry_private_key=_registry_private_key,
        verification_method=verification_method,
        ttl_days=CHARTER_TTL_DAYS,
        credential_status=credential_status,
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
def revoke_agent(
    agent_id: str,
    session: SessionDep,
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict:
    """
    Revoke an agent.  Requires an operator voucher with purpose="revoke" for the
    target agent_id.  Afterwards the DID document returns a tombstone, the charter
    endpoint returns 410, and the agent's bit is set in the Status List.
    """
    agent = session.exec(select(Agent).where(Agent.agent_id == agent_id)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    if agent.revoked_at:
        raise HTTPException(status_code=410, detail="Agent is already revoked.")

    grant = _verify_grant(authorization, agent_id, "revoke", session)

    agent.revoked_at = datetime.now(timezone.utc)
    session.add(agent)
    _consume(grant, session)
    session.commit()

    return make_tombstone(agent.did)
