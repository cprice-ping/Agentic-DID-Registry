# Agent Identity Registry

A lightweight service that mints and manages `did:web` identities for autonomous
agents — without human signup flows.

The registry acts as a **trust anchor**, not an IDP.  It issues birthright DIDs and
cryptographically signed charter Verifiable Credentials.  Private keys never leave
the agent.

---

## Architecture

```
Agent machine                          Registry (this service)
─────────────                          ───────────────────────
generate keypair locally
  │
  │  POST /agents  (public key + charter claims)
  ├─────────────────────────────────────────────►
  │                                              mint did:web DID
  │                                              issue signed charter VC
  │  ◄── { did, did_document, charter_vc } ──────
  │
store private key  ~/.agent/keys/{did}.pem
store charter VC   ~/.agent/charters/{did}.json
```

### DID document format

Standard W3C DID document served at the `did:web` resolution URL:

```
did:web:cpricedomain.net:agents:napanode01
  → https://cpricedomain.net/agents/napanode01/did.json
```

### Charter = Verifiable Credential

The charter is a W3C VC Data Model v2 credential, signed by the registry:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://cpricedomain.net/contexts/agent-charter/v1"
  ],
  "type": ["VerifiableCredential", "AgentCharterCredential"],
  "issuer": "did:web:cpricedomain.net",
  "credentialSubject": {
    "id": "did:web:cpricedomain.net:agents:napanode01",
    "name": "napa-node-01",
    "capabilities": ["observe", "publish"],
    "scope": "Napa Valley environmental monitoring",
    "intent": "Collect domain sensor data, reason locally, publish observations",
    "operator": "did:web:cpricedomain.net"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    ...
  }
}
```

### No wallet required

Agents handle their own keys.  The wallet layer is unnecessary:

- **Issuance** — registry issues the signed VC; agent stores it as a local file
- **Presentation** — agent wraps the VC in a Verifiable Presentation, signed with its own key
- **Verification** — any verifier checks two signatures against DID documents (no round-trip)

---

## API

| Method   | Path                          | Description                                  |
|----------|-------------------------------|----------------------------------------------|
| `GET`    | `/.well-known/did.json`       | Registry DID document (trust anchor)         |
| `POST`   | `/agents`                     | Register agent → returns DID + charter VC    |
| `GET`    | `/agents/{id}/did.json`       | Agent DID document (did:web resolution)      |
| `GET`    | `/agents/{id}/charter`        | Agent charter as W3C VC                      |
| `POST`   | `/agents/{id}/rotate`         | Key rotation — updates DID doc + re-issues VC|
| `DELETE` | `/agents/{id}`                | Revocation — DID doc returns tombstone       |

Interactive docs at `/docs` when the server is running.

---

## Stack

- **Python 3.11+**, FastAPI, Uvicorn
- **SQLite** via SQLModel (swap to Postgres by changing `DATABASE_URL`)
- **Ed25519** keys via the `cryptography` library
- **Data Integrity Proof** (`eddsa-jcs-2022`) for VC signing

---

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env
# Edit .env — set REGISTRY_DOMAIN to your domain
```

### Run

```bash
uvicorn app.main:app --reload
```

The registry generates its own Ed25519 keypair on first startup and saves it to
`REGISTRY_KEY_PATH` (default `registry.key.pem`).  Keep this file safe — it's the
signing key for all charter VCs.

### Test

```bash
pytest -v
```

---

## Client library

`registry_client.py` is the integration point for consuming projects.  Copy it
into the consuming repo (or install this package).

```python
from registry_client import registry          # module-level instance, reads AGENT_REGISTRY_URL

# ── One-time at agent setup ──────────────────────────────────────────────────
did = registry.provision({
    "name": "napa-node-01",
    "capabilities": ["observe", "publish"],
    "scope": "Napa Valley environmental monitoring — watershed, weather, AQI",
    "intent": "Collect domain sensor data, reason locally, publish observations",
    "operator": "did:web:cpricedomain.net",
})
# did:web:cpricedomain.net:agents:napanode01

# ── At publish time ──────────────────────────────────────────────────────────
signed_record = registry.sign(record, did=NODE_DID)

# ── At subscribe time (replaces TRUSTED_PUBLISHERS dict) ────────────────────
charter = registry.verify(publisher_did)       # cached with 5-min TTL
if not charter or "observe" not in charter.get("capabilities", []):
    return  # reject
```

Private keys are stored at `~/.agent/keys/{did}.pem` (mode 0600).
Charter VCs are stored at `~/.agent/charters/{did}.json`.

---

## Deployment

The registry must be reachable at its domain for `did:web` resolution to work.
Any HTTPS-capable host works.

**Environment variables:**

| Variable             | Default              | Description                              |
|----------------------|----------------------|------------------------------------------|
| `REGISTRY_DOMAIN`    | `cpricedomain.net`   | Domain used in minted DIDs               |
| `REGISTRY_KEY_PATH`  | `registry.key.pem`   | Path to the registry's Ed25519 private key |
| `DATABASE_URL`       | `sqlite:///./registry.db` | SQLAlchemy database URL             |

**Docker (example):**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -e .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## What this is NOT

- Not an IDP — does not issue tokens, manage sessions, or handle human login
- Not a PDS — does not store ATProto records or serve a firehose
- Not a key custodian — private keys never reach the registry

---

## First consumer

[Agentic-Watershed](https://github.com/cprice-ping/Agentic-Watershed) —
see `HANDOFF-watershed-registry.md` in that repo for the integration spec.
