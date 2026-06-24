# Agent Identity Registry

An **issuer**. It mints `did:web` identities for autonomous agents and issues
cryptographically signed charter Verifiable Credentials — without human signup
flows. Private keys never leave the agent.

That is the *whole* job. This repo issues; it does not consume. It makes no
authorization decisions, runs no policy engine, and drives no presentation
protocol. Read **[Scope & boundary](#scope--boundary)** before adding anything —
the pull to make it do more is structural, and the boundary is here to resist it.

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

| Method   | Path                          | Auth                     | Description                                  |
|----------|-------------------------------|--------------------------|----------------------------------------------|
| `GET`    | `/.well-known/did.json`       | none                     | Registry DID document (trust anchor)         |
| `GET`    | `/status/list`                | none                     | Bitstring Status List credential (revocation)|
| `POST`   | `/agents`                     | operator voucher         | Register agent → returns DID + charter VC    |
| `GET`    | `/agents/{id}/did.json`       | none                     | Agent DID document (did:web resolution)      |
| `GET`    | `/agents/{id}/charter`        | none                     | Agent charter as W3C VC                      |
| `POST`   | `/agents/{id}/rotate`         | agent self-proof         | Key rotation — updates DID doc + re-issues VC|
| `DELETE` | `/agents/{id}`                | operator voucher (revoke)| Revocation — DID doc returns tombstone       |

Interactive docs at `/docs` when the server is running.

### Enrollment auth — operator-signed vouchers

Identity bootstrapping can't authenticate itself: an agent holds no registry
identity at the moment it asks to be issued one. The registry terminates that
regress at an **operator-signed enrollment voucher** — a short-lived EdDSA JWT,
signed by a key the registry trusts out-of-band, that authorizes exactly one
`agent_id` and bounds the capabilities its charter may claim. The voucher is both
the authentication *and* the vetting: the registry clamps the submitted charter
to the grant, so it never signs capabilities the operator didn't authorize.

```bash
# Operator key, once. The registry trusts the public half (OPERATOR_JWKS_PATH).
python operator_cli.py keygen --out operator.key.pem
python operator_cli.py jwks  --key operator.key.pem --out operator_jwks.json

# Per agent: mint a voucher the agent carries to its own first-boot enrollment.
python operator_cli.py voucher \
    --key operator.key.pem \
    --registry-did did:web:cpricedomain.net \
    --agent-id napanode01 \
    --capabilities observe,publish \
    --ttl 3600
```

The agent presents it as `Authorization: Bearer <voucher>` (the client reads
`AGENT_ENROLLMENT_VOUCHER` automatically). Vouchers are single-use (`jti`),
audience-bound to the registry DID, and expire.

**The operating environment is not the identity.** An agent on a Raspberry Pi, in
k8s, or on any cloud enrolls the same way. The trusted-issuer set is pluggable —
a SPIFFE/SPIRE trust domain, a cloud workload-OIDC issuer, GitHub OIDC, or a TPM
attestation service can be added as additional trusted issuers without changing
the mint path. Where an agent runs can be carried as a *claim* in the charter; it
qualifies how the identity is used, it doesn't define the identity.

`POST /agents/{id}/rotate` is authenticated by the agent itself: the request
carries a proof over `{did, new_public_key_jwk}` signed with the key being
retired. Only the holder of the current private key can rotate — no voucher.

### Credential lifetime & revocation

Charters carry `validUntil` (`exp` in the JWT forms) bounded by `CHARTER_TTL_DAYS`.
Because `jwt_vc` / `sd_jwt_vc` are verified offline, revocation needs more than a
live `410`: the registry publishes a **W3C Bitstring Status List** credential at
`/status/list`, and every charter carries a `credentialStatus` pointing at its
bit. The bitstring is derived live from the agent table (bit set ⇔ revoked), so it
can't drift. An offline verifier fetches the list once and checks the bit.

> Note: `sd_jwt_vc` references the same Bitstring Status List via a `status` claim
> rather than the IETF token-status-list encoding — single source of revocation
> truth; native token-status-list is a follow-up.

> did:web caveat: domains with a port require `%3A` encoding per spec, which the
> registry does not yet apply (and the DID parsers assume an unported host). Use a
> plain custom domain (no port) — the normal production case.

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

| Variable                     | Default                   | Description                                      |
|------------------------------|---------------------------|--------------------------------------------------|
| `REGISTRY_DOMAIN`            | `cpricedomain.net`        | Domain used in minted DIDs                       |
| `REGISTRY_BASE_URL`         | `https://{REGISTRY_DOMAIN}` | Absolute base URL (used in `credentialStatus`) |
| `REGISTRY_KEY_PATH`         | `registry.key.pem`        | Path to the registry's Ed25519 private key       |
| `DATABASE_URL`              | `sqlite:///./registry.db` | SQLAlchemy database URL                          |
| `OPERATOR_JWKS_PATH`        | `operator_jwks.json`      | Trusted operator public keys for enrollment      |
| `REQUIRE_ENROLLMENT_VOUCHER`| `true`                    | Enforce vouchers on `POST /agents` / `DELETE`    |
| `CHARTER_TTL_DAYS`          | `90`                      | Charter lifetime; `0` = no expiry                |

> Pre-seed `registry.key.pem` into persistent storage before first boot rather
> than letting the app generate it on first request — it's the root of all trust,
> and auto-generation can race under multiple workers.

**Docker (example):**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -e .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Scope & boundary

This repo is the **issuance kernel**: charter out, operator voucher in,
pattern-agnostic. It is deliberately the *only* thing it is. The full reasoning —
why issuance is shared but consumption is not — lives in
**[docs/scope-and-boundaries.md](docs/scope-and-boundaries.md)**; the short version:

**Issuance is shared; consumption is pattern-specific.** Different agentic patterns
consume a charter in incompatible ways because their *trust topology* differs:

| | credential-model (e.g. Watershed) | policy-model (e.g. enterprise / PingOne) |
|---|---|---|
| Trust | peer-to-peer, decided by the consumer offline | centralized, decided by a PDP at the gate |
| Authority | travels with the credential | computed at the gate, per request |
| Verifier | a peer agent | an enterprise PDP (e.g. P1AZ + SpiceDB) |
| The charter is | a presented capability | a PIP attribute |

One issuer (this repo) can feed both. No single *consumption* design serves both —
so consumption does not belong here.

### This repo does NOT

- **Make authorization decisions.** No PDP, no policy, no allow/deny. It issues
  `can` + provenance; deciding `allowed` is the consumer's job.
- **Run a presentation protocol.** Not an OID4VP holder; it does not drive Neo
  presentation sessions (see [PingOne Neo / OID4VC compatibility](#pingone-neo--oid4vc-compatibility)).
- **Know about any consumer's substrate.** No SpiceDB, no ATProto, no Kong, no
  PIP, no token broker. **The moment this repo imports knowledge of SpiceDB or
  ATProto, the boundary is broken** — that coupling belongs in the consuming repo.
- **Issue OAuth tokens, manage sessions, or handle human login.** Not an IDP.
- **Custody keys or store agent data.** Private keys never reach the registry;
  it is not a PDS and serves no firehose.

### Consumption lives in consuming repos

Each verifier you own gets a thin adapter *in its own repo*:
- credential-model → present the charter, verify two signatures offline.
- policy-model → resolve the charter as an attribute into the PDP, intersect with
  the local grant + policy.

> Note: `registry_client.py`'s `present()` / `verify_presentation()` /
> `present_jwt()` / `present_sd_jwt()` are a **reference consumer** for the
> credential-model pattern, shipped for the demo and tests. They are consumption,
> not issuance — their canonical home is the consuming agent, and they may move
> out. Do not grow them here.

---

## PingOne Neo / OID4VC compatibility

The registry produces credentials in the right formats for Neo.  What it does
**not** do is drive the OID4VP presentation flow — that is the consumer's job.

### What this registry provides

| Format | Endpoint | Use |
|--------|----------|-----|
| `ldp_vc` | `GET /agents/{id}/charter` | Watershed / agent-to-agent trust |
| `jwt_vc` | `GET /agents/{id}/charter?format=jwt_vc` | OID4VC issuance to a wallet |
| `sd_jwt_vc` | `GET /agents/{id}/charter?format=sd_jwt_vc` | Selective disclosure presentation |

Both JWT formats include `cnf.jwk` binding the credential to the agent's public
key, which is what Neo's verifier checks during Key Binding JWT verification.

### What the OID4VP holder (consumer) must implement

Neo does not expose a "submit credential blob" endpoint.  Verification is
initiated by the verifier and the holder must respond to a presentation request:

```
1.  Verifier starts a session:
      POST /v1/environments/{envID}/presentationSessions
           protocol=OPENID4VP
    → returns request_uri / appOpenUrl

2.  Holder fetches the signed presentation request object from request_uri
    → contains nonce, aud (client_id), presentation_definition

3.  Holder selects matching credential (the sd_jwt_vc or jwt_vc from this registry)
    and constructs the response:

    For sd_jwt_vc:
      sd_jwt_presentation = present_sd_jwt(did, audience=aud, nonce=nonce)
      # <JWT>~<Disc1>~...~<KB-JWT>

    For jwt_vc:
      vp_jwt = present_jwt(did, audience=aud, nonce=nonce)
      # compact JWT VP containing the vc+jwt

4.  Holder POSTs the vp_token to the verifier's response_uri

5.  Verifier checks:
      - KB-JWT / VP-JWT signature against cnf.jwk in the credential
      - Credential signature against registry's DID document
      - nonce, aud, sd_hash (for SD-JWT)
      - presentation_definition constraints
```

`registry_client.present_jwt()` and `registry_client.present_sd_jwt()` produce
the correct `vp_token` strings for steps 3–4.  Everything else in the flow
(fetching `request_uri`, parsing `presentation_definition`, POSTing back) belongs
in the consuming agent.

### Separate consumer repo

The OID4VP holder logic — provisioning this registry, then answering a Neo
presentation request — is implemented in a separate repo so that the registry
stays focused on identity issuance rather than protocol orchestration.

---

## Consumers

This issuer is pattern-agnostic; each consumer adapts the charter in its own repo:

- **credential-model** — [Agentic-Watershed](https://github.com/cprice-ping/Agentic-Watershed):
  a subscriber verifies a presented charter offline (two signatures). See
  `HANDOFF-watershed-registry.md` in that repo.
- **policy-model** — an enterprise PDP (e.g. PingOne Authorize + SpiceDB) resolves
  the charter as an attribute and intersects it with the local grant. The PIP /
  policy wiring lives in the consuming repo, not here.

See **[docs/scope-and-boundaries.md](docs/scope-and-boundaries.md)** for why the
two consume differently and what stays out of this repo.
