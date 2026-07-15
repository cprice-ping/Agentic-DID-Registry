#!/usr/bin/env python3
"""
Provision Watershed node agents against a live Agent Identity Registry.

Bootstrap helper. It plays BOTH roles for convenience: the operator (mints
vouchers with operator.key.pem) and the agent (generates a keypair, enrolls,
stores the key + charter locally). In production these split — the operator mints
a voucher offline and hands it to the agent, which self-enrolls.

Identity model (see docs/thesis.md):
  agent_id     an opaque uuid4 — the immutable identifier, goes into the DID
  name         a friendly label — a charter claim, for humans, not the identity
  capabilities the standing ceiling the operator grants (clamped by the voucher)

Each agent gets ONE identity and ONE charter, reused across every service. A
second service does not mean a second charter.

Usage:
  export AGENT_REGISTRY_URL=https://registry.cpricedomain.net
  python provision_watershed.py \
      --operator-key operator.key.pem \
      --registry-did did:web:registry.cpricedomain.net \
      --only fire
"""
import argparse
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from operator_cli import _b64url, _load_key, _public_jwk
from registry_client import RegistryClient

# ── Agents on this node. Edit capabilities/scope/intent as needed. ────────────
NODE = "napa-node-01"

AGENTS = [
    {
        "name": "fire",
        "capabilities": ["observe", "publish"],
        "scope": f"{NODE} — wildfire and fire-risk monitoring",
        "intent": "Observe fire-risk signals and publish observations",
    },
    {
        "name": "weather",
        "capabilities": ["observe", "publish"],
        "scope": f"{NODE} — local weather monitoring",
        "intent": "Observe weather conditions and publish observations",
    },
    {
        "name": "river",
        "capabilities": ["observe", "publish"],
        "scope": f"{NODE} — river and watershed flow monitoring",
        "intent": "Observe river/watershed signals and publish observations",
    },
    {
        "name": "aqi",
        "capabilities": ["observe", "publish"],
        "scope": f"{NODE} — air quality (AQI) monitoring",
        "intent": "Observe air quality and publish observations",
    },
]


def mint_voucher(operator_key, registry_did, agent_id, capabilities, ttl=600):
    """Operator-signed enrollment voucher (EdDSA JWT). Bounds the charter."""
    jwk = _public_jwk(operator_key)
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "iss": "watershed-operator",
        "aud": registry_did,
        "sub": agent_id,
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
        "purpose": "enroll",
        "capabilities": capabilities,
    }
    header = {"alg": "EdDSA", "typ": "enrollment-voucher+jwt", "kid": jwk["kid"]}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64url(operator_key.sign(f"{h}.{p}".encode()))
    return f"{h}.{p}.{sig}"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--operator-key", default="operator.key.pem")
    ap.add_argument("--registry-did", required=True,
                    help="e.g. did:web:registry.cpricedomain.net")
    ap.add_argument("--registry-url", default=os.environ.get("AGENT_REGISTRY_URL"),
                    help="defaults to AGENT_REGISTRY_URL")
    ap.add_argument("--only", help="provision just this agent name (e.g. fire)")
    args = ap.parse_args()

    if not args.registry_url:
        raise SystemExit("Set --registry-url or AGENT_REGISTRY_URL.")

    operator_key = _load_key(Path(args.operator_key))
    rc = RegistryClient(registry_url=args.registry_url)

    agents = [a for a in AGENTS if not args.only or a["name"] == args.only]
    if not agents:
        raise SystemExit(f"No agent named {args.only!r} in the AGENTS list.")

    results = []
    for a in agents:
        agent_id = uuid.uuid4().hex  # opaque, immutable; becomes the DID path
        voucher = mint_voucher(operator_key, args.registry_did, agent_id, a["capabilities"])
        charter = {
            "agent_id": agent_id,
            "name": a["name"],
            "capabilities": a["capabilities"],
            "scope": a["scope"],
            "intent": a["intent"],
            "operator": args.registry_did,
        }
        try:
            did = rc.provision(charter, voucher=voucher)
        except Exception as exc:  # noqa: BLE001 — surface the failure per-agent
            print(f"  FAILED  {a['name']:>8}: {exc}")
            continue
        results.append((a["name"], did))
        print(f"  ok      {a['name']:>8}  →  {did}")

    if results:
        print("\nname → DID  (wire these into the publisher's agentDid):")
        for name, did in results:
            print(f"  {name:>8} : {did}")


if __name__ == "__main__":
    main()
