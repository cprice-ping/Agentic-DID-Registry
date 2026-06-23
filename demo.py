#!/usr/bin/env python3
"""
End-to-end demo of the Agent Identity Registry DID/VC trust chain.

Independent of ATProto, Watershed, or any other consuming system.
Demonstrates exactly what the DID + Verifiable Credential model enables:

  Provision → Present → Verify

Two independent cryptographic checks at verification time:
  1. Holder signature on the VP  → proves the presenter controls the DID
  2. Registry signature on the VC → proves the charter was issued by a
     trusted registry, not self-asserted

Usage:
  # Make sure the registry is running locally first:
  #   uvicorn app.main:app --reload
  .venv/bin/python demo.py
"""
import json
import os
import sys
import time

REGISTRY_URL = os.environ.get("AGENT_REGISTRY_URL", "http://localhost:8000")


def _banner(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def _ok(msg: str) -> None:
    print(f"  ✓  {msg}")


def _info(msg: str) -> None:
    print(f"     {msg}")


def _json(obj: dict) -> None:
    for line in json.dumps(obj, indent=2).splitlines():
        print(f"     {line}")


def main() -> None:
    from registry_client import RegistryClient, verify_presentation

    r = RegistryClient(registry_url=REGISTRY_URL)

    # ── Step 1: Provision a fresh agent ──────────────────────────────────────
    _banner("Step 1 — Provision a new agent")

    # Use a timestamp suffix so re-runs don't collide
    agent_name = f"demo-agent-{int(time.time())}"
    charter = {
        "name": agent_name,
        "capabilities": ["observe", "publish"],
        "scope": "End-to-end DID/VC demo — no ATProto dependency",
        "intent": "Demonstrate the full trust chain: provision → present → verify",
        "operator": "did:web:cpricedomain.net",
    }

    print(f"\n  Provisioning agent '{agent_name}'...")
    print(f"  Registry: {REGISTRY_URL}")
    try:
        did = r.provision(charter)
    except Exception as exc:
        print(f"\n  ERROR: {exc}")
        print(
            "\n  Is the registry running?\n"
            "    uvicorn app.main:app --reload\n"
        )
        sys.exit(1)

    _ok(f"DID minted:  {did}")
    _info("Private key: ~/.agent/keys/<did>.pem  (never left this machine)")
    _info("Charter VC:  ~/.agent/charters/<did>.json")

    # ── Step 2: Show the signed charter VC ───────────────────────────────────
    _banner("Step 2 — Signed charter VC (issued by the registry)")

    vc = r._registry_url  # just to confirm URL; we'll fetch the VC via client
    from pathlib import Path
    import re
    slug = re.sub(r"[^a-zA-Z0-9_\-]", "_", did)
    charter_path = Path.home() / ".agent" / "charters" / f"{slug}.json"
    charter_vc = json.loads(charter_path.read_text())

    _info(f"Issuer:   {charter_vc['issuer']}")
    _info(f"Subject:  {charter_vc['credentialSubject']['id']}")
    _info(f"Claims:   capabilities={charter_vc['credentialSubject']['capabilities']}")
    _info(f"Proof:    cryptosuite={charter_vc['proof']['cryptosuite']}")
    _info(f"          verificationMethod={charter_vc['proof']['verificationMethod']}")
    print()
    _info("Full VC:")
    _json(charter_vc)

    # ── Step 3: Agent creates a Verifiable Presentation ──────────────────────
    _banner("Step 3 — Agent creates a Verifiable Presentation")
    print()
    _info("The agent wraps its charter VC in a VP and signs it with its own key.")
    _info("This proves the presenter is the DID controller, not just someone who")
    _info("found the VC lying around.")

    challenge = "demo-challenge-abc123"
    print(f"\n  Using challenge: {challenge!r}  (replay protection)")

    vp = r.present(did, challenge=challenge)
    _ok(f"VP created and signed by {did}#key-1")
    print()
    _info("Full VP:")
    _json(vp)

    # ── Step 4: Third-party verifier checks the VP ────────────────────────────
    _banner("Step 4 — Third-party verifier checks the VP")
    print()
    _info("A verifier (e.g. a Synthesis agent, an MCP AuthZ server) receives")
    _info("the VP and verifies it independently — no call back to an auth server,")
    _info("no session, no token issuance.")
    print()
    _info("Two checks performed:")
    _info("  1. Holder signature on the VP  → agent controls the DID")
    _info("  2. Registry signature on the VC → charter issued by trusted registry")

    result = verify_presentation(vp, registry_url=REGISTRY_URL, challenge=challenge)

    print()
    if result.holder_signature_valid:
        _ok(f"Holder signature VALID")
        _info(f"    → Presenter controls {result.holder_did}")
    else:
        print("  ✗  Holder signature INVALID")

    if result.charter_signature_valid:
        _ok(f"Registry signature VALID")
        _info(f"    → Charter was issued by {charter_vc['issuer']}")
    else:
        print("  ✗  Registry signature INVALID")

    if result.valid:
        print()
        _ok("Presentation VERIFIED")
        print()
        _info("Charter claims confirmed:")
        for k, v in (result.charter or {}).items():
            if k != "id":
                _info(f"    {k}: {v}")
    else:
        print(f"\n  ✗  Verification FAILED: {result.error}")
        sys.exit(1)

    # ── Step 5: Tamper test ───────────────────────────────────────────────────
    _banner("Step 5 — Tamper test (what happens if the VP is modified)")
    print()
    _info("Modify the VP holder field after signing — signature should fail.")

    tampered_vp = {**vp, "holder": "did:web:evil.example.com:agents:impostor"}
    tampered_result = verify_presentation(tampered_vp, registry_url=REGISTRY_URL)

    if not tampered_result.valid and not tampered_result.holder_signature_valid:
        _ok("Tampered VP correctly REJECTED")
        _info(f"    Error: {tampered_result.error}")
    else:
        print("  ✗  UNEXPECTED: tampered VP was accepted — this is a bug")
        sys.exit(1)

    # ── Summary ───────────────────────────────────────────────────────────────
    _banner("Summary")
    print()
    print("  Trust established without:")
    print("    •  A central authority decision at verification time")
    print("    •  Any human login, consent, or session")
    print("    •  Any token issuance or expiry management")
    print("    •  Any runtime call back to an auth server")
    print()
    print("  What made it work:")
    print(f"    •  The registry ({charter_vc['issuer']}) signed the charter at issuance")
    print(f"    •  The agent ({did}) signed the presentation with its own key")
    print("    •  Both signatures are verifiable against public DID documents")
    print("    •  The DID chain is the trust chain")
    print()


if __name__ == "__main__":
    main()
