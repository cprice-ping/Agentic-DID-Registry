#!/usr/bin/env python3
"""
Operator CLI — the out-of-band root of the enrollment chain.

An operator holds an Ed25519 keypair provisioned once, out-of-band.  The registry
is configured to trust the operator's *public* key (via OPERATOR_JWKS_PATH); the
operator signs short-lived enrollment vouchers that authorize a single agent to
self-enroll and bound the capabilities its charter may claim.

This is deliberately platform-neutral: the same operator key vouches for an agent
whether it runs on a Raspberry Pi, in Kubernetes, or on any cloud.  Where the
agent runs is a *claim*, not the identity — pass it via --operator or extra
charter claims if you want it bound, but it is never required.

Usage
-----
  # 1. Create an operator keypair (once)
  python operator_cli.py keygen --out operator.key.pem

  # 2. Export the public JWKS the registry trusts (point OPERATOR_JWKS_PATH here)
  python operator_cli.py jwks --key operator.key.pem --out operator_jwks.json

  # 3. Sign an enrollment voucher for an agent
  python operator_cli.py voucher \
      --key operator.key.pem \
      --registry-did did:web:registry.example.com \
      --agent-id napanode01 \
      --capabilities observe,publish \
      --ttl 3600

  # Sign a revocation voucher
  python operator_cli.py voucher \
      --key operator.key.pem --registry-did did:web:registry.example.com \
      --agent-id napanode01 --purpose revoke --ttl 3600
"""
import argparse
import base64
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _operator_kid(public_raw: bytes) -> str:
    """Stable key id = first 16 chars of base64url(SHA-256(pubkey))."""
    return _b64url(hashlib.sha256(public_raw).digest())[:16]


def _load_key(path: Path) -> Ed25519PrivateKey:
    return load_pem_private_key(path.read_bytes(), password=None)


def _public_jwk(key: Ed25519PrivateKey) -> dict:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw),
        "kid": _operator_kid(raw),
    }


def cmd_keygen(args: argparse.Namespace) -> None:
    out = Path(args.out)
    if out.exists() and not args.force:
        sys.exit(f"{out} already exists — refusing to overwrite (use --force).")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    out.write_bytes(pem)
    out.chmod(0o600)
    print(f"Operator private key written to {out} (mode 0600). Keep it safe.")
    print(f"kid: {_public_jwk(key)['kid']}")


def cmd_jwks(args: argparse.Namespace) -> None:
    key = _load_key(Path(args.key))
    jwks = {"keys": [_public_jwk(key)]}
    text = json.dumps(jwks, indent=2)
    if args.out:
        Path(args.out).write_text(text)
        print(f"Trusted operator JWKS written to {args.out}.")
        print("Point the registry's OPERATOR_JWKS_PATH at this file.")
    else:
        print(text)


def cmd_voucher(args: argparse.Namespace) -> None:
    key = _load_key(Path(args.key))
    jwk = _public_jwk(key)

    now = int(datetime.now(timezone.utc).timestamp())
    payload: dict = {
        "iss": args.issuer or "operator",
        "aud": args.registry_did,
        "sub": args.agent_id,
        "iat": now,
        "exp": now + args.ttl,
        "jti": str(uuid.uuid4()),
        "purpose": args.purpose,
    }
    if args.purpose == "enroll":
        if args.capabilities is not None:
            payload["capabilities"] = [
                c.strip() for c in args.capabilities.split(",") if c.strip()
            ]
        if args.operator:
            payload["operator"] = args.operator

    header = {"alg": "EdDSA", "typ": "enrollment-voucher+jwt", "kid": jwk["kid"]}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64url(key.sign(f"{h}.{p}".encode()))
    print(f"{h}.{p}.{sig}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Registry operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    g = sub.add_parser("keygen", help="Generate an operator keypair")
    g.add_argument("--out", default="operator.key.pem")
    g.add_argument("--force", action="store_true")
    g.set_defaults(func=cmd_keygen)

    j = sub.add_parser("jwks", help="Export the public JWKS the registry trusts")
    j.add_argument("--key", default="operator.key.pem")
    j.add_argument("--out", default=None)
    j.set_defaults(func=cmd_jwks)

    v = sub.add_parser("voucher", help="Sign an enrollment or revocation voucher")
    v.add_argument("--key", default="operator.key.pem")
    v.add_argument("--registry-did", required=True, help="Audience: the registry DID")
    v.add_argument("--agent-id", required=True)
    v.add_argument("--purpose", choices=["enroll", "revoke"], default="enroll")
    v.add_argument(
        "--capabilities",
        default=None,
        help="Comma-separated max capabilities the charter may claim (enroll only).",
    )
    v.add_argument(
        "--operator", default=None, help="Pin charter.operator to this DID (enroll only)."
    )
    v.add_argument("--issuer", default=None, help="Voucher iss claim (default 'operator').")
    v.add_argument("--ttl", type=int, default=3600, help="Lifetime in seconds.")
    v.set_defaults(func=cmd_voucher)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
