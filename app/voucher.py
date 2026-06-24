"""
Enrollment voucher verification — the minting auth boundary.

Identity bootstrapping cannot authenticate itself: an agent holds no registry
identity at the moment it asks to be issued one.  The regress terminates at an
**operator-signed enrollment voucher** — a short-lived EdDSA JWT, signed by a key
the registry trusts out-of-band (loaded from OPERATOR_JWKS_PATH), that authorizes
exactly one agent_id and bounds the capabilities it may claim.

The voucher is *both* the authentication (a trusted operator vouched for this
enrollment) and the vetting (the registry clamps the charter to the grant, so it
never signs capabilities the operator did not authorize).

Voucher format (compact JWS, alg=EdDSA)
---------------------------------------
  header   { "alg": "EdDSA", "typ": "enrollment-voucher+jwt", "kid": <operator kid> }
  payload  {
             "iss":       <operator id / DID>,
             "aud":       <registry DID>,        # did:web:{domain}
             "sub":       <agent_id>,            # the single agent this voucher mints
             "iat":       <issued at>,
             "exp":       <expiry — short-lived>,
             "jti":       <unique id — single use>,
             "capabilities": [ ... ],            # max capabilities the charter may claim
             "operator":  <did>                  # optional — pins charter.operator
           }

The pluggability point: this module verifies a JWT against a configured trusted
issuer set.  Today that set is operator keys.  Additional trusted issuers (a
SPIFFE/SPIRE trust domain, a cloud workload-OIDC issuer, GitHub OIDC, a TPM
attestation service, ...) can be added later as a JWKS + issuer-allowlist change,
not a rewrite of the mint path.

The operating environment is **not** the identity, and the registry stays
platform-neutral: an agent on a Raspberry Pi, in k8s, on AWS, GCP, or Azure all
enroll the same way.  Where the agent runs can be carried as a *claim* in the
charter (e.g. an ``environment`` or attestation field the voucher authorizes) —
it qualifies how the identity is used, it does not define the identity.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.crypto import b64url_decode


class VoucherError(Exception):
    """Raised when an enrollment voucher is missing, malformed, or invalid."""


class VoucherGrant:
    """The authorization carried by a verified enrollment voucher."""

    def __init__(
        self,
        agent_id: str,
        capabilities: Optional[list[str]],
        operator: Optional[str],
        jti: str,
        issuer: str,
        purpose: str,
    ) -> None:
        self.agent_id = agent_id
        self.capabilities = capabilities  # None ⇒ voucher set no cap bound
        self.operator = operator
        self.jti = jti
        self.issuer = issuer
        self.purpose = purpose  # "enroll" (default) | "revoke"


def load_operator_keys(path: Path) -> dict[str, dict]:
    """
    Load trusted operator public keys from a JWKS file.

    Returns a mapping of kid → JWK.  Keys without a ``kid`` are indexed by ``""``
    so a voucher header that omits ``kid`` can still match a single-key JWKS.
    Missing file ⇒ empty trust set (every voucher will be rejected).
    """
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    keys: dict[str, dict] = {}
    for jwk in data.get("keys", []):
        keys[jwk.get("kid", "")] = jwk
    return keys


def _jwk_to_public_key(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise VoucherError("Operator key must be an Ed25519 OKP JWK.")
    return Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))


def verify_voucher(
    token: str,
    operator_keys: dict[str, dict],
    expected_audience: str,
) -> VoucherGrant:
    """
    Verify an enrollment voucher and return its grant.

    Checks, in order: structural validity, signature against a trusted operator
    key, audience binding to this registry, and expiry.  Raises VoucherError on
    any failure.  Replay (single-use jti) is enforced by the caller against
    persistent state — this function is pure.
    """
    if not operator_keys:
        raise VoucherError(
            "No trusted operator keys configured — cannot verify enrollment "
            "vouchers.  Set OPERATOR_JWKS_PATH."
        )

    parts = token.strip().split(".")
    if len(parts) != 3:
        raise VoucherError("Voucher is not a compact JWS (header.payload.signature).")
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
        signature = b64url_decode(sig_b64)
    except Exception as exc:  # noqa: BLE001 — any decode failure is a bad voucher
        raise VoucherError(f"Voucher could not be decoded: {exc}")

    if header.get("alg") != "EdDSA":
        raise VoucherError(f"Unsupported voucher alg: {header.get('alg')!r}")

    # Select the trusted key by kid; fall back to the sole key for kid-less vouchers.
    kid = header.get("kid", "")
    jwk = operator_keys.get(kid)
    if jwk is None and len(operator_keys) == 1:
        jwk = next(iter(operator_keys.values()))
    if jwk is None:
        raise VoucherError(f"No trusted operator key matches kid {kid!r}.")

    public_key = _jwk_to_public_key(jwk)
    signing_input = f"{header_b64}.{payload_b64}".encode()
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature:
        raise VoucherError("Voucher signature is invalid.")

    # Audience must bind the voucher to *this* registry.
    if payload.get("aud") != expected_audience:
        raise VoucherError(
            f"Voucher audience {payload.get('aud')!r} does not match this "
            f"registry ({expected_audience!r})."
        )

    exp = payload.get("exp")
    if exp is None:
        raise VoucherError("Voucher has no exp — refusing a non-expiring voucher.")
    now = int(datetime.now(timezone.utc).timestamp())
    if now >= int(exp):
        raise VoucherError("Voucher has expired.")

    agent_id = payload.get("sub")
    if not agent_id:
        raise VoucherError("Voucher has no sub (agent_id).")

    jti = payload.get("jti")
    if not jti:
        raise VoucherError("Voucher has no jti — cannot enforce single use.")

    capabilities = payload.get("capabilities")
    if capabilities is not None and not isinstance(capabilities, list):
        raise VoucherError("Voucher 'capabilities' must be a list if present.")

    return VoucherGrant(
        agent_id=agent_id,
        capabilities=capabilities,
        operator=payload.get("operator"),
        jti=jti,
        issuer=payload.get("iss", ""),
        purpose=payload.get("purpose", "enroll"),
    )
