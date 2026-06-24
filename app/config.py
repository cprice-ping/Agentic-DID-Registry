import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


REGISTRY_DOMAIN: str = os.environ.get("REGISTRY_DOMAIN", "cpricedomain.net")
REGISTRY_KEY_PATH: Path = Path(os.environ.get("REGISTRY_KEY_PATH", "registry.key.pem"))
DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./registry.db")

# Absolute base URL the registry is served at — used in credentialStatus URLs.
# Defaults to https://{REGISTRY_DOMAIN}; override if served behind a different host.
REGISTRY_BASE_URL: str = os.environ.get(
    "REGISTRY_BASE_URL", f"https://{REGISTRY_DOMAIN}"
).rstrip("/")

# ── Enrollment (minting) auth ────────────────────────────────────────────────
# Agents self-enroll by presenting an operator-signed enrollment voucher.
# The registry trusts the operator public keys listed in this JWKS file.
OPERATOR_JWKS_PATH: Path = Path(
    os.environ.get("OPERATOR_JWKS_PATH", "operator_jwks.json")
)
# Set False only for local development — disables voucher checks entirely.
REQUIRE_ENROLLMENT_VOUCHER: bool = _bool("REQUIRE_ENROLLMENT_VOUCHER", True)

# ── Charter freshness ────────────────────────────────────────────────────────
# Credential lifetime. 0 = no expiry (validUntil/exp omitted).
CHARTER_TTL_DAYS: int = int(os.environ.get("CHARTER_TTL_DAYS", "90"))
