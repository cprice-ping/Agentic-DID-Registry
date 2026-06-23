import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

REGISTRY_DOMAIN: str = os.environ.get("REGISTRY_DOMAIN", "cpricedomain.net")
REGISTRY_KEY_PATH: Path = Path(os.environ.get("REGISTRY_KEY_PATH", "registry.key.pem"))
DATABASE_URL: str = os.environ.get("DATABASE_URL", "sqlite:///./registry.db")
