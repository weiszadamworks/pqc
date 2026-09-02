"""
Application Configuration
"""

import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseModel):
    app_name: str = "QuantumShield CBOM & Compliance Engine"
    app_version: str = "1.0.0"
    debug: bool = os.getenv("DEBUG", "False").lower() in ("true", "1")
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    reports_dir: Path = BASE_DIR / "reports"
    default_timeout: int = 10
    # SSRF protection: prevent scanning internal loopback/private IPs unless explicitly allowed
    allow_private_ip_scan: bool = os.getenv("ALLOW_PRIVATE_IP_SCAN", "False").lower() in ("true", "1")

settings = Settings()

# Ensure reports directory exists
settings.reports_dir.mkdir(parents=True, exist_ok=True)
