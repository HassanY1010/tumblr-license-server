# -*- coding: utf-8 -*-
"""License Server Configuration and Cryptographic Key Management for Production / Railway."""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent


def get_normalized_database_url() -> str:
    """Retrieves and normalizes DATABASE_URL for SQLAlchemy 2.0 and PostgreSQL."""
    raw_url = (
        os.getenv("DATABASE_URL")
        or os.getenv("LICENSE_DATABASE_URL")
        or f"sqlite:///{BASE_DIR / 'license_server.db'}"
    )
    # Railway PostgreSQL injects postgres:// which SQLAlchemy 2.0 rejects
    if raw_url.startswith("postgres://"):
        raw_url = raw_url.replace("postgres://", "postgresql://", 1)
    return raw_url


class Settings(BaseSettings):
    """Server Environment Settings."""
    APP_NAME: str = "Tumblr Manager Pro - License Server"
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

    # Database
    DATABASE_URL: str = get_normalized_database_url()

    # Security Secrets
    SERVER_HMAC_SECRET: str = os.getenv(
        "SERVER_HMAC_SECRET",
        "TMP-LICENSE-HMAC-DEV-SECRET-KEY-CHANGE-IN-PROD-2026"
    )
    JWT_SECRET: str = os.getenv(
        "JWT_SECRET",
        "TMP-LICENSE-JWT-DEV-SECRET-KEY-CHANGE-IN-PROD-2026"
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 12

    # Trial & Timing Defaults
    DEFAULT_TRIAL_MINUTES: int = 60
    GRACE_PERIOD_MINUTES: int = 10

    # Rate Limiting & Proxy Configuration
    REDIS_URL: str = os.getenv("REDIS_URL", "")
    TRUST_FORWARDED_HEADERS: bool = os.getenv("TRUST_FORWARDED_HEADERS", "true").lower() in ("true", "1", "yes")
    # Trusted private subnets for reverse proxy (loopback, Railway internal CIDRs)
    TRUSTED_PROXIES: str = os.getenv(
        "TRUSTED_PROXIES",
        "127.0.0.1,::1,localhost,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10"
    )

    # Ed25519 Keys directory & Environment variable override
    KEYS_DIR: Path = BASE_DIR / "keys"
    ED25519_PRIVATE_KEY: Optional[str] = os.getenv("ED25519_PRIVATE_KEY", None)

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
