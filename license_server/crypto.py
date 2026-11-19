# -*- coding: utf-8 -*-
"""Cryptographic Services: Ed25519 Signatures, HMAC Hashing, Serial Generation, Passwords."""

import hmac
import hashlib
import json
import base64
import secrets
import string
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

import bcrypt
import jwt
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from license_server.config import settings

# Unambiguous 32-character alphabet (removes 0, O, 1, I to eliminate user transcription confusion)
SERIAL_CHARSET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
SERIAL_LENGTH = 10


def _load_private_key_bytes(raw: str) -> bytes:
    """Normalizes raw string or base64 into PEM bytes."""
    raw_stripped = raw.strip()
    if "-----BEGIN" in raw_stripped:
        return raw_stripped.encode("utf-8")
    try:
        decoded = base64.b64decode(raw_stripped)
        if b"-----BEGIN" in decoded:
            return decoded
    except Exception:
        pass
    return raw_stripped.encode("utf-8")


_ephemeral_dev_keypair: Optional[Tuple[ed25519.Ed25519PrivateKey, bytes]] = None


def get_or_generate_ed25519_keys(keys_dir: Optional[Path] = None) -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
    """Loads Ed25519 keypair from secure environment variable, or local files, or errors out in prod."""
    global _ephemeral_dev_keypair
    target_dir = keys_dir or settings.KEYS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    priv_path = target_dir / "ed25519_private.pem"
    pub_path = target_dir / "ed25519_public.pem"

    # Priority 1: Secure Environment Variable (Recommended for Railway & Cloud)
    env_priv = os.getenv("ED25519_PRIVATE_KEY") or settings.ED25519_PRIVATE_KEY
    if env_priv and env_priv.strip():
        key_bytes = _load_private_key_bytes(env_priv)
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, pub_pem

    # Priority 2: Persistent disk file
    if priv_path.exists() and pub_path.exists():
        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f:
            pub_pem = f.read()
        return private_key, pub_pem

    # Priority 3: Refuse to generate ephemeral keys in production
    current_env = os.getenv("ENVIRONMENT") or settings.ENVIRONMENT
    if current_env == "production":
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: ED25519_PRIVATE_KEY environment variable is missing in production! "
            "Ephemeral key generation in production is strictly forbidden to prevent invalidating client licenses upon restart."
        )

    # Priority 4: Development fallback ephemeral generation (in-memory cached across process lifetime)
    if _ephemeral_dev_keypair is not None:
        return _ephemeral_dev_keypair

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    _ephemeral_dev_keypair = (private_key, pub_pem)
    return _ephemeral_dev_keypair


def generate_serial_key(length: int = SERIAL_LENGTH) -> str:
    """Generates a cryptographically random, unambiguous 10-char uppercase alphanumeric serial key."""
    return "".join(secrets.choice(SERIAL_CHARSET) for _ in range(length))


def validate_serial_format(serial: str) -> bool:
    """Verifies that the serial is exactly 10 alphanumeric characters."""
    clean = serial.strip().upper()
    if len(clean) != SERIAL_LENGTH:
        return False
    valid_set = set(SERIAL_CHARSET) | {"0", "O", "1", "I"}
    return all(c in valid_set for c in clean)


def hash_serial_key(serial: str) -> str:
    """Computes HMAC-SHA256 hash of the normalized serial using the server secret key."""
    normalized = serial.strip().upper()
    return hmac.new(
        settings.SERVER_HMAC_SECRET.encode("utf-8"),
        normalized.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def sign_payload(payload: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> str:
    """Canonically serializes a dictionary and signs it using Ed25519, returning Base64 signature."""
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
    signature = private_key.sign(canonical_bytes)
    return base64.b64encode(signature).decode("utf-8")


def verify_payload_signature(payload: Dict[str, Any], signature_b64: str, public_key_pem: bytes) -> bool:
    """Verifies an Ed25519 signature against canonical JSON payload bytes."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        canonical_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode("utf-8")
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, canonical_bytes)
        return True
    except Exception:
        return False


def hash_password(password: str) -> str:
    """Hashes admin password with bcrypt and work factor 12."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies plain password against stored bcrypt hash."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a signed JWT admin access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=settings.JWT_EXPIRATION_HOURS))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT admin access token."""
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except Exception:
        return None
