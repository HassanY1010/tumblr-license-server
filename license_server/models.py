# -*- coding: utf-8 -*-
"""SQLAlchemy ORM Models for Central License Server."""

import enum
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    Index,
    UniqueConstraint
)
from sqlalchemy.orm import relationship

from license_server.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class LicenseType(str, enum.Enum):
    TRIAL = "TRIAL"
    FULL = "FULL"
    SUBSCRIPTION = "SUBSCRIPTION"


class LicenseStatus(str, enum.Enum):
    UNUSED = "UNUSED"
    USED = "USED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class DeviceStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"


class ActivationStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    DEACTIVATED = "DEACTIVATED"


class License(Base):
    """Stores generated serial keys in HMAC-SHA256 hashed form."""
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    license_type = Column(String(20), default=LicenseType.TRIAL.value, nullable=False)
    status = Column(String(20), default=LicenseStatus.UNUSED.value, nullable=False, index=True)
    trial_duration_minutes = Column(Integer, default=60, nullable=False)
    activation_limit = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    activated_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    metadata_json = Column(Text, nullable=True)

    # Relationships
    activations = relationship("Activation", back_populates="license", cascade="all, delete-orphan")


class Device(Base):
    """Tracks unique client machine fingerprints anonymously."""
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_fingerprint_hash = Column(String(64), unique=True, nullable=False, index=True)
    first_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    status = Column(String(20), default=DeviceStatus.ACTIVE.value, nullable=False)
    metadata_json = Column(Text, nullable=True)

    # Relationships
    activations = relationship("Activation", back_populates="device")
    trial_history = relationship("DeviceTrialHistory", back_populates="device", uselist=False)


class Activation(Base):
    """Tracks active bindings between a license and a device."""
    __tablename__ = "activations"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("licenses.id"), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    activated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    trial_expires_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(20), default=ActivationStatus.ACTIVE.value, nullable=False, index=True)
    last_verified_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    license = relationship("License", back_populates="activations")
    device = relationship("Device", back_populates="activations")

    __table_args__ = (
        Index("idx_active_license_device", "license_id", "device_id"),
    )


class DeviceTrialHistory(Base):
    """Enforces strictly: 1 trial per hardware device ever."""
    __tablename__ = "device_trial_history"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), unique=True, nullable=False, index=True)
    first_trial_started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    trial_consumed = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    device = relationship("Device", back_populates="trial_history")


class AdminUser(Base):
    """Stores administrative accounts for managing licenses."""
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(20), default="admin", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditLog(Base):
    """Full immutable audit logging for security and traceability."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String(100), nullable=False, default="system")
    action = Column(String(50), nullable=False, index=True)
    target_type = Column(String(50), nullable=False)
    target_id = Column(String(100), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    details_json = Column(Text, nullable=True)


class RateLimitEntry(Base):
    """Shared database store for rate limiting across multiple Uvicorn worker processes."""
    __tablename__ = "rate_limit_entries"

    id = Column(Integer, primary_key=True, index=True)
    bucket_key = Column(String(120), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


class AdminLockoutEntry(Base):
    """Shared database store for brute-force lockouts across multiple Uvicorn worker processes."""
    __tablename__ = "admin_lockout_entries"

    id = Column(Integer, primary_key=True, index=True)
    client_ip = Column(String(64), unique=True, nullable=False, index=True)
    failed_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
