# -*- coding: utf-8 -*-
"""Pydantic Schemas for Request Validation and Typed Responses."""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field


# --- Client License Endpoints Schemas ---

class ActivateRequest(BaseModel):
    serial_key: str = Field(..., min_length=10, max_length=10, description="10-char uppercase serial key")
    device_fingerprint_hash: str = Field(..., min_length=32, max_length=64, description="SHA256 hash of device hardware")
    device_metadata: Optional[Dict[str, Any]] = None
    nonce: Optional[str] = None


class ValidateRequest(BaseModel):
    license_id: int
    device_fingerprint_hash: str = Field(..., min_length=32, max_length=64)
    nonce: Optional[str] = None


class HeartbeatRequest(BaseModel):
    license_id: int
    device_fingerprint_hash: str = Field(..., min_length=32, max_length=64)


class LicensePayload(BaseModel):
    license_id: int
    device_id: int
    device_fingerprint_hash: str
    license_type: str
    status: str
    activated_at: str
    expires_at: Optional[str]
    server_time: str
    trial_remaining_seconds: int
    nonce: Optional[str] = None


class SignedLicenseResponse(BaseModel):
    payload: LicensePayload
    signature: str


# --- Admin Schemas ---

class AdminLoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, description="Minimum 8 characters")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_hours: int


class GenerateSerialsRequest(BaseModel):
    count: int = Field(default=1, ge=1, le=500, description="Number of serials to generate")
    license_type: str = Field(default="TRIAL", description="TRIAL or FULL")
    trial_minutes: int = Field(default=60, ge=5, le=43200, description="Trial duration in minutes")
    notes: Optional[str] = None


class GeneratedKeyItem(BaseModel):
    serial_key: str
    license_type: str
    trial_minutes: int
    created_at: str


class BatchGenerateResponse(BaseModel):
    generated_count: int
    keys: List[GeneratedKeyItem]


class LicenseAdminOut(BaseModel):
    id: int
    key_hash_prefix: str
    license_type: str
    status: str
    trial_duration_minutes: int
    activation_limit: int
    created_at: str
    activated_at: Optional[str] = None
    expires_at: Optional[str] = None
    revoked_at: Optional[str] = None
    device_fingerprint_prefix: Optional[str] = None
    time_remaining_seconds: Optional[int] = None
    notes: Optional[str] = None


class RevokeRequest(BaseModel):
    license_id: int
    reason: Optional[str] = "Admin manual revocation"


class ResetDeviceRequest(BaseModel):
    device_fingerprint_hash: Optional[str] = None
    license_id: Optional[int] = None
    reason: Optional[str] = "Admin authorized device reset"


class AuditLogOut(BaseModel):
    id: int
    actor: str
    action: str
    target_type: str
    target_id: Optional[str]
    timestamp: str
    details: Optional[str]
