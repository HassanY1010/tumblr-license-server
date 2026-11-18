# -*- coding: utf-8 -*-
"""Admin REST API for Generating Keys, Managing Activations, and Auditing."""

import csv
import io
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Security, status, Response, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from license_server.database import get_db
from license_server.models import AdminUser, AuditLog, utcnow
from license_server.crypto import verify_password, hash_password, create_access_token, decode_access_token
from license_server.rate_limiter import rate_limiter, get_real_client_ip
from license_server.schemas import (
    AdminLoginRequest,
    ChangePasswordRequest,
    TokenResponse,
    GenerateSerialsRequest,
    BatchGenerateResponse,
    LicenseAdminOut,
    RevokeRequest,
    ResetDeviceRequest,
    AuditLogOut
)
from license_server.services import LicenseService, LicenseServiceError

router = APIRouter(prefix="/api/v1/admin", tags=["Admin Licensing Portal"])
security = HTTPBearer()


def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
) -> AdminUser:
    """Verifies JWT bearer token and retrieves authenticated admin user."""
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired admin session token."
        )
    username = payload.get("sub")
    admin = db.query(AdminUser).filter(AdminUser.username == username, AdminUser.is_active == True).first()
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin user not found or disabled."
        )
    return admin


@router.post("/login", response_model=TokenResponse)
def admin_login(req: AdminLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticates admin and returns a signed JWT access token with brute-force defense."""
    client_ip = get_real_client_ip(request)
    rate_limiter.check_admin_login(client_ip)

    admin = db.query(AdminUser).filter(AdminUser.username == req.username).first()
    if not admin or not verify_password(req.password, admin.password_hash):
        rate_limiter.record_admin_login_failure(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials."
        )
    
    rate_limiter.record_admin_login_success(client_ip)
    token = create_access_token({"sub": admin.username, "role": admin.role})
    return TokenResponse(access_token=token, expires_in_hours=12)


@router.post("/change-password")
def change_admin_password(
    req: ChangePasswordRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Changes password for the authenticated admin user."""
    if not verify_password(req.current_password, admin.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect."
        )
    admin.password_hash = hash_password(req.new_password)
    db.commit()
    return {"status": "success", "message": "Admin password updated successfully."}


@router.post("/serials/generate", response_model=BatchGenerateResponse)
def generate_serials(
    req: GenerateSerialsRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Generates unique 10-char serials (1, 10, 20, 100...) with trial limits."""
    service = LicenseService(db)
    try:
        return service.generate_serials(
            count=req.count,
            license_type=req.license_type,
            trial_minutes=req.trial_minutes,
            notes=req.notes,
            actor=admin.username
        )
    except LicenseServiceError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("/serials", response_model=List[LicenseAdminOut])
def list_serials(
    status: Optional[str] = None,
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Lists all licenses with real-time derived status (UNUSED, USED, ACTIVE, EXPIRED, REVOKED)."""
    service = LicenseService(db)
    return service.list_licenses(status=status)


@router.post("/serials/revoke")
def revoke_serial(
    req: RevokeRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Revokes an unused or active serial immediately."""
    service = LicenseService(db)
    try:
        service.revoke_license(req.license_id, req.reason or "Admin revocation", actor=admin.username)
        return {"status": "success", "message": f"License {req.license_id} revoked."}
    except LicenseServiceError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/devices/reset-trial")
def reset_device_trial(
    req: ResetDeviceRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Allows admin to reset trial history for a legitimate customer machine replacement."""
    service = LicenseService(db)
    try:
        service.reset_device_trial(req.device_fingerprint_hash, req.reason or "Admin reset", actor=admin.username)
        return {"status": "success", "message": "Device trial history cleared."}
    except LicenseServiceError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("/audit-logs", response_model=List[AuditLogOut])
def get_audit_logs(
    limit: int = 100,
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Returns security audit trail of all administrative and activation actions."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [
        AuditLogOut(
            id=l.id,
            actor=l.actor,
            action=l.action,
            target_type=l.target_type,
            target_id=l.target_id,
            timestamp=l.timestamp.isoformat(),
            details=l.details_json
        ) for l in logs
    ]
