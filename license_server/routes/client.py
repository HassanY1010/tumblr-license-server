# -*- coding: utf-8 -*-
"""Client Endpoints for License Activation, Validation, and Heartbeats."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from license_server.database import get_db
from license_server.rate_limiter import rate_limit_activations, rate_limit_validations, get_real_client_ip
from license_server.schemas import (
    ActivateRequest,
    ValidateRequest,
    HeartbeatRequest,
    SignedLicenseResponse
)
from license_server.services import LicenseService, LicenseServiceError

router = APIRouter(prefix="/api/v1/licenses", tags=["Client Licensing"])


@router.post("/activate", response_model=SignedLicenseResponse, dependencies=[Depends(rate_limit_activations)])
def activate_license(
    req: ActivateRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Activates a 10-char serial key and binds it to the machine with trial enforcement."""
    service = LicenseService(db)
    client_ip = get_real_client_ip(request)
    try:
        return service.activate_license(req, client_ip=client_ip)
    except LicenseServiceError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/validate", response_model=SignedLicenseResponse, dependencies=[Depends(rate_limit_validations)])
def validate_license(
    req: ValidateRequest,
    db: Session = Depends(get_db)
):
    """Validates the license state against current server time and returns Ed25519 signed status."""
    service = LicenseService(db)
    try:
        return service.validate_license(req)
    except LicenseServiceError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/heartbeat", response_model=SignedLicenseResponse)
def heartbeat(
    req: HeartbeatRequest,
    db: Session = Depends(get_db)
):
    """Heartbeat endpoint pinged periodically by running desktop client."""
    service = LicenseService(db)
    try:
        return service.heartbeat(req)
    except LicenseServiceError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("/public-key")
def get_public_key(db: Session = Depends(get_db)):
    """Returns the Ed25519 Public Key in PEM format for client signature verification."""
    service = LicenseService(db)
    return {"public_key_pem": service.public_key_pem.decode("utf-8")}
