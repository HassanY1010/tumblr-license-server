# -*- coding: utf-8 -*-
"""Business Logic for License Generation, Activation, Validation, and Lifecycle Management."""

import json
from datetime import datetime, timezone, timedelta
from typing import List, Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select, and_

from license_server.models import (
    License,
    Device,
    Activation,
    DeviceTrialHistory,
    AuditLog,
    LicenseType,
    LicenseStatus,
    DeviceStatus,
    ActivationStatus,
    utcnow
)
from license_server.crypto import (
    generate_serial_key,
    hash_serial_key,
    validate_serial_format,
    sign_payload,
    get_or_generate_ed25519_keys
)
from license_server.schemas import (
    ActivateRequest,
    ValidateRequest,
    HeartbeatRequest,
    LicensePayload,
    SignedLicenseResponse,
    GeneratedKeyItem,
    BatchGenerateResponse,
    LicenseAdminOut
)


class LicenseServiceError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class LicenseService:
    def __init__(self, db: Session):
        self.db = db
        self.private_key, self.public_key_pem = get_or_generate_ed25519_keys()

    def generate_serials(
        self,
        count: int,
        license_type: str = "TRIAL",
        trial_minutes: int = 60,
        notes: Optional[str] = None,
        actor: str = "admin"
    ) -> BatchGenerateResponse:
        """Generates cryptographically random serial keys, stores HMAC hashes, and returns plain keys once."""
        generated_keys: List[GeneratedKeyItem] = []
        now = utcnow()
        
        for _ in range(count):
            # Collision retry loop
            for attempt in range(10):
                plain_serial = generate_serial_key()
                key_hash = hash_serial_key(plain_serial)
                
                # Check uniqueness in DB
                existing = self.db.query(License).filter(License.key_hash == key_hash).first()
                if not existing:
                    meta = json.dumps({"notes": notes}) if notes else None
                    lic = License(
                        key_hash=key_hash,
                        license_type=license_type.upper(),
                        status=LicenseStatus.UNUSED.value,
                        trial_duration_minutes=trial_minutes if license_type.upper() == "TRIAL" else 0,
                        activation_limit=1,
                        created_at=now,
                        metadata_json=meta
                    )
                    self.db.add(lic)
                    self.db.flush()
                    
                    generated_keys.append(GeneratedKeyItem(
                        serial_key=plain_serial,
                        license_type=license_type.upper(),
                        trial_minutes=trial_minutes,
                        created_at=now.isoformat()
                    ))
                    break
            else:
                raise LicenseServiceError("Failed to generate a unique serial key after multiple attempts", 500)

        # Audit Log
        log = AuditLog(
            actor=actor,
            action="GENERATE_SERIALS",
            target_type="LICENSE",
            target_id=f"count:{count}",
            timestamp=now,
            details_json=json.dumps({"count": count, "type": license_type, "trial_minutes": trial_minutes})
        )
        self.db.add(log)
        self.db.commit()

        return BatchGenerateResponse(generated_count=len(generated_keys), keys=generated_keys)

    def activate_license(self, req: ActivateRequest, client_ip: str = "unknown") -> SignedLicenseResponse:
        """Atomically activates a serial key, binds it to a device, and strictly enforces single-trial rule."""
        raw_serial = req.serial_key.strip().upper()
        if not validate_serial_format(raw_serial):
            raise LicenseServiceError("Invalid serial key format. Must be 10 alphanumeric characters.", 400)

        key_hash = hash_serial_key(raw_serial)
        now = utcnow()

        # Atomic query for license
        lic = self.db.query(License).filter(License.key_hash == key_hash).first()
        if not lic:
            raise LicenseServiceError("Serial key not found or invalid.", 404)

        if lic.status == LicenseStatus.REVOKED.value:
            raise LicenseServiceError("This license key has been revoked by the administrator.", 403)

        # Fetch or register device
        device = self.db.query(Device).filter(
            Device.device_fingerprint_hash == req.device_fingerprint_hash
        ).first()

        if not device:
            device = Device(
                device_fingerprint_hash=req.device_fingerprint_hash,
                first_seen_at=now,
                last_seen_at=now,
                status=DeviceStatus.ACTIVE.value,
                metadata_json=json.dumps(req.device_metadata or {})
            )
            self.db.add(device)
            self.db.flush()
        else:
            device.last_seen_at = now
            if req.device_metadata:
                device.metadata_json = json.dumps(req.device_metadata)
            if device.status == DeviceStatus.BLOCKED.value:
                raise LicenseServiceError("This machine has been blocked from activation.", 403)

        # Check existing activation on this specific license
        existing_act = self.db.query(Activation).filter(Activation.license_id == lic.id).first()
        if existing_act:
            if existing_act.device_id != device.id:
                raise LicenseServiceError("This license key is already bound to another machine.", 409)
            # Idempotent reactivation on the exact same device: calculate remaining time
            return self._build_signed_response(lic, device, existing_act, now, req.nonce)

        # For TRIAL licenses: Strictly check whether this physical device ever consumed a trial!
        if lic.license_type == LicenseType.TRIAL.value:
            trial_record = self.db.query(DeviceTrialHistory).filter(
                DeviceTrialHistory.device_id == device.id
            ).first()
            if trial_record and trial_record.trial_consumed:
                raise LicenseServiceError(
                    "This machine has already consumed its 60-minute trial period. "
                    "Each machine is entitled to one trial only.", 403
                )

        # Calculate expiration
        if lic.license_type == LicenseType.TRIAL.value:
            trial_expires_at = now + timedelta(minutes=lic.trial_duration_minutes)
        else:
            trial_expires_at = None

        # Update License
        lic.status = LicenseStatus.USED.value
        lic.activated_at = now
        lic.expires_at = trial_expires_at

        # Create Activation
        act = Activation(
            license_id=lic.id,
            device_id=device.id,
            activated_at=now,
            trial_expires_at=trial_expires_at,
            status=ActivationStatus.ACTIVE.value,
            last_verified_at=now
        )
        self.db.add(act)

        # Record in Device Trial History
        if lic.license_type == LicenseType.TRIAL.value:
            trial_hist = DeviceTrialHistory(
                device_id=device.id,
                first_trial_started_at=now,
                trial_consumed=True,
                created_at=now
            )
            self.db.add(trial_hist)

        # Audit
        self.db.add(AuditLog(
            actor=f"device:{device.id}:{client_ip}",
            action="ACTIVATE_LICENSE",
            target_type="LICENSE",
            target_id=str(lic.id),
            timestamp=now,
            details_json=json.dumps({
                "device_fingerprint": req.device_fingerprint_hash[:16] + "...",
                "type": lic.license_type,
                "expires_at": trial_expires_at.isoformat() if trial_expires_at else None
            })
        ))

        self.db.commit()
        return self._build_signed_response(lic, device, act, now, req.nonce)

    def validate_license(self, req: ValidateRequest) -> SignedLicenseResponse:
        """Validates license validity against current server UTC time and returns signed status."""
        now = utcnow()
        act = self.db.query(Activation).join(Device).filter(
            Activation.license_id == req.license_id,
            Device.device_fingerprint_hash == req.device_fingerprint_hash
        ).first()

        if not act:
            raise LicenseServiceError("Activation not found for this license and device.", 404)

        lic = act.license
        device = act.device

        if lic.status == LicenseStatus.REVOKED.value:
            act.status = ActivationStatus.DEACTIVATED.value
            self.db.commit()
            raise LicenseServiceError("This license has been revoked.", 403)

        # Check Trial Expiration
        if act.trial_expires_at:
            exp_utc = act.trial_expires_at
            if exp_utc.tzinfo is None:
                exp_utc = exp_utc.replace(tzinfo=timezone.utc)
            now_utc = now
            if now_utc.tzinfo is None:
                now_utc = now_utc.replace(tzinfo=timezone.utc)
            if now_utc >= exp_utc:
                act.status = ActivationStatus.EXPIRED.value
                lic.status = LicenseStatus.EXPIRED.value
                self.db.commit()

        act.last_verified_at = now
        device.last_seen_at = now
        self.db.commit()

        return self._build_signed_response(lic, device, act, now, req.nonce)

    def heartbeat(self, req: HeartbeatRequest) -> SignedLicenseResponse:
        """Updates last_seen and returns updated remaining seconds."""
        val_req = ValidateRequest(
            license_id=req.license_id,
            device_fingerprint_hash=req.device_fingerprint_hash
        )
        return self.validate_license(val_req)

    def _build_signed_response(
        self,
        lic: License,
        device: Device,
        act: Activation,
        server_now: datetime,
        nonce: Optional[str] = None
    ) -> SignedLicenseResponse:
        """Constructs an Ed25519 signed response."""
        remaining_seconds = 0
        status_str = act.status

        if lic.license_type == LicenseType.TRIAL.value:
            if act.trial_expires_at:
                expires_at_utc = act.trial_expires_at
                if expires_at_utc.tzinfo is None:
                    expires_at_utc = expires_at_utc.replace(tzinfo=timezone.utc)
                now_utc = server_now
                if now_utc.tzinfo is None:
                    now_utc = now_utc.replace(tzinfo=timezone.utc)
                delta = (expires_at_utc - now_utc).total_seconds()
                remaining_seconds = max(0, int(delta))
                if remaining_seconds == 0:
                    status_str = ActivationStatus.EXPIRED.value
        else:
            remaining_seconds = 999999999  # Unlimited for Full License

        payload_dict = {
            "license_id": lic.id,
            "device_id": device.id,
            "device_fingerprint_hash": device.device_fingerprint_hash,
            "license_type": lic.license_type,
            "status": status_str,
            "activated_at": act.activated_at.isoformat(),
            "expires_at": act.trial_expires_at.isoformat() if act.trial_expires_at else None,
            "server_time": server_now.isoformat(),
            "trial_remaining_seconds": remaining_seconds,
            "nonce": nonce
        }

        signature = sign_payload(payload_dict, self.private_key)

        return SignedLicenseResponse(
            payload=LicensePayload(**payload_dict),
            signature=signature
        )

    # --- Admin Operations ---

    def list_licenses(self, status: Optional[str] = None, search: Optional[str] = None) -> List[LicenseAdminOut]:
        now = utcnow()
        query = self.db.query(License)
        if status:
            query = query.filter(License.status == status.upper())
        licenses = query.order_by(License.created_at.desc()).all()

        results = []
        for l in licenses:
            act = l.activations[0] if l.activations else None
            rem_sec = None
            if l.expires_at:
                rem_sec = max(0, int((l.expires_at - now).total_seconds()))
            
            # Real-time state derivation
            derived_status = l.status
            if l.status == LicenseStatus.USED.value and rem_sec is not None and rem_sec == 0:
                derived_status = LicenseStatus.EXPIRED.value

            results.append(LicenseAdminOut(
                id=l.id,
                key_hash_prefix=l.key_hash[:12] + "...",
                license_type=l.license_type,
                status=derived_status,
                trial_duration_minutes=l.trial_duration_minutes,
                activation_limit=l.activation_limit,
                created_at=l.created_at.isoformat(),
                activated_at=l.activated_at.isoformat() if l.activated_at else None,
                expires_at=l.expires_at.isoformat() if l.expires_at else None,
                revoked_at=l.revoked_at.isoformat() if l.revoked_at else None,
                device_fingerprint_prefix=act.device.device_fingerprint_hash[:12] + "..." if act else None,
                time_remaining_seconds=rem_sec,
                notes=l.metadata_json
            ))
        return results

    def revoke_license(self, license_id: int, reason: str, actor: str = "admin") -> bool:
        lic = self.db.query(License).filter(License.id == license_id).first()
        if not lic:
            raise LicenseServiceError("License not found", 404)
        lic.status = LicenseStatus.REVOKED.value
        lic.revoked_at = utcnow()
        for act in lic.activations:
            act.status = ActivationStatus.DEACTIVATED.value
        self.db.add(AuditLog(
            actor=actor,
            action="REVOKE_LICENSE",
            target_type="LICENSE",
            target_id=str(license_id),
            timestamp=utcnow(),
            details_json=json.dumps({"reason": reason})
        ))
        self.db.commit()
        return True

    def reset_device_trial(self, device_fingerprint_hash: str, reason: str, actor: str = "admin") -> bool:
        dev = self.db.query(Device).filter(Device.device_fingerprint_hash == device_fingerprint_hash).first()
        if not dev:
            raise LicenseServiceError("Device not found", 404)
        trial_hist = self.db.query(DeviceTrialHistory).filter(DeviceTrialHistory.device_id == dev.id).first()
        if trial_hist:
            self.db.delete(trial_hist)
        self.db.add(AuditLog(
            actor=actor,
            action="RESET_DEVICE_TRIAL",
            target_type="DEVICE",
            target_id=str(dev.id),
            timestamp=utcnow(),
            details_json=json.dumps({"reason": reason, "fingerprint": device_fingerprint_hash})
        ))
        self.db.commit()
        return True
