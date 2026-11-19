# -*- coding: utf-8 -*-
"""Comprehensive Test Suite for Central License Server."""

import uuid
import pytest
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient

from license_server.main import app
from license_server.database import init_license_db, SessionLocal
from license_server.models import (
    License, Device, Activation, DeviceTrialHistory, LicenseStatus,
    AdminUser, AdminLockoutEntry, RateLimitEntry
)
from license_server.crypto import hash_serial_key, verify_payload_signature, hash_password, get_or_generate_ed25519_keys
from license_server.services import LicenseService

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_license_db()
    get_or_generate_ed25519_keys()
    db = SessionLocal()
    # Clean rate limiter state for clean test isolation
    db.query(AdminLockoutEntry).delete()
    db.query(RateLimitEntry).delete()
    admin = db.query(AdminUser).filter(AdminUser.username == "admin").first()
    if not admin:
        admin = AdminUser(
            username="admin",
            password_hash=hash_password("AdminTumblr2026!Secure"),
            role="admin",
            is_active=True
        )
        db.add(admin)
    db.commit()
    db.close()
    yield


def test_health_check():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"


def test_public_key_endpoint():
    res = client.get("/api/v1/licenses/public-key")
    assert res.status_code == 200
    pem = res.json()["public_key_pem"]
    assert "BEGIN PUBLIC KEY" in pem
    assert "END PUBLIC KEY" in pem


def test_admin_login_and_generate_serials():
    # 1. Login
    res = client.post("/api/v1/admin/login", json={
        "username": "admin",
        "password": "AdminTumblr2026!Secure"
    })
    assert res.status_code == 200
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Generate 20 Serials Batch
    res_gen = client.post(
        "/api/v1/admin/serials/generate",
        headers=headers,
        json={"count": 20, "license_type": "TRIAL", "trial_minutes": 60, "notes": "Test Batch 20"}
    )
    assert res_gen.status_code == 200
    data = res_gen.json()
    assert data["generated_count"] == 20
    assert len(data["keys"]) == 20

    # Verify each serial properties
    serials = [k["serial_key"] for k in data["keys"]]
    assert len(set(serials)) == 20  # Strict Uniqueness
    for s in serials:
        assert len(s) == 10
        assert s.isalnum() and s.isupper()

    # Verify Serials are NOT stored in plain text in database
    db = SessionLocal()
    for s in serials[:3]:
        # Searching by plain text should find nothing
        found_plain = db.query(License).filter(License.key_hash == s).first()
        assert found_plain is None
        # Searching by HMAC-SHA256 hash must find the row
        found_hash = db.query(License).filter(License.key_hash == hash_serial_key(s)).first()
        assert found_hash is not None
        assert found_hash.status == LicenseStatus.UNUSED.value
    db.close()


def test_single_device_trial_activation_and_signature():
    # 1. Admin generate 1 serial
    res_login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "AdminTumblr2026!Secure"})
    token = res_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res_gen = client.post("/api/v1/admin/serials/generate", headers=headers, json={"count": 1, "trial_minutes": 60})
    serial = res_gen.json()["keys"][0]["serial_key"]

    # 2. Activate on unique device
    dev_hash = uuid.uuid4().hex + uuid.uuid4().hex
    res_act = client.post("/api/v1/licenses/activate", json={
        "serial_key": serial,
        "device_fingerprint_hash": dev_hash,
        "device_metadata": {"win_version": "11"}
    })
    assert res_act.status_code == 200
    act_data = res_act.json()
    payload = act_data["payload"]
    signature = act_data["signature"]

    assert payload["status"] == "ACTIVE"
    assert payload["license_type"] == "TRIAL"
    assert 3500 <= payload["trial_remaining_seconds"] <= 3600
    assert payload["device_fingerprint_hash"] == dev_hash

    # 3. Cryptographic Signature Validation
    pub_res = client.get("/api/v1/licenses/public-key")
    pub_pem = pub_res.json()["public_key_pem"].encode("utf-8")
    assert verify_payload_signature(payload, signature, pub_pem) is True


def test_concurrent_activation_race_condition():
    """Two concurrent threads attempt to activate the exact same serial on different devices."""
    res_login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "AdminTumblr2026!Secure"})
    token = res_login.json()["access_token"]
    res_gen = client.post(
        "/api/v1/admin/serials/generate",
        headers={"Authorization": f"Bearer {token}"},
        json={"count": 1, "trial_minutes": 60}
    )
    serial = res_gen.json()["keys"][0]["serial_key"]

    dev1 = uuid.uuid4().hex + "1" * 32
    dev2 = uuid.uuid4().hex + "2" * 32

    def do_activate(dev_hash):
        with TestClient(app) as c:
            return c.post("/api/v1/licenses/activate", json={
                "serial_key": serial,
                "device_fingerprint_hash": dev_hash
            })

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(do_activate, dev1)
        f2 = executor.submit(do_activate, dev2)
        r1 = f1.result()
        r2 = f2.result()

    statuses = [r1.status_code, r2.status_code]
    # Exactly one request must succeed (200) and the other must be rejected (409)
    assert 200 in statuses
    assert 409 in statuses


def test_reject_multiple_trials_on_same_device():
    """Device A tries to activate Serial 1 (success), then tries Serial 2 (must be rejected)."""
    res_login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "AdminTumblr2026!Secure"})
    token = res_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res_gen = client.post("/api/v1/admin/serials/generate", headers=headers, json={"count": 2, "trial_minutes": 60})
    serial_1 = res_gen.json()["keys"][0]["serial_key"]
    serial_2 = res_gen.json()["keys"][1]["serial_key"]

    device_hash = uuid.uuid4().hex + "test" * 8

    # First trial activation -> Success
    res1 = client.post("/api/v1/licenses/activate", json={
        "serial_key": serial_1,
        "device_fingerprint_hash": device_hash
    })
    assert res1.status_code == 200

    # Second trial activation -> Forbidden 403
    res2 = client.post("/api/v1/licenses/activate", json={
        "serial_key": serial_2,
        "device_fingerprint_hash": device_hash
    })
    assert res2.status_code == 403
    assert "already consumed its 60-minute trial" in res2.json()["detail"]


def test_revoke_license_prevents_validation():
    res_login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "AdminTumblr2026!Secure"})
    token = res_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res_gen = client.post("/api/v1/admin/serials/generate", headers=headers, json={"count": 1, "trial_minutes": 60})
    serial = res_gen.json()["keys"][0]["serial_key"]
    dev_hash = uuid.uuid4().hex + "rev" * 10

    res_act = client.post("/api/v1/licenses/activate", json={
        "serial_key": serial,
        "device_fingerprint_hash": dev_hash
    })
    lic_id = res_act.json()["payload"]["license_id"]

    # Admin revokes license
    res_rev = client.post(
        "/api/v1/admin/serials/revoke",
        headers=headers,
        json={"license_id": lic_id, "reason": "Security violation"}
    )
    assert res_rev.status_code == 200

    # Validate must now be rejected with 403
    res_val = client.post("/api/v1/licenses/validate", json={
        "license_id": lic_id,
        "device_fingerprint_hash": dev_hash
    })
    assert res_val.status_code == 403
    assert "revoked" in res_val.json()["detail"]


def test_upgrade_from_trial_to_full_license_on_same_device():
    """Device consumes 60-min TRIAL, is rejected for another TRIAL, but succeeds when upgrading to FULL."""
    res_login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "AdminTumblr2026!Secure"})
    token = res_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Generate 1 TRIAL and 1 FULL
    res_trial = client.post("/api/v1/admin/serials/generate", headers=headers, json={"count": 1, "license_type": "TRIAL", "trial_minutes": 60})
    trial_serial = res_trial.json()["keys"][0]["serial_key"]

    res_full = client.post("/api/v1/admin/serials/generate", headers=headers, json={"count": 1, "license_type": "FULL", "notes": "Customer Upgrade"})
    full_serial = res_full.json()["keys"][0]["serial_key"]

    dev_hash = uuid.uuid4().hex + "upgrade" * 4

    # 1. Activate TRIAL -> Success
    res1 = client.post("/api/v1/licenses/activate", json={"serial_key": trial_serial, "device_fingerprint_hash": dev_hash})
    assert res1.status_code == 200
    assert res1.json()["payload"]["license_type"] == "TRIAL"

    # 2. Upgrade to FULL -> Must succeed on same device!
    res_up = client.post("/api/v1/licenses/activate", json={"serial_key": full_serial, "device_fingerprint_hash": dev_hash})
    assert res_up.status_code == 200
    payload = res_up.json()["payload"]
    assert payload["license_type"] == "FULL"
    assert payload["status"] == "ACTIVE"
    assert payload["trial_remaining_seconds"] == 999999999


def test_rate_limiter_and_admin_brute_force():
    """Verifies that excessive failed logins trigger lockout (HTTP 429)."""
    # 5 failed login attempts
    for _ in range(5):
        res = client.post("/api/v1/admin/login", json={"username": "admin", "password": "WrongPassword!"})
        assert res.status_code in (401, 429)

    # 6th attempt should be locked out (429)
    res_locked = client.post("/api/v1/admin/login", json={"username": "admin", "password": "WrongPassword!"})
    assert res_locked.status_code == 429
    assert "locked" in res_locked.json()["detail"].lower()

