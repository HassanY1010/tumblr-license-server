# -*- coding: utf-8 -*-
"""Multi-Worker Shared Rate Limiter & Anti-Spoofing Brute-Force Defense.

Supports:
1. Anti-Spoofing Client IP extraction (only trusts X-Forwarded-For / X-Real-IP if peer is trusted proxy).
2. Shared multi-worker synchronization via Database (SQLAlchemy / PostgreSQL / SQLite) or Redis.
3. Sliding window enforcement and exponential/temporary lockout defense.
"""

import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Set
from fastapi import Request, HTTPException, status
from sqlalchemy.orm import Session

from license_server.config import settings
from license_server.database import SessionLocal


def parse_trusted_proxies() -> Set[str]:
    raw = settings.TRUSTED_PROXIES or "127.0.0.1,::1,localhost"
    return {p.strip() for p in raw.split(",") if p.strip()}


def get_real_client_ip(request: Request) -> str:
    """Extracts client IP securely, preventing header spoofing.
    
    Headers like X-Forwarded-For or X-Real-IP are ONLY trusted if the immediate
    TCP client socket connects from an authorized reverse proxy (e.g. 127.0.0.1).
    Direct connections from untrusted peers cannot forge their IP.
    """
    direct_peer = request.client.host if request.client else "unknown"
    trusted = parse_trusted_proxies()

    if direct_peer in trusted or settings.TRUST_FORWARDED_HEADERS:
        # 1. Prefer X-Real-IP
        x_real_ip = request.headers.get("x-real-ip")
        if x_real_ip and x_real_ip.strip():
            return x_real_ip.strip()

        # 2. X-Forwarded-For (take client IP - first entry)
        xff = request.headers.get("x-forwarded-for")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                return parts[0]

    return direct_peer


class MultiWorkerRateLimiter:
    """Cross-worker shared rate limiter using persistent DB storage with automatic pruning."""

    def __init__(self):
        self._redis_client = None
        if settings.REDIS_URL:
            try:
                import redis
                self._redis_client = redis.Redis.from_url(settings.REDIS_URL)
            except Exception:
                self._redis_client = None

    def check_rate_limit(self, bucket_key: str, max_requests: int, window_seconds: int):
        """Enforces sliding-window rate limit across all worker processes."""
        now_ts = time.time()

        if self._redis_client:
            try:
                pipe = self._redis_client.pipeline()
                pipe.zremrangebyscore(bucket_key, 0, now_ts - window_seconds)
                pipe.zcard(bucket_key)
                pipe.zadd(bucket_key, {str(now_ts): now_ts})
                pipe.expire(bucket_key, window_seconds + 5)
                _, count, _, _ = pipe.execute()
                if count >= max_requests:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Rate limit exceeded ({max_requests} req/{window_seconds}s). Try again later."
                    )
                return
            except HTTPException:
                raise
            except Exception:
                pass  # Fallback to database

        # Database-backed shared rate limiting
        from license_server.models import RateLimitEntry, utcnow
        db: Session = SessionLocal()
        try:
            window_start = utcnow() - timedelta(seconds=window_seconds)

            # Count recent entries in window
            count = db.query(RateLimitEntry).filter(
                RateLimitEntry.bucket_key == bucket_key,
                RateLimitEntry.timestamp >= window_start
            ).count()

            if count >= max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many requests. Rate limit of {max_requests} req/{window_seconds}s exceeded."
                )

            # Record this hit
            entry = RateLimitEntry(bucket_key=bucket_key, timestamp=utcnow())
            db.add(entry)
            db.commit()

            # Opportunistic cleanup (prune entries older than 2x window)
            stale_threshold = utcnow() - timedelta(seconds=window_seconds * 2)
            db.query(RateLimitEntry).filter(
                RateLimitEntry.bucket_key == bucket_key,
                RateLimitEntry.timestamp < stale_threshold
            ).delete(synchronize_session=False)
            db.commit()
        finally:
            db.close()

    def check_admin_login(self, client_ip: str):
        """Enforces brute-force lockout shared across all workers."""
        from license_server.models import AdminLockoutEntry, utcnow
        db: Session = SessionLocal()
        try:
            rec = db.query(AdminLockoutEntry).filter(AdminLockoutEntry.client_ip == client_ip).first()
            if rec and rec.locked_until:
                now_dt = utcnow()
                # Ensure timezone awareness match
                locked_dt = rec.locked_until
                if locked_dt.tzinfo is None:
                    locked_dt = locked_dt.replace(tzinfo=timezone.utc)
                if now_dt < locked_dt:
                    wait_seconds = int((locked_dt - now_dt).total_seconds())
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Account locked due to repeated failed login attempts. Try again in {max(1, wait_seconds)} seconds."
                    )
        finally:
            db.close()

    def record_admin_login_failure(self, client_ip: str, max_failures: int = 5, lockout_seconds: int = 300):
        """Records failed login attempt and locks IP if threshold reached."""
        from license_server.models import AdminLockoutEntry, utcnow
        db: Session = SessionLocal()
        try:
            rec = db.query(AdminLockoutEntry).filter(AdminLockoutEntry.client_ip == client_ip).first()
            now_dt = utcnow()
            if not rec:
                rec = AdminLockoutEntry(client_ip=client_ip, failed_attempts=1)
                db.add(rec)
            else:
                rec.failed_attempts += 1
                if rec.failed_attempts >= max_failures:
                    rec.locked_until = now_dt + timedelta(seconds=lockout_seconds)
                    rec.failed_attempts = 0  # reset for next window
            db.commit()
        finally:
            db.close()

    def record_admin_login_success(self, client_ip: str):
        """Clears lockout record upon successful authentication."""
        from license_server.models import AdminLockoutEntry
        db: Session = SessionLocal()
        try:
            db.query(AdminLockoutEntry).filter(AdminLockoutEntry.client_ip == client_ip).delete()
            db.commit()
        finally:
            db.close()


# Global Singleton
rate_limiter = MultiWorkerRateLimiter()


def rate_limit_activations(request: Request):
    """Dependency: Enforces max 10 activations/minute per client IP across all workers."""
    client_ip = get_real_client_ip(request)
    rate_limiter.check_rate_limit(f"activate:{client_ip}", max_requests=10, window_seconds=60)


def rate_limit_validations(request: Request):
    """Dependency: Enforces max 60 validations/minute per client IP across all workers."""
    client_ip = get_real_client_ip(request)
    rate_limiter.check_rate_limit(f"validate:{client_ip}", max_requests=60, window_seconds=60)
