# -*- coding: utf-8 -*-
"""FastAPI License Server Main Application Entry Point with Embedded Admin UI."""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from license_server.config import settings
from license_server.database import init_license_db, get_db, SessionLocal
from license_server.models import AdminUser, License, Device, Activation
from license_server.crypto import hash_password, get_or_generate_ed25519_keys
from license_server.routes import client, admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Production configuration validations
    if settings.ENVIRONMENT == "production":
        if settings.SERVER_HMAC_SECRET.startswith("TMP-LICENSE-HMAC-DEV"):
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: SERVER_HMAC_SECRET must be configured with a strong, secret random key in production!"
            )
        if settings.JWT_SECRET.startswith("TMP-LICENSE-JWT-DEV"):
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: JWT_SECRET must be configured with a strong, secret random key in production!"
            )

    # Startup: initialize database and keys
    init_license_db()
    get_or_generate_ed25519_keys()
    
    # Ensure default admin user exists
    db = SessionLocal()
    try:
        admin_user = db.query(AdminUser).filter(AdminUser.username == "admin").first()
        if not admin_user:
            initial_password = os.getenv("ADMIN_INITIAL_PASSWORD", "AdminTumblr2026!Secure")
            if settings.ENVIRONMENT == "production" and initial_password == "AdminTumblr2026!Secure":
                raise RuntimeError(
                    "CRITICAL SECURITY ERROR: Cannot start License Server in 'production' mode with the default ADMIN_INITIAL_PASSWORD! "
                    "Please configure a strong, unique ADMIN_INITIAL_PASSWORD in your environment or .env file."
                )
            admin_user = AdminUser(
                username="admin",
                password_hash=hash_password(initial_password),
                role="admin",
                is_active=True
            )
            db.add(admin_user)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
    finally:
        db.close()
        
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Central Commercial Licensing Server for Tumblr Manager Pro",
    debug=settings.DEBUG,
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(client.router)
app.include_router(admin.router)


@app.get("/")
def root():
    """Root endpoint for Railway health probing and admin redirection."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/admin")


@app.get("/health")
def root_health():
    """Standard /health endpoint alias."""
    return health_check()


@app.get("/api/v1/health")
def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT
    }


@app.get("/admin", response_class=HTMLResponse)
def admin_portal():
    """Embedded Modern Web Admin Dashboard for the software owner."""
    return """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>لوحة إدارة التراخيص — Tumblr Manager Pro</title>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0F172A;
            --card-bg: #1E293B;
            --primary: #0284C7;
            --primary-hover: #0369A1;
            --text: #F8FAFC;
            --muted: #94A3B8;
            --border: #334155;
            --success: #10B981;
            --danger: #EF4444;
            --warning: #F59E0B;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Cairo', sans-serif; }
        body { background-color: var(--bg); color: var(--text); padding: 24px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
        .card { background-color: var(--card-bg); border-radius: 12px; border: 1px solid var(--border); padding: 20px; margin-bottom: 24px; }
        .title { font-size: 20px; font-weight: 700; color: #38BDF8; margin-bottom: 8px; }
        .subtitle { font-size: 13px; color: var(--muted); margin-bottom: 16px; }
        .btn { background: var(--primary); color: #fff; border: none; padding: 8px 18px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 14px; }
        .btn:hover { background: var(--primary-hover); }
        .btn-danger { background: var(--danger); }
        .btn-success { background: var(--success); }
        input, select { background: var(--bg); border: 1px solid var(--border); color: #fff; padding: 8px 12px; border-radius: 6px; font-size: 14px; outline: none; }
        table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
        th, td { padding: 10px 14px; text-align: right; border-bottom: 1px solid var(--border); }
        th { color: var(--muted); font-weight: 600; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: bold; }
        .badge-UNUSED { background: rgba(16, 185, 129, 0.2); color: var(--success); }
        .badge-ACTIVE, .badge-USED { background: rgba(2, 132, 199, 0.2); color: #38BDF8; }
        .badge-EXPIRED { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        .badge-REVOKED { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
        #authSection, #mainSection { display: none; }
        .grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-box { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
        .stat-num { font-size: 28px; font-weight: bold; color: #38BDF8; }
        .stat-label { font-size: 12px; color: var(--muted); }
        .key-box { background: #000; border: 1px dashed var(--primary); padding: 12px; border-radius: 6px; font-family: monospace; font-size: 16px; color: #34D399; margin: 8px 0; word-break: break-all; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Auth Section -->
        <div id="authSection" class="card" style="max-width: 400px; margin: 80px auto;">
            <div class="title" style="text-align: center;">🔐 تسجيل دخول المدير</div>
            <div class="subtitle" style="text-align: center;">لوحة التحكم المركزية بالسيريالات والتراخيص</div>
            <div style="display: flex; flex-direction: column; gap: 12px; margin-top: 16px;">
                <input type="text" id="username" placeholder="اسم المستخدم" value="admin">
                <input type="password" id="password" placeholder="كلمة المرور">
                <button class="btn" onclick="login()">دخول</button>
                <div id="loginError" style="color: var(--danger); font-size: 12px; display: none; text-align: center;"></div>
            </div>
        </div>

        <!-- Main Dashboard Section -->
        <div id="mainSection">
            <div class="header">
                <div>
                    <h1 style="font-size: 24px; color: #38BDF8;">Tumblr Manager Pro — License Authority</h1>
                    <p style="color: var(--muted); font-size: 12px;">إدارة المفاتيح التجريبية (60 دقيقة) والتراخيص الكاملة وتتبع العتاد</p>
                </div>
                <div>
                    <button class="btn btn-danger" onclick="logout()">تسجيل خروج</button>
                </div>
            </div>

            <!-- Stats -->
            <div class="grid-stats">
                <div class="stat-box">
                    <div class="stat-num" id="statTotal">0</div>
                    <div class="stat-label">إجمالي المفاتيح المنشأة</div>
                </div>
                <div class="stat-box">
                    <div class="stat-num" id="statUnused" style="color: var(--success);">0</div>
                    <div class="stat-label">مفاتيح جاهزة للتسليم (UNUSED)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-num" id="statActive" style="color: #38BDF8;">0</div>
                    <div class="stat-label">تراخيص نشطة / قيد التجربة</div>
                </div>
                <div class="stat-box">
                    <div class="stat-num" id="statExpired" style="color: var(--danger);">0</div>
                    <div class="stat-label">تجارب منتهية الصلاحية</div>
                </div>
            </div>

            <!-- Key Generator -->
            <div class="card">
                <div class="title">⚡ توليد سيريالات جديدة (Serial Generator)</div>
                <div class="subtitle">كل سيريال يتكون من 10 خانات فريدة مشفرة، وتمنح تجربة لمدة 60 دقيقة متصلة</div>
                <div style="display: flex; gap: 12px; flex-wrap: wrap; align-items: center;">
                    <label>العدد:</label>
                    <input type="number" id="genCount" value="1" min="1" max="100" style="width: 80px;">
                    <label>النوع:</label>
                    <select id="genType">
                        <option value="TRIAL">تجريبي (TRIAL 60 دقيقة)</option>
                        <option value="FULL">كامل مدى الحياة (FULL)</option>
                    </select>
                    <label>مدة التجربة (دقيقة):</label>
                    <input type="number" id="genMinutes" value="60" min="5" max="1440" style="width: 90px;">
                    <input type="text" id="genNotes" placeholder="ملاحظات (مثلاً: عميل X)" style="flex: 1; min-width: 180px;">
                    <button class="btn btn-success" onclick="generateKeys()">توليد المفاتيح الآن 🚀</button>
                </div>
                <div id="newKeysResult" style="display: none; margin-top: 16px;">
                    <div style="color: #38BDF8; font-weight: bold; margin-bottom: 6px;">المفاتيح المنشأة حديثاً (انسخها الآن وأعطها للعميل):</div>
                    <div id="keysDisplay" class="key-box"></div>
                </div>
            </div>

            <!-- Licenses List -->
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div class="title">📋 جدول التراخيص والأجهزة المسجلة</div>
                    <div style="display: flex; gap: 8px;">
                        <select id="filterStatus" onchange="loadLicenses()">
                            <option value="">جميع الحالات</option>
                            <option value="UNUSED">UNUSED (غير مستخدم)</option>
                            <option value="USED">USED / ACTIVE (مفعل)</option>
                            <option value="EXPIRED">EXPIRED (منتهي)</option>
                            <option value="REVOKED">REVOKED (ملغي)</option>
                        </select>
                        <button class="btn" onclick="loadLicenses()">تحديث 🔄</button>
                    </div>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>المعرف (ID)</th>
                            <th>تجزئة المفتاح (Hash Prefix)</th>
                            <th>النوع</th>
                            <th>الحالة الحالية</th>
                            <th>تاريخ الإنشاء</th>
                            <th>بداية التفعيل</th>
                            <th>الوقت المتبقي</th>
                            <th>بصمة الجهاز المربوط</th>
                            <th>إجراءات الإدارة</th>
                        </tr>
                    </thead>
                    <tbody id="licensesTableBody">
                        <tr><td colspan="9" style="text-align: center; color: var(--muted);">جاري التحميل...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let token = localStorage.getItem('license_admin_token');

        function checkAuth() {
            if (token) {
                document.getElementById('authSection').style.display = 'none';
                document.getElementById('mainSection').style.display = 'block';
                loadLicenses();
            } else {
                document.getElementById('authSection').style.display = 'block';
                document.getElementById('mainSection').style.display = 'none';
            }
        }

        async function login() {
            const u = document.getElementById('username').value;
            const p = document.getElementById('password').value;
            const errDiv = document.getElementById('loginError');
            errDiv.style.display = 'none';
            try {
                const res = await fetch('/api/v1/admin/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username: u, password: p})
                });
                const data = await res.json();
                if (res.ok) {
                    token = data.access_token;
                    localStorage.setItem('license_admin_token', token);
                    checkAuth();
                } else {
                    errDiv.innerText = data.detail || 'فشل تسجيل الدخول';
                    errDiv.style.display = 'block';
                }
            } catch(e) {
                errDiv.innerText = 'خطأ في الاتصال بالخادم';
                errDiv.style.display = 'block';
            }
        }

        function logout() {
            token = null;
            localStorage.removeItem('license_admin_token');
            checkAuth();
        }

        async function loadLicenses() {
            const filter = document.getElementById('filterStatus').value;
            const url = filter ? `/api/v1/admin/serials?status=${filter}` : '/api/v1/admin/serials';
            try {
                const res = await fetch(url, {
                    headers: {'Authorization': `Bearer ${token}`}
                });
                if (res.status === 401) return logout();
                const data = await res.json();
                renderTable(data);
            } catch(e) {
                console.error(e);
            }
        }

        function renderTable(licenses) {
            const tbody = document.getElementById('licensesTableBody');
            tbody.innerHTML = '';
            let total = licenses.length, unused = 0, active = 0, expired = 0;
            
            if (licenses.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--muted);">لا توجد مفاتيح مسجلة حتى الآن</td></tr>';
            }

            licenses.forEach(l => {
                if (l.status === 'UNUSED') unused++;
                if (l.status === 'ACTIVE' || l.status === 'USED') active++;
                if (l.status === 'EXPIRED') expired++;

                let remText = '-';
                if (l.time_remaining_seconds !== null && l.time_remaining_seconds !== undefined) {
                    const mins = Math.floor(l.time_remaining_seconds / 60);
                    remText = mins > 0 ? `${mins} دقيقة` : 'انتهى الوقت';
                }

                let actionsHtml = '';
                if (l.status !== 'REVOKED') {
                    actionsHtml += `<button class="btn btn-danger" style="padding: 4px 8px; font-size: 11px; margin-left: 4px;" onclick="revokeKey(${l.id})">إلغاء الترخيص</button>`;
                } else {
                    actionsHtml += `<span style="color: var(--muted); margin-left: 6px; font-size: 11px;">ملغي</span>`;
                }
                if (l.device_fingerprint_prefix && l.device_fingerprint_prefix !== '-') {
                    actionsHtml += `<button class="btn btn-success" style="padding: 4px 8px; font-size: 11px;" title="تصفير قيد التجربة لهذا الجهاز للسماح له بتفعيل كود تجريبي جديد" onclick="resetDeviceTrial(${l.id})">السماح بتجربة جديدة 🔄</button>`;
                }

                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>#${l.id}</td>
                    <td><code>${l.key_hash_prefix}</code></td>
                    <td><b>${l.license_type}</b></td>
                    <td><span class="badge badge-${l.status}">${l.status}</span></td>
                    <td>${l.created_at ? l.created_at.slice(0, 19).replace('T', ' ') : '-'}</td>
                    <td>${l.activated_at ? l.activated_at.slice(0, 19).replace('T', ' ') : 'لم يفعل بعد'}</td>
                    <td><b style="color: #38BDF8;">${remText}</b></td>
                    <td><code>${l.device_fingerprint_prefix || '-'}</code></td>
                    <td>${actionsHtml}</td>
                `;
                tbody.appendChild(tr);
            });

            document.getElementById('statTotal').innerText = total;
            document.getElementById('statUnused').innerText = unused;
            document.getElementById('statActive').innerText = active;
            document.getElementById('statExpired').innerText = expired;
        }

        async function generateKeys() {
            const count = parseInt(document.getElementById('genCount').value) || 1;
            const type = document.getElementById('genType').value;
            const mins = parseInt(document.getElementById('genMinutes').value) || 60;
            const notes = document.getElementById('genNotes').value;

            const res = await fetch('/api/v1/admin/serials/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({count: count, license_type: type, trial_minutes: mins, notes: notes})
            });
            const data = await res.json();
            if (res.ok) {
                const keys = data.keys.map(k => k.serial_key).join('  |  ');
                document.getElementById('keysDisplay').innerText = keys;
                document.getElementById('newKeysResult').style.display = 'block';
                loadLicenses();
            } else {
                alert(data.detail || 'حدث خطأ أثناء توليد المفاتيح');
            }
        }

        async function resetDeviceTrial(id) {
            if (!confirm(`هل أنت متأكد من رغبتك في السماح لهذا الجهاز بفترة تجريبية جديدة؟\n\nسيتم إزالة قيد التجربة عن هذا الجهاز حتى يتمكن العميل من إدخال وتفعيل سيريال تجريبي جديد.`)) return;
            try {
                const res = await fetch('/api/v1/admin/devices/reset-trial', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({license_id: id, reason: 'السماح بتجربة جديدة من لوحة الإدارة'})
                });
                const d = await res.json();
                if (res.ok) {
                    alert('✅ تم بنجاح! تم فك قيد التجربة عن هذا الجهاز.\n\nيمكن للعميل الآن إدخال السيريال التجريبي الجديد وتفعيله فوراً.');
                    loadLicenses();
                } else {
                    alert(d.detail || 'فشل تصفير سجل التجربة للجهاز');
                }
            } catch(e) {
                alert('خطأ في الاتصال بالخادم');
            }
        }

        async function revokeKey(id) {
            if (!confirm(`هل أنت متأكد من إلغاء الترخيص #${id}؟`)) return;
            const res = await fetch('/api/v1/admin/serials/revoke', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({license_id: id, reason: 'إلغاء يدوي من لوحة الإدارة'})
            });
            if (res.ok) {
                loadLicenses();
            } else {
                const d = await res.json();
                alert(d.detail || 'فشل الإلغاء');
            }
        }

        checkAuth();
    </script>
</body>
</html>
    """
