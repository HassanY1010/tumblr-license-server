# Tumblr Manager Pro — Central Commercial License Server

Central Authority and Licensing Microservice for **Tumblr Manager Pro v2.0 Enterprise Edition**.

Provides cryptographic serial key generation, hardware binding (MachineGuid + Volume Serial), monotonic trial enforcement (60 continuous minutes), offline grace period management, and an embedded Arabic administrative web dashboard.

---

## 🛠️ Architecture & Tech Stack

- **Framework:** FastAPI (Python 3.11+) + Uvicorn ASGI
- **Asymmetric Signatures:** Ed25519 (Elliptic Curve Cryptography via `cryptography`)
- **Key Hashing:** HMAC-SHA256 with server-side salt
- **Database:** PostgreSQL (Production / Railway) / SQLite (Local testing)
- **Migrations:** Alembic
- **Anti-Brute Force:** Shared database / Redis sliding-window rate limiter + lockout defense

---

## 🚀 Deployment on Railway

1. Push this repository to your private GitHub repo (`HassanY1010/tumblr-license-server`).
2. In [Railway.app](https://railway.app):
   - Click **New Project** → **Deploy from GitHub repo** → select `tumblr-license-server`.
   - Add a **PostgreSQL Database** service to the project.
   - Link the PostgreSQL service: Railway automatically injects `DATABASE_URL`.
3. In your service's **Variables** tab, configure the following:
   - `ENVIRONMENT=production`
   - `ADMIN_INITIAL_PASSWORD=<strong_password>`
   - `SERVER_HMAC_SECRET=<random_64_hex>`
   - `JWT_SECRET=<random_64_hex>`
   - `ED25519_PRIVATE_KEY=<your_ed25519_private_key_pem>`
4. Railway will automatically build via **Nixpacks** and launch the service with health checks at `/api/v1/health`.

---

## 🌐 Endpoints

- **Root Redirect:** `/` → Redirects to `/admin`
- **Health Checks:** `/health` & `/api/v1/health`
- **Admin Dashboard:** `/admin` (Web UI)
- **Admin Auth:** `POST /api/v1/admin/login`
- **Generate Serials:** `POST /api/v1/admin/serials/generate`
- **Client Activation:** `POST /api/v1/licenses/activate`
- **Client Validation:** `POST /api/v1/licenses/validate`
- **Client Heartbeat:** `POST /api/v1/licenses/heartbeat`
- **Public Key Retrieval:** `GET /api/v1/licenses/public-key`
