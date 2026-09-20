# Secure Password Manager

A web-based password manager built for the ICS0027 Web Application
Security course. The master password is sent once, over TLS, at login;
the server derives an encryption key from it and uses that key to
encrypt and decrypt vault items server-side for the duration of the
session. The key is never written to disk, only PostgreSQL ciphertext
and password hashes are persisted.

Design rationale, the threat model and the architecture diagram live in
[docs/checkpoint-1-design.md](docs/checkpoint-1-design.md), including the
tradeoffs of this server-side encryption model versus a zero-knowledge one.

## Scope

- Registration and login behind a single master password, with
  server-side sessions (not JWT) so access can be revoked instantly.
- Server-side key derivation (Argon2id) and encryption/decryption
  (AES-256-GCM) of every vault item.
- CRUD for vault items: title, username, password, URL, notes.
- Defense against the attack classes covered so far: HTML/content
  injection, XSS, input tampering and client-side control bypass, CSRF.
- Stretch goal: TOTP-based multi-factor authentication.

Not planned for this project: sharing vaults between users, a browser
extension/autofill, breach-monitoring integrations.

## Planned routes

| Method | Route | Purpose | Status |
|---|---|---|---|
| GET | `/health` | Liveness check | Implemented |
| POST | `/api/auth/register` | Create account, store Argon2id password hash + KDF salt | Checkpoint 2 |
| POST | `/api/auth/login` | Verify password, derive the encryption key, start session | Checkpoint 2 |
| POST | `/api/auth/logout` | Destroy session (and the in-memory encryption key with it) | Checkpoint 2 |
| POST | `/api/auth/mfa/verify` | TOTP second factor | Stretch goal |
| GET | `/api/vault/items` | List and decrypt the caller's vault items | Checkpoint 2 |
| POST | `/api/vault/items` | Encrypt and create a vault item | Checkpoint 2 |
| PUT | `/api/vault/items/:id` | Encrypt and update a vault item | Checkpoint 2 |
| DELETE | `/api/vault/items/:id` | Delete a vault item | Checkpoint 2 |

## Tech stack

Python/FastAPI API, PostgreSQL via SQLAlchemy, Redis-backed sessions
(holding the per-session encryption key in memory only), TLS termination
via a reverse proxy in production. Full justification in the design doc.

## Running locally

Currently only the API health check is implemented; the rest, including
the frontend, lands in Checkpoint 2. Requires Python 3.14
(pinned in `.python-version`). The virtual environment lives at the
repository root (`.venv`), not inside `backend/`, so PyCharm and the
commands below agree on a single interpreter.

1. From the repository root, create the virtual environment and install
   backend dependencies:
   ```bash
   python -m venv .venv
   ```
   Activate it:
   - macOS/Linux/Git Bash: `source .venv/bin/activate` (or `source .venv/Scripts/activate` on Git Bash for Windows)
   - Windows PowerShell: `.venv\Scripts\Activate.ps1`

   Then install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
2. Copy `backend/.env.example` to `backend/.env`:
   - macOS/Linux/Git Bash: `cp backend/.env.example backend/.env`
   - Windows PowerShell: `Copy-Item backend\.env.example backend\.env`
3. Run the API in dev mode, still from the repository root:
   ```bash
   uvicorn app.main:app --reload --port 8000 --app-dir backend
   ```
   The health check is then available at `http://localhost:8000/health`,
   and interactive API docs at `http://localhost:8000/docs`.

In PyCharm: **Settings → Project: WebAppSecurity → Python Interpreter →
Add Interpreter → Existing → `.venv\Scripts\python.exe`** (repository
root). That replaces whatever interpreter is currently selected with
this one venv.

The `DATABASE_URL`/`REDIS_URL` values in `.env` are not used yet, the
health check has no dependency on Postgres or Redis. Once Checkpoint 2
wires up the database and sessions, start that local infrastructure first
with:
```bash
docker compose up -d
```
(requires Docker Desktop; needed only from that point on).

## Repository

Version-controlled with Git; a commit is made for every project
checkpoint per the course requirements.
