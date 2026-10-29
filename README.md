# Secure Password Manager

A web-based password manager built for the ICS0027 Web Application
Security course. The master password is sent once, over TLS, at login;
the server derives an encryption key from it and uses that key to
encrypt and decrypt vault items server-side for the duration of the
session. The key is never written to disk, only ciphertext and password
hashes are persisted.

- Design rationale, threat model and architecture diagram:
  [docs/checkpoint-1-design.md](docs/checkpoint-1-design.md)
- What is built so far and what is not:
  [docs/checkpoint-2-progress.md](docs/checkpoint-2-progress.md)

## Features

- **Accounts:** register and log in with a master password (minimum 12
  characters). Passwords are hashed with Argon2id.
- **Vault:** add, edit, delete and search items (title, username, password,
  URL, notes). Every item is encrypted server-side with AES-256-GCM before
  it reaches the database.
- **Sessions:** opaque random session IDs in an `HttpOnly`, `Secure`,
  `SameSite=Strict` cookie, regenerated on every login, 15 minute idle
  timeout, 12 hour absolute limit, CSRF token on every state-changing
  request.
- **Hardening:** login and registration rate limits, server-side input
  validation, strict Content-Security-Policy, no inline scripts.
- **TLS in development:** the dev server runs over HTTPS with a
  self-signed certificate it generates itself.

Not planned: sharing vaults between users, a browser extension/autofill,
breach monitoring. Stretch goal not yet built: TOTP multi-factor
authentication.

## Routes

| Method | Route | Purpose | Status |
|---|---|---|---|
| GET | `/` | Web interface (static files from `frontend/`) | Implemented |
| GET | `/health` | Liveness check | Implemented |
| POST | `/api/auth/register` | Create account, store Argon2id password hash + KDF salt | Implemented |
| POST | `/api/auth/login` | Verify password, derive the encryption key, start session | Implemented |
| GET | `/api/auth/me` | Current user and CSRF token | Implemented |
| POST | `/api/auth/logout` | Destroy session (and the in-memory encryption key with it) | Implemented |
| POST | `/api/auth/mfa/verify` | TOTP second factor | Stretch goal |
| GET | `/api/vault/items` | List and decrypt the caller's vault items | Implemented |
| POST | `/api/vault/items` | Encrypt and create a vault item | Implemented |
| PUT | `/api/vault/items/{id}` | Encrypt and update a vault item | Implemented |
| DELETE | `/api/vault/items/{id}` | Delete a vault item | Implemented |

## Tech stack

Python 3.14 / FastAPI, SQLAlchemy (SQLite by default, PostgreSQL
optional), `argon2-cffi` and `cryptography` for the crypto, in-memory
sessions by default (Redis optional), static HTML/CSS/vanilla JS
frontend. Full justification in the design doc.

## Running locally

You need Python 3.14 (pinned in `.python-version`) and Git. Docker is not
needed. Nothing else has to be installed or configured: the database,
the TLS certificate and all settings have working defaults.

1. Get the code and open a terminal in the repository root.
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   ```
   - Windows PowerShell: `.venv\Scripts\Activate.ps1`
   - Windows Git Bash: `source .venv/Scripts/activate`
   - macOS/Linux: `source .venv/bin/activate`

   (Use `python3` instead of `python` if your system does not have the
   `python` command.)
3. Install the dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
4. Start the server:
   ```bash
   python backend/dev_server.py
   ```
5. Open <https://localhost:8443>. The first run generates a self-signed
   certificate in `certs/`, so the browser shows a certificate warning
   once: choose "Advanced" and continue to localhost. Then create an
   account and add some items.

Stop the server with Ctrl+C. Sessions live in server memory, so
restarting the server logs everyone out (by design: the encryption keys
disappear with it).

**Optional: a trusted certificate.** If you have
[mkcert](https://github.com/FiloSottile/mkcert) installed, run
`mkcert -install` and then
`mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1 ::1`
before step 4 to avoid the browser warning.

**Reset local data.** Stop the server and delete `backend/data/` (the
SQLite database). Delete `certs/` to generate a new certificate.

### Tests

```bash
pip install -r backend/requirements-dev.txt
python -m pytest backend/tests
```

### Configuration

All settings are optional environment variables, listed in
[backend/.env.example](backend/.env.example). To use PostgreSQL and
Redis instead of the defaults, start them with `docker compose up -d`
(requires Docker Desktop) and set `DATABASE_URL` and `REDIS_URL` in
`backend/.env`.

### PyCharm

**Settings, Project: WebAppSecurity, Python Interpreter, Add Interpreter,
Existing**, then select `.venv\Scripts\python.exe` in the repository
root. To run from the IDE, create a Python run configuration with the
script `backend/dev_server.py`.

## Repository

Version-controlled with Git; a commit is made for every project
checkpoint per the course requirements.
