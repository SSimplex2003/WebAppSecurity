# Secure Password Manager

A web-based, zero-knowledge password manager built for the ICS0027 Web
Application Security course. The server and database only ever see
ciphertext and password verifiers. The master password and decrypted
vault exist only in the user's browser.

Design rationale, the threat model and the architecture diagram live in
[docs/checkpoint-1-design.md](docs/checkpoint-1-design.md).

## Scope

- Registration and login behind a single master password, with
  server-side sessions (not JWT) so access can be revoked instantly.
- Client-side key derivation (Argon2id) and encryption/decryption
  (AES-256-GCM via the Web Crypto API) of every vault item.
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
| POST | `/api/auth/register` | Create account, store KDF salt + verifier + wrapped Vault Key | Checkpoint 2 |
| POST | `/api/auth/login` | Verify login hash, start session | Checkpoint 2 |
| POST | `/api/auth/logout` | Destroy session | Checkpoint 2 |
| POST | `/api/auth/mfa/verify` | TOTP second factor | Stretch goal |
| GET | `/api/vault/key` | Fetch the caller's wrapped Vault Key | Checkpoint 2 |
| GET | `/api/vault/items` | List the caller's encrypted vault items | Checkpoint 2 |
| POST | `/api/vault/items` | Create an encrypted vault item | Checkpoint 2 |
| PUT | `/api/vault/items/:id` | Update an encrypted vault item | Checkpoint 2 |
| DELETE | `/api/vault/items/:id` | Delete a vault item | Checkpoint 2 |

## Tech stack

Node.js/Express (TypeScript) API, PostgreSQL via Prisma, Redis-backed
sessions, TLS termination via a reverse proxy in production. Full
justification in the design doc.

## Running locally

Currently only the API health check and a placeholder frontend page are
implemented; the rest lands in Checkpoint 2. Requires Node.js 18+ and npm.

1. Install backend dependencies and configure environment (from the
   `backend/` folder):
   ```bash
   cd backend
   npm install
   ```
   Then copy `.env.example` to `.env`:
   - macOS/Linux/Git Bash: `cp .env.example .env`
   - Windows PowerShell: `Copy-Item .env.example .env`
2. Run the API in dev mode:
   ```bash
   npm run dev
   ```
   The health check is then available at `http://localhost:3000/health`.
3. Open `frontend/index.html` directly in a browser to view the
   placeholder page.

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
