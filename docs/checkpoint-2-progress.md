# Checkpoint 2: Progress Note

Project: **Web-Based Secure Password Manager**
Course: ICS0027 Web Application Security, Week 9

## Deliverables

| Deliverable | Status | Where |
|---|---|---|
| Basic working web interface with the core flows | Done | `frontend/` |
| Basic server-side encryption and decryption | Done | `backend/app/crypto.py`, `backend/app/routes_vault.py` |
| Password hashing and secure session management | Done | `backend/app/crypto.py`, `sessions.py`, `deps.py`, `routes_auth.py` |
| Application served over TLS in the development setup | Done | `backend/dev_server.py` |
| Run instructions for a clean machine, tests | Done | `README.md`, `backend/tests/` |

The brief says "file encryption and decryption". In a password manager the
data that must be encrypted is the vault items (title, username, password,
URL, notes), so that is what is encrypted and decrypted server-side.

## What was built

**Web interface.** Static HTML, CSS and vanilla JavaScript served by the
same FastAPI process (same origin, so no CORS and no cross-site cookies).
Flows: create account, log in, log out, add / edit / delete / search items,
show or copy a password, generate a random password. All user data is put
on the page with `textContent`, never as HTML, and only `http(s)` URLs
become links.

**Encryption (server-side).** At login the server derives a 256-bit key
with Argon2id (64 MiB, 3 passes, 4 lanes) from the master password and the
user's random 16 byte salt. Each item is serialized to JSON and sealed with
AES-256-GCM using a fresh random 96-bit nonce and the user id as
associated data. The database stores only `ciphertext`, `nonce` and
`auth_tag` per item. The key exists only inside the session record.

**Authentication.** The master password is hashed with Argon2id (random
salt per user) for login verification. The hash and the encryption key use
different salts, so the stored hash cannot be turned into the key. Login
answers "Invalid email or password" for both unknown emails and wrong
passwords, and verifies against a dummy hash for unknown emails so the
response time does not reveal which accounts exist.

**Sessions.**

- Opaque 256-bit random id, stored server-side together with the
  encryption key and a per-session CSRF token.
- Cookie `__Host-sid`: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`,
  no `Domain`, no expiry (browser-session cookie).
- Idle timeout 15 minutes (sliding), absolute timeout 12 hours, both
  enforced on the server.
- Fixation: the server never accepts a client-chosen id. Every login
  discards the presented session and issues a new random one.
- CSRF: every non-GET request needs an `X-CSRF-Token` header matching the
  session's token (constant-time comparison).
- Brute force: 5 failed logins per email and 20 per IP per 15 minutes
  lock further attempts (HTTP 429 with `Retry-After`); 10 registrations
  per IP per hour.

**Other hardening.** Pydantic validation on every request with unknown
fields rejected, validation errors that never echo the rejected value,
vault queries always scoped by the session's user id (another user's item
returns 404), strict Content-Security-Policy and related security headers,
`Cache-Control: no-store` on API responses, interactive API docs disabled,
audit log lines for auth and vault events (no secrets).

**TLS.** `python backend/dev_server.py` creates a self-signed certificate
for `localhost` on first run and serves the app on `https://localhost:8443`.
The `Secure` cookie flag therefore works in development exactly as it will
in production.

## Differences from the Checkpoint 1 design

- SQLite and in-memory sessions are the zero-setup defaults. PostgreSQL and
  Redis are supported through `DATABASE_URL` and `REDIS_URL`. The Redis
  session store is implemented but is not covered by the automated tests.
- Each item is encrypted as one JSON blob (including the title) rather than
  field by field.
- HSTS is implemented but off by default, because browsers apply it to the
  whole `localhost` hostname rather than one port.
- Rate limiting is a sliding-window lockout held in process memory, not a
  progressive back-off.

## Known limitations and next steps

- TOTP multi-factor authentication (stretch goal) is not built.
- The key is derived directly from the master password, so there is no
  "change master password" (it would require re-encrypting every item) and
  no account recovery: a forgotten master password means lost data.
- Registering an email that already exists returns 409, which reveals that
  the account exists.
- Sessions and rate-limit counters are per process. Running several
  workers needs the Redis session store and a shared limiter.
- The dev server does not redirect HTTP to HTTPS; that belongs to the
  reverse proxy planned for deployment.
- The self-signed certificate triggers a browser warning once (mkcert
  avoids it, see the README).

## How to check it

1. Follow "Running locally" in the README and open `https://localhost:8443`.
2. Create an account, add an item, reload the page: you stay logged in and
   the item is still there.
3. Open the browser developer tools, Application tab, Cookies: `__Host-sid`
   is `HttpOnly`, `Secure` and `SameSite=Strict`.
4. Stop the server, open `backend/data/vault.db` with any SQLite viewer: the
   `vault_items` rows contain only binary `ciphertext`, `nonce` and
   `auth_tag`, and the `users` row holds an Argon2id hash and a salt.
5. Run `python -m pytest backend/tests` (after installing
   `backend/requirements-dev.txt`).
