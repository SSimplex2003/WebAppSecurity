# Checkpoint 1: Threat Model & Architecture

Project: **Web-Based Secure Password Manager**
Course: ICS0027 Web Application Security, Week 4

**Contents:** [Scope](#1-scope) · [Architecture](#2-system-architecture) ·
[Threat Model](#3-threat-model) · [Tech Stack](#4-technology-stack) ·
[Auth & Sessions](#5-authentication--session-model) ·
[Crypto Design](#6-cryptographic-design) · [Repository](#7-repository)

## 1. Scope

A web application that lets a user store, retrieve and organize login
credentials ("vault items") behind a single master password. Encryption is
performed **server-side**: the master password is sent once, over TLS, at
login, the server derives an encryption key from it and uses that key to
encrypt and decrypt vault items for the duration of the session. The server
never writes the master password or the derived key to disk.

In scope for the semester project:

- Registration / login with a master password, session-based auth.
- Server-side key derivation (Argon2id) and encryption/decryption
  (AES-256-GCM) of every vault item.
- CRUD on vault items (title, username, password, URL, notes), stored
  encrypted at rest.
- CSRF and XSS-hardened rendering of user-supplied vault content.
- Optional stretch goal: TOTP-based multi-factor authentication.

Out of scope: password sharing between users, browser extension/autofill,
breach-monitoring integrations.

### Design tradeoff

This is deliberately **not** a zero-knowledge design. The server sees the
plaintext master password once per login and holds a derived encryption key
in memory for the session, which means a compromise of the running server
process during an active session can expose that user's vault. This is
simpler to build and to explain than a client-side (zero-knowledge) design,
and it is the model this checkpoint's brief describes. The mitigations in
§3 and §6 are chosen specifically to keep that exposure as small as
possible: the key is never persisted, never logged, and only lives as long
as the session does.

## 2. System Architecture

```
 BROWSER                                    [ trust boundary: user's device ]
   - types the master password, sends it once, at login/register
   - otherwise sends/receives plaintext vault fields for display & editing
     |
     |  every request/response, over TLS
     v
 =====================================================================
 TLS 1.2+ (HTTPS), terminated by a Caddy / nginx reverse proxy
                                                [ trust boundary: network ]
 =====================================================================
     |
     v
 APPLICATION SERVER                [ trust boundary: application server ]
   FastAPI (Python)
     - security headers, session + CSRF checks on every request
     - derives the encryption key (Argon2id) once, at login
     - encrypts / decrypts vault items (AES-256-GCM) on every vault call
     |
     |-- session id (HttpOnly cookie) ------> REDIS
     |                                         session record holds the
     |                                         encryption key, in memory
     |                                         only, never written to disk
     |
     `-- parameterized queries (SQLAlchemy) -> POSTGRESQL
                                        [ trust boundary: data tier,
                                          least trusted, ciphertext only ]
                                          users:       email,
                                                       Argon2id password hash,
                                                       KDF salt
                                          vault_items: ciphertext + nonce
                                                       + authTag only
```

**Where credentials are encrypted:** the master password itself is never
encrypted or stored, it is hashed (Argon2id) once at registration purely to
verify future logins. The actual vault items (username, password, URL,
notes) are encrypted **server-side**, inside the FastAPI process, using a
key derived from the master password at login time. That key lives only in
the Redis-backed session, never in PostgreSQL, never on disk, and never in
application logs.

**Trust boundaries:**

1. **User device to network:** the browser holds the master password only
   for the moment it is typed and submitted; TLS is mandatory for every
   request so it is never sent in the clear.
2. **Network to application server:** the server is trusted with the
   plaintext master password at login and with plaintext vault content on
   every subsequent request/response, this is the boundary where the
   design tradeoff in §1 applies.
3. **Application server to data tier:** the database is trusted the least.
   It must remain safe to leak on its own (ciphertext, password hashes and
   salts only) and is reached only through parameterized queries, never raw
   SQL built from request input.

## 3. Threat Model

Mapped to the **OWASP Top 10 (2025)** and to the attack classes covered in
Weeks 1-4 (HTTP/cookies, client-side controls & HTML injection, XSS).

**T1: Broken Access Control** (OWASP A01:2025)
Scenario: attacker changes a vault item ID in the URL/body and reads or
edits another user's credentials (IDOR).
Mitigation: every vault query is scoped server-side by the session's user
ID, never by a client-supplied user/owner field; deny-by-default
authorization dependency on all `/api/vault/*` routes.

**T2: Security Misconfiguration** (OWASP A02:2025)
Scenario: verbose error pages, default DB credentials, or an exposed debug
endpoint leak internals.
Mitigation: security headers on every response, generic error responses in
production (FastAPI's debug/docs pages disabled outside dev), no default
accounts, secrets only via environment variables (never committed),
least-privilege DB role.

**T3: Software Supply Chain Failures** (OWASP A03:2025)
Scenario: a compromised PyPI dependency (e.g. a crypto or logging package)
exfiltrates master passwords or derived keys from memory.
Mitigation: lockfile committed (pinned `requirements.txt`), `pip-audit`/
Dependabot in CI, minimal dependency surface for anything touching secrets,
pin and review versions before upgrading.

**T4: Cryptographic Failures** (OWASP A04:2025)
Scenario: server or DB breach exposes vault contents; a weak KDF lets a
stolen password hash be brute-forced offline.
Mitigation: Argon2id for both the login verifier and the encryption-key
derivation, tuned to OWASP-recommended cost parameters; AES-256-GCM with a
unique nonce per item; TLS 1.2+ in transit; the DB alone (without a live
session) yields only ciphertext and salts.

**T5: Injection** (OWASP A05:2025)
Scenario: `' OR '1'='1` style payload in the login or search field against
the database.
Mitigation: all DB access through SQLAlchemy parameterized queries/ORM,
never string-concatenated SQL; Pydantic request-schema validation
(allow-list) on every endpoint.

**T6: HTML Injection & Content Spoofing** (Week 3)
Scenario: attacker stores a `<form>`/`<meta>` tag in a vault item's title
or notes field that renders as a fake login prompt to phish the master
password.
Mitigation: vault content is always inserted via `textContent`/safe DOM
APIs on the frontend, never raw HTML interpolation; strict
Content-Security-Policy (no inline scripts/forms) as defense in depth.

**T7: Cross-Site Scripting** (Week 4 / OWASP A05:2025)
Scenario: a stored XSS payload in a vault field runs JavaScript that reads
other decrypted vault fields on the page or exfiltrates the session cookie.
Mitigation: output encoding on every render path; CSP with no
`unsafe-inline`; session cookie marked `HttpOnly` so it is unreadable even
if a script executes; input length/type validation server-side.

**T8: Bypassing Client-Side Controls** (Week 3)
Scenario: attacker disables a client-side password-strength check or
rate-limit via devtools/Burp and submits a weak master password, or
brute-forces `/login` directly against the API.
Mitigation: every client-side check is duplicated server-side (password
policy, field limits) with Pydantic validators; the server never trusts a
client-reported security decision (e.g. "already validated").

**T9: Input Tampering** (Client-Server Communication, Week 2)
Scenario: attacker edits a hidden field or JSON body parameter (`user_id`,
`vault_id`, `role`) in transit to act on another user's data.
Mitigation: server identity comes only from the authenticated session,
never from client-supplied identifiers; Pydantic schemas reject unexpected/
extra fields.

**T10: Authentication Failures** (OWASP A07:2025)
Scenario: credential stuffing or brute force against `/login`; session
fixation by pre-setting a victim's session ID.
Mitigation: Argon2id-hashed login verifier, rate limiting + progressive
lockout on auth endpoints, session ID regenerated on every successful login
(§5), optional TOTP MFA.

**T11: Cross-Site Request Forgery** (Week 10 preview, relevant from the
first auth flow)
Scenario: a malicious page auto-submits a request (e.g. "delete vault
item", "change master password") using the victim's live session.
Mitigation: `SameSite=Strict` session cookie, synchronizer CSRF token
required on all state-changing requests, re-authentication required for
changing the master password or exporting the vault.

**T12: Active-session server compromise** (accepted tradeoff of a
server-side encryption model, §1)
Scenario: server compromise (e.g. RCE, memory dump) while a user's session
is active exposes that session's in-memory encryption key, letting the
attacker decrypt that one user's vault until the session expires.
Mitigation: short session TTL, key exists only in Redis and only for the
session's lifetime, never written to disk or logs; Redis restricted to the
application network, not internet-facing; monitored/alerted for anomalous
decrypt volume (see T13).

**T13: Security Logging & Alerting Failures** (OWASP A09:2025)
Scenario: mass export or repeated failed logins go unnoticed because
nothing is logged.
Mitigation: structured audit log of auth events and vault access (metadata
only, never secrets or key material), alerting thresholds on failed logins
/ bulk export.

## 4. Technology Stack

**Backend framework: Python 3.14 / FastAPI**
Pydantic gives request-schema validation for free (mitigates A05 Injection
and input tampering at the boundary), async I/O suits an API of small
JSON/ciphertext payloads, auto-generated OpenAPI docs are useful for
demoing the design, and it is the language the team can read and explain
most confidently.

**Frontend: static HTML/CSS/vanilla JS calling the API with `fetch`**
No build step or framework auth quirks to reason about; keeps the
request/response flow (and therefore the trust boundary) easy to trace end
to end during the presentation.

**Database: PostgreSQL + SQLAlchemy ORM**
Parameterized queries by default (mitigates A05 Injection), relational
integrity between users and vault items, straightforward migrations,
first-class Docker support for local dev.

**Server-side crypto: `argon2-cffi` + `cryptography` (pyca)**
Argon2id (via `argon2-cffi`) handles both the login verifier and the raw
key derivation; `cryptography` handles AES-256-GCM. Both are the standard,
audited Python libraries for these primitives. Argon2id is OWASP's current
recommendation for password-based key derivation (memory-hard, resists
GPU/ASIC cracking) over faster hashes like plain PBKDF2/bcrypt.

**Session store: Redis, keyed by an opaque random session ID**
The derived encryption key must live somewhere server-side for the
session's duration; Redis keeps it in memory only (never on disk), and
sessions can be revoked instantly (logout-everywhere, admin action),
unlike a self-contained signed cookie.

**Reverse proxy / TLS: Caddy (or nginx) in front of FastAPI**
Automatic certificate management (Let's Encrypt) in production; local
development uses a self-signed cert via `mkcert` so HTTPS-only behaviors
(secure cookies, HSTS) can be tested locally instead of assumed.

**TLS plan:** TLS 1.2+ only, HTTP requests redirected to HTTPS, `HSTS`
enabled once the certificate chain is verified in each environment. No
application route is ever served over plain HTTP outside of local dev, this
matters even more here than in a zero-knowledge design because the master
password and plaintext vault fields cross the network on every relevant
request.

## 5. Authentication & Session Model

- **Cookie:** `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`. The cookie
  carries only an opaque session ID, never the encryption key itself, and
  is never readable from JavaScript.
- **Lifetime:** 15-minute idle timeout, 12-hour absolute maximum. When a
  session expires, Redis drops its record, including the derived encryption
  key, so the vault becomes unreadable again until the next login.
- **Fixation prevention:** the session ID is regenerated immediately after
  a successful login (issuing a fresh Redis-backed session), and any
  pre-authentication session is discarded rather than "upgraded" in place.
- **CSRF:** synchronizer token pattern. A per-session token is required on
  every non-GET request and validated server-side before the request is
  processed.
- **Brute-force protection:** rate limiting and progressive lockout on
  `/api/auth/login` and `/api/auth/register`, independent of any client-side
  throttling (see T8).
- **Multi-factor authentication (stretch goal):** TOTP (RFC 6238) as a
  second factor, required at login before the encryption key is derived and
  the session is issued. Planned after the Checkpoint 2 core flow is
  working.

## 6. Cryptographic Design

Goal: minimize what a database-only breach exposes, and be explicit about
what an active-session/server compromise can additionally expose (§3, T12).

1. **Registration.** The client submits `{email, master_password}` over
   TLS. The server generates a random per-user KDF salt and computes
   `password_hash = Argon2id(master_password)` purely for future login
   verification. Both `password_hash` and `kdf_salt` are stored; the
   plaintext master password is discarded from server memory immediately
   and never logged.
2. **Login.** The client submits `{email, master_password}` over TLS again.
   The server verifies `password_hash`, then, on success, separately
   derives `encryption_key = Argon2id_raw(master_password, kdf_salt,
   params)`, a raw 256-bit key used only for encrypting/decrypting this
   user's vault items. The master password is discarded from memory right
   after this step.
3. **Session.** The server creates a new Redis session (regenerated ID,
   §5) and stores `encryption_key` inside that session record only. The
   browser receives an opaque session ID in an `HttpOnly` cookie, nothing
   key-related ever reaches the client.
4. **Vault items.** On every create/update, the server encrypts the item's
   fields with `encryption_key` (AES-256-GCM, a fresh random nonce per
   item) before writing to PostgreSQL. On every read, it decrypts using the
   same session-held key before returning plaintext JSON to the browser
   over TLS.
5. **Logout / expiry.** The Redis session record (and the key inside it) is
   deleted. Nothing about the key was ever written to PostgreSQL or to disk
   at any point.

**What is encrypted server-side:** every vault item's fields (username,
password, URL, notes), using AES-256-GCM with a key derived server-side
from the master password at login.

**What the database stores:** email, `Argon2id(password)` verifier, the
per-user KDF salt, and per-item `{ciphertext, nonce, authTag}` plus
non-sensitive metadata (timestamps, item ID).

**What it never stores:** the plaintext master password, the derived
encryption key, or any decrypted vault content.

## 7. Repository

See the top-level [README](../README.md) for scope, planned routes and how
to run the current scaffold locally. This checkpoint intentionally ships
only a minimal backend health check. The registration/login flow,
server-side crypto, vault CRUD and the frontend itself are Checkpoint 2
work.
