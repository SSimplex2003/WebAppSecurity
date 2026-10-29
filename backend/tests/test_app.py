import uuid

from sqlalchemy import select

from app.db import SessionLocal
from app.models import VaultItem
from app.sessions import session_store

PASSWORD = "correct horse battery staple"
COOKIE = "__Host-sid"
ITEMS = "/api/vault/items"
ITEM = {
    "title": "Example",
    "username": "alice",
    "password": "s3cret-Value!",
    "url": "https://example.com",
    "notes": "a note",
}


def unique_email() -> str:
    return f"user-{uuid.uuid4().hex[:10]}@example.com"


def register(client, email, password=PASSWORD):
    return client.post("/api/auth/register", json={"email": email, "master_password": password})


def login(client, email, password=PASSWORD):
    return client.post("/api/auth/login", json={"email": email, "master_password": password})


def signed_in(client, email=None):
    email = email or unique_email()
    assert register(client, email).status_code == 201
    response = login(client, email)
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf_token"]}


# ---- authentication ------------------------------------------------------


def test_register_then_login_sets_a_hardened_cookie(client):
    email = unique_email()
    assert register(client, email).status_code == 201

    response = login(client, email)
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == email
    assert body["csrf_token"]

    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith(f"{COOKIE.lower()}=")
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie
    assert "max-age" not in cookie and "expires" not in cookie
    assert "domain" not in cookie

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == email


def test_email_is_normalised(client):
    email = unique_email()
    assert register(client, f"  {email.upper()}  ").status_code == 201
    assert login(client, email).status_code == 200


def test_duplicate_registration_is_rejected(client):
    email = unique_email()
    assert register(client, email).status_code == 201
    assert register(client, email).status_code == 409


def test_weak_master_password_is_rejected_without_echoing_it(client):
    response = register(client, unique_email(), "pw-xyz-1")
    assert response.status_code == 422
    assert "pw-xyz-1" not in response.text
    assert "at least 12" in response.json()["detail"]


def test_invalid_email_and_unknown_fields_are_rejected(client):
    assert register(client, "not-an-email").status_code == 422
    extra = client.post(
        "/api/auth/register",
        json={"email": unique_email(), "master_password": PASSWORD, "is_admin": True},
    )
    assert extra.status_code == 422


def test_failed_logins_do_not_reveal_whether_the_account_exists(client):
    email = unique_email()
    register(client, email)
    wrong_password = login(client, email, "wrong password!!")
    unknown_user = login(client, unique_email(), "wrong password!!")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_repeated_failures_lock_the_account_out(client):
    email = unique_email()
    register(client, email)
    for _ in range(5):
        assert login(client, email, "wrong password!!").status_code == 401

    blocked = login(client, email, "wrong password!!")
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0
    assert login(client, email).status_code == 429


def test_logout_requires_csrf_and_ends_the_session(client):
    headers = signed_in(client)
    sid = client.cookies.get(COOKIE)

    assert client.post("/api/auth/logout").status_code == 403
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/auth/me").status_code == 401

    replay = client.get("/api/auth/me", headers={"Cookie": f"{COOKIE}={sid}"})
    assert replay.status_code == 401


# ---- session management --------------------------------------------------


def test_login_never_adopts_a_client_supplied_session_id(make_client):
    attacker_value = "attacker-chosen-session-id"
    victim = make_client()
    email = unique_email()
    register(victim, email)

    response = victim.post(
        "/api/auth/login",
        json={"email": email, "master_password": PASSWORD},
        headers={"Cookie": f"{COOKIE}={attacker_value}"},
    )
    assert response.status_code == 200
    issued = victim.cookies.get(COOKIE)
    assert issued and issued != attacker_value

    attacker = make_client()
    probe = attacker.get("/api/auth/me", headers={"Cookie": f"{COOKIE}={attacker_value}"})
    assert probe.status_code == 401


def test_each_login_gets_a_fresh_session_id(client):
    email = unique_email()
    register(client, email)
    login(client, email)
    first = client.cookies.get(COOKIE)
    login(client, email)
    second = client.cookies.get(COOKIE)
    assert first != second
    assert client.get("/api/auth/me", headers={"Cookie": f"{COOKIE}={first}"}).status_code == 401


def test_idle_timeout_ends_the_session(client):
    signed_in(client)
    sid = client.cookies.get(COOKIE)
    session_store._data[sid].last_seen -= 10_000
    assert client.get("/api/auth/me").status_code == 401


def test_absolute_timeout_ends_the_session(client):
    signed_in(client)
    sid = client.cookies.get(COOKIE)
    session_store._data[sid].created_at -= 100_000
    assert client.get("/api/auth/me").status_code == 401


# ---- vault ----------------------------------------------------------------


def test_vault_requires_authentication(client):
    assert client.get(ITEMS).status_code == 401
    assert client.post(ITEMS, json=ITEM, headers={"X-CSRF-Token": "x"}).status_code == 401


def test_state_changing_requests_require_the_csrf_token(client):
    headers = signed_in(client)
    assert client.post(ITEMS, json=ITEM).status_code == 403
    assert client.post(ITEMS, json=ITEM, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert client.post(ITEMS, json=ITEM, headers=headers).status_code == 201


def test_item_crud_roundtrip(client):
    headers = signed_in(client)

    created = client.post(ITEMS, json=ITEM, headers=headers)
    assert created.status_code == 201
    item = created.json()
    assert {key: item[key] for key in ITEM} == ITEM

    listed = client.get(ITEMS).json()
    assert [row["id"] for row in listed] == [item["id"]]
    assert {key: listed[0][key] for key in ITEM} == ITEM

    changed = {**ITEM, "title": "Renamed", "password": "new-s3cret"}
    updated = client.put(f"{ITEMS}/{item['id']}", json=changed, headers=headers)
    assert updated.status_code == 200
    assert updated.json()["title"] == "Renamed"
    assert client.get(ITEMS).json()[0]["password"] == "new-s3cret"

    assert client.delete(f"{ITEMS}/{item['id']}", headers=headers).status_code == 204
    assert client.get(ITEMS).json() == []
    assert client.delete(f"{ITEMS}/{item['id']}", headers=headers).status_code == 404


def test_users_cannot_see_or_modify_each_others_items(make_client):
    alice, bob = make_client(), make_client()
    alice_headers, bob_headers = signed_in(alice), signed_in(bob)
    item_id = alice.post(ITEMS, json=ITEM, headers=alice_headers).json()["id"]

    assert bob.get(ITEMS).json() == []
    assert bob.put(f"{ITEMS}/{item_id}", json=ITEM, headers=bob_headers).status_code == 404
    assert bob.delete(f"{ITEMS}/{item_id}", headers=bob_headers).status_code == 404
    assert len(alice.get(ITEMS).json()) == 1


def test_item_input_is_validated_server_side(client):
    headers = signed_in(client)
    assert client.post(ITEMS, json={**ITEM, "title": "   "}, headers=headers).status_code == 422
    assert client.post(ITEMS, json={**ITEM, "user_id": 1}, headers=headers).status_code == 422
    assert client.post(ITEMS, json={**ITEM, "notes": "x" * 5001}, headers=headers).status_code == 422
    for bad_url in ("javascript:alert(1)", "data:text/html,<script>1</script>", "ftp://x.test"):
        response = client.post(ITEMS, json={**ITEM, "url": bad_url}, headers=headers)
        assert response.status_code == 422, bad_url


def test_vault_data_is_encrypted_at_rest(client, db_file):
    marker = f"TOPSECRET{uuid.uuid4().hex}"
    headers = signed_in(client)
    payload = {
        "title": marker,
        "username": f"{marker}-user",
        "password": f"{marker}-pass",
        "url": f"https://{marker}.example.com",
        "notes": f"{marker}-notes",
    }
    assert client.post(ITEMS, json=payload, headers=headers).status_code == 201

    with SessionLocal() as db:
        rows = db.scalars(select(VaultItem)).all()
    assert rows
    stored = b"".join(row.ciphertext + row.nonce + row.auth_tag for row in rows)
    assert marker.encode() not in stored
    assert marker.encode() not in db_file.read_bytes()

    listed = client.get(ITEMS).json()
    assert any(row["title"] == marker for row in listed)


# ---- hardening ------------------------------------------------------------


def test_security_headers_are_sent(client):
    for path in ("/", "/health", "/api/auth/me"):
        headers = client.get(path).headers
        assert "default-src 'self'" in headers["content-security-policy"]
        assert "script-src 'self'" in headers["content-security-policy"]
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "no-referrer"
    assert client.get("/api/auth/me").headers["cache-control"] == "no-store"
    assert "strict-transport-security" not in client.get("/").headers


def test_frontend_and_health_are_served(client):
    assert client.get("/health").json() == {"status": "ok"}
    index = client.get("/")
    assert index.status_code == 200
    assert "Secure Password Manager" in index.text
    assert client.get("/app.js").status_code == 200
    assert client.get("/style.css").status_code == 200
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
