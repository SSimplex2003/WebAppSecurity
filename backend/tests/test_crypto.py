import pytest
from cryptography.exceptions import InvalidTag

from app import crypto


def test_password_hash_verifies_and_rejects():
    stored = crypto.hash_password("correct horse battery staple")
    assert stored.startswith("$argon2id$")
    assert crypto.verify_password(stored, "correct horse battery staple")
    assert not crypto.verify_password(stored, "wrong password entirely")
    assert not crypto.verify_password("not-a-valid-hash", "anything")


def test_hash_is_salted():
    first = crypto.hash_password("same password, twice")
    second = crypto.hash_password("same password, twice")
    assert first != second


def test_key_derivation_is_deterministic_and_salt_dependent():
    salt = crypto.new_kdf_salt()
    key = crypto.derive_key("a long enough password", salt)
    assert len(key) == crypto.KEY_LENGTH
    assert key == crypto.derive_key("a long enough password", salt)
    assert key != crypto.derive_key("a long enough password", crypto.new_kdf_salt())
    assert key != crypto.derive_key("a different password!", salt)


def test_item_roundtrip():
    key = crypto.derive_key("a long enough password", crypto.new_kdf_salt())
    fields = {"title": "Bank", "password": "p@ss é中"}
    ciphertext, nonce, tag = crypto.encrypt_item(key, 7, fields)
    assert len(nonce) == crypto.NONCE_LENGTH
    assert len(tag) == crypto.TAG_LENGTH
    assert b"Bank" not in ciphertext
    assert crypto.decrypt_item(key, 7, ciphertext, nonce, tag) == fields


def test_nonce_is_never_reused():
    key = crypto.derive_key("a long enough password", crypto.new_kdf_salt())
    first = crypto.encrypt_item(key, 1, {"title": "same"})
    second = crypto.encrypt_item(key, 1, {"title": "same"})
    assert first[1] != second[1]
    assert first[0] != second[0]


def test_wrong_key_wrong_user_and_tampering_are_rejected():
    salt = crypto.new_kdf_salt()
    key = crypto.derive_key("a long enough password", salt)
    ciphertext, nonce, tag = crypto.encrypt_item(key, 1, {"title": "x"})

    other_key = crypto.derive_key("another long password", salt)
    with pytest.raises(InvalidTag):
        crypto.decrypt_item(other_key, 1, ciphertext, nonce, tag)

    with pytest.raises(InvalidTag):
        crypto.decrypt_item(key, 2, ciphertext, nonce, tag)

    flipped = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    with pytest.raises(InvalidTag):
        crypto.decrypt_item(key, 1, flipped, nonce, tag)

    bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
    with pytest.raises(InvalidTag):
        crypto.decrypt_item(key, 1, ciphertext, nonce, bad_tag)
