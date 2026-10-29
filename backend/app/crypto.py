import json
import os

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF_TIME_COST = 3
KDF_MEMORY_KIB = 65536
KDF_PARALLELISM = 4
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
TAG_LENGTH = 16

_hasher = PasswordHasher(
    time_cost=KDF_TIME_COST,
    memory_cost=KDF_MEMORY_KIB,
    parallelism=KDF_PARALLELISM,
)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


# Verified against when the email is unknown so that a missing account costs
# the same time as a wrong password.
DUMMY_PASSWORD_HASH = hash_password("not-a-real-password")


def new_kdf_salt() -> bytes:
    return os.urandom(SALT_LENGTH)


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=KDF_TIME_COST,
        memory_cost=KDF_MEMORY_KIB,
        parallelism=KDF_PARALLELISM,
        hash_len=KEY_LENGTH,
        type=Type.ID,
    )


def _aad(user_id: int) -> bytes:
    return f"user:{user_id}".encode("utf-8")


def encrypt_item(key: bytes, user_id: int, fields: dict) -> tuple[bytes, bytes, bytes]:
    plaintext = json.dumps(fields, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(NONCE_LENGTH)
    sealed = AESGCM(key).encrypt(nonce, plaintext, _aad(user_id))
    return sealed[:-TAG_LENGTH], nonce, sealed[-TAG_LENGTH:]


def decrypt_item(key: bytes, user_id: int, ciphertext: bytes, nonce: bytes, tag: bytes) -> dict:
    plaintext = AESGCM(key).decrypt(nonce, ciphertext + tag, _aad(user_id))
    return json.loads(plaintext.decode("utf-8"))
