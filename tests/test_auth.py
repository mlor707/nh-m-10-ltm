import time

import jwt
import pytest

from securetransfer.auth import (
    AuthError,
    JWT_ISSUER,
    JWT_TTL_SECONDS,
    TokenManager,
    hash_password,
    set_password,
    verify_password,
)


SECRET = "test-only-secret-key-with-at-least-32-bytes"


def test_scrypt_password_hash_roundtrip():
    encoded = hash_password("a-long-test-password")
    assert encoded.startswith("scrypt$")
    assert verify_password("a-long-test-password", encoded)
    assert not verify_password("a-different-password", encoded)
    assert not verify_password("a-long-test-password", None)


def test_password_length_is_enforced():
    with pytest.raises(ValueError):
        hash_password("short")
    assert not verify_password("short", hash_password("a-long-test-password"))


def test_token_has_one_hour_lifetime_and_verifies():
    manager = TokenManager(SECRET)
    token = manager.issue("alice")
    payload = jwt.decode(token, SECRET, algorithms=["HS256"], issuer=JWT_ISSUER)
    assert payload["sub"] == "alice"
    assert payload["exp"] - payload["iat"] == JWT_TTL_SECONDS == 3600
    assert manager.verify(token) == "alice"


def test_token_rejects_wrong_key_expiry_and_modified_lifetime():
    manager = TokenManager(SECRET)
    with pytest.raises(AuthError):
        TokenManager("another-test-secret-with-at-least-32-bytes").verify(manager.issue("alice"))
    expired = jwt.encode(
        {"iss": JWT_ISSUER, "sub": "alice", "iat": int(time.time()) - 7200,
         "exp": int(time.time()) - 3600},
        SECRET, algorithm="HS256",
    )
    with pytest.raises(AuthError):
        manager.verify(expired)
    altered_lifetime = jwt.encode(
        {"iss": JWT_ISSUER, "sub": "alice", "iat": int(time.time()),
         "exp": int(time.time()) + 300},
        SECRET, algorithm="HS256",
    )
    with pytest.raises(AuthError):
        manager.verify(altered_lifetime)


def test_token_secret_must_be_long_enough():
    with pytest.raises(ValueError):
        TokenManager("too-short")


def test_set_password_updates_user_record(tmp_path):
    users_path = tmp_path / "users.json"
    users_path.write_text('{"alice": {"role": "admin", "clearance": "SECRET"}}', encoding="utf-8")
    set_password(str(users_path), "alice", "a-long-test-password")
    import json
    record = json.loads(users_path.read_text(encoding="utf-8"))["alice"]
    assert verify_password("a-long-test-password", record["password_hash"])
