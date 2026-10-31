"""Phân quyền RBAC + mức mật tài liệu.

TODO (mở rộng): thay UserStore bằng LDAP (ldap3) và xác thực Kerberos (SSO).
"""
from __future__ import annotations
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

import jwt

from dataclasses import dataclass
from enum import Enum, IntEnum

SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64
SCRYPT_SALT_BYTES = 16
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 1024
JWT_TTL_SECONDS = 60 * 60
JWT_ISSUER = "securetransfer"


class Level(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3


class Role(str, Enum):
    ADMIN = "admin"
    STAFF = "staff"
    AUDITOR = "auditor"


PERMISSIONS = {
    Role.ADMIN: {"send", "receive", "audit", "benchmark"},
    Role.STAFF: {"send", "receive"},
    Role.AUDITOR: {"audit"},
}


class AuthError(Exception):
    pass


@dataclass
class User:
    username: str
    role: Role
    clearance: Level
    password_hash: str | None = None


def hash_password(password: str) -> str:
    if not isinstance(password, str) or not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
        raise ValueError(f"Mật khẩu phải dài từ {PASSWORD_MIN_LENGTH} đến {PASSWORD_MAX_LENGTH} ký tự")
    salt = secrets.token_bytes(SCRYPT_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    hash_text = base64.urlsafe_b64encode(derived).decode("ascii").rstrip("=")
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt_text}${hash_text}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not isinstance(password, str) or len(password) > PASSWORD_MAX_LENGTH:
        return False
    if not isinstance(encoded, str):
        return False
    try:
        algorithm, n_text, r_text, p_text, salt_text, hash_text = encoded.split("$")
        n, r, p = int(n_text), int(r_text), int(p_text)
        if algorithm != "scrypt" or (n, r, p) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
            return False
        salt = _decode_base64url(salt_text)
        expected = _decode_base64url(hash_text)
        if len(salt) != SCRYPT_SALT_BYTES or len(expected) != SCRYPT_DKLEN:
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeEncodeError):
        return False


def _decode_base64url(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def set_password(path: str, username: str, password: str) -> None:
    users_path = Path(path)
    users = json.loads(users_path.read_text(encoding="utf-8"))
    if not isinstance(users, dict) or username not in users:
        raise ValueError(f"Không tìm thấy người dùng '{username}' trong {users_path}")
    if not isinstance(users[username], dict):
        raise ValueError(f"Cấu hình người dùng '{username}' không hợp lệ")
    users[username]["password_hash"] = hash_password(password)
    temporary = users_path.with_name(f".{users_path.name}.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_text(json.dumps(users, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, users_path)
    finally:
        if temporary.exists():
            temporary.unlink()


class TokenManager:
    def __init__(self, secret: str, ttl_seconds: int = JWT_TTL_SECONDS):
        if len(secret.encode("utf-8")) < 32:
            raise ValueError("ST_JWT_SECRET phải có ít nhất 32 byte")
        if ttl_seconds < 1:
            raise ValueError("Thời hạn JWT phải lớn hơn 0")
        self._secret = secret
        self.ttl_seconds = ttl_seconds

    def issue(self, username: str) -> str:
        now = int(time.time())
        return jwt.encode(
            {"iss": JWT_ISSUER, "sub": username, "iat": now, "exp": now + self.ttl_seconds},
            self._secret,
            algorithm="HS256",
        )

    def verify(self, token: str) -> str:
        try:
            payload: Any = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                issuer=JWT_ISSUER,
                options={"require": ["iss", "sub", "iat", "exp"]},
            )
            if not isinstance(payload, dict) or not isinstance(payload.get("sub"), str):
                raise ValueError("Token không hợp lệ")
            if type(payload.get("iat")) is not int or type(payload.get("exp")) is not int:
                raise ValueError("Token không hợp lệ")
            if payload["exp"] - payload["iat"] != self.ttl_seconds:
                raise ValueError("Token không hợp lệ")
            return payload["sub"]
        except (jwt.InvalidTokenError, ValueError, TypeError, KeyError) as exc:
            raise AuthError("Token không hợp lệ hoặc đã hết hạn") from exc


def authorize(user: User, action: str, level: Level = Level.PUBLIC) -> None:
    if action not in PERMISSIONS[user.role]:
        raise AuthError(f"Vai trò '{user.role.value}' không được phép '{action}'")
    if action in ("send", "receive") and level > user.clearance:
        raise AuthError(f"Không đủ cấp độ: cần {level.name}, bạn có {user.clearance.name}")
    # TODO: tài liệu SECRET cần quy trình phê duyệt (2 người) trước khi chia sẻ ra ngoài


class UserStore:
    def __init__(self, path: str):
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            raise ValueError("Cấu hình người dùng phải là một JSON object")
        self._users = {
            name: User(name, Role(v["role"]), Level[v["clearance"]], v.get("password_hash"))
            for name, v in raw.items()
        }
        if any(user.password_hash is not None and not isinstance(user.password_hash, str)
               for user in self._users.values()):
            raise ValueError("password_hash phải là chuỗi")
        self._dummy_hash = hash_password("invalid-login-timing-placeholder")

    def get(self, username: str) -> User:
        try:
            return self._users[username]
        except KeyError:
            raise AuthError(f"Người dùng '{username}' không tồn tại") from None

    def authenticate(self, username: str, password: str) -> User:
        user = self._users.get(username)
        encoded = user.password_hash if user and user.password_hash else self._dummy_hash
        valid = verify_password(password, encoded)
        if user is None or not user.password_hash or not valid:
            raise AuthError("Tên đăng nhập hoặc mật khẩu không đúng")
        return user


def _main() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Quản lý mật khẩu người dùng SecureTransfer")
    commands = parser.add_subparsers(dest="command", required=True)
    password_parser = commands.add_parser("set-password", help="Đặt mật khẩu tài khoản")
    password_parser.add_argument("username")
    args = parser.parse_args()
    from .config import Settings

    path = Settings.from_env().users_path
    password = getpass.getpass("Mật khẩu mới (12 ký tự trở lên): ")
    if password != getpass.getpass("Nhập lại mật khẩu: "):
        parser.error("Hai mật khẩu không khớp")
    try:
        set_password(path, args.username, password)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"Đã đặt mật khẩu cho tài khoản '{args.username}'.")


if __name__ == "__main__":
    _main()
