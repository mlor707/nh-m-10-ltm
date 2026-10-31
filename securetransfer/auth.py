"""Phân quyền RBAC + mức mật tài liệu.

TODO (mở rộng): thay UserStore bằng LDAP (ldap3) và xác thực Kerberos (SSO).
"""
from __future__ import annotations
import json
from dataclasses import dataclass
from enum import Enum, IntEnum


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
        self._users = {
            name: User(name, Role(v["role"]), Level[v["clearance"]]) for name, v in raw.items()
        }

    def get(self, username: str) -> User:
        try:
            return self._users[username]
        except KeyError:
            raise AuthError(f"Người dùng '{username}' không tồn tại") from None
