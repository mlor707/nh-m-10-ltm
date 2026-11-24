"""Đăng nhập sai nhiều lần -> HTTP 429 (cần fastapi/httpx)."""
import json

import pytest
from fastapi.testclient import TestClient

from securetransfer.api import create_app
from securetransfer.auth import hash_password
from securetransfer.config import Settings


def make_client(tmp_path, **settings):
    users_path = tmp_path / "users.json"
    users_path.write_text(json.dumps({
        "alice": {"role": "admin", "clearance": "SECRET", "password_hash": hash_password("dung-mat-khau-1")},
        "bob": {"role": "staff", "clearance": "INTERNAL", "password_hash": hash_password("dung-mat-khau-2")},
    }), encoding="utf-8")
    s = Settings(data_dir=str(tmp_path / "data"), users_path=str(users_path), remote_dir="/",
                 jwt_secret="test-only-secret-key-with-at-least-32-bytes", **settings)
    return TestClient(create_app(s))


def login(c, user, pw):
    return c.post("/login", json={"username": user, "password": pw})


def test_lockout_blocks_even_correct_password(tmp_path):
    c = make_client(tmp_path, login_max_failures=3)
    assert [login(c, "alice", "sai").status_code for _ in range(3)] == [401, 401, 401]
    r = login(c, "alice", "dung-mat-khau-1")          # mật khẩu đúng nhưng đang bị khóa
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) > 0
    assert "access_token" not in r.text


def test_other_user_not_affected_and_lock_is_audited_once(tmp_path):
    c = make_client(tmp_path, login_max_failures=3)
    for _ in range(3): login(c, "alice", "sai")
    for _ in range(5): login(c, "alice", "sai")        # các lần bị chặn không được ghi thêm vào audit
    assert login(c, "bob", "dung-mat-khau-2").status_code == 200
    log = c.app.state.audit.read_all()
    denied = [e for e in log if e["action"] == "login" and e["status"] == "denied"]
    assert len(denied) == 3
    assert sum(1 for e in denied if e["details"].get("locked")) == 1
    assert c.app.state.audit.verify() == (True, None)


def test_unknown_username_is_throttled_too(tmp_path):
    c = make_client(tmp_path, login_max_failures=3)
    codes = [login(c, "khong-ton-tai", "x").status_code for _ in range(4)]
    assert codes == [401, 401, 401, 429]


def test_successful_login_resets_pair_counter(tmp_path):
    c = make_client(tmp_path, login_max_failures=3)
    login(c, "alice", "sai"); login(c, "alice", "sai")
    assert login(c, "alice", "dung-mat-khau-1").status_code == 200
    assert [login(c, "alice", "sai").status_code for _ in range(2)] == [401, 401]   # đếm lại từ 0


def test_can_be_disabled(tmp_path):
    c = make_client(tmp_path, login_max_failures=0)
    assert all(login(c, "alice", "sai").status_code == 401 for _ in range(30))
