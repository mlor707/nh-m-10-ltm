"""Kiểm thử API + giao diện, đi qua toàn bộ luồng: web -> gateway -> FTPS -> giải mã."""
import json

import pytest
from fastapi.testclient import TestClient

from securetransfer.api import create_app
from securetransfer.auth import hash_password
from securetransfer.config import Settings
from securetransfer.devserver import make_server, start_in_thread

PASSWORDS = {"alice": "alice-test-password", "bob": "bob-test-password", "carol": "carol-test-password"}


@pytest.fixture
def client(tmp_path):
    root = tmp_path / "ftp_root"
    server = make_server(str(root), port=0, cert=str(tmp_path / "c.pem"), key=str(tmp_path / "k.pem"))
    start_in_thread(server)
    users_path = tmp_path / "users.json"
    users_path.write_text(json.dumps({
        "alice": {"role": "admin", "clearance": "SECRET", "password_hash": hash_password(PASSWORDS["alice"])},
        "bob": {"role": "staff", "clearance": "INTERNAL", "password_hash": hash_password(PASSWORDS["bob"])},
        "carol": {"role": "auditor", "clearance": "CONFIDENTIAL", "password_hash": hash_password(PASSWORDS["carol"])},
    }), encoding="utf-8")
    settings = Settings(
        data_dir=str(tmp_path / "data"), users_path=str(users_path),
        remote_dir="/", ftps_port=server.address[1],
        jwt_secret="test-only-secret-key-with-at-least-32-bytes",
    )
    test_client = TestClient(create_app(settings))
    headers = {}
    for username, password in PASSWORDS.items():
        response = test_client.post("/login", json={"username": username, "password": password})
        assert response.status_code == 200
        headers[username] = {"Authorization": f"Bearer {response.json()['access_token']}"}
    yield test_client, root, headers
    server.close_all()


def _send(c, who, name, content, level="INTERNAL"):
    return c.post("/documents", headers=who, data={"level": level, "scenario": "partner"},
                  files={"file": (name, content)})


def test_ui_served(client):
    c, _, _ = client
    r = c.get("/")
    assert r.status_code == 200 and "Truyền tải tài liệu nội bộ an toàn" in r.text
    assert 'id="loginForm"' in r.text


def test_login_required_and_username_header_rejected(client):
    c, _, _ = client
    assert c.get("/me").status_code == 401
    assert c.get("/me", headers={"X-Username": "alice"}).status_code == 401
    assert c.get("/users").status_code == 404


def test_login_rejects_bad_credentials_and_audits_denial(client):
    c, _, headers = client
    response = c.post("/login", json={"username": "bob", "password": "incorrect-password"})
    assert response.status_code == 401
    assert c.post("/login", json={"username": "unknown", "password": "incorrect-password"}).status_code == 401
    log = c.get("/audit", headers=headers["carol"]).json()
    denials = [entry for entry in log if entry["action"] == "login" and entry["status"] == "denied"]
    assert [entry["user"] for entry in denials] == ["bob", "unknown"]
    assert c.get("/audit/verify", headers=headers["carol"]).json()["valid"] is True


def test_me_permissions(client):
    c, _, headers = client
    assert "audit" in c.get("/me", headers=headers["carol"]).json()["permissions"]
    assert "send" not in c.get("/me", headers=headers["carol"]).json()["permissions"]


def test_send_list_download_roundtrip(client):
    c, root, headers = client
    r = _send(c, headers["bob"], "bao-cao.txt", "Báo cáo giao dịch mật".encode())
    assert r.status_code == 200 and r.json()["protocol"] == "ftps"
    assert b"giao dich" not in (root / "bao-cao.txt.enc").read_bytes()

    docs = c.get("/documents", headers=headers["bob"]).json()
    assert [d["name"] for d in docs] == ["bao-cao.txt"] and docs[0]["level"] == "INTERNAL"

    d = c.get("/documents/bao-cao.txt/download", headers=headers["bob"])
    assert d.status_code == 200 and d.content == "Báo cáo giao dịch mật".encode()


def test_clearance_enforced(client):
    c, _, headers = client
    assert _send(c, headers["bob"], "tuyet-mat.txt", b"x", level="SECRET").status_code == 403
    assert _send(c, headers["alice"], "tuyet-mat.txt", b"top secret", level="SECRET").status_code == 200
    assert c.get("/documents", headers=headers["bob"]).json() == []
    assert c.get("/documents/tuyet-mat.txt/download", headers=headers["bob"]).status_code == 404
    assert c.get("/documents/tuyet-mat.txt/download", headers=headers["alice"]).content == b"top secret"


def test_audit_permissions_and_verify(client):
    c, _, headers = client
    _send(c, headers["bob"], "a.txt", b"a")
    assert c.get("/audit", headers=headers["bob"]).status_code == 403
    assert c.get("/documents", headers=headers["carol"]).status_code == 403
    assert c.get("/audit/verify", headers=headers["carol"]).json() == {"valid": True, "first_bad_line": None}
    assert len(c.get("/audit", headers=headers["carol"]).json()) >= 1


def test_benchmark_admin_only(client):
    c, _, headers = client
    assert c.get("/benchmark", headers=headers["bob"]).status_code == 403
    rows = c.get("/benchmark?size_mb=1", headers=headers["alice"]).json()
    ftps = next(r for r in rows if r["protocol"] == "ftps")
    assert ftps["intact"] is True
    assert all("error" in r for r in rows if r["protocol"] != "ftps")


def test_upload_size_limit(client, monkeypatch):
    import securetransfer.api as api
    c, _, headers = client
    monkeypatch.setattr(api, "MAX_UPLOAD_MB", 0)
    assert _send(c, headers["bob"], "big.bin", b"x" * 10).status_code == 413


def test_denied_attempts_are_audited(client):
    c, _, headers = client
    assert _send(c, headers["bob"], "tuyet-mat.txt", b"x", level="SECRET").status_code == 403
    assert c.get("/audit", headers=headers["bob"]).status_code == 403
    log = c.get("/audit", headers=headers["carol"]).json()
    denials = [(e["user"], e["action"], e["status"]) for e in log if e["status"] == "denied"]
    assert denials == [("bob", "send", "denied"), ("bob", "audit", "denied")]
    assert c.get("/audit/verify", headers=headers["carol"]).json()["valid"] is True
