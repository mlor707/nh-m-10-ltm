"""Kiểm thử API + giao diện, đi qua toàn bộ luồng: web -> gateway -> FTPS -> giải mã."""
import json
import time

import jwt
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


# ---------- Chống ghi đè / hạ mức mật (409) ----------
def test_overwriting_secret_document_by_lower_clearance_returns_409(client):
    c, root, headers = client
    assert _send(c, headers["alice"], "tuyet-mat.txt", b"top secret", level="SECRET").status_code == 200
    stored = (root / "tuyet-mat.txt.enc").read_bytes()
    r = _send(c, headers["bob"], "tuyet-mat.txt", b"gia mao", level="INTERNAL")
    assert r.status_code == 409
    assert (root / "tuyet-mat.txt.enc").read_bytes() == stored          # file trên máy chủ không đổi
    assert c.get("/documents/tuyet-mat.txt/download", headers=headers["alice"]).content == b"top secret"
    assert c.get("/documents", headers=headers["bob"]).json() == []     # bob vẫn không thấy tài liệu mật
    denied = [(e["user"], e["action"], e["status"]) for e in c.get("/audit", headers=headers["carol"]).json()
              if e["status"] == "denied"]
    assert denied == [("bob", "send", "denied")]


def test_lowering_level_by_overwrite_returns_409(client):
    c, _, headers = client
    assert _send(c, headers["alice"], "a.txt", b"v1", level="SECRET").status_code == 200
    assert _send(c, headers["alice"], "a.txt", b"v2", level="INTERNAL").status_code == 409
    docs = c.get("/documents", headers=headers["alice"]).json()
    assert [(d["name"], d["level"]) for d in docs] == [("a.txt", "SECRET")]
    assert _send(c, headers["alice"], "a.txt", b"v3", level="SECRET").status_code == 200   # cùng mức vẫn được cập nhật


# ---------- Token đăng nhập hết hạn ----------
def test_expired_token_rejected(client):
    c, _, _ = client
    now = int(time.time())
    expired = jwt.encode({"iss": "securetransfer", "sub": "bob", "iat": now - 7200, "exp": now - 3600},
                         "test-only-secret-key-with-at-least-32-bytes", algorithm="HS256")
    assert c.get("/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


# ---------- Link chia sẻ có thời hạn ----------
def _share(c, who, name, **body):
    return c.post(f"/documents/{name}/share", headers=who, json=body)


def _audit(c, headers):
    return c.get("/audit", headers=headers["carol"]).json()


def test_share_requires_login_and_valid_body(client):
    c, _, headers = client
    _send(c, headers["bob"], "a.txt", b"a")
    assert c.post("/documents/a.txt/share", json={"expires_minutes": 30, "max_downloads": 3}).status_code == 401
    assert _share(c, headers["bob"], "a.txt", expires_minutes=0, max_downloads=3).status_code == 422
    assert _share(c, headers["bob"], "a.txt", expires_minutes=30, max_downloads=0).status_code == 422
    assert _share(c, headers["bob"], "khong-co.txt", expires_minutes=30, max_downloads=3).status_code == 404
    assert _share(c, headers["carol"], "a.txt", expires_minutes=30, max_downloads=3).status_code == 403


def test_share_valid_link_downloads_without_login_and_is_audited(client):
    c, _, headers = client
    _send(c, headers["bob"], "hop-dong.txt", "Hợp đồng NDA".encode())
    r = _share(c, headers["bob"], "hop-dong.txt", expires_minutes=30, max_downloads=3)
    assert r.status_code == 200
    token = r.json()["token"]
    assert r.json()["max_downloads"] == 3 and r.json()["url"] == f"/share/{token}"

    d = c.get(f"/share/{token}")  # không gửi Authorization
    assert d.status_code == 200 and d.content == "Hợp đồng NDA".encode()

    log = _audit(c, headers)
    assert any(e["action"] == "share_create" and e["status"] == "ok" and e["user"] == "bob" for e in log)
    dl = [e for e in log if e["action"] == "share_download" and e["status"] == "ok"]
    assert len(dl) == 1 and dl[0]["target"] == "hop-dong.txt" and dl[0]["details"]["downloads"] == 1
    assert token not in json.dumps(log)  # token gốc không bao giờ nằm trong nhật ký
    assert c.get("/audit/verify", headers=headers["carol"]).json()["valid"] is True


def test_share_expired_returns_410(client):
    c, _, headers = client
    _send(c, headers["bob"], "a.txt", b"a")
    token = _share(c, headers["bob"], "a.txt", expires_minutes=30, max_downloads=3).json()["token"]
    assert c.get(f"/share/{token}").status_code == 200
    shares = c.app.state.shares
    real_clock = shares.clock
    shares.clock = lambda: time.time() + 31 * 60
    try:
        assert c.get(f"/share/{token}").status_code == 410
    finally:
        shares.clock = real_clock
    denied = [e for e in _audit(c, headers) if e["action"] == "share_download" and e["status"] == "denied"]
    assert len(denied) == 1 and "hết hạn" in denied[0]["details"]["error"]


def test_share_over_download_limit_returns_410(client):
    c, _, headers = client
    _send(c, headers["bob"], "a.txt", b"a")
    token = _share(c, headers["bob"], "a.txt", expires_minutes=30, max_downloads=2).json()["token"]
    assert c.get(f"/share/{token}").status_code == 200
    assert c.get(f"/share/{token}").status_code == 200
    assert c.get(f"/share/{token}").status_code == 410
    log = _audit(c, headers)
    assert len([e for e in log if e["action"] == "share_download" and e["status"] == "ok"]) == 2
    assert len([e for e in log if e["action"] == "share_download" and e["status"] == "denied"]) == 1


def test_share_revoked_returns_410(client):
    c, _, headers = client
    _send(c, headers["bob"], "a.txt", b"a")
    token = _share(c, headers["bob"], "a.txt", expires_minutes=30, max_downloads=5).json()["token"]
    assert c.delete(f"/share/{token}").status_code == 401                         # cần đăng nhập
    assert c.delete(f"/share/{token}", headers=headers["carol"]).status_code == 403  # không phải người tạo
    assert c.delete(f"/share/{token}", headers=headers["bob"]).json() == {"revoked": True}
    assert c.get(f"/share/{token}").status_code == 410
    log = _audit(c, headers)
    assert any(e["action"] == "share_revoke" and e["status"] == "ok" for e in log)
    assert any(e["action"] == "share_revoke" and e["status"] == "denied" for e in log)


def test_share_admin_can_revoke_others_link(client):
    c, _, headers = client
    _send(c, headers["bob"], "a.txt", b"a")
    token = _share(c, headers["bob"], "a.txt", expires_minutes=30, max_downloads=5).json()["token"]
    assert c.delete(f"/share/{token}", headers=headers["alice"]).status_code == 200
    assert c.get(f"/share/{token}").status_code == 410


def test_share_secret_document_refused_and_audited(client):
    c, _, headers = client
    _send(c, headers["alice"], "tuyet-mat.txt", b"top secret", level="SECRET")
    assert _share(c, headers["alice"], "tuyet-mat.txt", expires_minutes=30, max_downloads=3).status_code == 403
    assert _share(c, headers["bob"], "tuyet-mat.txt", expires_minutes=30, max_downloads=3).status_code == 404
    denied = [e for e in _audit(c, headers) if e["action"] == "share_create" and e["status"] == "denied"]
    assert [e["user"] for e in denied] == ["alice"]


def test_share_unknown_token_returns_404(client):
    c, _, headers = client
    assert c.get("/share/khong-ton-tai").status_code == 404
    assert c.delete("/share/khong-ton-tai", headers=headers["bob"]).status_code == 404


def test_share_only_sender_or_admin_can_create(client):
    c, _, headers = client
    _send(c, headers["alice"], "cua-alice.txt", b"a")           # INTERNAL, gửi bởi alice
    assert _share(c, headers["bob"], "cua-alice.txt", expires_minutes=30, max_downloads=1).status_code == 403
    assert _share(c, headers["alice"], "cua-alice.txt", expires_minutes=30, max_downloads=1).status_code == 200
    _send(c, headers["bob"], "cua-bob.txt", b"b")
    assert _share(c, headers["alice"], "cua-bob.txt", expires_minutes=30, max_downloads=1).status_code == 200  # admin
    denied = [e for e in _audit(c, headers) if e["action"] == "share_create" and e["status"] == "denied"]
    assert [e["user"] for e in denied] == ["bob"]


def test_share_link_dies_when_document_is_replaced(client):
    c, _, headers = client
    _send(c, headers["bob"], "a.txt", b"ban cu")
    token = _share(c, headers["bob"], "a.txt", expires_minutes=30, max_downloads=5).json()["token"]
    assert c.get(f"/share/{token}").content == b"ban cu"
    assert _send(c, headers["bob"], "a.txt", b"ban moi").status_code == 200      # chủ tài liệu cập nhật
    r = c.get(f"/share/{token}")
    assert r.status_code == 410 and b"ban moi" not in r.content
    denied = [e for e in _audit(c, headers) if e["action"] == "share_download" and e["status"] == "denied"]
    assert len(denied) == 1 and "cập nhật" in denied[0]["details"]["error"]


def test_share_link_never_serves_a_document_raised_to_secret(client):
    c, _, headers = client
    _send(c, headers["alice"], "x.txt", b"noi bo", level="INTERNAL")
    token = _share(c, headers["alice"], "x.txt", expires_minutes=30, max_downloads=5).json()["token"]
    assert _send(c, headers["alice"], "x.txt", b"gio la tuyet mat", level="SECRET").status_code == 200
    r = c.get(f"/share/{token}")
    assert r.status_code == 410 and b"tuyet mat" not in r.content


def test_documents_listing_does_not_leak_internal_version_field(client):
    c, _, headers = client
    _send(c, headers["bob"], "a.txt", b"a")
    assert set(c.get("/documents", headers=headers["bob"]).json()[0]) == {"name", "level", "protocol", "sender", "ts"}
