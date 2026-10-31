"""Kiểm thử API + giao diện, đi qua toàn bộ luồng: web -> gateway -> FTPS -> giải mã."""
import pytest
from fastapi.testclient import TestClient

from securetransfer.api import create_app
from securetransfer.config import Settings
from securetransfer.devserver import make_server, start_in_thread

ALICE, BOB, CAROL = {"X-Username": "alice"}, {"X-Username": "bob"}, {"X-Username": "carol"}


@pytest.fixture
def client(tmp_path):
    root = tmp_path / "ftp_root"
    server = make_server(str(root), port=0, cert=str(tmp_path / "c.pem"), key=str(tmp_path / "k.pem"))
    start_in_thread(server)
    s = Settings(data_dir=str(tmp_path / "data"), remote_dir="/", ftps_port=server.address[1])
    yield TestClient(create_app(s)), root
    server.close_all()


def _send(c, who, name, content, level="INTERNAL"):
    return c.post("/documents", headers=who, data={"level": level, "scenario": "partner"},
                  files={"file": (name, content)})


def test_ui_served(client):
    c, _ = client
    r = c.get("/")
    assert r.status_code == 200 and "Truyền tải tài liệu nội bộ an toàn" in r.text


def test_login_required_and_unknown_user(client):
    c, _ = client
    assert c.get("/me").status_code == 401
    assert c.get("/me", headers={"X-Username": "nobody"}).status_code == 401


def test_me_permissions(client):
    c, _ = client
    assert "audit" in c.get("/me", headers=CAROL).json()["permissions"]
    assert "send" not in c.get("/me", headers=CAROL).json()["permissions"]


def test_send_list_download_roundtrip(client):
    c, root = client
    r = _send(c, BOB, "bao-cao.txt", "Báo cáo giao dịch mật".encode())
    assert r.status_code == 200 and r.json()["protocol"] == "ftps"
    assert b"giao dich" not in (root / "bao-cao.txt.enc").read_bytes()   # server chỉ thấy bản mã hóa

    docs = c.get("/documents", headers=BOB).json()
    assert [d["name"] for d in docs] == ["bao-cao.txt"] and docs[0]["level"] == "INTERNAL"

    d = c.get("/documents/bao-cao.txt/download", headers=BOB)
    assert d.status_code == 200 and d.content == "Báo cáo giao dịch mật".encode()


def test_clearance_enforced(client):
    c, _ = client
    assert _send(c, BOB, "tuyet-mat.txt", b"x", level="SECRET").status_code == 403
    assert _send(c, ALICE, "tuyet-mat.txt", b"top secret", level="SECRET").status_code == 200
    # bob (INTERNAL) không thấy và không tải được tài liệu SECRET
    assert c.get("/documents", headers=BOB).json() == []
    assert c.get("/documents/tuyet-mat.txt/download", headers=BOB).status_code == 404
    assert c.get("/documents/tuyet-mat.txt/download", headers=ALICE).content == b"top secret"


def test_audit_permissions_and_verify(client):
    c, _ = client
    _send(c, BOB, "a.txt", b"a")
    assert c.get("/audit", headers=BOB).status_code == 403         # nhân viên không xem audit
    assert c.get("/documents", headers=CAROL).status_code == 403   # kiểm toán viên không tải tài liệu
    assert c.get("/audit/verify", headers=CAROL).json() == {"valid": True, "first_bad_line": None}
    assert len(c.get("/audit", headers=CAROL).json()) >= 1


def test_benchmark_admin_only(client):
    c, _ = client
    assert c.get("/benchmark", headers=BOB).status_code == 403
    rows = c.get("/benchmark?size_mb=1", headers=ALICE).json()
    ftps = next(r for r in rows if r["protocol"] == "ftps")
    assert ftps["intact"] is True
    assert all("error" in r for r in rows if r["protocol"] != "ftps")  # chưa có SSH server


def test_upload_size_limit(client, monkeypatch):
    import securetransfer.api as api
    c, _ = client
    monkeypatch.setattr(api, "MAX_UPLOAD_MB", 0)
    assert _send(c, BOB, "big.bin", b"x" * 10).status_code == 413


def test_denied_attempts_are_audited(client):
    c, _ = client
    assert _send(c, BOB, "tuyet-mat.txt", b"x", level="SECRET").status_code == 403
    assert c.get("/audit", headers=BOB).status_code == 403
    log = c.get("/audit", headers=CAROL).json()
    assert [(e["user"], e["action"], e["status"]) for e in log] == [
        ("bob", "send", "denied"), ("bob", "audit", "denied")]
    assert c.get("/audit/verify", headers=CAROL).json()["valid"] is True
