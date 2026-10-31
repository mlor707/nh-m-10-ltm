"""Kiểm thử end-to-end: Gateway -> FTPS (server giả lập) -> tải về -> giải mã."""
import pytest
from securetransfer.auth import AuthError, Level, Role, User
from securetransfer.config import Settings
from securetransfer.devserver import make_server, start_in_thread
from securetransfer.gateway import Gateway


@pytest.fixture
def env(tmp_path):
    root = tmp_path / "ftp_root"
    server = make_server(str(root), port=0, cert=str(tmp_path / "c.pem"), key=str(tmp_path / "k.pem"))
    start_in_thread(server)
    s = Settings(data_dir=str(tmp_path / "data"), remote_dir="/", ftps_port=server.address[1])
    yield s, root
    server.close_all()


def test_send_receive_roundtrip(env, tmp_path):
    s, root = env
    gw = Gateway(s)
    user = User("alice", Role.ADMIN, Level.SECRET)
    doc = tmp_path / "hopdong.txt"
    doc.write_text("Hợp đồng M&A tuyệt mật")
    gw.send(user, str(doc), level=Level.SECRET, scenario="partner")

    stored = (root / "hopdong.txt.enc").read_bytes()
    assert b"M&A" not in stored                          # server chỉ thấy bản mã hóa

    out = tmp_path / "out.txt"
    gw.receive(user, "hopdong.txt", str(out), level=Level.SECRET)
    assert out.read_text() == "Hợp đồng M&A tuyệt mật"
    assert gw.audit.verify() == (True, None)
    assert [e["action"] for e in gw.audit.read_all()] == ["send", "receive"]


def test_denied_is_audited(env, tmp_path):
    s, _ = env
    gw = Gateway(s)
    bob = User("bob", Role.STAFF, Level.INTERNAL)
    doc = tmp_path / "x.txt"; doc.write_text("x")
    with pytest.raises(AuthError):
        gw.send(bob, str(doc), level=Level.SECRET)
    assert gw.audit.read_all()[-1]["status"] == "denied"


def test_path_traversal_blocked(env, tmp_path):
    s, root = env
    gw = Gateway(s)
    u = User("alice", Role.ADMIN, Level.SECRET)
    doc = tmp_path / "x.txt"; doc.write_text("x")
    remote = gw.send(u, str(doc), remote_name="../../etc/passwd")
    assert remote == "/passwd.enc"
