import pytest
from securetransfer.audit import AuditLog
from securetransfer.auth import AuthError, Level, Role, User, authorize


def test_audit_chain_ok_and_tamper(tmp_path):
    a = AuditLog(str(tmp_path / "audit.log"))
    for i in range(3):
        a.record("bob", "send", f"f{i}")
    assert a.verify() == (True, None)
    lines = (tmp_path / "audit.log").read_text().splitlines()
    lines[1] = lines[1].replace('"bob"', '"eve"')
    (tmp_path / "audit.log").write_text("\n".join(lines) + "\n")
    assert a.verify() == (False, 2)


def test_rbac():
    staff = User("bob", Role.STAFF, Level.INTERNAL)
    authorize(staff, "send", Level.INTERNAL)
    with pytest.raises(AuthError):
        authorize(staff, "send", Level.SECRET)       # vượt cấp độ
    with pytest.raises(AuthError):
        authorize(staff, "audit")                    # sai vai trò


def test_dotenv_loaded(tmp_path, monkeypatch):
    from securetransfer.config import Settings
    (tmp_path / ".env").write_text('ST_SSH_PORT=2222  # cổng docker\nST_SSH_USER="transfer"\nST_FTPS_PORT=9999\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ST_FTPS_PORT", "1234")           # biến môi trường thắng .env
    for k in ("ST_SSH_PORT", "ST_SSH_USER"):   # đặt rồi xóa để monkeypatch dọn sạch sau test
        monkeypatch.setenv(k, "x"); monkeypatch.delenv(k)
    s = Settings.from_env()
    assert (s.ssh_port, s.ssh_user, s.ftps_port) == (2222, "transfer", 1234)
