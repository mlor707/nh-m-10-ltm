"""Chế độ strict host key, trust-host, timeout và ssh-check (dùng sshd thật qua fixture ssh_server)."""
import os
import time

import paramiko
import pytest

from securetransfer import sshcheck
from securetransfer.config import Settings
from securetransfer.devssh import gen_ssh_keypair, trust_host
from securetransfer.transfer import build_backends
from securetransfer.transfer._ssh import SSHConn, host_entry
from securetransfer.transfer.base import TransferError

PROTOS = ["scp", "sftp", "rsync"]


@pytest.fixture
def cfg(ssh_server, tmp_path):
    remote = tmp_path / "remote"
    remote.mkdir()
    s = Settings(data_dir=str(tmp_path / "data"), remote_dir=str(remote),
                 ssh_host="127.0.0.1", ssh_port=ssh_server["port"],
                 ssh_user=ssh_server["user"], ssh_key_file=ssh_server["key"],
                 ssh_known_hosts=str(tmp_path / "known_hosts"))
    return s, remote


def _roundtrip(s, tmp_path, proto, remote):
    b = build_backends(s)[proto]
    src, back = tmp_path / f"s_{proto}.bin", tmp_path / f"b_{proto}.bin"   # file riêng cho mỗi giao thức
    src.write_bytes(os.urandom(5000))
    b.upload(str(src), str(remote / f"{proto}.bin"))
    b.download(str(remote / f"{proto}.bin"), str(back))
    assert back.read_bytes() == src.read_bytes()


# ---------- chế độ strict ----------
@pytest.mark.parametrize("proto", PROTOS)
def test_strict_rejects_unknown_host(cfg, tmp_path, proto):
    s, remote = cfg
    s.ssh_strict_host_key = True                      # known_hosts chưa có gì
    with pytest.raises(TransferError) as e:
        _roundtrip(s, tmp_path, proto, remote)
    assert "trust-host" in str(e.value)               # có hướng dẫn xử lý
    assert not (remote / f"{proto}.bin").exists()     # không có byte nào được gửi đi


@pytest.mark.parametrize("proto", PROTOS)
def test_strict_accepts_trusted_host(cfg, tmp_path, proto):
    s, remote = cfg
    s.ssh_strict_host_key = True
    trust_host(s.ssh_host, s.ssh_port, s.ssh_known_hosts, assume_yes=True, out=lambda *_: None)
    _roundtrip(s, tmp_path, proto, remote)


@pytest.mark.parametrize("proto", PROTOS)
def test_strict_rejects_changed_host_key(cfg, tmp_path, proto):
    s, remote = cfg
    s.ssh_strict_host_key = True
    trust_host(s.ssh_host, s.ssh_port, s.ssh_known_hosts, assume_yes=True, out=lambda *_: None)
    # kẻ giả mạo: thay khóa đã lưu bằng một khóa ed25519 khác
    fake = gen_ssh_keypair(str(tmp_path / "fake")).split()[1]
    entry = host_entry(s.ssh_host, s.ssh_port)
    open(s.ssh_known_hosts, "w").write(f"{entry} ssh-ed25519 {fake}\n")
    with pytest.raises(TransferError) as e:
        _roundtrip(s, tmp_path, proto, remote)
    assert not (remote / f"{proto}.bin").exists()
    if proto != "rsync":
        assert "THAY ĐỔI" in str(e.value)


def test_non_strict_default_accepts_new_host(cfg, tmp_path):
    s, remote = cfg
    assert s.ssh_strict_host_key is False
    for p in PROTOS:
        _roundtrip(s, tmp_path, p, remote)


# ---------- trust-host ----------
def test_trust_host_user_declines(cfg):
    s, _ = cfg
    out = []
    r = trust_host(s.ssh_host, s.ssh_port, s.ssh_known_hosts, input_fn=lambda _: "n", out=out.append)
    assert r is None and not os.path.exists(s.ssh_known_hosts)
    assert any("SHA256:" in line for line in out)      # có hiện vân tay để đối chiếu


def test_trust_host_refuses_to_overwrite_different_key(cfg, tmp_path):
    s, _ = cfg
    fake = gen_ssh_keypair(str(tmp_path / "fake")).split()[1]
    open(s.ssh_known_hosts, "w").write(f"{host_entry(s.ssh_host, s.ssh_port)} ssh-ed25519 {fake}\n")
    with pytest.raises(ValueError, match="KHÁC"):
        trust_host(s.ssh_host, s.ssh_port, s.ssh_known_hosts, assume_yes=True, out=lambda *_: None)
    assert fake in open(s.ssh_known_hosts).read()      # file không bị ghi đè


def test_trust_host_idempotent(cfg):
    s, _ = cfg
    a = trust_host(s.ssh_host, s.ssh_port, s.ssh_known_hosts, assume_yes=True, out=lambda *_: None)
    b = trust_host(s.ssh_host, s.ssh_port, s.ssh_known_hosts, assume_yes=True, out=lambda *_: None)
    assert a == b and len(open(s.ssh_known_hosts).read().splitlines()) == 1


# ---------- timeout & cấu hình ----------
@pytest.mark.parametrize("proto", ["scp", "sftp"])
def test_timeout_on_unreachable_host(tmp_path, proto):
    s = Settings(ssh_host="10.255.255.1", ssh_port=22, ssh_user="x", ssh_key_file=None,
                 ssh_password="x", ssh_timeout=1)
    src = tmp_path / "a"; src.write_text("x")
    t0 = time.time()
    with pytest.raises(TransferError):
        build_backends(s)[proto].upload(str(src), "/tmp/a")
    assert time.time() - t0 < 8


def test_settings_from_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ST_SSH_STRICT_HOST_KEY", "true")
    monkeypatch.setenv("ST_SSH_KNOWN_HOSTS", "kh")
    monkeypatch.setenv("ST_SSH_TIMEOUT", "7")
    c = Settings.from_env().ssh_conn()
    assert (c.strict_host_key, c.known_hosts, c.timeout) == (True, "kh", 7)


# ---------- ssh-check ----------
def test_ssh_check_all_ok(cfg):
    s, remote = cfg
    rows = sshcheck.run(s)
    assert all(r["ok"] for r in rows), rows
    assert [r["step"] for r in rows][-3:] == ["SCP", "SFTP", "RSYNC"]
    assert list(remote.iterdir()) == []                # đã dọn file thử trên máy chủ
    assert "Tất cả đạt" in sshcheck.format_report(rows)


def test_ssh_check_missing_config():
    rows = sshcheck.run(Settings())
    assert len(rows) == 1 and not rows[0]["ok"] and "ST_SSH_USER" in rows[0]["detail"]


def test_ssh_check_wrong_port_stops_at_tcp(cfg):
    s, _ = cfg
    s.ssh_port = 1                                     # cổng không có ai nghe
    rows = sshcheck.run(s)
    assert rows[-1]["step"] == "Kết nối cổng SSH" and not rows[-1]["ok"]
    assert "docker compose ps" in rows[-1]["hint"]


def test_ssh_check_wrong_key(cfg, tmp_path):
    s, _ = cfg
    gen_ssh_keypair(str(tmp_path / "bad"))
    s.ssh_key_file = str(tmp_path / "bad")
    rows = sshcheck.run(s)
    assert rows[-1]["step"] == "Đăng nhập SSH" and not rows[-1]["ok"]
    assert "ST_SSH_KEY_FILE" in rows[-1]["hint"]


def test_ssh_check_strict_unknown_host_hint(cfg):
    s, _ = cfg
    s.ssh_strict_host_key = True
    rows = sshcheck.run(s)
    assert rows[-1]["step"] == "Đăng nhập SSH" and "trust-host" in rows[-1]["hint"]


def test_ssh_check_without_rsync(cfg, monkeypatch):
    s, _ = cfg
    monkeypatch.setattr(sshcheck.shutil, "which", lambda name: None)
    rows = sshcheck.run(s)
    rs = next(r for r in rows if r["step"] == "rsync")
    assert not rs["ok"] and "WSL" in rs["hint"]
    assert all(r["ok"] for r in rows if r["step"] in ("SCP", "SFTP"))
