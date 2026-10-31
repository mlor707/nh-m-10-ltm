"""Kiểm thử SCP / SFTP / rsync với một sshd thật (fixture ssh_server trong conftest.py)."""
import os

import pytest

from securetransfer.auth import Level, Role, User
from securetransfer.config import Settings
from securetransfer.gateway import Gateway
from securetransfer.transfer import build_backends
from securetransfer.transfer.base import TransferError


@pytest.fixture
def cfg(ssh_server, tmp_path):
    remote = tmp_path / "remote"
    remote.mkdir()
    s = Settings(data_dir=str(tmp_path / "data"), remote_dir=str(remote),
                 ssh_host="127.0.0.1", ssh_port=ssh_server["port"],
                 ssh_user=ssh_server["user"], ssh_key_file=ssh_server["key"],
                 ssh_known_hosts=str(tmp_path / "known_hosts"))   # không đụng ~/.ssh/known_hosts của máy dev
    return s, remote


def _backends(s):
    return build_backends(s)


@pytest.mark.parametrize("proto", ["scp", "sftp", "rsync"])
def test_upload_download_roundtrip(cfg, tmp_path, proto):
    s, remote = cfg
    b = _backends(s)[proto]
    data = os.urandom(300_000)
    src, back = tmp_path / "src.bin", tmp_path / "back.bin"
    src.write_bytes(data)
    b.upload(str(src), str(remote / f"{proto}.bin"))
    assert (remote / f"{proto}.bin").read_bytes() == data
    b.download(str(remote / f"{proto}.bin"), str(back))
    assert back.read_bytes() == data


@pytest.mark.parametrize("proto", ["scp", "sftp", "rsync"])
def test_download_missing_file_raises(cfg, tmp_path, proto):
    s, remote = cfg
    with pytest.raises(TransferError):
        _backends(s)[proto].download(str(remote / "khong-ton-tai.bin"), str(tmp_path / "x"))


def test_wrong_key_is_rejected(cfg, tmp_path):
    s, remote = cfg
    from securetransfer.devssh import gen_ssh_keypair
    bad = str(tmp_path / "bad_key")
    gen_ssh_keypair(bad)
    s.ssh_key_file = bad
    src = tmp_path / "a"; src.write_text("x")
    for proto in ("scp", "sftp"):
        with pytest.raises(TransferError):
            _backends(s)[proto].upload(str(src), str(remote / "a"))


@pytest.mark.parametrize("scenario,proto", [("admin", "scp"), ("baseline", "sftp"), ("sync", "rsync")])
def test_gateway_end_to_end(cfg, tmp_path, monkeypatch, scenario, proto):
    s, remote = cfg
    gw = Gateway(s, backends=_backends(s))
    alice = User("alice", Role.ADMIN, Level.SECRET)
    doc = tmp_path / "so-sach.txt"
    doc.write_text("Sổ sách kế toán 2026", encoding="utf-8")
    gw.send(alice, str(doc), level=Level.CONFIDENTIAL, scenario=scenario)
    stored = (remote / "so-sach.txt.enc").read_bytes()
    assert "Sổ sách".encode() not in stored            # trên máy chủ chỉ có bản mã hóa
    out = tmp_path / "out.txt"
    gw.receive(alice, "so-sach.txt", str(out), level=Level.CONFIDENTIAL, scenario=scenario)
    assert out.read_text(encoding="utf-8") == "Sổ sách kế toán 2026"
    assert gw.audit.read_all()[0]["details"]["protocol"] == proto
    assert gw.audit.verify() == (True, None)


def test_benchmark_all_ssh_protocols(cfg):
    from securetransfer import benchmark
    s, remote = cfg
    rows = benchmark.run(s, size_mb=1, protocols=["scp", "sftp", "rsync"])
    assert [r["protocol"] for r in rows] == ["scp", "sftp", "rsync"]
    assert all(r.get("intact") is True for r in rows), rows
    assert all(r["upload_s"] > 0 for r in rows)
    assert list(remote.iterdir()) == []             # file đo đã được dọn khỏi máy chủ


@pytest.mark.parametrize("proto", ["scp", "sftp", "rsync"])
def test_delete_remote_file(cfg, tmp_path, proto):
    s, remote = cfg
    b = _backends(s)[proto]
    src = tmp_path / "x.bin"; src.write_bytes(b"abc")
    b.upload(str(src), str(remote / "x.bin"))
    assert (remote / "x.bin").exists()
    b.delete(str(remote / "x.bin"))
    assert not (remote / "x.bin").exists()
    with pytest.raises(TransferError):
        b.delete(str(remote / "x.bin"))             # xóa file không tồn tại phải báo lỗi
