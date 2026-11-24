"""rsync: tên file đặc biệt không được lọt vào shell của máy chủ. Không cần sshd hay rsync thật."""
import shlex
import subprocess

import pytest

from securetransfer.transfer import rsync as R
from securetransfer.transfer._ssh import SSHConn

NASTY = "/srv/x/báo cáo; $(touch PWNED) `id` 'q' \"d\" & |.txt.enc"


@pytest.mark.parametrize("text,expected", [
    ("rsync  version 3.2.7  protocol version 32\nCopyright...", (3, 2, 7)),
    ("rsync  version 3.4.1  protocol version 32", (3, 4, 1)),
    ("rsync  version v3.0.9  protocol version 30", (3, 0, 9)),
    ("rsync  version 2.6.9  protocol version 29", (2, 6, 9)),
    ("openrsync: protocol version 29\nrsync version 2.6.9 compatible", None),
    ("", None),
    ("không phải rsync", None),
])
def test_parse_version(text, expected):
    assert R._parse_version(text) == expected


def _patch_version(monkeypatch, v):
    monkeypatch.setattr(R, "_rsync_version", lambda: v)


@pytest.mark.parametrize("v", [(3, 0, 9), (3, 1, 3), (3, 2, 3), (3, 2, 7), (3, 4, 1)])
def test_modern_rsync_uses_protect_args_and_leaves_path_alone(monkeypatch, v):
    _patch_version(monkeypatch, v)
    assert R._remote_spec(NASTY) == (["-s"], NASTY)


@pytest.mark.parametrize("v", [(3, 0, 8), (2, 6, 9), None])
def test_old_unknown_or_openrsync_quotes_for_remote_shell(monkeypatch, v):
    _patch_version(monkeypatch, v)
    opts, spec = R._remote_spec(NASTY)
    assert opts == []
    assert shlex.split(spec) == [NASTY]               # shell từ xa sẽ thấy đúng MỘT đối số, không thực thi gì


def test_plain_paths_are_unchanged_in_quote_mode(monkeypatch):
    _patch_version(monkeypatch, None)
    assert R._remote_spec("/tmp/x/rsync.bin") == ([], "/tmp/x/rsync.bin")
    assert R._remote_spec("./hopdong.txt.enc") == ([], "./hopdong.txt.enc")


@pytest.mark.parametrize("direction", ["upload", "download"])
def test_argv_passed_to_rsync(monkeypatch, tmp_path, direction):
    calls = []
    monkeypatch.setattr(R.shutil, "which", lambda name: "/usr/bin/rsync")
    monkeypatch.setattr(R.subprocess, "run",
                        lambda argv, **kw: calls.append(argv) or subprocess.CompletedProcess(argv, 0, "", ""))
    _patch_version(monkeypatch, (3, 2, 7))
    b = R.RsyncBackend(SSHConn(host="h", port=22, username="u", password=None, key_file=None,
                               known_hosts=None, strict_host_key=True, timeout=5))
    local = str(tmp_path / "payload.enc")
    getattr(b, direction)(*((local, NASTY) if direction == "upload" else (NASTY, local)))
    argv = calls[0]
    assert argv[:3] == ["rsync", "-az", "-s"]
    remote = f"u@h:{NASTY}"
    assert (argv[-2:] == [local, remote]) if direction == "upload" else (argv[-2:] == [remote, local])
