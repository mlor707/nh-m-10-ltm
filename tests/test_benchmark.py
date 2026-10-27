"""Benchmark nhiều cỡ file, lặp nhiều lần, dọn file, CSV, CLI."""
import csv
import json
import time

import pytest

from securetransfer import benchmark
from securetransfer.config import Settings
from securetransfer.devserver import make_server, start_in_thread


@pytest.fixture
def ssh_cfg(ssh_server, tmp_path):
    remote = tmp_path / "remote"
    remote.mkdir()
    s = Settings(data_dir=str(tmp_path / "data"), remote_dir=str(remote),
                 ssh_host="127.0.0.1", ssh_port=ssh_server["port"],
                 ssh_user=ssh_server["user"], ssh_key_file=ssh_server["key"],
                 ssh_known_hosts=str(tmp_path / "known_hosts"))
    return s, remote


def test_matrix_sizes_repeat_and_cleanup(ssh_cfg):
    s, remote = ssh_cfg
    seen = []
    rows = benchmark.run_matrix(s, [1, 2], repeat=2, protocols=["scp", "sftp", "rsync"],
                                progress=lambda *a: seen.append(a))
    assert [(r["protocol"], r["size_mb"]) for r in rows] == [
        ("scp", 1), ("scp", 2), ("sftp", 1), ("sftp", 2), ("rsync", 1), ("rsync", 2)]
    for r in rows:
        assert r["runs"] == 2 and r["intact"] is True
        assert 0 < r["upload_s_min"] <= r["upload_s_mean"] <= r["upload_s_max"]
        assert 0 < r["download_s_min"] <= r["download_s_mean"] <= r["download_s_max"]
        assert r["upload_mbit_s"] > 0 and r["download_mbit_s"] > 0
    assert len(seen) == 3 * 2 * 2                     # báo tiến độ cho từng lần đo
    assert list(remote.iterdir()) == []               # máy chủ không còn file đo nào


def test_error_stops_that_protocol_only(tmp_path):
    s = Settings(ssh_host="127.0.0.1", ssh_port=1, ssh_user="x", ssh_password="x", ssh_timeout=1)
    t0 = time.time()
    rows = benchmark.run_matrix(s, [1, 5, 10], repeat=3, protocols=["scp", "sftp"])
    assert [r["protocol"] for r in rows] == ["scp", "sftp"]      # mỗi giao thức chỉ 1 dòng lỗi, không lặp 9 lần
    assert all("error" in r and r["size_mb"] == 1 for r in rows)
    assert time.time() - t0 < 10


@pytest.mark.parametrize("kwargs", [
    {"sizes_mb": [0]}, {"sizes_mb": [201]}, {"sizes_mb": []}, {"sizes_mb": [1], "repeat": 0},
    {"sizes_mb": [1], "repeat": 11}, {"sizes_mb": [1], "protocols": ["ftp"]}])
def test_invalid_arguments(kwargs):
    with pytest.raises(ValueError):
        benchmark.run_matrix(Settings(), **kwargs)


def test_write_csv_roundtrip(tmp_path):
    rows = [benchmark._aggregate("scp", 10, [1.0, 2.0, 3.0], [0.5, 0.5, 0.5], True),
            {"protocol": "rsync", "size_mb": 10, "error": "không có lệnh rsync, có dấu phẩy"}]
    path = tmp_path / "sub" / "bench.csv"
    benchmark.write_csv(rows, str(path))
    with open(path, encoding="utf-8-sig", newline="") as f:
        got = list(csv.DictReader(f))
    assert list(got[0].keys()) == benchmark.CSV_FIELDS
    assert got[0]["protocol"] == "scp" and got[0]["upload_s_mean"] == "2.0" and got[0]["upload_s_max"] == "3.0"
    assert got[1]["error"] == "không có lệnh rsync, có dấu phẩy" and got[1]["upload_s_mean"] == ""


def test_format_table_has_rows_and_errors():
    rows = [benchmark._aggregate("scp", 10, [1.0], [1.0], True),
            {"protocol": "rsync", "size_mb": 10, "error": "thiếu rsync"}]
    out = benchmark.format_table(rows)
    assert "SCP" in out and "đúng" in out and "Không đo được" in out and "thiếu rsync" in out


def test_ftps_matrix_and_cleanup(tmp_path):
    root = tmp_path / "ftp_root"
    server = make_server(str(root), port=0, cert=str(tmp_path / "c.pem"), key=str(tmp_path / "k.pem"))
    start_in_thread(server)
    try:
        s = Settings(remote_dir="/", ftps_port=server.address[1])
        rows = benchmark.run_matrix(s, [1], repeat=2, protocols=["ftps"])
        assert rows[0]["intact"] is True and rows[0]["runs"] == 2
        assert list(root.iterdir()) == []             # FTPS cũng dọn file đo
    finally:
        server.close_all()


def test_legacy_run_keeps_old_keys(ssh_cfg):
    s, _ = ssh_cfg
    rows = benchmark.run(s, size_mb=1, protocols=["sftp"])
    assert set(rows[0]) == {"protocol", "upload_s", "download_s", "mbps_up", "intact"}


# ---------- CLI ----------
def _cli(monkeypatch, tmp_path, ssh_server, remote, *args):
    from securetransfer import cli
    monkeypatch.chdir(tmp_path)
    for k, v in {"ST_SSH_HOST": "127.0.0.1", "ST_SSH_PORT": str(ssh_server["port"]),
                 "ST_SSH_USER": ssh_server["user"], "ST_SSH_KEY_FILE": ssh_server["key"],
                 "ST_SSH_KNOWN_HOSTS": str(tmp_path / "kh"), "ST_REMOTE_DIR": str(remote),
                 "ST_DATA_DIR": str(tmp_path / "d")}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr("sys.argv", ["securetransfer", "benchmark", *args])
    with pytest.raises(SystemExit) as e:
        cli.main()
    return e.value.code


def test_cli_table_and_csv(monkeypatch, tmp_path, ssh_server, ssh_cfg, capsys):
    _, remote = ssh_cfg
    code = _cli(monkeypatch, tmp_path, ssh_server, remote,
                "--sizes", "1", "--repeat", "2", "--protocols", "scp", "sftp", "--csv", "out/b.csv")
    out = capsys.readouterr()
    assert code == 0 and "SCP" in out.out and "SFTP" in out.out and "Giao thức" in out.out
    assert "lần 2/2" in out.err
    with open(tmp_path / "out" / "b.csv", encoding="utf-8-sig") as f:
        assert [r["protocol"] for r in csv.DictReader(f)] == ["scp", "sftp"]


def test_cli_json_and_legacy_size_mb(monkeypatch, tmp_path, ssh_server, ssh_cfg, capsys):
    _, remote = ssh_cfg
    code = _cli(monkeypatch, tmp_path, ssh_server, remote,
                "--size-mb", "1", "--repeat", "1", "--protocols", "sftp", "--json")
    rows = json.loads(capsys.readouterr().out)
    assert code == 0 and rows[0]["size_mb"] == 1 and rows[0]["intact"] is True


def test_cli_exit_code_1_when_nothing_measured(monkeypatch, tmp_path, ssh_server, ssh_cfg, capsys):
    _, remote = ssh_cfg
    monkeypatch.setenv("ST_SSH_PORT", "1")
    from securetransfer import cli
    monkeypatch.chdir(tmp_path)
    for k, v in {"ST_SSH_HOST": "127.0.0.1", "ST_SSH_USER": "x", "ST_SSH_PASSWORD": "x",
                 "ST_SSH_TIMEOUT": "1", "ST_DATA_DIR": str(tmp_path / "d")}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr("sys.argv", ["securetransfer", "benchmark", "--sizes", "1", "--protocols", "scp"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 1 and "Không đo được" in capsys.readouterr().out


def test_cli_rejects_bad_size(monkeypatch, tmp_path, ssh_server, ssh_cfg, capsys):
    _, remote = ssh_cfg
    code = _cli(monkeypatch, tmp_path, ssh_server, remote, "--sizes", "0")
    assert code == 2 and "từ 1 đến" in capsys.readouterr().err
