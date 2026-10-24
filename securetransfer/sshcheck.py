"""Chẩn đoán máy chủ SSH từng bước, mỗi lỗi kèm hướng xử lý.  Chạy:  python -m securetransfer.cli ssh-check"""
from __future__ import annotations
import os
import posixpath
import shutil
import socket
import tempfile
import time

from .config import Settings
from .transfer import build_backends
from .transfer._ssh import friendly, open_ssh
from .transfer.base import TransferError


def run(s: Settings) -> list[dict]:
    res: list[dict] = []

    def add(step: str, ok: bool, detail: str = "", hint: str = "") -> bool:
        res.append({"step": step, "ok": ok, "detail": detail, "hint": hint})
        return ok

    c = s.ssh_conn()
    problems = []
    if not c.username:
        problems.append("thiếu ST_SSH_USER")
    if not (c.key_file or c.password):
        problems.append("thiếu ST_SSH_KEY_FILE (hoặc ST_SSH_PASSWORD)")
    if c.key_file and not os.path.exists(c.key_file):
        problems.append(f"không thấy file khóa '{c.key_file}'")
    if not add("Cấu hình .env", not problems, "; ".join(problems) or
               f"{c.username}@{c.host}:{c.port}, chế độ {'strict' if c.strict_host_key else 'dev (tự tin cậy)'}",
               "Chạy python -m securetransfer.devssh keygen rồi điền .env theo hướng dẫn" if problems else ""):
        return res

    try:
        socket.create_connection((c.host, c.port), timeout=min(c.timeout, 5)).close()
        add("Kết nối cổng SSH", True, f"{c.host}:{c.port} mở")
    except OSError as e:
        add("Kết nối cổng SSH", False, str(e), "Máy chủ chưa chạy hoặc sai cổng. Docker: docker compose ps")
        return res

    try:
        open_ssh(c).close()
        add("Đăng nhập SSH", True, "đăng nhập bằng khóa thành công")
    except Exception as e:  # noqa: BLE001 – muốn báo mọi loại lỗi cho người dùng
        add("Đăng nhập SSH", False, type(e).__name__, friendly(e))
        return res

    probe = posixpath.join(s.remote_dir, ".st_check_probe")
    try:
        cl = open_ssh(c)
        try:
            sf = cl.open_sftp()
            with sf.open(probe, "w") as f:
                f.write(b"ok")
            sf.remove(probe)
        finally:
            cl.close()
        add("Thư mục đích ghi được", True, s.remote_dir)
    except Exception as e:  # noqa: BLE001
        add("Thư mục đích ghi được", False, str(e),
            f"ST_REMOTE_DIR='{s.remote_dir}' không tồn tại hoặc không có quyền ghi trên máy chủ")
        return res

    backends = build_backends(s)
    created: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "probe.bin")
        data = os.urandom(64 * 1024)
        open(src, "wb").write(data)
        for name in ("scp", "sftp", "rsync"):
            if name == "rsync" and shutil.which("rsync") is None:
                add("rsync", False, "không có lệnh rsync trên máy này",
                    "Windows: cài WSL2 và chạy dự án trong WSL (sudo apt install rsync). Linux/macOS: cài rsync.")
                continue
            remote = posixpath.join(s.remote_dir, f"st_check_{name}.bin")
            back = os.path.join(tmp, f"back_{name}.bin")
            try:
                t0 = time.perf_counter()
                backends[name].upload(src, remote)
                created.append(remote)
                backends[name].download(remote, back)
                ok = open(back, "rb").read() == data
                add(name.upper(), ok, f"gửi + nhận {time.perf_counter() - t0:.2f}s, " +
                    ("nội dung khớp" if ok else "NỘI DUNG KHÔNG KHỚP"),
                    "" if ok else "Dữ liệu bị thay đổi khi truyền, kiểm tra lại máy chủ")
            except TransferError as e:
                add(name.upper(), False, str(e))
    try:
        cl = open_ssh(c)
        try:
            sf = cl.open_sftp()
            for r in created:
                try:
                    sf.remove(r)
                except OSError:
                    pass
        finally:
            cl.close()
    except Exception:  # noqa: BLE001 – dọn dẹp là cố gắng tối đa
        pass
    return res


def format_report(rows: list[dict]) -> str:
    lines = []
    for r in rows:
        lines.append(f"[{'OK ' if r['ok'] else 'LỖI'}] {r['step']}: {r['detail']}")
        if not r["ok"] and r["hint"]:
            lines.append(f"       -> {r['hint']}")
    bad = sum(not r["ok"] for r in rows)
    lines.append("\nTất cả đạt, có thể chạy benchmark." if not bad else f"\n{bad} bước chưa đạt, xử lý theo gợi ý ở trên.")
    return "\n".join(lines)
