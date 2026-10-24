"""Kết nối SSH dùng chung cho SCP / SFTP / rsync.

Hai chế độ kiểm tra khóa máy chủ:
  - strict_host_key=False (mặc định, tiện khi dev): tự chấp nhận máy chủ lạ lần đầu.
  - strict_host_key=True  (nên dùng khi chạy thật): CHỈ chấp nhận máy chủ đã có trong known_hosts,
    chống kẻ tấn công đứng giữa giả mạo máy chủ. Thêm máy chủ bằng:  python -m securetransfer.devssh trust-host
"""
from __future__ import annotations
import os
from dataclasses import dataclass

import paramiko


@dataclass(frozen=True)
class SSHConn:
    host: str
    port: int
    username: str
    password: str | None = None
    key_file: str | None = None
    strict_host_key: bool = False
    known_hosts: str | None = None
    timeout: int = 20


def host_entry(host: str, port: int) -> str:
    """Tên dòng trong known_hosts: 'host' nếu cổng 22, ngược lại '[host]:port'."""
    return host if port == 22 else f"[{host}]:{port}"


def open_ssh(c: SSHConn) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    if c.known_hosts:
        if os.path.exists(c.known_hosts):
            client.load_host_keys(c.known_hosts)
        elif c.strict_host_key:
            raise paramiko.SSHException(
                f"Chưa có file known_hosts ({c.known_hosts}): server not found in known_hosts")
    else:
        client.load_system_host_keys()
    client.set_missing_host_key_policy(
        paramiko.RejectPolicy() if c.strict_host_key else paramiko.AutoAddPolicy())
    explicit = bool(c.key_file or c.password)   # đã chỉ rõ khóa/mật khẩu thì không thử khóa khác của máy
    client.connect(c.host, port=c.port, username=c.username, password=c.password,
                   key_filename=c.key_file, timeout=c.timeout, banner_timeout=c.timeout,
                   auth_timeout=c.timeout, look_for_keys=not explicit, allow_agent=not explicit)
    return client


def friendly(e: Exception) -> str:
    """Biến lỗi kỹ thuật thành thông báo dễ hiểu, có hướng xử lý."""
    msg = str(e)
    if isinstance(e, paramiko.BadHostKeyException):
        return ("KHÓA MÁY CHỦ ĐÃ THAY ĐỔI so với known_hosts. Có thể đang bị tấn công giữa đường. "
                "Nếu chắc chắn máy chủ vừa cài lại, xóa dòng cũ trong known_hosts rồi chạy lại trust-host.")
    if "not found in known_hosts" in msg:
        return ("Máy chủ chưa được tin cậy (chế độ strict). "
                "Chạy:  python -m securetransfer.devssh trust-host   rồi thử lại. " + msg)
    if isinstance(e, paramiko.AuthenticationException):
        return "Xác thực SSH thất bại: kiểm tra ST_SSH_USER và ST_SSH_KEY_FILE (hoặc mật khẩu)."
    if isinstance(e, TimeoutError):
        return f"Hết thời gian chờ kết nối: {msg}"
    return msg
