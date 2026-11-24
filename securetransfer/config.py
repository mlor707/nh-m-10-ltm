"""Cấu hình đọc từ biến môi trường (tiền tố ST_). Xem .env.example."""
from __future__ import annotations
import os
import re
from dataclasses import dataclass


def _parse_dotenv_value(raw: str) -> str:
    """Giá trị trong .env. Dấu # chỉ mở đầu chú thích khi đứng sau khoảng trắng và giá trị không đặt trong
    ngoặc kép/đơn, nên mật khẩu như 'p#ss' hay 'abc#123' không bị cắt cụt."""
    raw = raw.strip()
    if raw[:1] in ("'", '"'):
        end = raw.find(raw[0], 1)
        if end != -1:                       # có ngoặc đóng: lấy nguyên nội dung bên trong, bỏ phần sau
            return raw[1:end]
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def _load_dotenv(path: str = ".env") -> None:
    """Đọc file .env (KEY=VALUE) nếu có. Biến môi trường đã đặt sẵn sẽ được ưu tiên."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8-sig") as f:   # utf-8-sig: bỏ BOM mà Notepad hay thêm vào
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                if k:
                    os.environ.setdefault(k, _parse_dotenv_value(v))


def _bool(v: str | None, default: bool) -> bool:
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    data_dir: str = "data"
    users_path: str = "config/users.json"
    jwt_secret: str | None = None
    remote_dir: str = "."
    # FTPS
    ftps_host: str = "127.0.0.1"
    ftps_port: int = 2121
    ftps_user: str = "test"
    ftps_password: str = "test123"
    ftps_verify: bool = False          # True + ftps_ca_file khi chạy thật
    ftps_ca_file: str | None = None
    # SSH (dùng chung cho SCP / SFTP / rsync)
    ssh_host: str = "127.0.0.1"
    ssh_port: int = 22
    ssh_user: str = ""
    ssh_password: str | None = None
    ssh_key_file: str | None = None
    ssh_strict_host_key: bool = False   # True: chỉ tin máy chủ có trong known_hosts (nên bật khi chạy thật)
    ssh_known_hosts: str | None = None  # None: dùng ~/.ssh/known_hosts của hệ thống
    ssh_timeout: int = 20
    # Nhật ký kiểm toán: đặt khóa (>= 32 byte) để dùng HMAC và chống sửa/xóa dòng cuối
    audit_key: str | None = None
    # Cho phép giải mã file STF1 cũ (không gắn với tài liệu). Mặc định tắt; chỉ bật tạm khi di chuyển dữ liệu cũ.
    allow_legacy_enc: bool = False
    # Giới hạn đăng nhập sai: quá `login_max_failures` lần trong `login_window_seconds` giây thì khóa
    # `login_lockout_seconds` giây. Đặt login_max_failures = 0 để tắt (chỉ nên dùng khi phát triển).
    login_max_failures: int = 5
    login_window_seconds: int = 300
    login_lockout_seconds: int = 300
    # Syslog (tùy chọn)
    syslog_host: str | None = None
    syslog_port: int = 514

    def ssh_conn(self):
        from .transfer._ssh import SSHConn
        return SSHConn(self.ssh_host, self.ssh_port, self.ssh_user, self.ssh_password, self.ssh_key_file,
                       self.ssh_strict_host_key, self.ssh_known_hosts, self.ssh_timeout)

    @property
    def key_path(self) -> str:
        return os.path.join(self.data_dir, "master.key")

    @property
    def audit_path(self) -> str:
        return os.path.join(self.data_dir, "audit.log")

    @classmethod
    def from_env(cls) -> "Settings":
        _load_dotenv()
        g = lambda k, d=None: os.environ.get(f"ST_{k}", d)  # noqa: E731
        s = cls()
        s.data_dir = g("DATA_DIR", s.data_dir)
        s.users_path = g("USERS_PATH", s.users_path)
        s.jwt_secret = g("JWT_SECRET") or None
        s.remote_dir = g("REMOTE_DIR", s.remote_dir)
        s.ftps_host = g("FTPS_HOST", s.ftps_host)
        s.ftps_port = int(g("FTPS_PORT", s.ftps_port))
        s.ftps_user = g("FTPS_USER", s.ftps_user)
        s.ftps_password = g("FTPS_PASSWORD", s.ftps_password)
        s.ftps_verify = _bool(g("FTPS_VERIFY"), s.ftps_verify)
        s.ftps_ca_file = g("FTPS_CA_FILE")
        s.ssh_host = g("SSH_HOST", s.ssh_host)
        s.ssh_port = int(g("SSH_PORT", s.ssh_port))
        s.ssh_user = g("SSH_USER", s.ssh_user)
        s.ssh_password = g("SSH_PASSWORD") or None
        s.ssh_key_file = g("SSH_KEY_FILE") or None
        s.ssh_strict_host_key = _bool(g("SSH_STRICT_HOST_KEY"), s.ssh_strict_host_key)
        s.ssh_known_hosts = g("SSH_KNOWN_HOSTS") or None
        s.ssh_timeout = int(g("SSH_TIMEOUT", s.ssh_timeout))
        s.audit_key = g("AUDIT_KEY") or None
        s.allow_legacy_enc = _bool(g("ALLOW_LEGACY_ENC"), s.allow_legacy_enc)
        s.login_max_failures = int(g("LOGIN_MAX_FAILURES", s.login_max_failures))
        s.login_window_seconds = int(g("LOGIN_WINDOW_SECONDS", s.login_window_seconds))
        s.login_lockout_seconds = int(g("LOGIN_LOCKOUT_SECONDS", s.login_lockout_seconds))
        s.syslog_host = g("SYSLOG_HOST")
        s.syslog_port = int(g("SYSLOG_PORT", s.syslog_port))
        return s
