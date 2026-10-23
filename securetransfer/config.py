"""Cấu hình đọc từ biến môi trường (tiền tố ST_). Xem .env.example."""
from __future__ import annotations
import os
from dataclasses import dataclass


def _load_dotenv(path: str = ".env") -> None:
    """Đọc file .env (KEY=VALUE) nếu có. Biến môi trường đã đặt sẵn sẽ được ưu tiên."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _bool(v: str | None, default: bool) -> bool:
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    data_dir: str = "data"
    users_path: str = "config/users.json"
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
    # Syslog (tùy chọn)
    syslog_host: str | None = None
    syslog_port: int = 514

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
        s.syslog_host = g("SYSLOG_HOST")
        s.syslog_port = int(g("SYSLOG_PORT", s.syslog_port))
        return s
