"""Gateway: điểm vào duy nhất. Kiểm quyền -> mã hóa -> chọn giao thức -> truyền -> ghi audit."""
from __future__ import annotations
import os
import posixpath
import tempfile

from .audit import AuditLog
from .auth import AuthError, Level, User, authorize
from .config import Settings
from .crypto import decrypt_file, encrypt_file, load_or_create_key
from .transfer import TransferBackend, TransferError, build_backends

# Chính sách chọn giao thức theo tình huống (sửa tại đây khi nhóm thống nhất)
SCENARIO_PROTOCOL = {
    "partner": "ftps",   # đối tác / hệ thống cũ
    "admin": "scp",      # quản trị chuyển nhanh
    "sync": "rsync",     # đồng bộ chi nhánh
    "baseline": "sftp",  # chỉ để so sánh
}


class Gateway:
    def __init__(self, settings: Settings, audit: AuditLog | None = None,
                 backends: dict[str, TransferBackend] | None = None):
        self.s = settings
        self.audit = audit or AuditLog(
            settings.audit_path,
            (settings.syslog_host, settings.syslog_port) if settings.syslog_host else None)
        self.backends = backends or build_backends(settings)
        self.key = load_or_create_key(settings.key_path)

    def _pick(self, scenario: str) -> TransferBackend:
        if scenario not in SCENARIO_PROTOCOL:
            raise ValueError(f"Tình huống không hợp lệ: {scenario}")
        return self.backends[SCENARIO_PROTOCOL[scenario]]

    def _remote(self, name: str) -> str:
        safe = os.path.basename(name.replace("\\", "/"))  # chống path traversal (../)
        if not safe or safe in (".", ".."):
            raise ValueError("Tên file không hợp lệ")
        return posixpath.join(self.s.remote_dir, safe + ".enc")

    def send(self, user: User, local_path: str, remote_name: str | None = None,
             level: Level = Level.INTERNAL, scenario: str = "partner") -> str:
        name = remote_name or os.path.basename(local_path)
        backend = self._pick(scenario)
        try:
            authorize(user, "send", level)
            remote = self._remote(name)
            with tempfile.TemporaryDirectory() as tmp:
                enc = os.path.join(tmp, "payload.enc")
                encrypt_file(local_path, enc, self.key)
                backend.upload(enc, remote)
        except (AuthError, TransferError, ValueError, OSError) as e:
            self.audit.record(user.username, "send", name, "denied" if isinstance(e, AuthError) else "error",
                              {"protocol": backend.name, "level": level.name, "error": str(e)})
            raise
        self.audit.record(user.username, "send", name, "ok",
                          {"protocol": backend.name, "level": level.name})
        return remote

    def receive(self, user: User, remote_name: str, dest_path: str,
                level: Level = Level.INTERNAL, scenario: str = "partner") -> str:
        backend = self._pick(scenario)
        try:
            authorize(user, "receive", level)
            remote = self._remote(remote_name)
            with tempfile.TemporaryDirectory() as tmp:
                enc = os.path.join(tmp, "payload.enc")
                backend.download(remote, enc)
                decrypt_file(enc, dest_path, self.key)
        except Exception as e:
            self.audit.record(user.username, "receive", remote_name,
                              "denied" if isinstance(e, AuthError) else "error",
                              {"protocol": backend.name, "error": str(e)})
            raise
        self.audit.record(user.username, "receive", remote_name, "ok", {"protocol": backend.name})
        return dest_path
