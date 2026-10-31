"""Gateway: điểm vào duy nhất. Kiểm quyền -> mã hóa -> chọn giao thức -> truyền -> ghi audit."""
from __future__ import annotations
import os
import posixpath
import tempfile
import threading
import unicodedata

from .audit import AuditLog
from .auth import AuthError, Level, Role, User, authorize
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


class ConflictError(Exception):
    """Tên tài liệu đã được dùng, hoặc việc ghi đè không được phép (API trả HTTP 409)."""


class Gateway:
    def __init__(self, settings: Settings, audit: AuditLog | None = None,
                 backends: dict[str, TransferBackend] | None = None):
        self.s = settings
        self.audit = audit or AuditLog(
            settings.audit_path,
            (settings.syslog_host, settings.syslog_port) if settings.syslog_host else None)
        self.backends = backends or build_backends(settings)
        self.key = load_or_create_key(settings.key_path)
        self._locks_guard = threading.Lock()
        self._name_locks: dict[str, threading.Lock] = {}

    def _pick(self, scenario: str) -> TransferBackend:
        if scenario not in SCENARIO_PROTOCOL:
            raise ValueError(f"Tình huống không hợp lệ: {scenario}")
        return self.backends[SCENARIO_PROTOCOL[scenario]]

    @staticmethod
    def _basename(name: str) -> str:
        return os.path.basename(name.replace("\\", "/"))

    @classmethod
    def document_key(cls, name: str) -> str:
        """Khóa định danh tài liệu. Chuẩn hóa Unicode và bỏ phân biệt hoa/thường, vì Windows và macOS
        coi 'Báo-Cáo.TXT' và 'báo-cáo.txt' là MỘT file; thư mục (../, x\\) cũng bị cắt như _remote()."""
        return unicodedata.normalize("NFC", cls._basename(name)).casefold()

    def _name_lock(self, key: str) -> threading.Lock:
        with self._locks_guard:
            return self._name_locks.setdefault(key, threading.Lock())

    def _latest_send(self, key: str) -> dict | None:
        last = None
        for e in self.audit.read_all():
            if e["action"] == "send" and e["status"] == "ok" and self.document_key(e["target"]) == key:
                last = e
        return last

    def _check_overwrite(self, user: User, key: str, level: Level) -> None:
        """Gửi trùng tên = ghi đè file trên máy chủ. Chỉ cho phép khi không làm mất hay hạ cấp tài liệu của người khác."""
        last = self._latest_send(key)
        if last is None:
            return
        old = Level.__members__.get(last.get("details", {}).get("level", "SECRET"), Level.SECRET)
        if old > user.clearance or (last["user"] != user.username and user.role != Role.ADMIN):
            # Cố ý không nói tài liệu cũ của ai, mức mật gì
            raise ConflictError("Tên tài liệu đã được dùng. Hãy đổi tên file rồi gửi lại.")
        if level < old:
            raise ConflictError(f"Không được hạ mức mật khi ghi đè tài liệu đã có ({old.name} xuống {level.name}).")

    def _remote(self, name: str) -> str:
        safe = os.path.basename(name.replace("\\", "/"))  # chống path traversal (../)
        if not safe or safe in (".", ".."):
            raise ValueError("Tên file không hợp lệ")
        return posixpath.join(self.s.remote_dir, safe + ".enc")

    def send(self, user: User, local_path: str, remote_name: str | None = None,
             level: Level = Level.INTERNAL, scenario: str = "partner") -> str:
        name = self._basename(remote_name or local_path)
        backend = self._pick(scenario)
        try:
            authorize(user, "send", level)
            remote = self._remote(name)
            key = self.document_key(name)
            with self._name_lock(key):  # kiểm tra trùng tên + ghi file + ghi audit là một khối, tránh hai người gửi cùng lúc
                self._check_overwrite(user, key, level)
                with tempfile.TemporaryDirectory() as tmp:
                    enc = os.path.join(tmp, "payload.enc")
                    encrypt_file(local_path, enc, self.key)
                    backend.upload(enc, remote)
                self.audit.record(user.username, "send", name, "ok",
                                  {"protocol": backend.name, "level": level.name})
        except (AuthError, ConflictError, TransferError, ValueError, OSError) as e:
            self.audit.record(user.username, "send", name,
                              "denied" if isinstance(e, (AuthError, ConflictError)) else "error",
                              {"protocol": backend.name, "level": level.name, "error": str(e)})
            raise
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
