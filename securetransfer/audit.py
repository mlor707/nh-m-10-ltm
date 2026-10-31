"""Audit log dạng hash-chain (mỗi dòng chứa hash của dòng trước) + gửi Syslog tùy chọn.

Sửa/xóa một dòng bất kỳ => verify() phát hiện.
"""
from __future__ import annotations
import hashlib
import json
import logging
import logging.handlers
import os
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str, syslog_address: tuple[str, int] | None = None):
        self.path = path
        self._lock = threading.RLock()  # RLock: record() gọi read_all() khi đang giữ khóa
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._logger = None
        if syslog_address:  # Giao thức Syslog
            self._logger = logging.getLogger("securetransfer.audit")
            self._logger.setLevel(logging.INFO)
            self._logger.addHandler(logging.handlers.SysLogHandler(address=syslog_address))

    @staticmethod
    def _hash(prev: str, entry: dict) -> str:
        body = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256((prev + body).encode()).hexdigest()

    def _last_hash(self) -> str:
        entries = self.read_all()
        return entries[-1]["hash"] if entries else GENESIS

    def record(self, user: str, action: str, target: str, status: str = "ok",
               details: dict | None = None) -> dict:
        # TODO: dùng thời gian đồng bộ NTP của hệ điều hành (chrony / w32time)
        with self._lock:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "user": user, "action": action, "target": target,
                "status": status, "details": details or {},
            }
            prev = self._last_hash()
            entry["prev"] = prev
            entry["hash"] = self._hash(prev, {k: v for k, v in entry.items() if k not in ("prev", "hash")})
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        if self._logger:
            self._logger.info("securetransfer user=%s action=%s target=%s status=%s",
                              user, action, target, status)
        return entry

    def read_all(self) -> list[dict]:
        with self._lock:  # không đọc phải dòng đang được ghi dở bởi luồng khác
            if not os.path.exists(self.path):
                return []
            with open(self.path, encoding="utf-8") as f:
                return [json.loads(l) for l in f if l.strip()]

    def verify(self) -> tuple[bool, int | None]:
        """Trả về (hợp lệ?, số dòng lỗi đầu tiên – đếm từ 1)."""
        prev = GENESIS
        for i, e in enumerate(self.read_all(), start=1):
            body = {k: v for k, v in e.items() if k not in ("prev", "hash")}
            if e.get("prev") != prev or e.get("hash") != self._hash(prev, body):
                return False, i
            prev = e["hash"]
        return True, None
