"""Link chia sẻ có thời hạn.

- Token chỉ hiện ra một lần lúc tạo; file lưu trữ chỉ giữ SHA-256 của token,
  nên lộ file shares.json cũng không lộ link.
- Mỗi lần tải được đếm dưới khóa (lock) để hai yêu cầu cùng lúc không vượt quá số lần cho phép.
- Link hết hạn, quá số lần hoặc đã thu hồi đều trả 410; token không tồn tại trả 404.
- Link gắn với một phiên bản tài liệu (`version`). Tài liệu bị gửi đè thì link hết hiệu lực, nên link không
  bao giờ phục vụ nhầm một bản mới hơn hoặc mật hơn bản đã được cho phép chia sẻ.
"""
from __future__ import annotations
import hashlib
import json
import os
import secrets
import tempfile
import threading
import time
from typing import Callable

MAX_EXPIRES_MINUTES = 7 * 24 * 60
MAX_DOWNLOADS_LIMIT = 100


class ShareError(Exception):
    def __init__(self, status: int, message: str, share_id: str | None = None):
        super().__init__(message)
        self.status = status
        self.share_id = share_id


def _key(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class ShareStore:
    def __init__(self, path: str, clock: Callable[[], float] = time.time):
        self.path = path
        self.clock = clock
        self._lock = threading.Lock()

    # ---------- lưu trữ ----------
    def _load(self) -> dict[str, dict]:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict[str, dict]) -> None:
        folder = os.path.dirname(self.path) or "."
        os.makedirs(folder, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    @staticmethod
    def _public(key: str, rec: dict) -> dict:
        return {"id": key[:12], **rec}

    # ---------- thao tác ----------
    def create(self, doc: str, level: str, scenario: str, created_by: str,
               expires_minutes: int, max_downloads: int, version: str = "") -> tuple[str, dict]:
        if not 1 <= expires_minutes <= MAX_EXPIRES_MINUTES:
            raise ValueError(f"expires_minutes phải từ 1 đến {MAX_EXPIRES_MINUTES}")
        if not 1 <= max_downloads <= MAX_DOWNLOADS_LIMIT:
            raise ValueError(f"max_downloads phải từ 1 đến {MAX_DOWNLOADS_LIMIT}")
        token = secrets.token_urlsafe(32)
        now = self.clock()
        rec = {
            "doc": doc, "level": level, "scenario": scenario, "created_by": created_by, "version": version,
            "created_at": now, "expires_at": now + expires_minutes * 60,
            "max_downloads": max_downloads, "downloads": 0, "revoked": False,
        }
        key = _key(token)
        with self._lock:
            data = self._load()
            data[key] = rec
            self._save(data)
        return token, self._public(key, rec)

    def get(self, token: str) -> dict:
        key = _key(token)
        with self._lock:
            rec = self._load().get(key)
        if rec is None:
            raise ShareError(404, "Link không tồn tại")
        return self._public(key, rec)

    def consume(self, token: str) -> dict:
        """Kiểm tra và tính một lượt tải. Lỗi 410 nếu link không còn dùng được."""
        key = _key(token)
        with self._lock:
            data = self._load()
            rec = data.get(key)
            if rec is None:
                raise ShareError(404, "Link không tồn tại")
            sid = key[:12]
            if rec["revoked"]:
                raise ShareError(410, "Link đã bị thu hồi", sid)
            if self.clock() >= rec["expires_at"]:
                raise ShareError(410, "Link đã hết hạn", sid)
            if rec["downloads"] >= rec["max_downloads"]:
                raise ShareError(410, "Link đã hết số lần tải", sid)
            rec["downloads"] += 1
            self._save(data)
            return self._public(key, rec)

    def refund(self, token: str) -> None:
        """Hoàn lại một lượt tải khi việc giải mã/truyền thất bại phía máy chủ."""
        key = _key(token)
        with self._lock:
            data = self._load()
            rec = data.get(key)
            if rec and rec["downloads"] > 0:
                rec["downloads"] -= 1
                self._save(data)

    def revoke(self, token: str) -> dict:
        key = _key(token)
        with self._lock:
            data = self._load()
            rec = data.get(key)
            if rec is None:
                raise ShareError(404, "Link không tồn tại")
            rec["revoked"] = True
            self._save(data)
            return self._public(key, rec)
