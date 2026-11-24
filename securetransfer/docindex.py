"""Chỉ mục "tài liệu -> lần gửi thành công mới nhất", suy ra từ audit log và cập nhật tăng dần.

Trước đây mỗi lần gửi, nhận, liệt kê hay chia sẻ đều quét lại toàn bộ audit log (O(số dòng log)). Giờ chỉ mục
nhớ offset đã đọc tới đâu và mỗi lần hỏi chỉ đọc phần log mới (AuditLog.read_from), nên chi phí tỉ lệ với số
dòng mới. Log là nguồn sự thật duy nhất; chỉ mục không lưu gì ra đĩa, mất đi thì tự dựng lại từ log.
Nếu log bị cắt ngắn/thay mới (AuditResetError) chỉ mục tự dựng lại từ đầu. Một thay đổi giữ nguyên hoặc làm
tăng kích thước file mà không phải ghi nối thêm (sửa tay) thì không phát hiện được ở đây; đó là việc của
AuditLog.verify().
"""
from __future__ import annotations

import threading
from typing import Callable

from .audit import AuditLog, AuditResetError


class DocumentIndex:
    def __init__(self, audit: AuditLog, key_fn: Callable[[str], str]):
        self.audit = audit
        self._key_fn = key_fn
        self._latest: dict[str, dict] = {}
        self._offset = 0
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        try:
            entries, offset = self.audit.read_from(self._offset)
        except AuditResetError:
            self._latest.clear()
            self._offset = 0
            entries, offset = self.audit.read_from(0)
        for e in entries:
            if e.get("action") == "send" and e.get("status") == "ok":
                self._latest[self._key_fn(e["target"])] = e
        self._offset = offset

    def latest(self, key: str) -> dict | None:
        """Bản ghi audit của lần gửi thành công mới nhất cho tài liệu có khóa `key`; None nếu chưa từng gửi."""
        with self._lock:
            self._refresh()
            return self._latest.get(key)

    def latest_all(self) -> list[dict]:
        """Lần gửi thành công mới nhất của mọi tài liệu (thứ tự theo lần gửi đầu tiên của từng tài liệu)."""
        with self._lock:
            self._refresh()
            return list(self._latest.values())
