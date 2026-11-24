"""Giới hạn đăng nhập sai (chống đoán mật khẩu). Chỉ dùng thư viện chuẩn, lưu trong bộ nhớ của tiến trình.

Hai bộ đếm chạy song song:
  - theo cặp (địa chỉ IP, tên đăng nhập): khóa nhanh kẻ đang đoán từ một máy mà không ảnh hưởng người khác;
  - theo riêng tên đăng nhập (ngưỡng cao gấp 4): chặn đoán rải qua nhiều IP.
Khóa kiểm tra TRƯỚC khi xác thực, nên bị khóa rồi thì mật khẩu đúng cũng không vào được (nếu không, kẻ tấn công
vẫn đoán tiếp được). Đăng nhập thành công chỉ xóa bộ đếm của cặp (IP, tên), không xóa bộ đếm theo tên.

Hạn chế đã biết: bộ đếm theo tên cho phép ai đó cố tình làm người dùng thật bị khóa tạm thời (DoS có chủ đích);
bộ nhớ riêng từng tiến trình, nên chạy nhiều worker thì mỗi worker đếm riêng; sau reverse proxy thì IP là
của proxy (cần cấu hình để lấy IP thật trước khi dựa vào bộ đếm theo IP).
"""
from __future__ import annotations

import math
import threading
import time
import unicodedata
from typing import Callable


class FailureLimiter:
    """Đếm số lần thất bại trong một cửa sổ thời gian; đủ ngưỡng thì khóa `lockout` giây."""

    def __init__(self, max_failures: int, window: float, lockout: float,
                 clock: Callable[[], float] = time.monotonic, max_entries: int = 10_000):
        self.max_failures, self.window, self.lockout = max_failures, window, lockout
        self._clock, self._max_entries = clock, max_entries
        self._entries: dict[str, list] = {}          # key -> [danh sách thời điểm thất bại, locked_until]
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.max_failures > 0

    def retry_after(self, key: str) -> int:
        """Số giây còn bị khóa (làm tròn lên); 0 nếu không bị khóa."""
        if not self.enabled:
            return 0
        with self._lock:
            entry = self._entries.get(key)
            if not entry:
                return 0
            remaining = entry[1] - self._clock()
            return math.ceil(remaining) if remaining > 0 else 0

    def record_failure(self, key: str) -> bool:
        """Ghi một lần thất bại. Trả True nếu chính lần này kích hoạt khóa."""
        if not self.enabled:
            return False
        with self._lock:
            now = self._clock()
            entry = self._entries.setdefault(key, [[], 0.0])
            entry[0] = [t for t in entry[0] if now - t < self.window]
            entry[0].append(now)
            locked = False
            if len(entry[0]) >= self.max_failures and entry[1] <= now:
                entry[1] = now + self.lockout
                entry[0] = []
                locked = True
            if len(self._entries) > self._max_entries:
                self._evict(now)
            return locked

    def reset(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def _evict(self, now: float) -> None:
        """Giữ bộ nhớ có giới hạn khi bị tràn tên đăng nhập ngẫu nhiên: bỏ mục đã hết hạn trước, rồi mục cũ nhất."""
        for k in [k for k, (fails, until) in self._entries.items()
                  if until <= now and all(now - t >= self.window for t in fails)]:
            del self._entries[k]
        while len(self._entries) > self._max_entries:
            del self._entries[next(iter(self._entries))]


class LoginThrottle:
    def __init__(self, max_failures: int = 5, window: float = 300, lockout: float = 300,
                 clock: Callable[[], float] = time.monotonic):
        self._pair = FailureLimiter(max_failures, window, lockout, clock)
        self._user = FailureLimiter(max_failures * 4, window, lockout, clock)

    @staticmethod
    def _norm(username: str) -> str:
        return unicodedata.normalize("NFC", username or "").strip().casefold()[:128]

    def _keys(self, ip: str, username: str) -> tuple[str, str]:
        user = self._norm(username)
        return f"{ip}|{user}", user

    def blocked(self, ip: str, username: str) -> int:
        """Số giây còn bị khóa cho lần đăng nhập này; 0 nghĩa là được phép thử."""
        pair, user = self._keys(ip, username)
        return max(self._pair.retry_after(pair), self._user.retry_after(user))

    def failure(self, ip: str, username: str) -> bool:
        """Ghi một lần sai (kể cả tên không tồn tại, để không lộ tên nào có thật). True nếu vừa bị khóa."""
        pair, user = self._keys(ip, username)
        a = self._pair.record_failure(pair)
        b = self._user.record_failure(user)
        return a or b

    def success(self, ip: str, username: str) -> None:
        self._pair.reset(self._keys(ip, username)[0])
