"""Audit log dạng hash-chain (mỗi dòng chứa hash của dòng trước) + gửi Syslog tùy chọn.

Hai chế độ:
  - Không khóa (mặc định, ST_AUDIT_KEY trống): hash = SHA-256. Sửa một dòng giữa file thì verify() báo lỗi,
    nhưng kẻ có quyền ghi file có thể sửa rồi tính lại cả chuỗi, hoặc xóa các dòng cuối mà không bị phát hiện.
  - Có khóa (đặt ST_AUDIT_KEY, ít nhất 32 byte): hash = HMAC-SHA256 nên không tính lại được nếu không có khóa,
    và file `<log>.head` (có chữ ký HMAC) ghi số dòng + hash dòng cuối để phát hiện việc xóa dòng cuối.
    Giới hạn còn lại: kẻ có cả khóa, hoặc khôi phục lại cả log lẫn .head từ bản sao cũ, thì local không phát hiện được.
    Vì vậy mỗi dòng gửi Syslog kèm hash, để máy chủ log từ xa giữ bản đối chiếu.

Hiệu năng: record() KHÔNG đọc lại cả file. Số dòng và hash dòng cuối được giữ trong bộ nhớ; chỉ khi kích thước
file khác với lần ghi/quét trước (tiến trình khác ghi vào, file bị thay) mới quét lại một lần. Người đọc dùng
read_from(offset) để chỉ lấy các dòng mới kể từ lần đọc trước (xem docindex.py). Mỗi lần ghi vẫn là một lần
append + một lần ghi file .head (chế độ có khóa), tức chi phí không tăng theo độ dài log.
Giới hạn: chưa có khóa file giữa nhiều TIẾN TRÌNH; chạy nhiều worker cùng ghi vào một log vẫn có thể làm lệch
chuỗi hash (verify() sẽ phát hiện). Hiện chỉ hỗ trợ một tiến trình ghi.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import tempfile
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64
ALG_HMAC = "hmac-sha256"
MIN_KEY_BYTES = 32


class AuditResetError(Exception):
    """Offset người đọc giữ đã quá kích thước file: log bị cắt ngắn/thay mới, phải đọc lại từ đầu."""


class AuditLog:
    def __init__(self, path: str, syslog_address: tuple[str, int] | None = None,
                 key: bytes | str | None = None):
        self.path = path
        self.head_path = path + ".head"
        # RLock: record() gọi read_all() khi đang giữ khóa. Dùng chung MỘT instance cho cả tiến trình.
        self._lock = threading.RLock()
        if isinstance(key, str):
            key = key.encode("utf-8")
        if key is not None and len(key) < MIN_KEY_BYTES:
            raise ValueError(f"ST_AUDIT_KEY phải có ít nhất {MIN_KEY_BYTES} byte")
        self._key = key or None
        # Trạng thái đuôi log trong bộ nhớ (xem docstring đầu file)
        self._synced = False
        self._n, self._last, self._size, self._needs_newline = 0, GENESIS, 0, False
        self.scan_count = 0            # số lần phải quét cả file; dùng cho test và theo dõi
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._logger = None
        if syslog_address:  # Giao thức Syslog
            self._logger = logging.getLogger("securetransfer.audit")
            self._logger.setLevel(logging.INFO)
            if not any(isinstance(h, logging.handlers.SysLogHandler) and h.address == syslog_address
                       for h in self._logger.handlers):
                self._logger.addHandler(logging.handlers.SysLogHandler(address=syslog_address))

    @classmethod
    def from_settings(cls, s) -> "AuditLog":
        host = getattr(s, "syslog_host", None)
        address = (host, s.syslog_port) if host else None
        return cls(s.audit_path, address, getattr(s, "audit_key", None))

    @property
    def keyed(self) -> bool:
        return self._key is not None

    # ---------- băm ----------
    @staticmethod
    def _body(entry: dict) -> str:
        return json.dumps({k: v for k, v in entry.items() if k not in ("prev", "hash")},
                          sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _hash(prev: str, entry: dict) -> str:
        body = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256((prev + body).encode()).hexdigest()

    def _mac(self, prev: str, entry: dict) -> str:
        body = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        return hmac.new(self._key, (prev + body).encode(), hashlib.sha256).hexdigest()

    def _head_mac(self, n: int, last_hash: str) -> str:
        return hmac.new(self._key, f"head|{n}|{last_hash}".encode(), hashlib.sha256).hexdigest()

    # ---------- ghi ----------
    def _write_head(self, n: int, last_hash: str) -> None:
        folder = os.path.dirname(self.head_path) or "."
        fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"n": n, "hash": last_hash, "mac": self._head_mac(n, last_hash)}, f)
            os.replace(tmp, self.head_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _tail(self) -> tuple[str, int]:
        """(hash dòng cuối, số dòng). O(1) khi file không đổi kể từ lần ghi/quét trước; nếu khác thì quét lại."""
        try:
            size = os.path.getsize(self.path)
        except FileNotFoundError:
            size = 0
        if self._synced and size == self._size:
            return self._last, self._n
        self.scan_count += 1
        n, last_raw, ends_nl = 0, None, True
        if size:
            with open(self.path, "rb") as f:
                for raw in f:                       # duyệt từng dòng, không nạp cả file vào bộ nhớ
                    ends_nl = raw.endswith(b"\n")
                    if raw.strip():
                        n, last_raw = n + 1, raw
        last = json.loads(last_raw)["hash"] if last_raw else GENESIS
        self._n, self._last, self._size = n, last, size
        self._needs_newline, self._synced = not ends_nl, True
        return last, n

    def record(self, user: str, action: str, target: str, status: str = "ok",
               details: dict | None = None) -> dict:
        # TODO: dùng thời gian đồng bộ NTP của hệ điều hành (chrony / w32time)
        with self._lock:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "user": user, "action": action, "target": target,
                "status": status, "details": details or {},
            }
            if self._key:
                entry["alg"] = ALG_HMAC
            prev, n = self._tail()
            entry["prev"] = prev
            body = {k: v for k, v in entry.items() if k not in ("prev", "hash")}
            entry["hash"] = self._mac(prev, body) if self._key else self._hash(prev, body)
            # Ghi nhị phân: kích thước tính được chính xác, không bị Windows đổi \n thành \r\n
            data = (b"\n" if self._needs_newline else b"") + \
                   (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
            with open(self.path, "ab") as f:
                f.write(data)
            expected = self._size + len(data)
            actual = os.path.getsize(self.path)
            self._n, self._last, self._size, self._needs_newline = n + 1, entry["hash"], actual, False
            if actual != expected:                  # có tiến trình khác chen vào giữa: lần sau quét lại cho chắc
                self._synced = False
            if self._key:
                self._write_head(n + 1, entry["hash"])
        if self._logger:
            self._logger.info("securetransfer user=%s action=%s target=%s status=%s hash=%s",
                              user, action, target, status, entry["hash"])
        return entry

    def read_from(self, offset: int = 0) -> tuple[list[dict], int]:
        """Đọc các dòng từ byte `offset` đến hết file. Trả (các bản ghi, offset mới) để lần sau đọc tiếp, nhờ đó
        người đọc chỉ trả giá cho phần log MỚI. Dòng cuối đang ghi dở (chưa trọn JSON) thì để lại cho lần sau.
        Raise AuditResetError nếu offset vượt quá kích thước file (log đã bị cắt/thay)."""
        with self._lock:  # không đọc phải dòng đang được ghi dở bởi luồng khác
            try:
                size = os.path.getsize(self.path)
            except FileNotFoundError:
                size = 0
            if offset > size:
                raise AuditResetError(f"offset {offset} vượt quá kích thước log ({size})")
            entries: list[dict] = []
            if offset == size:
                return entries, offset
            with open(self.path, "rb") as f:
                f.seek(offset)
                for raw in f:
                    if raw.strip():
                        try:
                            entries.append(json.loads(raw))
                        except ValueError:
                            if raw.endswith(b"\n"):
                                raise                # dòng đầy đủ mà hỏng: báo lỗi như trước đây
                            break                    # dòng cuối ghi dở: đọc lần sau
                    offset += len(raw)
            return entries, offset

    def read_all(self) -> list[dict]:
        return self.read_from(0)[0]

    # ---------- kiểm tra ----------
    def _read_head(self):
        """None nếu không có file; 'invalid' nếu hỏng hoặc sai chữ ký; (n, hash) nếu hợp lệ."""
        if not os.path.exists(self.head_path):
            return None
        try:
            with open(self.head_path, encoding="utf-8") as f:
                data = json.load(f)
            n, last_hash, mac = data["n"], data["hash"], data["mac"]
            if type(n) is int and isinstance(last_hash, str) and isinstance(mac, str) \
                    and hmac.compare_digest(mac, self._head_mac(n, last_hash)):
                return n, last_hash
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return "invalid"

    def verify(self) -> tuple[bool, int | None]:
        """Trả về (hợp lệ?, số dòng lỗi đầu tiên – đếm từ 1).

        Khi phát hiện mất dòng cuối, 'dòng lỗi' là dòng đầu tiên bị thiếu (số dòng còn lại cộng 1).
        """
        with self._lock:
            entries = self.read_all()
        prev = GENESIS
        seen_hmac = False
        for i, e in enumerate(entries, start=1):
            body = {k: v for k, v in e.items() if k not in ("prev", "hash")}
            if e.get("alg") == ALG_HMAC:
                if not self._key:
                    return False, i                      # không có khóa thì không kiểm được dòng HMAC
                expected = self._mac(prev, body)
                seen_hmac = True
            else:
                if seen_hmac:
                    return False, i                      # dòng không khóa chen sau dòng có khóa: bị hạ cấp
                expected = self._hash(prev, body)
            if e.get("prev") != prev or not hmac.compare_digest(str(e.get("hash")), expected):
                return False, i
            prev = e["hash"]
        if self._key:
            head = self._read_head()
            if head == "invalid" or (head is None and seen_hmac):
                return False, len(entries) + 1           # file .head bị sửa/xóa
            if head is not None:
                n, last_hash = head
                if len(entries) < n:
                    return False, len(entries) + 1       # bị xóa dòng cuối
                if n > 0 and entries[n - 1]["hash"] != last_hash:
                    return False, n
        return True, None
