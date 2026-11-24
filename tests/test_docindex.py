"""DocumentIndex: tra cứu tài liệu mới nhất mà không quét lại cả audit log; đồng thời kiểm tra Gateway dùng nó."""
import pytest

from securetransfer.audit import AuditLog
from securetransfer.auth import Level, Role, User
from securetransfer.config import Settings
from securetransfer.docindex import DocumentIndex
from securetransfer.gateway import Gateway
from securetransfer.transfer import TransferBackend

ALICE = User("alice", Role.ADMIN, Level.SECRET)


def key_fn(name):
    return name.casefold()


def make(tmp_path):
    log = AuditLog(str(tmp_path / "audit.log"))
    return log, DocumentIndex(log, key_fn)


def test_latest_wins_and_only_successful_sends_count(tmp_path):
    log, idx = make(tmp_path)
    log.record("u", "send", "A.txt", "ok", {"level": "INTERNAL"})
    log.record("u", "send", "A.TXT", "ok", {"level": "SECRET"})         # cùng khóa (không phân biệt hoa/thường)
    log.record("u", "send", "B.txt", "denied", {"level": "SECRET"})      # bị từ chối: không tính
    log.record("u", "receive", "A.txt", "ok")                            # không phải send: không tính
    log.record("u", "send", "C.txt", "error")
    assert idx.latest("a.txt")["details"]["level"] == "SECRET"
    assert idx.latest("b.txt") is None and idx.latest("c.txt") is None and idx.latest("zzz") is None
    assert [e["target"] for e in idx.latest_all()] == ["A.TXT"]


def test_index_reads_only_new_part_of_the_log(tmp_path, monkeypatch):
    log, idx = make(tmp_path)
    for i in range(50):
        log.record("u", "send", f"f{i}", "ok", {"level": "INTERNAL"})
    idx.latest("f0")
    seen = []
    real = log.read_from
    monkeypatch.setattr(log, "read_from", lambda off=0: (lambda r: (seen.append((off, len(r[0]))), r)[1])(real(off)))
    log.record("u", "send", "f50", "ok", {"level": "INTERNAL"})
    assert idx.latest("f50") is not None
    idx.latest("f0"); idx.latest("f1")
    assert seen[0][0] > 0 and seen[0][1] == 1          # lần đầu sau khi ghi: bắt đầu từ offset cũ, đọc đúng 1 dòng mới
    assert all(n == 0 for _, n in seen[1:])            # các lần sau không còn gì mới
    assert len(idx.latest_all()) == 51


def test_rebuilds_when_log_is_replaced_by_a_shorter_one(tmp_path):
    log, idx = make(tmp_path)
    for i in range(10):
        log.record("u", "send", f"old{i}", "ok", {"level": "INTERNAL"})
    assert idx.latest("old9") is not None
    open(log.path, "wb").close()                        # log bị cắt/thay mới
    fresh = AuditLog(log.path)
    fresh.record("u", "send", "new", "ok", {"level": "INTERNAL"})
    assert idx.latest("old9") is None and idx.latest("new") is not None


def test_sees_entries_written_by_another_instance(tmp_path):
    log, idx = make(tmp_path)
    log.record("u", "send", "a", "ok", {"level": "INTERNAL"})
    assert idx.latest("a") is not None
    AuditLog(log.path).record("u", "send", "b", "ok", {"level": "INTERNAL"})
    assert idx.latest("b") is not None


# ---------- Gateway ----------

class MemoryBackend(TransferBackend):
    name = "ftps"
    def __init__(self): self.files = {}
    def upload(self, local_path, remote_path):
        self.files[remote_path] = open(local_path, "rb").read()
    def download(self, remote_path, local_path):
        open(local_path, "wb").write(self.files[remote_path])


def test_gateway_send_and_receive_never_scan_the_whole_log(tmp_path, monkeypatch):
    gw = Gateway(Settings(data_dir=str(tmp_path / "data"), remote_dir="/"), backends={"ftps": MemoryBackend()})
    src = tmp_path / "s.txt"; src.write_text("noi dung", encoding="utf-8")
    gw.send(ALICE, str(src), remote_name="a.txt", level=Level.INTERNAL)
    monkeypatch.setattr(gw.audit, "read_all", lambda: (_ for _ in ()).throw(AssertionError("quét cả log")))
    for i in range(10):
        gw.send(ALICE, str(src), remote_name=f"f{i}.txt", level=Level.INTERNAL)
    out = tmp_path / "o.txt"
    gw.receive(ALICE, "a.txt", str(out))
    assert out.read_text(encoding="utf-8") == "noi dung"
    assert gw.audit.scan_count == 1


def test_gateway_follows_a_replaced_audit_object(tmp_path):
    gw = Gateway(Settings(data_dir=str(tmp_path / "data"), remote_dir="/"), backends={"ftps": MemoryBackend()})
    src = tmp_path / "s.txt"; src.write_text("x", encoding="utf-8")
    gw.send(ALICE, str(src), remote_name="a.txt", level=Level.INTERNAL)
    gw.audit = AuditLog(str(tmp_path / "other.log"))    # log khác, trống
    assert gw._latest_send("a.txt") is None
