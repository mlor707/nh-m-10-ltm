"""AuditLog.record() không được đọc lại cả file mỗi lần ghi; read_from() chỉ trả phần log mới."""
import json
import os
import threading

import pytest

from securetransfer.audit import GENESIS, AuditLog, AuditResetError

KEY = "khoa-audit-thu-nghiem-dai-hon-32-byte!"


def make(tmp_path, keyed=False, name="audit.log"):
    return AuditLog(str(tmp_path / name), key=KEY if keyed else None)


@pytest.mark.parametrize("keyed", [False, True])
def test_many_records_scan_file_at_most_once(tmp_path, keyed):
    log = make(tmp_path, keyed)
    for i in range(300):
        log.record("u", "send", f"f{i}", "ok")
    assert log.scan_count == 1                      # chỉ lần đầu (file chưa có); không quét lại sau mỗi lần ghi
    assert log.verify() == (True, None)
    assert len(log.read_all()) == 300


def test_record_never_calls_read_all(tmp_path, monkeypatch):
    log = make(tmp_path)
    log.record("u", "send", "a", "ok")
    monkeypatch.setattr(log, "read_all", lambda: (_ for _ in ()).throw(AssertionError("record() đã đọc cả file")))
    for i in range(20):
        log.record("u", "send", f"f{i}", "ok")
    assert log.scan_count == 1


def test_keyed_head_tracks_count_without_rescan(tmp_path):
    log = make(tmp_path, keyed=True)
    for i in range(25):
        log.record("u", "login", "-", "ok")
    head = json.loads(open(log.head_path, encoding="utf-8").read())
    assert head["n"] == 25 and head["hash"] == log.read_all()[-1]["hash"]
    assert log.verify() == (True, None)


@pytest.mark.parametrize("keyed", [False, True])
def test_restart_continues_the_chain(tmp_path, keyed):
    a = make(tmp_path, keyed)
    for i in range(5):
        a.record("u", "send", f"a{i}", "ok")
    b = make(tmp_path, keyed)                       # tiến trình khởi động lại: instance mới trên cùng file
    for i in range(5):
        b.record("u", "send", f"b{i}", "ok")
    assert b.scan_count == 1                        # quét đúng một lần lúc khởi động rồi ghi O(1)
    assert b.verify() == (True, None)
    entries = b.read_all()
    assert len(entries) == 10 and entries[5]["prev"] == entries[4]["hash"]
    if keyed:
        assert json.loads(open(b.head_path, encoding="utf-8").read())["n"] == 10


def test_external_append_is_detected_and_chain_stays_valid(tmp_path):
    a = make(tmp_path)
    a.record("u", "send", "a1", "ok")
    other = make(tmp_path)                          # instance khác (mô phỏng tiến trình khác) ghi xen vào
    other.record("u", "send", "x1", "ok")
    a.record("u", "send", "a2", "ok")               # a thấy kích thước file đã đổi -> quét lại, không ghi sai prev
    assert a.scan_count == 2
    assert a.verify() == (True, None)
    assert [e["target"] for e in a.read_all()] == ["a1", "x1", "a2"]


def test_file_without_trailing_newline_is_repaired_on_next_record(tmp_path):
    log = make(tmp_path)
    log.record("u", "send", "a", "ok"); log.record("u", "send", "b", "ok")
    raw = open(log.path, "rb").read().rstrip(b"\n")
    open(log.path, "wb").write(raw)                 # mất dấu xuống dòng cuối
    fresh = make(tmp_path)
    fresh.record("u", "send", "c", "ok")
    assert fresh.verify() == (True, None)
    assert [e["target"] for e in fresh.read_all()] == ["a", "b", "c"]


def test_file_uses_unix_newlines_only(tmp_path):
    log = make(tmp_path)
    for i in range(3):
        log.record("u", "send", f"f{i}", "ok")
    assert b"\r" not in open(log.path, "rb").read()


def test_unicode_targets_roundtrip_and_sizes_match(tmp_path):
    log = make(tmp_path)
    log.record("u", "send", "Báo cáo Quý 3 – tuyệt mật.txt", "ok", {"ghi_chu": "Hợp đồng M&A"})
    log.record("u", "send", "x", "ok")
    assert log.read_all()[0]["target"] == "Báo cáo Quý 3 – tuyệt mật.txt"
    assert log.scan_count == 1 and log.verify() == (True, None)


def test_mixed_crlf_legacy_lines_still_read_and_verify(tmp_path):
    """Log cũ ghi trên Windows có CRLF; dòng mới ghi bằng LF. Phải đọc và verify bình thường."""
    log = make(tmp_path)
    log.record("u", "send", "cu1", "ok"); log.record("u", "send", "cu2", "ok")
    text = open(log.path, "rb").read().replace(b"\n", b"\r\n")
    open(log.path, "wb").write(text)
    fresh = make(tmp_path)
    fresh.record("u", "send", "moi", "ok")
    assert fresh.verify() == (True, None)
    assert [e["target"] for e in fresh.read_all()] == ["cu1", "cu2", "moi"]


def test_threads_share_one_instance(tmp_path):
    log = make(tmp_path, keyed=True)
    ts = [threading.Thread(target=lambda i=i: [log.record(f"u{i}", "send", f"f{j}", "ok") for j in range(25)])
          for i in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert len(log.read_all()) == 200 and log.verify() == (True, None)
    assert log.scan_count == 1


def test_tampered_log_after_recording_is_still_caught(tmp_path):
    log = make(tmp_path)
    for i in range(4):
        log.record("u", "send", f"f{i}", "ok")
    rows = open(log.path, encoding="utf-8").read().splitlines()
    e = json.loads(rows[1]); e["user"] = "ke-gian"; rows[1] = json.dumps(e, ensure_ascii=False)
    open(log.path, "w", encoding="utf-8", newline="\n").write("\n".join(rows) + "\n")
    log.record("u", "send", "tiep", "ok")           # ghi tiếp sau khi bị sửa: verify vẫn phải báo đúng dòng bị sửa
    assert log.verify() == (False, 2)


# ---------- read_from ----------

def test_read_from_returns_only_new_entries(tmp_path):
    log = make(tmp_path)
    assert log.read_from(0) == ([], 0)              # file chưa tồn tại
    log.record("u", "send", "a", "ok"); log.record("u", "send", "b", "ok")
    entries, off = log.read_from(0)
    assert [e["target"] for e in entries] == ["a", "b"] and off == os.path.getsize(log.path)
    assert log.read_from(off) == ([], off)          # không có gì mới
    log.record("u", "send", "c", "ok")
    entries, off2 = log.read_from(off)
    assert [e["target"] for e in entries] == ["c"] and off2 == os.path.getsize(log.path)


def test_read_from_leaves_partial_last_line_for_later(tmp_path):
    log = make(tmp_path)
    log.record("u", "send", "a", "ok")
    good = os.path.getsize(log.path)
    with open(log.path, "ab") as f:
        f.write(b'{"ts": "2026", "user": "u", "act')   # đang ghi dở
    entries, off = log.read_from(0)
    assert [e["target"] for e in entries] == ["a"] and off == good


def test_read_from_offset_beyond_file_means_reset(tmp_path):
    log = make(tmp_path)
    log.record("u", "send", "a", "ok")
    with pytest.raises(AuditResetError):
        log.read_from(os.path.getsize(log.path) + 1)


def test_read_from_corrupt_complete_line_raises_like_before(tmp_path):
    log = make(tmp_path)
    log.record("u", "send", "a", "ok")
    with open(log.path, "ab") as f:
        f.write(b"khong phai json\n")
    with pytest.raises(ValueError):
        log.read_all()


def test_first_record_on_empty_log_uses_genesis(tmp_path):
    log = make(tmp_path)
    assert log.record("u", "send", "a", "ok")["prev"] == GENESIS
