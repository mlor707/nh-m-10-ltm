"""Audit log có khóa HMAC: chống tính lại chuỗi, chống xóa dòng cuối. Chỉ dùng thư viện chuẩn, chạy được trên Windows."""
import hashlib
import json
import os
import threading

import pytest

from securetransfer.audit import GENESIS, AuditLog
from securetransfer.config import Settings

KEY = "khoa-audit-thu-nghiem-dai-hon-32-byte!"


def make(tmp_path, key=KEY, n=5):
    log = AuditLog(str(tmp_path / "audit.log"), key=key)
    for i in range(n):
        log.record("bob", "send", f"f{i}.txt", "ok", {"level": "INTERNAL"})
    return log


def lines(log):
    return open(log.path, encoding="utf-8").read().splitlines()


def write(log, rows):
    open(log.path, "w", encoding="utf-8").write("\n".join(rows) + ("\n" if rows else ""))


def test_keyed_log_roundtrip_and_head_file(tmp_path):
    log = make(tmp_path)
    assert log.keyed and log.verify() == (True, None)
    head = json.load(open(log.head_path, encoding="utf-8"))
    assert head["n"] == 5 and head["hash"] == log.read_all()[-1]["hash"]


def test_edit_in_the_middle_is_detected(tmp_path):
    log = make(tmp_path)
    rows = lines(log)
    e = json.loads(rows[2]); e["user"] = "alice"; rows[2] = json.dumps(e, ensure_ascii=False)
    write(log, rows)
    assert log.verify() == (False, 3)


def test_chain_recomputed_without_key_is_rejected(tmp_path):
    """Kẻ sửa 1 dòng rồi tính lại cả chuỗi bằng SHA-256 thường: trước đây qua được, giờ phải bị bắt."""
    log = make(tmp_path)
    entries = log.read_all()
    entries[1]["user"] = "alice"
    prev, rows = GENESIS, []
    for e in entries:
        body = {k: v for k, v in e.items() if k not in ("prev", "hash")}
        e["prev"] = prev
        e["hash"] = AuditLog._hash(prev, body)
        prev = e["hash"]
        rows.append(json.dumps(e, ensure_ascii=False))
    write(log, rows)
    ok, bad = log.verify()
    assert ok is False and bad == 1


def test_chain_recomputed_as_legacy_entries_is_rejected(tmp_path):
    """Kẻ bỏ trường 'alg' để biến dòng HMAC thành dòng cũ rồi tính lại chuỗi."""
    log = make(tmp_path)
    entries = log.read_all()
    prev, rows = GENESIS, []
    for e in entries:
        e.pop("alg")
        body = {k: v for k, v in e.items() if k not in ("prev", "hash")}
        e["prev"] = prev
        e["hash"] = AuditLog._hash(prev, body)
        prev = e["hash"]
        rows.append(json.dumps(e, ensure_ascii=False))
    write(log, rows)
    assert log.verify()[0] is False         # head ghi 5 dòng + hash HMAC nên không khớp


def test_deleting_last_lines_is_detected(tmp_path):
    log = make(tmp_path)
    write(log, lines(log)[:-2])
    assert log.verify() == (False, 4)       # dòng số 4 bị mất


def test_deleting_all_lines_is_detected(tmp_path):
    log = make(tmp_path)
    write(log, [])
    assert log.verify()[0] is False


def test_deleting_head_file_together_with_tail_is_detected(tmp_path):
    log = make(tmp_path)
    write(log, lines(log)[:-2])
    os.remove(log.head_path)
    assert log.verify()[0] is False


def test_forged_head_is_rejected(tmp_path):
    log = make(tmp_path)
    rows = lines(log)[:-2]
    write(log, rows)
    last = json.loads(rows[-1])["hash"]
    with open(log.head_path, "w", encoding="utf-8") as f:
        json.dump({"n": 3, "hash": last, "mac": hashlib.sha256(b"doan").hexdigest()}, f)
    assert log.verify()[0] is False


def test_wrong_key_cannot_verify(tmp_path):
    log = make(tmp_path)
    other = AuditLog(log.path, key="mot-khoa-khac-hoan-toan-dai-hon-32-byte")
    assert other.verify()[0] is False


def test_log_without_key_cannot_verify_keyed_entries(tmp_path):
    log = make(tmp_path)
    assert AuditLog(log.path).verify() == (False, 1)


def test_unkeyed_mode_behaves_as_before(tmp_path):
    log = AuditLog(str(tmp_path / "audit.log"))
    for i in range(3):
        log.record("bob", "send", f"f{i}", "ok")
    assert not log.keyed and log.verify() == (True, None)
    assert "alg" not in log.read_all()[0] and not os.path.exists(log.head_path)
    rows = lines(log)
    e = json.loads(rows[1]); e["user"] = "x"; rows[1] = json.dumps(e)
    write(log, rows)
    assert log.verify() == (False, 2)


def test_upgrading_an_existing_unkeyed_log(tmp_path):
    path = str(tmp_path / "audit.log")
    old = AuditLog(path)
    for i in range(3):
        old.record("bob", "send", f"cu{i}", "ok")
    keyed = AuditLog(path, key=KEY)
    for i in range(2):
        keyed.record("bob", "send", f"moi{i}", "ok")
    assert keyed.verify() == (True, None)
    write(keyed, lines(keyed)[:3])          # cắt bỏ phần có khóa, chỉ để lại phần cũ
    assert keyed.verify()[0] is False


def test_key_must_be_long_enough(tmp_path):
    with pytest.raises(ValueError):
        AuditLog(str(tmp_path / "a.log"), key="ngan")


def test_settings_build_keyed_log(tmp_path):
    s = Settings(data_dir=str(tmp_path / "data"), audit_key=KEY)
    log = AuditLog.from_settings(s)
    log.record("bob", "send", "x", "ok")
    assert log.keyed and log.verify() == (True, None) and os.path.exists(log.head_path)
    assert not AuditLog.from_settings(Settings(data_dir=str(tmp_path / "d2"))).keyed


def test_many_threads_on_one_instance_keep_chain_valid(tmp_path):
    log = AuditLog(str(tmp_path / "audit.log"), key=KEY)
    threads = [threading.Thread(target=log.record, args=(f"u{i}", "login", "-", "denied")) for i in range(30)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(log.read_all()) == 30 and log.verify() == (True, None)
