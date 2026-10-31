"""Chống ghi đè / hạ mức mật tài liệu ở Gateway. Dùng backend giả trong bộ nhớ nên không cần FTPS hay SSH."""
import threading
import unicodedata

import pytest

from securetransfer.auth import Level, Role, User
from securetransfer.config import Settings
from securetransfer.gateway import ConflictError, Gateway
from securetransfer.transfer import TransferBackend

ALICE = User("alice", Role.ADMIN, Level.SECRET)
ROOT = User("root", Role.ADMIN, Level.SECRET)
BOB = User("bob", Role.STAFF, Level.INTERNAL)
DAVE = User("dave", Role.STAFF, Level.CONFIDENTIAL)


class MemoryBackend(TransferBackend):
    name = "ftps"

    def __init__(self):
        self.files = {}

    def upload(self, local_path, remote_path):
        with open(local_path, "rb") as f:
            self.files[remote_path] = f.read()

    def download(self, remote_path, local_path):
        with open(local_path, "wb") as f:
            f.write(self.files[remote_path])


def make(tmp_path):
    backend = MemoryBackend()
    gw = Gateway(Settings(data_dir=str(tmp_path / "data"), remote_dir="/"), backends={"ftps": backend})
    return gw, backend


_counter = [0]


def doc(tmp_path, text):
    _counter[0] += 1
    path = tmp_path / f"src{_counter[0]}.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def read(gw, user, name, level, tmp_path):
    out = tmp_path / "out.txt"
    gw.receive(user, name, str(out), level=level)
    return out.read_text(encoding="utf-8")


def send(gw, tmp_path, user, name, text, level):
    return gw.send(user, doc(tmp_path, text), remote_name=name, level=level)


def test_other_user_cannot_overwrite_secret_document(tmp_path):
    gw, backend = make(tmp_path)
    send(gw, tmp_path, ALICE, "tuyet-mat.txt", "top secret", Level.SECRET)
    before = dict(backend.files)
    with pytest.raises(ConflictError):
        send(gw, tmp_path, BOB, "tuyet-mat.txt", "gia mao", Level.INTERNAL)
    assert backend.files == before
    assert read(gw, ALICE, "tuyet-mat.txt", Level.SECRET, tmp_path) == "top secret"
    denied = [(e["user"], e["action"], e["status"]) for e in gw.audit.read_all() if e["status"] == "denied"]
    assert denied == [("bob", "send", "denied")]
    assert gw.audit.verify() == (True, None)


def test_name_variants_all_collide(tmp_path):
    gw, backend = make(tmp_path)
    send(gw, tmp_path, ALICE, "Báo-Cáo.txt", "goc", Level.SECRET)
    before = dict(backend.files)
    variants = ["BÁO-CÁO.TXT", "bao/../Báo-Cáo.txt", "x/Báo-Cáo.txt", "x\\Báo-Cáo.txt", "../../Báo-Cáo.txt",
                unicodedata.normalize("NFD", "Báo-Cáo.txt")]
    for variant in variants:
        with pytest.raises(ConflictError):
            send(gw, tmp_path, BOB, variant, "gia mao", Level.INTERNAL)
    assert backend.files == before


def test_owner_can_update_and_raise_level_but_not_lower(tmp_path):
    gw, _ = make(tmp_path)
    send(gw, tmp_path, DAVE, "a.txt", "v1", Level.INTERNAL)
    send(gw, tmp_path, DAVE, "a.txt", "v2", Level.INTERNAL)
    assert read(gw, DAVE, "a.txt", Level.INTERNAL, tmp_path) == "v2"
    send(gw, tmp_path, DAVE, "a.txt", "v3", Level.CONFIDENTIAL)
    with pytest.raises(ConflictError) as info:
        send(gw, tmp_path, DAVE, "a.txt", "v4", Level.INTERNAL)
    assert "hạ mức mật" in str(info.value)
    assert read(gw, DAVE, "a.txt", Level.CONFIDENTIAL, tmp_path) == "v3"


def test_admin_can_replace_others_document_but_not_lower_its_level(tmp_path):
    gw, _ = make(tmp_path)
    send(gw, tmp_path, BOB, "b.txt", "cua bob", Level.INTERNAL)
    send(gw, tmp_path, ALICE, "b.txt", "admin sua", Level.INTERNAL)
    assert read(gw, ALICE, "b.txt", Level.INTERNAL, tmp_path) == "admin sua"
    with pytest.raises(ConflictError):
        send(gw, tmp_path, ALICE, "b.txt", "ha cap", Level.PUBLIC)
    send(gw, tmp_path, ALICE, "s.txt", "mat", Level.SECRET)
    with pytest.raises(ConflictError):
        send(gw, tmp_path, ROOT, "s.txt", "ha cap", Level.INTERNAL)
    send(gw, tmp_path, ROOT, "s.txt", "cap nhat", Level.SECRET)


def test_owner_with_reduced_clearance_cannot_overwrite_higher_level_document(tmp_path):
    gw, backend = make(tmp_path)
    send(gw, tmp_path, DAVE, "c.txt", "mat", Level.CONFIDENTIAL)
    before = dict(backend.files)
    demoted = User("dave", Role.STAFF, Level.INTERNAL)
    with pytest.raises(ConflictError):
        send(gw, tmp_path, demoted, "c.txt", "moi", Level.INTERNAL)
    assert backend.files == before


def test_different_names_do_not_conflict(tmp_path):
    gw, _ = make(tmp_path)
    send(gw, tmp_path, ALICE, "x.txt", "1", Level.SECRET)
    send(gw, tmp_path, BOB, "y.txt", "2", Level.INTERNAL)
    assert [e["status"] for e in gw.audit.read_all()] == ["ok", "ok"]


def test_concurrent_uploads_of_same_new_name_only_one_wins(tmp_path):
    gw, _ = make(tmp_path)
    users = [User(f"u{i}", Role.STAFF, Level.INTERNAL) for i in range(6)]
    paths = [doc(tmp_path, f"noi dung {i}") for i in range(6)]
    results = []

    def run(user, path):
        try:
            gw.send(user, path, remote_name="chung.txt", level=Level.INTERNAL)
            results.append("ok")
        except ConflictError:
            results.append("conflict")

    threads = [threading.Thread(target=run, args=(u, p)) for u, p in zip(users, paths)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results) == ["conflict"] * 5 + ["ok"]
    assert gw.audit.verify() == (True, None)


def test_concurrent_uploads_of_different_names_all_succeed(tmp_path):
    gw, _ = make(tmp_path)
    paths = [doc(tmp_path, f"noi dung {i}") for i in range(10)]
    errors = []

    def run(i):
        try:
            gw.send(BOB, paths[i], remote_name=f"file{i}.txt", level=Level.INTERNAL)
        except Exception as e:  # noqa: BLE001
            errors.append(repr(e))

    threads = [threading.Thread(target=run, args=(i,)) for i in range(10)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []
    assert len(gw.audit.read_all()) == 10 and gw.audit.verify() == (True, None)
