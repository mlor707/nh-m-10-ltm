"""receive() phải dùng mức mật THẬT của tài liệu (ghi lúc gửi), không tin mức do người gọi khai.
Và bản mã phải gắn với đúng tài liệu: tráo file .enc giữa hai tài liệu thì giải mã thất bại.
Dùng backend giả trong bộ nhớ nên không cần FTPS hay SSH."""
import pytest

from securetransfer.auth import AuthError, Level, Role, User
from securetransfer.config import Settings
from securetransfer.crypto import CryptoError, MAGIC_V1, encrypt_file
from securetransfer.gateway import DocumentNotFoundError, Gateway
from securetransfer.transfer import TransferBackend

ALICE = User("alice", Role.ADMIN, Level.SECRET)
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


def make(tmp_path, **settings):
    backend = MemoryBackend()
    s = Settings(data_dir=str(tmp_path / "data"), remote_dir="/", **settings)
    return Gateway(s, backends={"ftps": backend}), backend


def send(gw, tmp_path, user, name, text, level):
    src = tmp_path / "src.txt"
    src.write_text(text, encoding="utf-8")
    return gw.send(user, str(src), remote_name=name, level=level)


def recv(gw, user, name, tmp_path, **kw):
    out = tmp_path / "out.txt"
    gw.receive(user, name, str(out), **kw)
    return out.read_text(encoding="utf-8")


# ---------- (1) mức mật lấy từ nhật ký ----------

@pytest.mark.parametrize("claimed", [None, Level.PUBLIC, Level.INTERNAL])
def test_caller_cannot_lower_level_to_read_secret(tmp_path, claimed):
    gw, _ = make(tmp_path)
    send(gw, tmp_path, ALICE, "tuyet-mat.txt", "top secret", Level.SECRET)
    with pytest.raises(AuthError):
        recv(gw, BOB, "tuyet-mat.txt", tmp_path, level=claimed)
    last = gw.audit.read_all()[-1]
    assert (last["user"], last["action"], last["status"]) == ("bob", "receive", "denied")
    assert not (tmp_path / "out.txt").exists()


def test_level_argument_is_optional_for_authorised_user(tmp_path):
    gw, _ = make(tmp_path)
    send(gw, tmp_path, ALICE, "mat.txt", "noi dung", Level.CONFIDENTIAL)
    assert recv(gw, DAVE, "mat.txt", tmp_path) == "noi dung"


def test_level_argument_can_only_tighten(tmp_path):
    gw, _ = make(tmp_path)
    send(gw, tmp_path, ALICE, "noi-bo.txt", "x", Level.INTERNAL)
    with pytest.raises(AuthError):
        recv(gw, BOB, "noi-bo.txt", tmp_path, level=Level.SECRET)   # khai cao hơn thật -> bị siết chặt
    assert recv(gw, BOB, "noi-bo.txt", tmp_path, level=Level.INTERNAL) == "x"


def test_receive_uses_latest_level_after_upgrade(tmp_path):
    gw, _ = make(tmp_path)
    send(gw, tmp_path, ALICE, "ds.txt", "v1", Level.INTERNAL)
    send(gw, tmp_path, ALICE, "ds.txt", "v2", Level.SECRET)         # nâng mức mật khi ghi đè
    with pytest.raises(AuthError):
        recv(gw, BOB, "ds.txt", tmp_path)
    assert recv(gw, ALICE, "ds.txt", tmp_path) == "v2"


def test_unknown_document_is_not_found_and_audited(tmp_path):
    gw, _ = make(tmp_path)
    with pytest.raises(DocumentNotFoundError):
        recv(gw, ALICE, "khong-co.txt", tmp_path)
    last = gw.audit.read_all()[-1]
    assert (last["action"], last["status"]) == ("receive", "error")


def test_missing_level_in_audit_fails_closed(tmp_path):
    gw, _ = make(tmp_path)
    send(gw, tmp_path, ALICE, "x.txt", "x", Level.INTERNAL)
    # bản ghi gửi không có trường level (ví dụ log cũ): coi như SECRET
    gw.audit.record("alice", "send", "y.txt", "ok", {"protocol": "ftps"})
    with pytest.raises(AuthError):
        recv(gw, BOB, "y.txt", tmp_path)


# ---------- (2) bản mã gắn với tài liệu ----------

def test_swapping_enc_files_between_documents_fails(tmp_path):
    gw, backend = make(tmp_path)
    send(gw, tmp_path, ALICE, "cong-khai.txt", "ai cung xem duoc", Level.INTERNAL)
    send(gw, tmp_path, ALICE, "luong.txt", "bang luong mat", Level.INTERNAL)
    a, b = "/cong-khai.txt.enc", "/luong.txt.enc"
    backend.files[a], backend.files[b] = backend.files[b], backend.files[a]
    with pytest.raises(CryptoError):
        recv(gw, ALICE, "cong-khai.txt", tmp_path)
    with pytest.raises(CryptoError):
        recv(gw, ALICE, "luong.txt", tmp_path)
    assert not (tmp_path / "out.txt").exists()


def test_replaying_lower_level_ciphertext_fails(tmp_path):
    """Chép bản mã của tài liệu mức INTERNAL đè lên tài liệu cùng tên vừa nâng lên SECRET: giải mã phải lỗi."""
    gw, backend = make(tmp_path)
    send(gw, tmp_path, ALICE, "ds.txt", "ban cu", Level.INTERNAL)
    old = backend.files["/ds.txt.enc"]
    send(gw, tmp_path, ALICE, "ds.txt", "ban mat", Level.SECRET)
    backend.files["/ds.txt.enc"] = old
    with pytest.raises(CryptoError):
        recv(gw, ALICE, "ds.txt", tmp_path)


def test_legacy_stf1_rejected_by_default_and_accepted_when_enabled(tmp_path):
    from securetransfer.crypto import _aad
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os, struct

    gw, backend = make(tmp_path)
    send(gw, tmp_path, ALICE, "cu.txt", "moi", Level.INTERNAL)       # tạo bản ghi audit
    # dựng một file STF1 thật (không context) bằng khóa của gateway
    nonce = os.urandom(12)
    ct = AESGCM(gw.key).encrypt(nonce, b"du lieu cu", _aad(0, True))
    backend.files["/cu.txt.enc"] = MAGIC_V1 + struct.pack(">I", len(ct)) + nonce + ct
    with pytest.raises(CryptoError):
        recv(gw, ALICE, "cu.txt", tmp_path)

    gw2, backend2 = make(tmp_path / "b", allow_legacy_enc=True)
    (tmp_path / "b").mkdir(exist_ok=True)
    send(gw2, tmp_path / "b", ALICE, "cu.txt", "moi", Level.INTERNAL)
    backend2.files["/cu.txt.enc"] = backend.files["/cu.txt.enc"]
    gw2.key = gw.key
    assert recv(gw2, ALICE, "cu.txt", tmp_path / "b") == "du lieu cu"


def test_normal_roundtrip_still_works_and_server_sees_ciphertext(tmp_path):
    gw, backend = make(tmp_path)
    send(gw, tmp_path, ALICE, "hd.txt", "Hợp đồng M&A", Level.SECRET)
    assert b"M&A" not in backend.files["/hd.txt.enc"]
    assert recv(gw, ALICE, "hd.txt", tmp_path) == "Hợp đồng M&A"
    assert gw.audit.verify() == (True, None)
