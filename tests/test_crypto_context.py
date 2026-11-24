import os

import pytest

from securetransfer.crypto import MAGIC_V1, CryptoError, decrypt_file, encrypt_file, generate_key, CHUNK_SIZE


def _enc(tmp_path, data, key, context=b""):
    src, enc = tmp_path / "a", tmp_path / "a.enc"
    src.write_bytes(data)
    encrypt_file(str(src), str(enc), key, context)
    return enc


@pytest.mark.parametrize("n", [0, 1, CHUNK_SIZE + 1])
def test_roundtrip_with_context(tmp_path, n):
    key, data = generate_key(), os.urandom(n)
    enc = _enc(tmp_path, data, key, b"tai-lieu-A")
    out = tmp_path / "o"
    decrypt_file(str(enc), str(out), key, b"tai-lieu-A")
    assert out.read_bytes() == data


@pytest.mark.parametrize("wrong", [b"tai-lieu-B", b"", b"tai-lieu-A "])
def test_wrong_context_rejected_and_no_plaintext_left(tmp_path, wrong):
    key = generate_key()
    enc = _enc(tmp_path, b"bi mat", key, b"tai-lieu-A")
    out = tmp_path / "o"
    with pytest.raises(CryptoError):
        decrypt_file(str(enc), str(out), key, wrong)
    assert not out.exists()


def test_context_required_when_encrypted_with_one(tmp_path):
    key = generate_key()
    enc = _enc(tmp_path, b"x", key)                      # không context
    with pytest.raises(CryptoError):
        decrypt_file(str(enc), str(tmp_path / "o"), key, b"tai-lieu-A")


def test_legacy_magic_needs_opt_in(tmp_path):
    key = generate_key()
    enc = _enc(tmp_path, b"x", key)
    raw = enc.read_bytes()
    legacy = tmp_path / "legacy.enc"
    legacy.write_bytes(MAGIC_V1 + raw[len(MAGIC_V1):])    # STF1 + cùng thân (AAD rỗng nên hợp lệ)
    with pytest.raises(CryptoError):
        decrypt_file(str(legacy), str(tmp_path / "o"), key)
    decrypt_file(str(legacy), str(tmp_path / "o"), key, allow_legacy=True)
    assert (tmp_path / "o").read_bytes() == b"x"


def test_unknown_magic_rejected(tmp_path):
    p = tmp_path / "bad.enc"
    p.write_bytes(b"XXXX" + os.urandom(40))
    with pytest.raises(CryptoError):
        decrypt_file(str(p), str(tmp_path / "o"), generate_key(), allow_legacy=True)
