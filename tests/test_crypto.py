import os
import pytest
from securetransfer.crypto import CryptoError, decrypt_file, encrypt_file, generate_key, CHUNK_SIZE


def _rt(tmp_path, data, key=None, tamper=None):
    key = key or generate_key()
    src, enc, out = (tmp_path / n for n in ("a", "a.enc", "a.out"))
    src.write_bytes(data)
    encrypt_file(str(src), str(enc), key)
    if tamper:
        tamper(enc)
    decrypt_file(str(enc), str(out), key)
    return out.read_bytes()


@pytest.mark.parametrize("n", [0, 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE + 7])
def test_roundtrip(tmp_path, n):
    data = os.urandom(n)
    assert _rt(tmp_path, data) == data


def test_wrong_key(tmp_path):
    src, enc = tmp_path / "a", tmp_path / "a.enc"
    src.write_bytes(b"secret")
    encrypt_file(str(src), str(enc), generate_key())
    with pytest.raises(CryptoError):
        decrypt_file(str(enc), str(tmp_path / "o"), generate_key())


def test_tamper_detected(tmp_path):
    def flip(p):
        b = bytearray(p.read_bytes()); b[-1] ^= 1; p.write_bytes(bytes(b))
    with pytest.raises(CryptoError):
        _rt(tmp_path, b"hello world", tamper=flip)


def test_truncation_detected(tmp_path):
    def cut(p):
        p.write_bytes(p.read_bytes()[:-5])
    with pytest.raises(CryptoError):
        _rt(tmp_path, os.urandom(2 * CHUNK_SIZE + 10), tamper=cut)
