"""Mã hóa đầu-cuối phía client: AES-256-GCM theo từng khối (chunk).

Định dạng file: MAGIC | { len(4B) | nonce(12B) | ciphertext+tag }*
AAD của mỗi khối = (số thứ tự khối, cờ khối cuối) => phát hiện đảo khối / cắt cụt file.
"""
from __future__ import annotations
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"STF1"
CHUNK_SIZE = 1024 * 1024  # 1 MiB


class CryptoError(Exception):
    pass


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def load_or_create_key(path: str) -> bytes:
    """Đọc khóa; nếu chưa có thì tạo mới. TODO: dùng KMS/HSM hoặc khóa theo người nhận."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise CryptoError("Khóa phải dài 32 byte (AES-256)")
        return key
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    key = generate_key()
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def _aad(index: int, last: bool) -> bytes:
    return struct.pack(">QB", index, 1 if last else 0)


def encrypt_file(src: str, dst: str, key: bytes) -> None:
    aes = AESGCM(key)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(MAGIC)
        index = 0
        chunk = fin.read(CHUNK_SIZE)
        while True:
            nxt = fin.read(CHUNK_SIZE)
            last = len(nxt) == 0
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, chunk, _aad(index, last))
            fout.write(struct.pack(">I", len(ct)) + nonce + ct)
            if last:
                break
            chunk, index = nxt, index + 1


def decrypt_file(src: str, dst: str, key: bytes) -> None:
    aes = AESGCM(key)
    size = os.path.getsize(src)
    try:
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            if fin.read(len(MAGIC)) != MAGIC:
                raise CryptoError("Sai định dạng file mã hóa")
            index = 0
            while True:
                hdr = fin.read(4)
                if len(hdr) != 4:
                    raise CryptoError("File bị cắt cụt")
                (n,) = struct.unpack(">I", hdr)
                nonce = fin.read(12)
                ct = fin.read(n)
                if len(nonce) != 12 or len(ct) != n:
                    raise CryptoError("File bị cắt cụt")
                last = fin.tell() == size
                fout.write(aes.decrypt(nonce, ct, _aad(index, last)))
                if last:
                    return
                index += 1
    except CryptoError:
        _silent_remove(dst)
        raise
    except Exception as e:  # InvalidTag...
        _silent_remove(dst)
        raise CryptoError("Giải mã thất bại: sai khóa hoặc dữ liệu bị sửa") from e


def _silent_remove(p: str) -> None:
    try:
        os.remove(p)
    except OSError:
        pass
