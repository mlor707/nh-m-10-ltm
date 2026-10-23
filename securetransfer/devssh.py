"""Công cụ cho máy chủ SSH dev (docker/ hoặc máy ảo).

  python -m securetransfer.devssh keygen     # tạo khóa ở data/ssh_dev/ và in cấu hình .env cần thêm
"""
from __future__ import annotations
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

KEY_DIR = os.path.join("data", "ssh_dev")


def gen_ssh_keypair(private_path: str) -> str:
    """Tạo khóa ed25519 dạng OpenSSH. Trả về dòng public key (để đưa vào authorized_keys)."""
    key = ed25519.Ed25519PrivateKey.generate()
    os.makedirs(os.path.dirname(private_path) or ".", exist_ok=True)
    with open(private_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                  serialization.NoEncryption()))
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                        serialization.PublicFormat.OpenSSH).decode()
    pub_line = pub + " securetransfer-dev\n"
    with open(private_path + ".pub", "w", encoding="utf-8") as f:
        f.write(pub_line)
    return pub_line


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] != "keygen":
        print(__doc__)
        return
    priv = os.path.join(KEY_DIR, "id_ed25519")
    if os.path.exists(priv):
        print(f"Đã có khóa tại {priv}, giữ nguyên.")
        pub_line = open(priv + ".pub", encoding="utf-8").read()
    else:
        pub_line = gen_ssh_keypair(priv)
        print(f"Đã tạo khóa: {priv}")
    with open(os.path.join(KEY_DIR, "authorized_keys"), "w", encoding="utf-8") as f:
        f.write(pub_line)
    print(f"Đã ghi {os.path.join(KEY_DIR, 'authorized_keys')} (docker compose sẽ mount file này).")
    print("\nThêm vào file .env:\n  ST_SSH_HOST=127.0.0.1\n  ST_SSH_PORT=2222\n  ST_SSH_USER=transfer\n"
          f"  ST_SSH_KEY_FILE={priv.replace(os.sep, '/')}\n  ST_REMOTE_DIR=.")


if __name__ == "__main__":
    main()
