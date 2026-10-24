"""Công cụ cho máy chủ SSH (docker/ hoặc máy ảo).

  python -m securetransfer.devssh keygen        # tạo khóa đăng nhập ở data/ssh_dev/
  python -m securetransfer.devssh trust-host    # tin cậy khóa máy chủ SSH (cho chế độ strict)
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import os
import socket

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .transfer._ssh import host_entry

KEY_DIR = os.path.join("data", "ssh_dev")
DEFAULT_KNOWN_HOSTS = os.path.join(KEY_DIR, "known_hosts")


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


def fingerprint(key: paramiko.PKey) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def trust_host(host: str, port: int, known_hosts: str = DEFAULT_KNOWN_HOSTS,
               assume_yes: bool = False, input_fn=input, out=print) -> str | None:
    """Lấy khóa máy chủ, hiện vân tay để người dùng đối chiếu, rồi lưu vào known_hosts.

    Trả về vân tay nếu đã lưu, None nếu người dùng từ chối.
    Từ chối (ValueError) nếu known_hosts đã có khóa KHÁC cho cùng máy chủ: dấu hiệu bị giả mạo.
    """
    sock = socket.create_connection((host, port), timeout=10)
    t = paramiko.Transport(sock)
    try:
        t.start_client(timeout=10)
        key = t.get_remote_server_key()
    finally:
        t.close()

    entry = host_entry(host, port)
    fp = fingerprint(key)
    hk = paramiko.HostKeys()
    if os.path.exists(known_hosts):
        hk.load(known_hosts)
    old = hk.lookup(entry)
    if old is not None and key.get_name() in old.keys():
        if old[key.get_name()] != key:
            raise ValueError(
                f"Khóa của {entry} KHÁC với khóa đã lưu trong {known_hosts}. Có thể máy chủ bị giả mạo. "
                "Chỉ xóa dòng cũ nếu bạn chắc chắn máy chủ vừa được cài lại.")
        out(f"{entry} đã được tin cậy từ trước ({fp}).")
        return fp

    out(f"Máy chủ {entry} đưa ra khóa {key.get_name()}\nVân tay: {fp}")
    out("Hãy đối chiếu vân tay này với máy chủ thật (ví dụ: docker compose exec sshd "
        "ssh-keygen -lf /hostkeys/ssh_host_ed25519_key.pub).")
    if not assume_yes and input_fn("Tin cậy máy chủ này? [y/N] ").strip().lower() not in ("y", "yes"):
        out("Đã hủy, chưa lưu gì.")
        return None
    os.makedirs(os.path.dirname(known_hosts) or ".", exist_ok=True)
    hk.add(entry, key.get_name(), key)
    hk.save(known_hosts)
    out(f"Đã lưu vào {known_hosts}. Bật chế độ strict bằng ST_SSH_STRICT_HOST_KEY=true "
        f"và ST_SSH_KNOWN_HOSTS={known_hosts.replace(os.sep, '/')}")
    return fp


def _keygen() -> None:
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


def main() -> None:
    from .config import Settings
    s = Settings.from_env()
    p = argparse.ArgumentParser(prog="securetransfer.devssh", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen", help="tạo khóa đăng nhập")
    t = sub.add_parser("trust-host", help="tin cậy khóa máy chủ SSH")
    t.add_argument("--host", default=s.ssh_host)
    t.add_argument("--port", type=int, default=s.ssh_port)
    t.add_argument("--known-hosts", default=s.ssh_known_hosts or DEFAULT_KNOWN_HOSTS)
    t.add_argument("--yes", action="store_true", help="không hỏi lại (chỉ dùng khi đã tự đối chiếu vân tay)")
    a = p.parse_args()
    if a.cmd == "keygen":
        _keygen()
    else:
        try:
            trust_host(a.host, a.port, a.known_hosts, a.yes)
        except (OSError, paramiko.SSHException, ValueError) as e:
            raise SystemExit(f"Lỗi: {e}")


if __name__ == "__main__":
    main()
