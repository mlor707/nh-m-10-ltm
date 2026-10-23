"""Server FTPS giả lập để dev/test local (KHÔNG dùng production).

Chạy:  python -m securetransfer.devserver          (cổng 2121, user test / test123)
"""
from __future__ import annotations
import datetime
import os
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def gen_self_signed_cert(cert_path: str, key_path: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    os.makedirs(os.path.dirname(cert_path) or ".", exist_ok=True)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))


def make_server(root: str, host="127.0.0.1", port=2121, user="test", password="test123",
                cert="data/dev_cert.pem", key="data/dev_key.pem"):
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import TLS_FTPHandler
    from pyftpdlib.servers import ThreadedFTPServer

    if not os.path.exists(cert):
        gen_self_signed_cert(cert, key)
    os.makedirs(root, exist_ok=True)
    auth = DummyAuthorizer()
    auth.add_user(user, password, root, perm="elradfmw")

    class Handler(TLS_FTPHandler):
        pass

    Handler.authorizer = auth
    Handler.certfile, Handler.keyfile = cert, key
    Handler.tls_control_required = True   # ép mã hóa kênh điều khiển
    Handler.tls_data_required = True      # ép mã hóa kênh dữ liệu
    return ThreadedFTPServer((host, port), Handler)


def start_in_thread(server) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, kwargs={"handle_exit": False}, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    srv = make_server("data/ftps_root")
    print("FTPS dev server: 127.0.0.1:2121  user=test pass=test123  (Ctrl+C để dừng)")
    srv.serve_forever()
