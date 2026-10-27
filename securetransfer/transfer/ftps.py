"""FTPS = FTP + TLS. Dùng thư viện chuẩn ftplib."""
from __future__ import annotations
import ssl
from ftplib import FTP_TLS, all_errors
from .base import TransferBackend, TransferError


class FTPSBackend(TransferBackend):
    name = "ftps"

    def __init__(self, host, port, username, password, verify=True, ca_file=None):
        self.host, self.port, self.username, self.password = host, port, username, password
        self.verify, self.ca_file = verify, ca_file

    def _ctx(self) -> ssl.SSLContext:
        if self.verify:
            return ssl.create_default_context(cafile=self.ca_file)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # CHỈ dùng khi dev với cert tự ký
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _connect(self) -> FTP_TLS:
        ftp = FTP_TLS(context=self._ctx())
        ftp.connect(self.host, self.port, timeout=20)
        ftp.login(self.username, self.password)  # tự gọi AUTH TLS
        ftp.prot_p()                              # mã hóa luôn kênh dữ liệu
        return ftp

    def upload(self, local_path, remote_path):
        try:
            ftp = self._connect()
            try:
                with open(local_path, "rb") as f:
                    ftp.storbinary(f"STOR {remote_path}", f)
            finally:
                ftp.close()
        except all_errors as e:
            raise TransferError(f"FTPS upload lỗi: {e}") from e

    def download(self, remote_path, local_path):
        try:
            ftp = self._connect()
            try:
                with open(local_path, "wb") as f:
                    ftp.retrbinary(f"RETR {remote_path}", f.write)
            finally:
                ftp.close()
        except all_errors as e:
            raise TransferError(f"FTPS download lỗi: {e}") from e

    def delete(self, remote_path):
        try:
            ftp = self._connect()
            try:
                ftp.delete(remote_path)
            finally:
                ftp.close()
        except all_errors as e:
            raise TransferError(f"FTPS delete lỗi: {e}") from e
