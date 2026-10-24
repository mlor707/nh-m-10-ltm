"""SFTP – chỉ dùng làm MỐC SO SÁNH với FTPS / SCP / rsync."""
from __future__ import annotations
import paramiko

from ._ssh import SSHConn, friendly, open_ssh
from .base import TransferBackend, TransferError


class SFTPBackend(TransferBackend):
    name = "sftp"

    def __init__(self, conn: SSHConn):
        self.conn = conn

    def upload(self, local_path, remote_path):
        try:
            c = open_ssh(self.conn)
            try:
                c.open_sftp().put(local_path, remote_path)
            finally:
                c.close()
        except (paramiko.SSHException, OSError) as e:
            raise TransferError(f"SFTP upload lỗi: {friendly(e)}") from e

    def download(self, remote_path, local_path):
        try:
            c = open_ssh(self.conn)
            try:
                c.open_sftp().get(remote_path, local_path)
            finally:
                c.close()
        except (paramiko.SSHException, OSError) as e:
            raise TransferError(f"SFTP download lỗi: {friendly(e)}") from e
