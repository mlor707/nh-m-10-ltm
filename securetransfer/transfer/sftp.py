"""SFTP – chỉ dùng làm MỐC SO SÁNH với FTPS / SCP / rsync."""
from __future__ import annotations
import paramiko
from ._ssh import open_ssh
from .base import TransferBackend, TransferError


class SFTPBackend(TransferBackend):
    name = "sftp"

    def __init__(self, host, port, username, password=None, key_file=None):
        self.args = (host, port, username, password, key_file)

    def upload(self, local_path, remote_path):
        try:
            c = open_ssh(*self.args)
            try:
                s = c.open_sftp()
                s.put(local_path, remote_path)
            finally:
                c.close()
        except (paramiko.SSHException, OSError) as e:
            raise TransferError(f"SFTP upload lỗi: {e}") from e

    def download(self, remote_path, local_path):
        try:
            c = open_ssh(*self.args)
            try:
                s = c.open_sftp()
                s.get(remote_path, local_path)
            finally:
                c.close()
        except (paramiko.SSHException, OSError) as e:
            raise TransferError(f"SFTP download lỗi: {e}") from e
