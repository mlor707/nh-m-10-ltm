"""SCP: copy tệp qua SSH (thư viện paramiko + scp)."""
from __future__ import annotations
from scp import SCPClient, SCPException
import paramiko
from ._ssh import open_ssh
from .base import TransferBackend, TransferError


class SCPBackend(TransferBackend):
    name = "scp"

    def __init__(self, host, port, username, password=None, key_file=None):
        self.args = (host, port, username, password, key_file)

    def upload(self, local_path, remote_path):
        try:
            c = open_ssh(*self.args)
            try:
                with SCPClient(c.get_transport()) as s:
                    s.put(local_path, remote_path)
            finally:
                c.close()
        except (SCPException, paramiko.SSHException, OSError) as e:
            raise TransferError(f"SCP upload lỗi: {e}") from e

    def download(self, remote_path, local_path):
        try:
            c = open_ssh(*self.args)
            try:
                with SCPClient(c.get_transport()) as s:
                    s.get(remote_path, local_path)
            finally:
                c.close()
        except (SCPException, paramiko.SSHException, OSError) as e:
            raise TransferError(f"SCP download lỗi: {e}") from e
