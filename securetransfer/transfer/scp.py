"""SCP: copy tệp qua SSH (thư viện paramiko + scp)."""
from __future__ import annotations
import paramiko
from scp import SCPClient, SCPException

from ._ssh import SSHConn, friendly, open_ssh
from .base import TransferBackend, TransferError


class SCPBackend(TransferBackend):
    name = "scp"

    def __init__(self, conn: SSHConn):
        self.conn = conn

    def upload(self, local_path, remote_path):
        try:
            c = open_ssh(self.conn)
            try:
                with SCPClient(c.get_transport()) as s:
                    s.put(local_path, remote_path)
            finally:
                c.close()
        except (SCPException, paramiko.SSHException, OSError) as e:
            raise TransferError(f"SCP upload lỗi: {friendly(e)}") from e

    def download(self, remote_path, local_path):
        try:
            c = open_ssh(self.conn)
            try:
                with SCPClient(c.get_transport()) as s:
                    s.get(remote_path, local_path)
            finally:
                c.close()
        except (SCPException, paramiko.SSHException, OSError) as e:
            raise TransferError(f"SCP download lỗi: {friendly(e)}") from e
