"""rsync qua SSH: gọi chương trình rsync có sẵn trên máy (Linux/macOS; Windows dùng WSL hoặc cwRsync)."""
from __future__ import annotations
import shlex
import shutil
import subprocess

import paramiko

from ._ssh import SSHConn, friendly, host_entry, open_ssh
from .base import TransferBackend, TransferError


class RsyncBackend(TransferBackend):
    name = "rsync"

    def __init__(self, conn: SSHConn, extra_ssh_opts: str = ""):
        self.conn = conn
        self.extra_ssh_opts = extra_ssh_opts

    def _ssh_cmd(self) -> str:
        c = self.conn
        parts = ["ssh", "-p", str(c.port),
                 "-o", f"StrictHostKeyChecking={'yes' if c.strict_host_key else 'accept-new'}",
                 "-o", f"ConnectTimeout={c.timeout}",
                 "-o", "BatchMode=yes"]               # không bao giờ chờ nhập mật khẩu
        if c.key_file:
            parts += ["-i", c.key_file]
        if c.known_hosts:
            parts += ["-o", f"UserKnownHostsFile={c.known_hosts}"]
        cmd = shlex.join(parts)
        return f"{cmd} {self.extra_ssh_opts}".strip()

    def _run(self, src: str, dst: str) -> None:
        if shutil.which("rsync") is None:
            raise TransferError("Không tìm thấy lệnh 'rsync' trên máy này (Windows: chạy trong WSL2)")
        proc = subprocess.run(["rsync", "-az", "-e", self._ssh_cmd(), src, dst],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            err = proc.stderr.strip()
            if "Host key verification failed" in err:
                c = self.conn
                err = ("Không xác minh được khóa máy chủ (chưa tin cậy hoặc đã thay đổi). "
                       "Chạy: python -m securetransfer.devssh trust-host. Nếu máy chủ Docker vừa được tạo lại: "
                       f"ssh-keygen -R \"{host_entry(c.host, c.port)}\" "
                       "(thêm -f <file> nếu bạn dùng ST_SSH_KNOWN_HOSTS). Chi tiết từ ssh: " + err)
            raise TransferError(f"rsync lỗi ({proc.returncode}): {err}")

    def upload(self, local_path, remote_path):
        self._run(local_path, f"{self.conn.username}@{self.conn.host}:{remote_path}")

    def download(self, remote_path, local_path):
        self._run(f"{self.conn.username}@{self.conn.host}:{remote_path}", local_path)

    def delete(self, remote_path):
        try:
            c = open_ssh(self.conn)
            try:
                c.open_sftp().remove(remote_path)
            finally:
                c.close()
        except (paramiko.SSHException, OSError) as e:
            raise TransferError(f"rsync delete lỗi: {friendly(e)}") from e
