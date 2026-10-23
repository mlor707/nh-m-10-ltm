"""rsync qua SSH: gọi chương trình rsync có sẵn trên máy (Linux/macOS; Windows dùng WSL hoặc cwRsync)."""
from __future__ import annotations
import shutil
import subprocess
from .base import TransferBackend, TransferError


class RsyncBackend(TransferBackend):
    name = "rsync"

    def __init__(self, host, port, username, key_file=None, extra_ssh_opts: str = ""):
        self.host, self.port, self.username, self.key_file = host, port, username, key_file
        self.extra_ssh_opts = extra_ssh_opts

    def _ssh_cmd(self) -> str:
        cmd = f"ssh -p {self.port} -o StrictHostKeyChecking=accept-new"
        if self.key_file:
            cmd += f" -i {self.key_file}"
        if self.extra_ssh_opts:
            cmd += " " + self.extra_ssh_opts
        return cmd

    def _run(self, src: str, dst: str) -> None:
        if shutil.which("rsync") is None:
            raise TransferError("Không tìm thấy lệnh 'rsync' trên máy này")
        proc = subprocess.run(["rsync", "-az", "-e", self._ssh_cmd(), src, dst],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            raise TransferError(f"rsync lỗi ({proc.returncode}): {proc.stderr.strip()}")

    def upload(self, local_path, remote_path):
        self._run(local_path, f"{self.username}@{self.host}:{remote_path}")

    def download(self, remote_path, local_path):
        self._run(f"{self.username}@{self.host}:{remote_path}", local_path)
