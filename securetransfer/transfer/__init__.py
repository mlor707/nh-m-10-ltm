from __future__ import annotations
from ..config import Settings
from .base import TransferBackend, TransferError
from .ftps import FTPSBackend
from .rsync import RsyncBackend
from .scp import SCPBackend
from .sftp import SFTPBackend

__all__ = ["TransferBackend", "TransferError", "build_backends"]


def build_backends(s: Settings) -> dict[str, TransferBackend]:
    ssh = s.ssh_conn()
    return {
        "ftps": FTPSBackend(s.ftps_host, s.ftps_port, s.ftps_user, s.ftps_password,
                            verify=s.ftps_verify, ca_file=s.ftps_ca_file),
        "scp": SCPBackend(ssh),
        "rsync": RsyncBackend(ssh),
        "sftp": SFTPBackend(ssh),
    }
