import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


import getpass
import shutil
import socket
import subprocess
import time

import pytest

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def ssh_server(tmp_path_factory):
    """Khởi động một sshd THẬT (cổng ngẫu nhiên, đăng nhập bằng khóa) để test SCP / SFTP / rsync."""
    if not SSHD or not shutil.which("rsync") or not shutil.which("scp"):
        pytest.skip("Máy này không có sshd + rsync + scp (cài openssh-server, rsync)")
    from securetransfer.devssh import gen_ssh_keypair

    d = tmp_path_factory.mktemp("sshd")
    client_key = str(d / "id_ed25519")
    (d / "authorized_keys").write_text(gen_ssh_keypair(client_key))
    host_key = str(d / "host_key")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", host_key], check=True)
    port = _free_port()
    (d / "sshd_config").write_text(
        f"Port {port}\nListenAddress 127.0.0.1\nHostKey {host_key}\nPidFile {d / 'sshd.pid'}\n"
        f"AuthorizedKeysFile {d / 'authorized_keys'}\nPasswordAuthentication no\nPubkeyAuthentication yes\n"
        "UsePAM no\nPermitRootLogin yes\nStrictModes no\nLogLevel ERROR\nSubsystem sftp internal-sftp\n")
    proc = subprocess.Popen([SSHD, "-D", "-e", "-f", str(d / "sshd_config")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            if proc.poll() is not None:
                pytest.skip(f"sshd không khởi động được (thử: sudo mkdir -p /run/sshd): {proc.stderr.read().decode()[:300]}")
            time.sleep(0.1)
    yield {"port": port, "user": getpass.getuser(), "key": client_key}
    proc.terminate()
    proc.wait(timeout=5)
