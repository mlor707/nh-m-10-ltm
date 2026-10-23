"""So sánh giao thức: đo thời gian upload + download một file ngẫu nhiên (chưa mã hóa client)."""
from __future__ import annotations
import os
import posixpath
import tempfile
import time

from .config import Settings
from .transfer import TransferError, build_backends


def run(settings: Settings, size_mb: int = 5, protocols: list[str] | None = None) -> list[dict]:
    backends = build_backends(settings)
    names = protocols or list(backends)
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "bench.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(size_mb * 1024 * 1024))
        for n in names:
            b = backends[n]
            remote = posixpath.join(settings.remote_dir, f"bench_{n}.bin")
            dst = os.path.join(tmp, f"back_{n}.bin")
            try:
                t0 = time.perf_counter(); b.upload(src, remote)
                t1 = time.perf_counter(); b.download(remote, dst)
                t2 = time.perf_counter()
                with open(src, "rb") as a, open(dst, "rb") as b2:
                    ok = a.read() == b2.read()
                results.append({"protocol": n, "upload_s": round(t1 - t0, 3),
                                "download_s": round(t2 - t1, 3),
                                "mbps_up": round(size_mb * 8 / max(t1 - t0, 1e-9), 1), "intact": ok})
            except (TransferError, OSError) as e:
                results.append({"protocol": n, "error": str(e)})
    # TODO: đo thêm CPU/RAM, thử nhiều kích thước file, nhiều lần lặp, xuất CSV/biểu đồ
    return results
