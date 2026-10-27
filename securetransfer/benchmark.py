"""So sánh giao thức: đo nhiều cỡ file, lặp nhiều lần, xuất bảng và CSV.

Mỗi lần đo = gửi + nhận lại 1 file ngẫu nhiên (KHÔNG nén được) qua một kết nối mới, nên thời gian
đã gồm cả bắt tay/đăng nhập. Sau mỗi lần đo, file trên máy chủ được xóa.
Quy ước: 1 MB = 1.048.576 byte; tốc độ tính bằng Mbit/s (1 Mbit = 1.000.000 bit).
"""
from __future__ import annotations
import csv
import hashlib
import os
import posixpath
import statistics
import tempfile
import time
from typing import Callable, Iterable

from .config import Settings
from .transfer import TransferError, build_backends

DEFAULT_SIZES = (1, 10, 50)
DEFAULT_REPEAT = 3
MAX_SIZE_MB = 200
MAX_REPEAT = 10
CSV_FIELDS = ["protocol", "size_mb", "runs", "upload_s_mean", "upload_s_min", "upload_s_max",
              "download_s_mean", "download_s_min", "download_s_max",
              "upload_mbit_s", "download_mbit_s", "intact", "error"]

Progress = Callable[[str, int, int, int], None]   # (giao thức, cỡ MB, lần thứ, tổng số lần)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _make_random_file(path: str, size_mb: int) -> None:
    with open(path, "wb") as f:
        for _ in range(size_mb):
            f.write(os.urandom(1024 * 1024))


def _mbit_s(size_mb: int, seconds: float) -> float:
    return round(size_mb * 1024 * 1024 * 8 / 1e6 / max(seconds, 1e-9), 1)


def _aggregate(name: str, size: int, ups: list[float], downs: list[float], intact: bool) -> dict:
    return {
        "protocol": name, "size_mb": size, "runs": len(ups),
        "upload_s_mean": round(statistics.mean(ups), 3), "upload_s_min": round(min(ups), 3),
        "upload_s_max": round(max(ups), 3),
        "download_s_mean": round(statistics.mean(downs), 3), "download_s_min": round(min(downs), 3),
        "download_s_max": round(max(downs), 3),
        "upload_mbit_s": _mbit_s(size, statistics.mean(ups)),
        "download_mbit_s": _mbit_s(size, statistics.mean(downs)),
        "intact": intact,
    }


def run_matrix(settings: Settings, sizes_mb: Iterable[int] = DEFAULT_SIZES, repeat: int = DEFAULT_REPEAT,
               protocols: list[str] | None = None, progress: Progress | None = None) -> list[dict]:
    sizes = list(sizes_mb)
    if not sizes or any(not 1 <= s <= MAX_SIZE_MB for s in sizes):
        raise ValueError(f"Cỡ file phải từ 1 đến {MAX_SIZE_MB} MB")
    if not 1 <= repeat <= MAX_REPEAT:
        raise ValueError(f"Số lần lặp phải từ 1 đến {MAX_REPEAT}")
    backends = build_backends(settings)
    names = list(protocols) if protocols else list(backends)
    unknown = [n for n in names if n not in backends]
    if unknown:
        raise ValueError(f"Giao thức không hợp lệ: {', '.join(unknown)} (có: {', '.join(backends)})")

    rows: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        sources = {}
        for size in dict.fromkeys(sizes):          # bỏ trùng, giữ thứ tự
            path = os.path.join(tmp, f"src_{size}.bin")
            _make_random_file(path, size)
            sources[size] = (path, _sha256(path))

        for name in names:
            backend = backends[name]
            failed = False
            for size, (src, digest) in sources.items():
                if failed:
                    break                          # đã lỗi ở cỡ trước: không thử tiếp, tránh chờ timeout nhiều lần
                ups: list[float] = []
                downs: list[float] = []
                intact = True
                try:
                    for i in range(repeat):
                        if progress:
                            progress(name, size, i + 1, repeat)
                        remote = posixpath.join(settings.remote_dir, f"bench_{name}_{size}mb_{i}.bin")
                        back = os.path.join(tmp, f"back_{name}_{size}_{i}.bin")
                        uploaded = False
                        try:
                            t0 = time.perf_counter()
                            backend.upload(src, remote)
                            uploaded = True
                            t1 = time.perf_counter()
                            backend.download(remote, back)
                            t2 = time.perf_counter()
                        finally:
                            if uploaded:           # dọn file đo trên máy chủ (cố gắng tối đa)
                                try:
                                    backend.delete(remote)
                                except TransferError:
                                    pass
                        ups.append(t1 - t0)
                        downs.append(t2 - t1)
                        intact = intact and _sha256(back) == digest
                        os.remove(back)
                except (TransferError, OSError) as e:
                    rows.append({"protocol": name, "size_mb": size, "error": str(e)})
                    failed = True
                    continue
                rows.append(_aggregate(name, size, ups, downs, intact))
    return rows


def run(settings: Settings, size_mb: int = 5, protocols: list[str] | None = None) -> list[dict]:
    """Bản đơn giản (1 cỡ, 1 lần) dùng cho API và giao diện web."""
    out = []
    for r in run_matrix(settings, [size_mb], repeat=1, protocols=protocols):
        if "error" in r:
            out.append({"protocol": r["protocol"], "error": r["error"]})
        else:
            out.append({"protocol": r["protocol"], "upload_s": r["upload_s_mean"],
                        "download_s": r["download_s_mean"], "mbps_up": r["upload_mbit_s"],
                        "intact": r["intact"]})
    return out


def write_csv(rows: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:   # BOM để Excel đọc đúng tiếng Việt
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore", restval="")
        w.writeheader()
        w.writerows(rows)


def format_table(rows: list[dict]) -> str:
    head = ["Giao thức", "Cỡ (MB)", "Lần", "Gửi TB (s)", "Nhận TB (s)", "Gửi (Mbit/s)", "Nhận (Mbit/s)", "Toàn vẹn"]
    body, errors = [], []
    for r in rows:
        if "error" in r:
            errors.append(f"  {r['protocol'].upper()} ({r['size_mb']} MB): không đo được. {r['error']}")
            continue
        body.append([r["protocol"].upper(), str(r["size_mb"]), str(r["runs"]),
                     f"{r['upload_s_mean']:.3f}", f"{r['download_s_mean']:.3f}",
                     f"{r['upload_mbit_s']:.1f}", f"{r['download_mbit_s']:.1f}",
                     "đúng" if r["intact"] else "SAI"])
    lines = []
    if body:
        widths = [max(len(row[i]) for row in [head] + body) for i in range(len(head))]
        fmt = lambda row: "  ".join(c.ljust(w) for c, w in zip(row, widths))  # noqa: E731
        lines += [fmt(head), "  ".join("-" * w for w in widths)] + [fmt(r) for r in body]
    if errors:
        lines += ["", "Không đo được:"] + errors
    return "\n".join(lines)
