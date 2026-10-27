"""CLI:  python -m securetransfer.cli <lệnh> ..."""
from __future__ import annotations
import argparse
import json
import sys

from .audit import AuditLog
from .auth import Level, UserStore
from .config import Settings
from .gateway import SCENARIO_PROTOCOL, Gateway


def main() -> None:
    p = argparse.ArgumentParser(prog="securetransfer")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name in ("send", "receive"):
        sp = sub.add_parser(name)
        sp.add_argument("--user", required=True)
        sp.add_argument("--scenario", choices=list(SCENARIO_PROTOCOL), default="partner")
        sp.add_argument("--level", choices=[l.name for l in Level], default="INTERNAL")
    sub.choices["send"].add_argument("file")
    sub.choices["receive"].add_argument("remote_name")
    sub.choices["receive"].add_argument("dest")

    b = sub.add_parser("benchmark", help="so sánh tốc độ các giao thức")
    b.add_argument("--sizes", type=int, nargs="+", help="các cỡ file (MB), mặc định: 1 10 50")
    b.add_argument("--size-mb", type=int, help="một cỡ duy nhất (cách viết cũ)")
    b.add_argument("--repeat", type=int, default=3, help="số lần lặp mỗi cỡ (mặc định 3)")
    b.add_argument("--protocols", nargs="*", help="ftps scp rsync sftp (mặc định: tất cả)")
    b.add_argument("--csv", help="ghi kết quả ra file CSV")
    b.add_argument("--json", action="store_true", help="in JSON thay vì bảng")
    sub.add_parser("audit-verify")
    sub.add_parser("ssh-check", help="chẩn đoán máy chủ SSH và thử SCP/SFTP/rsync")

    a = p.parse_args()
    s = Settings.from_env()

    if a.cmd == "ssh-check":
        from . import sshcheck
        rows = sshcheck.run(s)
        print(sshcheck.format_report(rows))
        raise SystemExit(0 if all(r["ok"] for r in rows) else 1)
    if a.cmd == "audit-verify":
        ok, bad = AuditLog(s.audit_path).verify()
        print("Audit log hợp lệ ✅" if ok else f"Audit log BỊ SỬA ❌ tại dòng {bad}")
    elif a.cmd == "benchmark":
        from . import benchmark
        sizes = a.sizes or ([a.size_mb] if a.size_mb else list(benchmark.DEFAULT_SIZES))

        def progress(name, size, i, n):
            print(f"  đang đo {name} {size} MB, lần {i}/{n}...", file=sys.stderr)

        try:
            rows = benchmark.run_matrix(s, sizes, a.repeat, a.protocols, progress)
        except ValueError as e:
            p.error(str(e))
        print(json.dumps(rows, indent=2, ensure_ascii=False) if a.json else benchmark.format_table(rows))
        if a.csv:
            benchmark.write_csv(rows, a.csv)
            print(f"\nĐã ghi {a.csv}", file=sys.stderr)
        raise SystemExit(0 if any("error" not in r for r in rows) else 1)
    else:
        user = UserStore(s.users_path).get(a.user)
        gw = Gateway(s)
        if a.cmd == "send":
            print("Đã gửi ->", gw.send(user, a.file, level=Level[a.level], scenario=a.scenario))
        else:
            print("Đã nhận ->", gw.receive(user, a.remote_name, a.dest, Level[a.level], a.scenario))


if __name__ == "__main__":
    main()
