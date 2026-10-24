"""CLI:  python -m securetransfer.cli <lệnh> ..."""
from __future__ import annotations
import argparse
import json

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

    b = sub.add_parser("benchmark")
    b.add_argument("--size-mb", type=int, default=5)
    b.add_argument("--protocols", nargs="*")
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
        print(json.dumps(benchmark.run(s, a.size_mb, a.protocols), indent=2, ensure_ascii=False))
    else:
        user = UserStore(s.users_path).get(a.user)
        gw = Gateway(s)
        if a.cmd == "send":
            print("Đã gửi ->", gw.send(user, a.file, level=Level[a.level], scenario=a.scenario))
        else:
            print("Đã nhận ->", gw.receive(user, a.remote_name, a.dest, Level[a.level], a.scenario))


if __name__ == "__main__":
    main()
