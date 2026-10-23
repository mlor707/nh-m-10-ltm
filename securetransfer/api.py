"""REST API + giao diện web (FastAPI).

Chạy:  uvicorn securetransfer.api:app --reload
Mở:    http://127.0.0.1:8000        (giao diện)   |   http://127.0.0.1:8000/docs  (Swagger)

CẢNH BÁO: header X-Username chỉ để DEMO. Bản thật phải dùng đăng nhập (JWT / LDAP / Kerberos).
"""
from __future__ import annotations
import os
import shutil
import tempfile

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from .audit import AuditLog
from .auth import PERMISSIONS, AuthError, Level, User, UserStore, authorize
from .config import Settings
from .crypto import CryptoError
from .gateway import SCENARIO_PROTOCOL, Gateway
from .transfer import TransferError

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
MAX_UPLOAD_MB = 50  # TODO: chỉnh theo nhu cầu / cấu hình
PROTOCOL_TO_SCENARIO = {v: k for k, v in SCENARIO_PROTOCOL.items()}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="Secure Internal Document Transfer", version="0.2.0")
    users = UserStore(settings.users_path)
    holder: dict[str, Gateway] = {}

    def gateway() -> Gateway:
        if "gw" not in holder:
            holder["gw"] = Gateway(settings)
        return holder["gw"]

    def audit() -> AuditLog:
        return AuditLog(settings.audit_path)

    def current_user(x_username: str | None = Header(default=None)) -> User:
        if not x_username:
            raise HTTPException(401, "Thiếu thông tin đăng nhập")
        try:
            return users.get(x_username)
        except AuthError as e:
            raise HTTPException(401, str(e))

    def require(user: User, action: str, level: Level = Level.PUBLIC, target: str = "-") -> None:
        try:
            authorize(user, action, level)
        except AuthError as e:
            # Mọi lần bị từ chối đều phải để lại dấu vết trong nhật ký kiểm toán
            audit().record(user.username, action, target, "denied", {"level": level.name, "error": str(e)})
            raise HTTPException(403, str(e))

    def visible_documents(user: User) -> list[dict]:
        """Danh sách tài liệu suy ra từ audit log (các lần gửi thành công), chỉ gồm tài liệu user đủ cấp độ mở."""
        latest: dict[str, dict] = {}
        for e in audit().read_all():
            if e["action"] == "send" and e["status"] == "ok":
                latest[e["target"]] = {
                    "name": e["target"], "level": e["details"].get("level", "SECRET"),
                    "protocol": e["details"].get("protocol", ""), "sender": e["user"], "ts": e["ts"],
                }
        docs = [d for d in latest.values() if Level[d["level"]] <= user.clearance]
        return sorted(docs, key=lambda d: d["ts"], reverse=True)

    # ---------- Giao diện ----------
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(os.path.join(WEB_DIR, "index.html"))

    # ---------- Thông tin chung ----------
    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/protocols")
    def protocols():
        return SCENARIO_PROTOCOL

    @app.get("/users")
    def list_users():
        # DEMO: để giao diện cho chọn người dùng. Bản thật bỏ endpoint này và dùng đăng nhập.
        return [{"username": u.username, "role": u.role.value, "clearance": u.clearance.name}
                for u in users._users.values()]

    @app.get("/me")
    def me(user: User = Depends(current_user)):
        return {"username": user.username, "role": user.role.value, "clearance": user.clearance.name,
                "permissions": sorted(PERMISSIONS[user.role]), "levels": [l.name for l in Level]}

    # ---------- Tài liệu ----------
    @app.post("/documents")
    def send_document(file: UploadFile = File(...), level: str = Form("INTERNAL"),
                      scenario: str = Form("partner"), user: User = Depends(current_user)):
        if level not in Level.__members__:
            raise HTTPException(400, "Mức mật không hợp lệ")
        if scenario not in SCENARIO_PROTOCOL:
            raise HTTPException(400, "Tình huống không hợp lệ")
        require(user, "send", Level[level], file.filename or "tai-lieu")  # kiểm quyền trước khi nhận file
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "upload.bin")
            size = 0
            with open(path, "wb") as out:
                while chunk := file.file.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_UPLOAD_MB * 1024 * 1024:
                        raise HTTPException(413, f"File vượt quá {MAX_UPLOAD_MB} MB")
                    out.write(chunk)
            try:
                remote = gateway().send(user, path, remote_name=file.filename or "tai-lieu",
                                        level=Level[level], scenario=scenario)
            except AuthError as e:
                raise HTTPException(403, str(e))
            except (TransferError, ValueError) as e:
                raise HTTPException(502, str(e))
        return {"stored_as": remote, "protocol": SCENARIO_PROTOCOL[scenario], "level": level}

    @app.get("/documents")
    def documents(user: User = Depends(current_user)):
        require(user, "receive")
        return visible_documents(user)

    @app.get("/documents/{name}/download")
    def download_document(name: str, user: User = Depends(current_user)):
        require(user, "receive")
        doc = next((d for d in visible_documents(user) if d["name"] == name), None)
        if doc is None:
            raise HTTPException(404, "Không tìm thấy tài liệu (hoặc bạn không đủ cấp độ để mở)")
        tmp = tempfile.mkdtemp()
        dest = os.path.join(tmp, "plain.bin")
        try:
            gateway().receive(user, name, dest, level=Level[doc["level"]],
                              scenario=PROTOCOL_TO_SCENARIO.get(doc["protocol"], "partner"))
        except AuthError as e:
            shutil.rmtree(tmp, ignore_errors=True)
            raise HTTPException(403, str(e))
        except (TransferError, CryptoError) as e:
            shutil.rmtree(tmp, ignore_errors=True)
            raise HTTPException(502, str(e))
        return FileResponse(dest, filename=name,
                            background=BackgroundTask(shutil.rmtree, tmp, ignore_errors=True))

    # ---------- Kiểm toán & so sánh ----------
    @app.get("/audit")
    def audit_list(user: User = Depends(current_user)):
        require(user, "audit")
        return audit().read_all()

    @app.get("/audit/verify")
    def audit_verify(user: User = Depends(current_user)):
        require(user, "audit")
        ok, bad = audit().verify()
        return {"valid": ok, "first_bad_line": bad}

    @app.get("/benchmark")
    def benchmark_run(size_mb: int = 2, user: User = Depends(current_user)):
        require(user, "benchmark")
        if not 1 <= size_mb <= 50:
            raise HTTPException(400, "size_mb phải từ 1 đến 50")
        from . import benchmark
        return benchmark.run(settings, size_mb)

    return app


app = create_app()
