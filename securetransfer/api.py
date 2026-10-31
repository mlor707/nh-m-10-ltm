"""REST API + giao diện web (FastAPI).

Chạy:  uvicorn securetransfer.api:app --reload
Mở:    http://127.0.0.1:8000        (giao diện)   |   http://127.0.0.1:8000/docs  (Swagger)

"""
from __future__ import annotations
import os
import shutil
import tempfile

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from .audit import AuditLog
from .auth import PERMISSIONS, AuthError, Level, Role, TokenManager, User, UserStore, authorize
from .config import Settings
from .crypto import CryptoError
from .gateway import SCENARIO_PROTOCOL, ConflictError, Gateway
from .shares import ShareError, ShareStore
from .transfer import TransferError

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
MAX_UPLOAD_MB = 50  # TODO: chỉnh theo nhu cầu / cấu hình
PROTOCOL_TO_SCENARIO = {v: k for k, v in SCENARIO_PROTOCOL.items()}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class ShareRequest(BaseModel):
    expires_minutes: int = Field(default=30, ge=1, le=7 * 24 * 60)
    max_downloads: int = Field(default=1, ge=1, le=100)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="Secure Internal Document Transfer", version="0.2.0")
    users = UserStore(settings.users_path)
    tokens = TokenManager(settings.jwt_secret) if settings.jwt_secret else None
    audit_log = AuditLog.from_settings(settings)  # MỘT instance cho cả API và Gateway (khóa, Syslog, HMAC dùng chung)
    app.state.audit = audit_log
    holder: dict[str, Gateway] = {}
    shares = ShareStore(os.path.join(settings.data_dir, "shares.json"))
    app.state.shares = shares

    def gateway() -> Gateway:
        if "gw" not in holder:
            holder["gw"] = Gateway(settings, audit=audit_log)
        return holder["gw"]

    def audit() -> AuditLog:
        return audit_log

    def current_user(authorization: str | None = Header(default=None)) -> User:
        if not authorization:
            raise HTTPException(401, "Thiếu access token")
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token.strip():
            raise HTTPException(401, "Authorization phải dùng Bearer token")
        try:
            if tokens is None:
                raise HTTPException(503, "Chưa cấu hình ST_JWT_SECRET")
            return users.get(tokens.verify(token.strip()))
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
                latest[Gateway.document_key(e["target"])] = {
                    "name": e["target"], "level": e["details"].get("level", "SECRET"),
                    "protocol": e["details"].get("protocol", ""), "sender": e["user"], "ts": e["ts"],
                    "version": e["hash"],
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

    @app.post("/login")
    def login(credentials: LoginRequest):
        if tokens is None:
            raise HTTPException(503, "Chưa cấu hình ST_JWT_SECRET")
        try:
            user = users.authenticate(credentials.username, credentials.password)
        except AuthError as e:
            audit().record(credentials.username, "login", "-", "denied", {"error": str(e)})
            raise HTTPException(401, "Tên đăng nhập hoặc mật khẩu không đúng") from e
        audit().record(user.username, "login", "-", "ok")
        return {
            "access_token": tokens.issue(user.username),
            "token_type": "bearer",
            "expires_in": tokens.ttl_seconds,
        }

    @app.get("/protocols")
    def protocols():
        return SCENARIO_PROTOCOL

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
            except ConflictError as e:
                raise HTTPException(409, str(e))
            except (TransferError, ValueError) as e:
                raise HTTPException(502, str(e))
        return {"stored_as": remote, "protocol": SCENARIO_PROTOCOL[scenario], "level": level}

    @app.get("/documents")
    def documents(user: User = Depends(current_user)):
        require(user, "receive")
        return [{k: v for k, v in d.items() if k != "version"} for d in visible_documents(user)]

    def current_version(name: str) -> str | None:
        """Mã phiên bản (hash dòng audit) của lần gửi mới nhất của tài liệu; None nếu chưa từng gửi."""
        key = Gateway.document_key(name)
        last = None
        for e in audit().read_all():
            if e["action"] == "send" and e["status"] == "ok" and Gateway.document_key(e["target"]) == key:
                last = e["hash"]
        return last

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

    # ---------- Link chia sẻ có thời hạn ----------
    @app.post("/documents/{name}/share")
    def create_share(name: str, body: ShareRequest, user: User = Depends(current_user)):
        require(user, "send", Level.PUBLIC, name)
        doc = next((d for d in visible_documents(user) if d["name"] == name), None)
        if doc is None:
            raise HTTPException(404, "Không tìm thấy tài liệu (hoặc bạn không đủ cấp độ để mở)")
        level = Level[doc["level"]]
        if level >= Level.SECRET:
            msg = "Không được tạo link chia sẻ cho tài liệu mức SECRET"
            audit().record(user.username, "share_create", name, "denied", {"level": level.name, "error": msg})
            raise HTTPException(403, msg)
        if doc["sender"] != user.username and user.role != Role.ADMIN:
            msg = "Chỉ người gửi tài liệu hoặc quản trị viên mới được tạo link chia sẻ"
            audit().record(user.username, "share_create", name, "denied", {"level": level.name, "error": msg})
            raise HTTPException(403, msg)
        scenario = PROTOCOL_TO_SCENARIO.get(doc["protocol"], "partner")
        token, share = shares.create(name, level.name, scenario, user.username,
                                     body.expires_minutes, body.max_downloads, version=doc["version"])
        audit().record(user.username, "share_create", name, "ok", {
            "share_id": share["id"], "level": level.name,
            "expires_minutes": body.expires_minutes, "max_downloads": body.max_downloads})
        return {"token": token, "url": f"/share/{token}", "expires_at": share["expires_at"],
                "max_downloads": share["max_downloads"]}

    @app.get("/share/{token}")
    def download_share(token: str):
        """Không cần đăng nhập: người giữ link được tải. Mọi lần dùng, kể cả bị từ chối, đều ghi audit."""
        try:
            share = shares.get(token)
        except ShareError as e:
            audit().record("anonymous", "share_download", "-", "denied", {"error": str(e)})
            raise HTTPException(e.status, str(e))
        viewer = User(f"share:{share['id']}", Role.STAFF, Level[share["level"]])
        if current_version(share["doc"]) != share["version"]:
            msg = "Tài liệu đã được cập nhật hoặc thay thế, link này không còn hiệu lực"
            audit().record(viewer.username, "share_download", share["doc"], "denied", {"error": msg})
            raise HTTPException(410, msg)
        try:
            share = shares.consume(token)
        except ShareError as e:
            audit().record(viewer.username, "share_download", share["doc"], "denied", {"error": str(e)})
            raise HTTPException(e.status, str(e))
        tmp = tempfile.mkdtemp()
        dest = os.path.join(tmp, "plain.bin")
        try:
            gateway().receive(viewer, share["doc"], dest, level=Level[share["level"]],
                              scenario=share["scenario"])
        except (AuthError, TransferError, CryptoError) as e:
            shutil.rmtree(tmp, ignore_errors=True)
            shares.refund(token)  # lỗi phía máy chủ thì không tính vào số lần tải của người dùng
            audit().record(viewer.username, "share_download", share["doc"], "error", {"error": str(e)})
            raise HTTPException(502, str(e))
        audit().record(viewer.username, "share_download", share["doc"], "ok", {
            "share_id": share["id"], "created_by": share["created_by"],
            "downloads": share["downloads"], "max_downloads": share["max_downloads"]})
        return FileResponse(dest, filename=share["doc"],
                            background=BackgroundTask(shutil.rmtree, tmp, ignore_errors=True))

    @app.delete("/share/{token}")
    def revoke_share(token: str, user: User = Depends(current_user)):
        try:
            share = shares.get(token)
        except ShareError as e:
            raise HTTPException(e.status, str(e))
        if share["created_by"] != user.username and user.role != Role.ADMIN:
            msg = "Chỉ người tạo link hoặc quản trị viên mới được thu hồi"
            audit().record(user.username, "share_revoke", share["doc"], "denied",
                           {"share_id": share["id"], "error": msg})
            raise HTTPException(403, msg)
        shares.revoke(token)
        audit().record(user.username, "share_revoke", share["doc"], "ok", {"share_id": share["id"]})
        return {"revoked": True}

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
