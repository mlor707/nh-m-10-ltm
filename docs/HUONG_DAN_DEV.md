# Hướng dẫn phát triển (dành cho nhóm)

## 1. Cài đặt (Windows / macOS / Linux)
```bash
python -m venv .venv
.venv\Scripts\activate          # Windows;  macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env          # macOS/Linux: cp .env.example .env
python -m pytest -q             # phải xanh toàn bộ (56 test; test SSH tự bỏ qua nếu máy không có sshd)
```

## 2. Chạy thử nhanh (FTPS local)
```bash
# Terminal 1 – server FTPS giả lập
python -m securetransfer.devserver

# Terminal 2 – gửi / nhận tài liệu qua gateway (đặt biến môi trường từ .env trước)
python -m securetransfer.cli send --user alice --level SECRET hopdong.pdf
python -m securetransfer.cli receive --user alice --level SECRET hopdong.pdf ra.pdf
python -m securetransfer.cli audit-verify

# Giao diện web:  uvicorn securetransfer.api:app --reload   rồi mở http://127.0.0.1:8000
#   (chọn alice / bob / carol ở góc trái để thử các vai trò; Swagger UI tại /docs)
```
SCP / SFTP / rsync cần một máy chủ SSH. Làm theo `docs/DUNG_SSH_DEV.md` (Docker hoặc máy ảo); mất khoảng 5 phút.

## 3. Cấu trúc code
| File | Chức năng | Trạng thái |
|------|-----------|-----------|
| `crypto.py` | Mã hóa AES-256-GCM theo khối, chống sửa/cắt cụt | ✅ xong + test |
| `audit.py` | Audit log hash-chain + gửi Syslog | ✅ xong + test |
| `auth.py` | RBAC + mức mật | ✅ cơ bản (users.json) |
| `transfer/ftps.py` | FTPS | ✅ test end-to-end |
| `transfer/scp.py`, `sftp.py`, `rsync.py` | SCP / SFTP / rsync | ✅ test với sshd thật (`tests/test_ssh_backends.py`) |
| `transfer/_ssh.py` | Kết nối SSH: strict host key, timeout, báo lỗi dễ hiểu | ✅ test (`tests/test_ssh_strict.py`) |
| `sshcheck.py` | Lệnh `ssh-check` chẩn đoán máy chủ SSH | ✅ test |
| `gateway.py` | Kiểm quyền → mã hóa → chọn giao thức → truyền → audit | ✅ |
| `benchmark.py` | So sánh giao thức | ⚠️ đo được 1 file/1 lần, chưa có nhiều cỡ file, lặp lại, CPU/RAM |
| `devssh.py`, `docker/` | Tạo khóa, tin cậy máy chủ (`trust-host`), máy chủ SSH dev | ✅ đã chạy với sshd thật; ⚠️ `docker compose up` chưa chạy thử |
| `api.py` | REST API + phục vụ giao diện | ✅ test end-to-end; ⚠️ đăng nhập demo bằng header |
| `web/index.html` | Giao diện: gửi, tải về, audit, so sánh giao thức | ✅ 1 file HTML/JS thuần, dễ sửa |
| `devserver.py` | FTPS server giả lập | ✅ |

## 4. Lộ trình gợi ý & phân công (3 người)
**Tuần 1 – nền tảng:** cả nhóm tạo GitHub repo, mỗi người clone, chạy `pytest` xanh, tạo branch riêng.
Dựng máy chủ SSH theo `docs/DUNG_SSH_DEV.md`.

| Người | Phụ trách | Việc cụ thể |
|-------|-----------|-------------|
| A – Giao thức | `transfer/*`, `benchmark.py` | Test SCP/rsync/SFTP với VM; hoàn thiện benchmark (nhiều cỡ file, xuất CSV, biểu đồ); FTPS chạy cert thật |
| B – Bảo mật | `crypto.py`, `auth.py`, `audit.py` | Khóa theo người nhận; LDAP/Kerberos; phê duyệt tài liệu SECRET; link chia sẻ có thời hạn; Syslog server (rsyslog) |
| C – Ứng dụng | `api.py`, `web/index.html` | Đăng nhập thật (JWT/LDAP) thay cho chọn user demo; thanh tiến trình upload; biểu đồ benchmark; Docker Compose |

**Quy tắc Git:** mỗi người commit thường xuyên vào branch riêng, mở Pull Request vào `main` (thầy chấm theo commit từng thành viên).

## 5. Lưu ý bảo mật khi phát triển
- Không commit `.env`, `data/`, `*.key`, `*.pem` (đã nằm trong `.gitignore`).
- `AutoAddPolicy` (SSH) và `FTPS_VERIFY=false` chỉ dùng khi dev. Bản demo cuối nên bật xác minh.
- Khóa chủ `data/master.key` hiện lưu file; hướng phát triển: khóa riêng cho từng người nhận.
