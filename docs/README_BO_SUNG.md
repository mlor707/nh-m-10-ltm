# Nội dung bổ sung cho README (Người 1 chuẩn bị)

File này **không phải README**. README.md là file chung của nhóm, nên các đoạn dưới đây để **copy dán vào README.md**
đúng chỗ muốn (thường là sau mục 3, trước hết phần "Giấy phép"). Báo nhóm trước khi sửa README để khỏi đụng nhau.

---

## Phần A. Dán vào README.md

### 🖼️ Giao diện

| Gửi tài liệu | Tài liệu đã gửi | Nhật ký kiểm toán |
|:---:|:---:|:---:|
| ![Gửi tài liệu](docs/images/gui-gui-tai-lieu.png) | ![Tài liệu đã gửi](docs/images/gui-tai-lieu-da-gui.png) | ![Nhật ký kiểm toán](docs/images/gui-nhat-ky-kiem-toan.png) |

### 🚀 Cài đặt & chạy thử

**Yêu cầu:** Python 3.10 trở lên (đã kiểm tra với 3.12) và Git. Tùy chọn: Docker Desktop để chạy máy chủ SSH;
WSL2 trên Windows nếu muốn thử rsync.

```bash
git clone https://github.com/mlor707/nh-m-10-ltm.git
cd nh-m-10-ltm
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q             # test SSH tự bỏ qua nếu máy không có sshd
```

**Chạy giao diện web** (dùng máy chủ FTPS giả lập, không cần Docker). Trước khi chạy, tạo `.env` từ `.env.example`,
đặt `ST_JWT_SECRET` thành giá trị ngẫu nhiên dài ít nhất 32 byte, rồi đặt mật khẩu cho từng tài khoản:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -m securetransfer.auth set-password alice
python -m securetransfer.auth set-password bob
python -m securetransfer.auth set-password carol
```

Mỗi lệnh sẽ hỏi mật khẩu (tối thiểu 12 ký tự) hai lần và lưu hash scrypt trong `config/users.json`.
Không dùng lại mật khẩu cá nhân; không chia sẻ `ST_JWT_SECRET`.

Mở hai cửa sổ terminal:

```bash
# Cửa sổ 1: máy chủ FTPS giả lập
python -m securetransfer.devserver

# Cửa sổ 2: ứng dụng
uvicorn securetransfer.api:app --reload
```
Mở http://127.0.0.1:8000 và đăng nhập bằng một tài khoản đã đặt mật khẩu. Phiên JWT hết hạn sau 60 phút.

**Thử SCP, SFTP, rsync** cần một máy chủ SSH. Làm theo [docs/DUNG_SSH_DEV.md](docs/DUNG_SSH_DEV.md), sau đó:

```bash
python -m securetransfer.cli ssh-check                       # chẩn đoán từng bước
python -m securetransfer.cli benchmark --sizes 1 10 50 --repeat 3 --csv data/benchmark.csv
```
Kết quả so sánh giao thức: [docs/SO_SANH_GIAO_THUC.md](docs/SO_SANH_GIAO_THUC.md). Hướng dẫn phát triển: [docs/HUONG_DAN_DEV.md](docs/HUONG_DAN_DEV.md).

### 👥 Phân công & tiến độ

| Thành viên | Vai trò | File phụ trách |
|------------|---------|----------------|
| [Tên – MSSV] | Người 1 – Giao thức | `securetransfer/transfer/`, `benchmark.py`, `docker/` |
| [Tên – MSSV] | Người 2 – Bảo mật | `auth.py`, `audit.py`, `crypto.py`, `api.py` (đăng nhập, chia sẻ) |
| [Tên – MSSV] | Người 3 – Ứng dụng | `web/index.html`, `.github/`, `Dockerfile`, `docker-compose.yml` |

Tiến độ (tick khi đã merge vào `main`):

- [x] Gateway FTPS/SCP/rsync/SFTP, mã hóa AES-256-GCM phía client, phân quyền theo mức mật, audit log hash-chain
- [x] Giao diện web: gửi, tải về, nhật ký kiểm toán, so sánh giao thức
- [x] Máy chủ SSH dev bằng Docker, lệnh `ssh-check`, chế độ strict host key, `trust-host`
- [x] Benchmark nhiều cỡ file, lặp nhiều lần, xuất CSV
- [ ] Số đo thật và hoàn thiện `docs/SO_SANH_GIAO_THUC.md` (Người 1)
- [x] Đăng nhập bằng mật khẩu scrypt và JWT bearer (Người 2)
- [ ] Link chia sẻ có thời hạn (Người 2)
- [ ] Màn hình đăng nhập, thanh tiến trình upload (Người 3)
- [ ] GitHub Actions chạy test, Dockerfile cho ứng dụng (Người 3)
- [ ] Phát hành v1.0

Quy ước làm việc: mỗi người một nhánh `feature/...`, mở Pull Request vào `main`, người khác xem rồi mới merge.

> Ảnh giao diện ở trên chụp **trước khi** có màn hình đăng nhập. Sau khi Người 3 merge, hãy chụp lại và thay các file trong `docs/images/`.

---

## Phần B. Thiết lập trên GitHub (chỉ người có quyền admin repo làm được)

1. **Mô tả và topics:** trang repo, bấm biểu tượng bánh răng cạnh mục **About**.
   - *Description:* `Hệ thống truyền tải tài liệu nội bộ an toàn: gateway FTPS/SCP/rsync, mã hóa AES-256-GCM phía client, phân quyền theo mức mật, audit log chống sửa. Python + FastAPI.`
   - *Topics* (gõ từng cái, Enter): `secure-file-transfer` `ftps` `scp` `rsync` `sftp` `python` `fastapi` `aes-gcm` `audit-log` `network-protocols`
2. **Bật Issues:** Settings, General, mục Features, tick **Issues**. Dùng Issues để ghi lỗi và việc cần làm.
3. **License:** file `LICENSE` (MIT) đã có trong repo, GitHub sẽ tự nhận. MIT cho phép người khác dùng và sửa miễn là giữ thông báo bản quyền.
   Cả nhóm nên đồng ý chọn MIT trước khi công khai; dòng tên bản quyền trong `LICENSE` có thể sửa cho đúng tên nhóm.
4. **Phát hành v1.0** (làm sau khi chốt code, 30/10):
   - Đảm bảo `main` đã có đủ code và `python -m pytest -q` không có test lỗi.
   - Trang repo, bên phải bấm **Releases**, rồi **Draft a new release**.
   - Ở ô **Choose a tag**, gõ `v1.0` rồi chọn **Create new tag**. Target là `main`.
   - Đặt tiêu đề `v1.0`, bấm **Generate release notes**, rồi **Publish release**.

## Phần C. Kiểm tra trước khi nộp

- [ ] Bảng thành viên trong README đã điền tên và MSSV.
- [ ] `main` chạy được từ đầu: clone mới, làm theo mục Cài đặt & chạy thử, test không có lỗi.
- [ ] Không có file bí mật trong repo. Trên Windows chạy `git ls-files | findstr /i "\.key \.pem \.env"`:
      chỉ được thấy `.env.example`.
- [ ] Ảnh trong `docs/images/` là ảnh giao diện mới nhất.
- [ ] Mỗi thành viên có commit mang tên mình (xem tab **Insights, Contributors**).
- [ ] Mục 3 của README (nhóm làm thêm gì) khớp với những gì ứng dụng làm được thật.
