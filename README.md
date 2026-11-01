# Hệ thống Truyền tải Tài liệu Nội bộ An toàn (Secure Internal Document Transfer)

> Bài tập nhóm – Môn Mạng máy tính / Giao thức mạng (nhóm 3 SV)
> **Nhóm giao thức đề xuất (ngoài danh sách 20 giao thức):** Truyền tệp bảo mật – **FTPS, SCP, rsync**. Dùng **SFTP** làm mốc so sánh. Hỗ trợ thêm **Syslog** (gửi nhật ký kiểm toán, tùy chọn). **LDAP/Kerberos** nằm trong kế hoạch nhưng **chưa làm** (xem mục 3).

## Thành viên

| STT | Họ và tên | MSSV | Vai trò |
|-----|-----------|------|---------|
| 1 | Ngô Tùng Anh Tú | 2431540112 | Nhóm Trưởng |
| 2 | Dương Trần Bảo Linh | 2431540211 | Thành Viên |
| 3 | Nguyễn Huỳnh Bảo Hoàng | 2331540326 | Thành Viên |

## Tình trạng hiện tại

**Đã chạy được và có test tự động (128 test, chạy bằng `python -m pytest -q`):**
- Gửi và nhận tài liệu qua **FTPS, SCP, rsync, SFTP** bằng một gateway duy nhất, chọn giao thức theo tình huống.
- Tài liệu được mã hóa **AES-256-GCM** trước khi gửi tới máy chủ lưu trữ, nên máy chủ lưu trữ chỉ thấy bản mã hóa.
- Đăng nhập bằng mật khẩu (băm scrypt) và token JWT; phân quyền theo 3 vai trò và 4 mức mật.
- Nhật ký kiểm toán chống sửa (hash-chain, có thể bật chữ ký HMAC), link chia sẻ có thời hạn, giao diện web, công cụ so sánh giao thức.

**Chưa làm:** đăng nhập một lần bằng LDAP/Kerberos, quy trình phê duyệt hai người, xuất báo cáo tuân thủ, số đo thật trong tài liệu so sánh giao thức, đóng gói ứng dụng bằng Docker, tự động chạy test trên GitHub.

---

## 1. Định hướng làm đề tài

### 1.1. Bài toán
Các tổ chức xử lý dữ liệu nhạy cảm vẫn thường chia sẻ tài liệu nội bộ qua email, USB, Zalo/Messenger hoặc FTP không mã hóa. Cách này dễ gây **rò rỉ dữ liệu, không kiểm soát được ai đã truy cập, không có bằng chứng truy vết** khi xảy ra sự cố.

### 1.2. Mục tiêu
Xây dựng ứng dụng **truyền tải tài liệu nội bộ an toàn**, trong đó:
- Hỗ trợ **nhiều giao thức truyền tệp bảo mật (FTPS, SCP, rsync)** và chọn giao thức phù hợp theo từng tình huống sử dụng.
- Mọi thao tác (gửi, tải, chia sẻ, đăng nhập) đều được **xác thực, phân quyền và ghi nhật ký kiểm toán**.
- Dữ liệu được bảo vệ trên đường truyền (TLS hoặc SSH) **và** được mã hóa AES-256-GCM tại gateway trước khi lưu, nên máy chủ lưu trữ không đọc được nội dung.
- Có chức năng **so sánh hiệu năng** giữa các giao thức (kèm SFTP làm mốc) để giúp tổ chức lựa chọn.
- Dễ triển khai on-premise trong mạng nội bộ.

### 1.3. Thị trường & tệp khách hàng hướng tới
Ứng dụng được thiết kế linh hoạt để phục vụ các tổ chức có yêu cầu bảo mật dữ liệu ở mức cao nhất:

| Lĩnh vực | Nhu cầu chính | Tài liệu cần bảo vệ |
|----------|---------------|---------------------|
| **Ngân hàng & Tài chính** | Chống rò rỉ, tuân thủ chuẩn an toàn thông tin **PCI DSS** | Hồ sơ tín dụng, báo cáo giao dịch mật |
| **Y tế & Bệnh viện lớn** | Bảo vệ quyền riêng tư bệnh nhân | Hồ sơ bệnh án điện tử, kết quả xét nghiệm |
| **Văn phòng Luật sư & Kiểm toán** | Bảo mật thông tin khách hàng, có bằng chứng truy vết | Hợp đồng M&A, sổ sách kế toán, thỏa thuận NDA |

### 1.4. Giao thức sử dụng trong đề tài

**Nhóm giao thức chính – Truyền tệp bảo mật (nhóm tự đề xuất):**

| Giao thức | Làm gì | Tầng OSI | Tình huống sử dụng trong hệ thống |
|-----------|--------|----------|-----------------------------------|
| **FTPS** (FTP over TLS) | Truyền tệp, kênh điều khiển và kênh dữ liệu mã hóa bằng TLS | L7 (TLS ở L5-L6), chạy trên TCP (L4) | Trao đổi với đối tác hoặc hệ thống cũ (ngân hàng, bệnh viện) vẫn dùng FTP |
| **SCP** | Sao chép tệp qua SSH | L7, chạy trên TCP (L4) | Quản trị viên chuyển nhanh từng tệp giữa các máy chủ |
| **rsync** | Đồng bộ tệp, chỉ gửi phần thay đổi | L7, chạy qua SSH/TCP (L4) | Đồng bộ và sao lưu tài liệu giữa các chi nhánh |

**Giao thức đối chiếu (có trong danh sách 20 giao thức):** **SFTP** dùng làm mốc so sánh hiệu năng và bảo mật với FTPS, SCP, rsync.

**Giao thức hỗ trợ:**

| Giao thức | Vai trò | Tình trạng |
|-----------|---------|-----------|
| **Syslog** | Gửi nhật ký kiểm toán tới máy chủ log tập trung | Có sẵn, bật bằng `ST_SYSLOG_HOST`; chưa thử với máy chủ rsyslog thật |
| **LDAP/LDAPS** | Thư mục người dùng, phòng ban | Dự kiến, **chưa làm** |
| **Kerberos** | Xác thực bằng vé (ticket), đăng nhập một lần (SSO) | Dự kiến, **chưa làm** |

### 1.5. Kiến trúc tổng quan

```
 Trình duyệt ──(nên đặt sau HTTPS khi triển khai thật)──> API (FastAPI)
                    đăng nhập scrypt + JWT · phân quyền theo vai trò và mức mật
                    nhật ký kiểm toán (hash-chain, HMAC tùy chọn)
                                        │
                                        ▼
                        Gateway: mã hóa AES-256-GCM theo khối
                                        │  chọn giao thức theo tình huống
                  ┌─────────────┬───────┴──────┬─────────────┐
                  ▼             ▼              ▼             ▼
                FTPS           SCP           rsync         SFTP
                  │             └──────── SSH ─┴─────────────┘   (mốc so sánh)
                  ▼                          ▼
           Máy chủ FTPS                 Máy chủ SSH
                  └────── chỉ lưu các file .enc (bản mã hóa) ──────┘
```

---

## 2. Các project tham khảo + Link GitHub

Các link dưới đây đã được kiểm tra còn truy cập được vào ngày 01/11/2026.

| # | Giao thức | Project | Link GitHub | Dùng để tham khảo |
|---|-----------|---------|-------------|-------------------|
| 1 | FTPS | fclairamb/ftpserverlib | https://github.com/fclairamb/ftpserverlib | Thư viện FTP server (Go) có hỗ trợ TLS/FTPS |
| 2 | FTPS | goftp/server | https://github.com/goftp/server | Xây FTP server tùy biến, cấu hình TLS |
| 3 | SCP / SSH | OpenSSH Portable | https://github.com/openssh/openssh-portable | Cài đặt chuẩn của SSH và scp |
| 4 | SCP | bramvdbogaerde/go-scp | https://github.com/bramvdbogaerde/go-scp | Thư viện SCP client bằng Go |
| 5 | rsync | RsyncProject/rsync | https://github.com/RsyncProject/rsync | Cài đặt chính thức của rsync, thuật toán delta |
| 6 | Syslog | rsyslog/rsyslog | https://github.com/rsyslog/rsyslog | Gom và chuyển tiếp log tập trung |
| 7 | LDAP | go-ldap/ldap | https://github.com/go-ldap/ldap | Thư viện LDAP client bằng Go |
| 8 | Kerberos | jcmturner/gokrb5 | https://github.com/jcmturner/gokrb5 | Thư viện Kerberos bằng Go |
| 9 | SFTP (mốc so sánh) | pkg/sftp | https://github.com/pkg/sftp | Thư viện SFTP, dùng đo so sánh |

---

## 3. Nhóm làm thêm / phát triển thêm những gì mà các project tham khảo chưa có

Các project trên mỗi cái chỉ giải quyết **một giao thức hoặc một khâu riêng lẻ**: chúng lo việc *truyền*, hoặc *xác thực*, hoặc *ghi log*, nhưng **chưa có hệ thống gắn kết tất cả thành giải pháp hoàn chỉnh cho nghiệp vụ bảo mật của tổ chức**. Nhóm bổ sung các phần sau:

| # | Tính năng nhóm phát triển thêm | Các project tham khảo còn thiếu gì? | Tình trạng |
|---|--------------------------------|--------------------------------------|-----------|
| 1 | **Gateway hợp nhất FTPS + SCP + rsync** (kèm SFTP làm mốc), tự chọn giao thức theo tình huống | Mỗi project chỉ hỗ trợ một giao thức, người dùng phải tự cấu hình riêng | **Đã làm**, đã thử với máy chủ FTPS giả lập và OpenSSH thật |
| 2 | **Công cụ so sánh giao thức**: nhiều cỡ file, lặp nhiều lần, xuất CSV, biểu đồ trên web | Không có | **Một phần**: công cụ đã xong, nhưng bảng số đo thật trong `docs/SO_SANH_GIAO_THUC.md` chưa được điền |
| 3 | **Mã hóa AES-256-GCM theo khối** trước khi gửi tới máy chủ lưu trữ, phát hiện file bị sửa hoặc cắt cụt | Các giao thức chỉ bảo vệ trên đường truyền; file nằm trên máy chủ ở dạng rõ | **Đã làm**. Mã hóa diễn ra tại gateway, không phải trong trình duyệt (xem mục 6) |
| 4 | **Phân quyền theo vai trò (admin, staff, auditor)** và 4 mức mật (Công khai, Nội bộ, Mật, Tuyệt mật) | Chỉ có quyền file/thư mục cơ bản | **Đã làm**. Đồng bộ người dùng từ LDAP: **chưa làm** |
| 5 | **Đăng nhập một lần (SSO) bằng Kerberos** | Thường chỉ có tên và mật khẩu | **Chưa làm** |
| 6 | **Nhật ký kiểm toán chống sửa**: hash-chain, chữ ký HMAC (đặt `ST_AUDIT_KEY`), file `.head` phát hiện xóa dòng cuối, nút kiểm tra toàn vẹn | Log rời rạc theo từng dịch vụ, có thể bị sửa | **Đã làm**. Gửi tập trung qua Syslog: có sẵn tùy chọn, chưa thử với rsyslog thật |
| 7 | **Link chia sẻ có thời hạn**: tối đa 7 ngày, giới hạn số lần tải (tối đa 100), thu hồi được, không cho chia sẻ tài liệu mức Tuyệt mật | Không có | **Đã làm** |
| 8 | **Quy trình phê duyệt hai người** trước khi chia sẻ tài liệu tuyệt mật ra ngoài | Không có | **Chưa làm** |
| 9 | **Giao diện web** (đăng nhập, gửi, tải, chia sẻ, nhật ký, so sánh giao thức) và **báo cáo tuân thủ** | Hầu hết chỉ dùng dòng lệnh hoặc file cấu hình | Giao diện: **đã làm**. Xuất báo cáo tuân thủ ra file: **chưa làm** |

**Các phần làm thêm ngoài kế hoạch ban đầu:**
- Đăng nhập bằng mật khẩu băm scrypt (tối thiểu 12 ký tự) và token JWT hết hạn sau 60 phút; mọi lần đăng nhập, kể cả thất bại, đều ghi vào nhật ký.
- Chặn gửi đè tài liệu trùng tên và chặn hạ mức mật khi ghi đè; link chia sẻ gắn với một phiên bản tài liệu nên hết hiệu lực khi tài liệu bị thay.
- Kết nối SSH an toàn hơn: chế độ `strict host key` (chỉ tin máy chủ đã được xác nhận, chặn khi khóa máy chủ đổi), lệnh `trust-host` và lệnh chẩn đoán `ssh-check`.
- Giới hạn dung lượng upload 50 MB, thông báo lỗi tiếng Việt, 128 test tự động.

---

## 4. Kết quả đã đạt được

| Nhóm | Đã làm được | Nơi xem |
|------|-------------|---------|
| Truyền tệp | Gateway FTPS, SCP, rsync, SFTP (mốc so sánh); tự chọn giao thức theo tình huống | `securetransfer/gateway.py`, `transfer/` |
| Mã hóa | AES-256-GCM chia khối 1 MiB, mỗi khối có nonce riêng và AAD (số thứ tự, cờ khối cuối) nên phát hiện đảo khối và cắt cụt file | `securetransfer/crypto.py` |
| Xác thực, phân quyền | Mật khẩu băm scrypt, JWT hết hạn sau 60 phút, 3 vai trò (admin, staff, auditor), 4 mức mật | `auth.py`, `api.py` |
| Nhật ký kiểm toán | Hash-chain; bật `ST_AUDIT_KEY` để dùng HMAC và file `.head` chống xóa dòng cuối; ghi cả lần bị từ chối; gửi Syslog tùy chọn | `audit.py` |
| Chống ghi đè | Gửi trùng tên chỉ cho chủ tài liệu hoặc admin ghi đè, không được hạ mức mật (API trả 409) | `gateway.py` |
| Chia sẻ có kiểm soát | Link có hạn dùng, giới hạn số lần tải, thu hồi, chặn tài liệu Tuyệt mật, gắn với một phiên bản tài liệu | `shares.py` |
| So sánh giao thức | Đo thời gian gửi và nhận, tốc độ, kiểm tra toàn vẹn SHA-256, xuất CSV | `benchmark.py` |
| Giao diện web | Đăng nhập, gửi tài liệu, danh sách tài liệu kèm nút Chia sẻ, nhật ký kiểm toán, so sánh giao thức | `securetransfer/web/index.html` |
| Kiểm thử | Hàng trăm ca kiểm thử tự động: mã hóa, audit, phân quyền, API, SSH, chống ghi đè, link chia sẻ | `tests/` |

###Giao diện

| Gửi tài liệu | Tài liệu đã gửi | Nhật ký kiểm toán |
|:---:|:---:|:---:|
| ![Gửi tài liệu](docs/images/gui-gui-tai-lieu.png) | ![Tài liệu đã gửi](docs/images/gui-tai-lieu-da-gui.png) | ![Nhật ký kiểm toán](docs/images/gui-nhat-ky-kiem-toan.png) |


## 5. Cài đặt & chạy thử

**Yêu cầu:** Python 3.10 trở lên (đã chạy với 3.11), Git. Tùy chọn: Docker Desktop để dựng máy chủ SSH thử SCP, SFTP, rsync; WSL2 trên Windows nếu muốn thử rsync.

**Bước 1: Lấy code và cài thư viện** (Windows PowerShell; macOS/Linux dùng `source .venv/bin/activate` và `cp`):
```
git clone https://github.com/mlor707/nh-m-10-ltm.git
cd nh-m-10-ltm
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

**Bước 2: Điền khóa vào `.env`.** Tạo hai chuỗi ngẫu nhiên khác nhau bằng lệnh dưới (chạy hai lần) rồi dán vào `ST_JWT_SECRET` (bắt buộc) và `ST_AUDIT_KEY` (khuyên dùng):
```
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

**Bước 3: Đặt mật khẩu cho ba tài khoản demo** (tối thiểu 12 ký tự, lệnh hỏi hai lần):
```
python -m securetransfer.auth set-password alice
python -m securetransfer.auth set-password bob
python -m securetransfer.auth set-password carol
```
Mật khẩu được lưu dưới dạng hash scrypt trong `config/users.json`. Không commit file này sau khi đặt mật khẩu; có thể tách ra file riêng bằng cách đặt `ST_USERS_PATH=data/users.local.json` trong `.env` (thư mục `data/` đã nằm trong `.gitignore`).

**Bước 4: Chạy** (hai cửa sổ terminal, cả hai đã activate `.venv`):
```
python -m securetransfer.devserver          # cửa sổ 1: máy chủ FTPS giả lập
uvicorn securetransfer.api:app --reload     # cửa sổ 2: ứng dụng
```
Mở http://127.0.0.1:8000 và đăng nhập. Trang tài liệu API (Swagger) ở http://127.0.0.1:8000/docs.

**Tài khoản demo**

| Tài khoản | Vai trò | Mức mật tối đa | Làm được gì |
|-----------|---------|----------------|-------------|
| alice | Quản trị | Tuyệt mật | Gửi, nhận, xem nhật ký, chạy so sánh giao thức |
| bob | Nhân viên | Nội bộ | Gửi và nhận tài liệu, tối đa mức Nội bộ |
| carol | Kiểm toán viên | Mật | Chỉ xem nhật ký kiểm toán |

**Kịch bản thử nhanh**
1. Đăng nhập `bob`, gửi một file mức Nội bộ.
2. `bob` thử gửi mức Tuyệt mật: bị từ chối. `alice` gửi được.
3. Đăng nhập `carol`, mở Nhật ký kiểm toán: thấy cả lần thành công lẫn lần bị từ chối.
4. `bob` mở Tài liệu đã gửi, bấm **Chia sẻ**, chọn hạn dùng và số lần tải, sao chép link và mở ở cửa sổ ẩn danh: tải được mà không cần đăng nhập. Mở quá số lần hoặc sau khi thu hồi thì báo lỗi 410.
5. Kiểm tra nhật ký: `python -m securetransfer.cli audit-verify`. Sửa tay một dòng trong `data/audit.log` rồi chạy lại: hệ thống báo lỗi đúng dòng bị sửa.

**Dòng lệnh**
```
python -m securetransfer.cli send --user alice --level SECRET hopdong.pdf
python -m securetransfer.cli receive --user alice --level SECRET hopdong.pdf ra.pdf
python -m securetransfer.cli audit-verify
python -m securetransfer.cli ssh-check
python -m securetransfer.cli benchmark --sizes 1 10 50 --repeat 3 --protocols scp sftp rsync ftps --csv data/benchmark.csv
```

**SCP, SFTP, rsync** cần một máy chủ SSH: làm theo [docs/DUNG_SSH_DEV.md](docs/DUNG_SSH_DEV.md) (dựng bằng Docker, khoảng 5 phút). rsync không chạy trên Windows thuần, cần WSL2.

**Chạy kiểm thử:** `python -m pytest -q`. Các test SSH tự bỏ qua nếu máy không có `sshd` hoặc `rsync` (trên Windows hãy chạy trong WSL để chạy đủ).

## 6. Giới hạn đã biết

- **Mã hóa thực hiện tại gateway, không phải mã hóa đầu-cuối phía client.** File đi tới gateway ở dạng rõ rồi được mã hóa bằng một khóa duy nhất `data/master.key`; quản trị viên gateway vẫn đọc được. Mã hóa đầu-cuối thật (trong trình duyệt, khóa theo từng người nhận) là hướng phát triển.
- **Giao diện web chạy HTTP.** Khi triển khai ngoài máy cá nhân phải đặt sau TLS.
- **Cấu hình mặc định là chế độ phát triển:** `ST_FTPS_VERIFY=false`, `ST_SSH_STRICT_HOST_KEY` chưa bật. Khi chạy thật phải bật xác minh chứng chỉ và strict host key (xem `docs/DUNG_SSH_DEV.md`).
- Audit log cục bộ không phát hiện được việc khôi phục cả log lẫn file `.head` từ bản sao cũ; nên gửi Syslog sang máy chủ riêng để đối chiếu.
- Danh sách tài liệu hiện được suy ra từ nhật ký kiểm toán.
- Chưa có giới hạn số lần đăng nhập sai.
- **Chưa làm:** đồng bộ LDAP, SSO Kerberos, quy trình phê duyệt 2 người, xuất báo cáo tuân thủ.
- Số đo so sánh giao thức đang được cập nhật trong [docs/SO_SANH_GIAO_THUC.md](docs/SO_SANH_GIAO_THUC.md) (mục 5).

## 7. Tài liệu trong repo

| File | Nội dung |
|------|----------|
| [docs/HUONG_DAN_DEV.md](docs/HUONG_DAN_DEV.md) | Hướng dẫn phát triển, cấu trúc code |
| [docs/DUNG_SSH_DEV.md](docs/DUNG_SSH_DEV.md) | Dựng máy chủ SSH, chế độ strict host key, xử lý lỗi |
| [docs/SO_SANH_GIAO_THUC.md](docs/SO_SANH_GIAO_THUC.md) | So sánh FTPS, SCP, rsync, SFTP và cách đo |

## 8. Hướng phát triển tiếp
Mã hóa trong trình duyệt với khóa theo người nhận hoặc KMS; LDAP và Kerberos; phê duyệt 2 người cho tài liệu Tuyệt mật; báo cáo tuân thủ xuất CSV hoặc PDF; HTTPS bắt buộc; GitHub Actions chạy test; cơ sở dữ liệu cho thông tin tài liệu.

## 9. Cấu trúc thư mục và làm việc nhóm 

```
securetransfer/
  api.py          REST API và phục vụ giao diện
  auth.py         scrypt, JWT, phân quyền theo vai trò và mức mật
  gateway.py      kiểm quyền, chống ghi đè, mã hóa, chọn giao thức, ghi nhật ký
  crypto.py       AES-256-GCM theo khối
  audit.py        nhật ký hash-chain / HMAC, Syslog
  shares.py       link chia sẻ có thời hạn
  benchmark.py    so sánh giao thức
  transfer/       FTPS, SCP, rsync, SFTP (chung giao diện TransferBackend)
  web/index.html  giao diện
tests/            kiểm thử tự động
docs/             hướng dẫn dựng SSH, hướng dẫn phát triển, so sánh giao thức
docker/, docker-compose.yml   máy chủ SSH để thử
```

**Quy ước làm việc:** mỗi người làm trên nhánh riêng, mở Pull Request vào `main`, người khác xem rồi mới merge; commit mang đúng tên người làm. Tài liệu chi tiết: [docs/HUONG_DAN_DEV.md](docs/HUONG_DAN_DEV.md).

## Giấy phép

MIT, xem file [LICENSE](LICENSE).
