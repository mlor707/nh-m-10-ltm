# 🔐 Hệ thống Truyền tải Tài liệu Nội bộ An toàn (Secure Internal Document Transfer)

> Bài tập nhóm – Môn Mạng máy tính / Giao thức mạng (nhóm 3 SV)
> **Nhóm giao thức đề xuất (ngoài danh sách 20 giao thức):** Truyền tệp bảo mật – **FTPS, SCP, rsync**, kết hợp **Syslog** (nhật ký kiểm toán) và **LDAP/Kerberos** (xác thực tập trung). Dùng **SFTP** làm mốc so sánh.

## 👥 Thành viên

| STT | Họ và tên | MSSV | Vai trò |
|-----|-----------|------|---------|
| 1 | _..._ | _..._ | _..._ |
| 2 | _..._ | _..._ | _..._ |
| 3 | _..._ | _..._ | _..._ |

---

## 1. Định hướng làm đề tài

### 1.1. Bài toán
Các tổ chức xử lý dữ liệu nhạy cảm vẫn thường chia sẻ tài liệu nội bộ qua email, USB, Zalo/Messenger hoặc FTP không mã hóa. Cách này dễ gây **rò rỉ dữ liệu, không kiểm soát được ai đã truy cập, không có bằng chứng truy vết** khi xảy ra sự cố.

### 1.2. Mục tiêu
Xây dựng ứng dụng **truyền tải tài liệu nội bộ an toàn**, trong đó:
- Hỗ trợ **nhiều giao thức truyền tệp bảo mật (FTPS, SCP, rsync)** và tự chọn giao thức phù hợp theo từng tình huống sử dụng.
- Mọi thao tác (upload / download / xóa / chia sẻ) đều được **xác thực, phân quyền và ghi nhật ký kiểm toán tập trung**.
- Dữ liệu được mã hóa trên đường truyền **và** mã hóa phía client trước khi gửi (end-to-end).
- Có chức năng **so sánh hiệu năng và mức độ bảo mật** giữa các giao thức (kèm SFTP làm mốc) để giúp tổ chức lựa chọn.
- Dễ triển khai on-premise trong mạng nội bộ.

### 1.3. Thị trường & tệp khách hàng hướng tới
Ứng dụng được thiết kế linh hoạt để phục vụ các tổ chức có yêu cầu bảo mật dữ liệu ở mức cao nhất:

| Lĩnh vực | Nhu cầu chính | Tài liệu cần bảo vệ |
|----------|---------------|---------------------|
| 🏦 **Ngân hàng & Tài chính** | Chống rò rỉ, tuân thủ chuẩn an toàn thông tin **PCI DSS** | Hồ sơ tín dụng, báo cáo giao dịch mật |
| 🏥 **Y tế & Bệnh viện lớn** | Bảo vệ quyền riêng tư bệnh nhân | Hồ sơ bệnh án điện tử, kết quả xét nghiệm |
| ⚖️ **Văn phòng Luật sư & Kiểm toán** | Bảo mật thông tin khách hàng, có bằng chứng truy vết | Hợp đồng M&A, sổ sách kế toán, thỏa thuận NDA |

### 1.4. Giao thức sử dụng trong đề tài

**Nhóm giao thức chính – Truyền tệp bảo mật (nhóm tự đề xuất):**

| Giao thức | Làm gì | Tầng OSI | Tình huống sử dụng trong hệ thống |
|-----------|--------|----------|-----------------------------------|
| **FTPS** (FTP over TLS) | Truyền tệp, kênh điều khiển/dữ liệu mã hóa bằng TLS | L7 (TLS ở L5-L6), chạy trên TCP (L4) | Trao đổi với đối tác/hệ thống cũ (ngân hàng, bệnh viện) vẫn dùng FTP |
| **SCP** | Sao chép tệp qua SSH | L7, chạy trên TCP (L4) | Quản trị viên chuyển nhanh từng tệp giữa các máy chủ |
| **rsync** | Đồng bộ tệp, chỉ gửi phần thay đổi | L7, thường qua SSH/TCP (L4) | Đồng bộ và sao lưu tài liệu giữa các chi nhánh |

**Giao thức hỗ trợ:**

| Giao thức | Vai trò | Tầng OSI |
|-----------|---------|----------|
| **Syslog** | Gom nhật ký truy cập tập trung phục vụ kiểm toán | L7 |
| **LDAP/LDAPS** | Thư mục người dùng, phòng ban, phân quyền | L7 |
| **Kerberos** | Xác thực bằng vé (ticket), đăng nhập một lần (SSO) | L7 |

**Giao thức đối chiếu (có trong danh sách 20 giao thức):** **SFTP** – dùng làm mốc so sánh hiệu năng/bảo mật với FTPS, SCP, rsync.

### 1.5. Kiến trúc tổng quan (dự kiến)

```
                         ┌─ FTPS  (đối tác / hệ thống cũ)
[Client App] ─ mã hóa ─> [Gateway chọn giao thức] ─ SCP   (quản trị, chuyển nhanh)
  AES-256 phía client             │                └─ rsync (đồng bộ chi nhánh)
                                  │
        Xác thực (LDAP / Kerberos) ┤
        Nhật ký kiểm toán (Syslog) ┘──> [Kho lưu trữ mã hóa]
```

---

## 2. Các project tham khảo + Link GitHub

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

> 📝 _Nhóm sẽ rà soát lại và bổ sung/cập nhật danh sách trong quá trình làm._

---

## 3. Nhóm sẽ làm thêm / phát triển thêm những gì mà các project tham khảo chưa có

Các project trên mỗi cái chỉ giải quyết **một giao thức hoặc một khâu riêng lẻ**: chúng lo việc *truyền* hoặc *xác thực* hoặc *ghi log*, nhưng **chưa có hệ thống gắn kết tất cả thành giải pháp hoàn chỉnh cho nghiệp vụ bảo mật của tổ chức**. Nhóm sẽ bổ sung:

| # | Tính năng nhóm phát triển thêm | Các project tham khảo còn thiếu gì? | Giá trị cho khách hàng |
|---|--------------------------------|--------------------------------------|------------------------|
| 1 | **Gateway hợp nhất FTPS + SCP + rsync**, tự chọn giao thức theo tình huống | Mỗi project chỉ hỗ trợ 1 giao thức, người dùng phải tự cấu hình riêng | Một giao diện duy nhất cho mọi nhu cầu |
| 2 | **Công cụ so sánh giao thức** (tốc độ, tài nguyên, mức mã hóa) kèm SFTP làm mốc | Không có | Giúp tổ chức chọn giao thức phù hợp, có số liệu |
| 3 | **Mã hóa đầu-cuối phía client** (AES-256-GCM) trước khi upload | Các giao thức chỉ mã hóa trên đường truyền; file nằm trên server ở dạng rõ | Admin server cũng không đọc được nội dung |
| 4 | **Phân quyền theo vai trò (RBAC)** và mức mật, đồng bộ từ LDAP | Chỉ có quyền file/thư mục cơ bản | Đúng quy trình nội bộ ngân hàng, bệnh viện |
| 5 | **Đăng nhập một lần (SSO) bằng Kerberos** | Thường chỉ user/password | Giảm nguy cơ lộ tài khoản |
| 6 | **Audit log tập trung qua Syslog, chống chỉnh sửa** (hash chain) | Log rời rạc theo từng dịch vụ, có thể bị sửa | Truy vết khi có sự cố, phục vụ kiểm toán |
| 7 | **Link chia sẻ có thời hạn / giới hạn số lần tải / thu hồi** | Không có | Chia sẻ hợp đồng NDA, M&A có kiểm soát |
| 8 | **Quy trình phê duyệt** trước khi tài liệu mật được chia sẻ ra ngoài | Không có | Chống rò rỉ do nhầm lẫn hoặc nội gián |
| 9 | **Giao diện quản trị & báo cáo tuân thủ** (dashboard, xuất báo cáo) | Hầu hết chỉ dòng lệnh / cấu hình file | Phù hợp người dùng nghiệp vụ không chuyên IT |

### Phạm vi thực hiện

- **MVP (bắt buộc):** Gateway FTPS + SCP + rsync, mã hóa phía client, ghi log qua Syslog, công cụ so sánh với SFTP, giao diện web cơ bản.
- **Mở rộng (nếu đủ thời gian):** LDAP + RBAC, SSO Kerberos, link chia sẻ có thời hạn, quy trình phê duyệt, báo cáo tuân thủ.

---

## 🚀 Cài đặt & chạy thử
_(Sẽ cập nhật khi hoàn thiện ứng dụng)_

## 🗂️ Phân công & tiến độ
_(Sẽ cập nhật theo commit của từng thành viên)_

## 📄 Giấy phép
_(Chọn license, ví dụ MIT)_
