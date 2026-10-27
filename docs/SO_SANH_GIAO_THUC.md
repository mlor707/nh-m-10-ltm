# So sánh giao thức truyền tệp: FTPS, SCP, rsync (SFTP làm mốc)

> Tài liệu của **Người 1 – Giao thức**. Phần 1 đến 4 là kiến thức giao thức và cách dự án dùng chúng.
> **Phần 5 (số đo) còn trống: phải chạy benchmark trên máy nhóm rồi điền vào.** Không điền số của người khác.

## 1. Chọn nhanh theo tình huống

Gateway của dự án (`securetransfer/gateway.py`, bảng `SCENARIO_PROTOCOL`) chọn giao thức theo tình huống gửi:

| Tình huống trên giao diện | Giao thức | Lý do chọn |
|---------------------------|-----------|-----------|
| Đối tác hoặc hệ thống cũ (`partner`) | **FTPS** | Nhiều hệ thống ngân hàng, bệnh viện vẫn dùng FTP; thêm TLS để giữ nguyên quy trình cũ mà vẫn được mã hóa |
| Quản trị viên chuyển nhanh (`admin`) | **SCP** | Một lệnh, một kết nối, dùng ngay khóa SSH sẵn có |
| Đồng bộ giữa các chi nhánh (`sync`) | **rsync** | Chỉ truyền phần thay đổi, hợp khi đồng bộ cùng một thư mục nhiều lần |
| Chỉ để so sánh (`baseline`) | **SFTP** | Mốc đối chiếu cho ba giao thức còn lại |

Không có giao thức "tốt nhất tuyệt đối". Mỗi giao thức hợp với một hoàn cảnh, nên dự án để người dùng chọn theo tình huống.

## 2. Bảng so sánh kỹ thuật

| Tiêu chí | FTPS | SCP | rsync (qua SSH) | SFTP |
|----------|------|-----|-----------------|------|
| Nền tảng | FTP cộng TLS | Chạy trên SSH | Chạy trên SSH | Hệ con (subsystem) của SSH |
| Cổng mặc định | 21 (explicit, dùng lệnh AUTH TLS) hoặc 990 (implicit, kiểu cũ), cộng cổng dữ liệu | 22 | 22 (rsync daemon riêng dùng 873) | 22 |
| Số kết nối | 2 (điều khiển và dữ liệu) | 1 | 1 | 1 |
| Mã hóa đường truyền | TLS, phải bật cho cả kênh dữ liệu (`PROT P`) | SSH | SSH | SSH |
| Xác thực máy chủ | Chứng chỉ X.509 (CA cấp hoặc tự ký) | Khóa máy chủ SSH (`known_hosts`) | Như SCP | Như SCP |
| Xác thực người dùng | Tên và mật khẩu (có thể thêm chứng chỉ client) | Khóa SSH hoặc mật khẩu | Như SCP | Như SCP |
| Truyền tiếp khi đứt (resume) | Có (tùy máy chủ và client) | Không | Có (`--partial`) | Có (tùy client) |
| Chỉ gửi phần thay đổi | Không | Không | **Có** (thuật toán delta) | Không |
| Quản lý file từ xa (liệt kê, xóa, đổi tên) | Có | Không | Một phần (liệt kê, `--delete`) | Có |
| Qua tường lửa và NAT | Khó hơn vì cổng dữ liệu thay đổi (chế độ passive phải mở một dải cổng) | Dễ, một cổng | Dễ, một cổng | Dễ, một cổng |

## 3. Điểm yếu và rủi ro cần nói rõ

- **FTPS:** nếu chỉ mã hóa kênh điều khiển mà quên kênh dữ liệu thì nội dung file đi dạng rõ. Dự án ép mã hóa cả hai: client gọi `prot_p()` (`transfer/ftps.py`) và server thử nghiệm bật `tls_data_required`. Chứng chỉ tự ký chỉ dùng khi phát triển (`ST_FTPS_VERIFY=false`); chạy thật phải dùng chứng chỉ do CA cấp và bật xác minh.
- **SCP:** giao thức SCP/RCP kiểu cũ bị OpenSSH coi là lỗi thời; từ OpenSSH 9.0 lệnh `scp` mặc định đã dùng giao thức SFTP bên dưới. SCP không có resume và không quản lý được file từ xa.
- **rsync:** chạy qua SSH thì an toàn bằng SSH. Chế độ daemon (cổng 873) mặc định **không mã hóa**, nên dự án chỉ dùng rsync qua SSH.
- **Khóa máy chủ SSH:** chế độ dev tự chấp nhận máy chủ lạ ở lần đầu. Chế độ strict (`ST_SSH_STRICT_HOST_KEY=true`) chỉ chấp nhận máy chủ đã được tin cậy bằng `trust-host`, và chặn khi khóa đổi (chống tấn công giữa đường).
- **Bảo vệ ở tầng ứng dụng:** dù dùng giao thức nào, tài liệu đã được mã hóa AES-256-GCM phía client trước khi gửi (`crypto.py`), nên máy chủ chỉ thấy bản mã hóa. Vì vậy khác biệt bảo mật giữa các giao thức nằm chủ yếu ở bảo vệ đường truyền và xác thực máy chủ.

## 4. Cách dự án hiện thực từng giao thức

| Giao thức | File | Cách làm |
|-----------|------|----------|
| FTPS | `securetransfer/transfer/ftps.py` | `ftplib.FTP_TLS`: đăng nhập (tự gọi AUTH TLS), rồi `prot_p()` mã hóa kênh dữ liệu |
| SCP | `securetransfer/transfer/scp.py` | Thư viện `paramiko` cộng `scp` |
| rsync | `securetransfer/transfer/rsync.py` | Gọi lệnh `rsync -az -e "ssh ..."`, cần có `rsync` trên máy (Windows: dùng WSL2) |
| SFTP | `securetransfer/transfer/sftp.py` | `paramiko` mở phiên SFTP |

Cả bốn dùng chung giao diện `TransferBackend` (`upload`, `download`, `delete`), nên thêm giao thức mới chỉ cần viết một lớp con.

## 5. Số đo thật (NHÓM ĐIỀN SAU KHI CHẠY)

### 5.1. Cách đo

Bật máy chủ SSH theo `docs/DUNG_SSH_DEV.md` (và `python -m securetransfer.devserver` nếu muốn đo cả FTPS), rồi chạy:

```
python -m securetransfer.cli benchmark --sizes 1 10 50 --repeat 3 --protocols scp sftp rsync ftps --csv data/benchmark.csv
```

Lệnh in bảng ra màn hình và ghi `data/benchmark.csv` (mở được bằng Excel). Mỗi dòng là kết quả trung bình của 3 lần đo; file CSV còn có thời gian nhỏ nhất và lớn nhất của từng dòng.

### 5.2. Điều kiện đo (điền)

| Mục | Giá trị |
|-----|---------|
| Máy chạy (CPU, RAM, hệ điều hành) | … |
| Máy chủ SSH | … (ví dụ Docker Desktop trên cùng máy) |
| rsync chạy ở đâu | … (ví dụ WSL2) |
| Ngày đo | … |

### 5.3. Kết quả (điền từ bảng in ra hoặc file CSV)

Thời gian gửi + nhận trung bình (giây) và tốc độ gửi (Mbit/s):

| Giao thức | 1 MB | 10 MB | 50 MB |
|-----------|------|-------|-------|
| FTPS | … | … | … |
| SCP | … | … | … |
| rsync | … | … | … |
| SFTP | … | … | … |

### 5.4. Nhận xét (viết sau khi có số)

Các điều nên kiểm tra khi nhìn số, rồi viết kết luận dựa trên số thật của nhóm:
- So cỡ 1 MB với 50 MB: với file nhỏ, thời gian có bị chi phối bởi bắt tay và đăng nhập không? Với file lớn, tốc độ có ổn định không?
- Ba lần lặp lệch nhau nhiều không (xem cột min và max trong CSV)?
- Giao thức nào có chênh lệch lớn so với SFTP, và có thể do đâu (xem phần 6)?

## 6. Giới hạn của phép đo (phải nói khi thuyết trình)

1. **Phần mềm máy chủ khác nhau.** FTPS thử nghiệm dùng `pyftpdlib` (viết bằng Python), còn SCP, SFTP và rsync dùng OpenSSH (viết bằng C). Chênh lệch tốc độ có thể đến từ phần mềm máy chủ chứ không hẳn từ giao thức.
2. **Mỗi lần đo mở kết nối mới**, nên thời gian đã gồm bắt tay và đăng nhập. Điều này sát thực tế khi gửi từng file, nhưng bất lợi cho giao thức tốn nhiều bước bắt tay.
3. **Dữ liệu đo là dữ liệu ngẫu nhiên, không nén được.** Tùy chọn nén `-z` của rsync không giúp được gì ở đây; tài liệu thật (văn bản, Word...) có thể cho kết quả khác.
4. **Chỉ đo lần gửi đầu tiên.** Lợi thế "chỉ gửi phần thay đổi" của rsync khi sửa một phần file chưa được đo.
5. **Đo trên cùng một máy** (Docker, localhost) nên không có độ trễ mạng thật. Qua mạng LAN hay WAN, kết quả có thể khác, nhất là với giao thức dùng nhiều kết nối như FTPS.
6. **Chỉ lặp 3 lần**, đủ để thấy độ dao động chứ không phải phân tích thống kê chặt chẽ.
7. **rsync chạy trong WSL2** còn các giao thức khác chạy trên Windows (nếu nhóm đo kiểu đó), nên không so sánh trực tiếp được. Cách tốt nhất là chạy cả bốn trong cùng WSL2.

## 7. Hướng mở rộng

- Đo thêm kịch bản "sửa 1% nội dung rồi gửi lại" để kiểm chứng lợi thế của rsync.
- Đo qua mạng thật (hai máy khác nhau) thay vì cùng một máy.
- Đo mức dùng CPU và RAM, không chỉ thời gian.
