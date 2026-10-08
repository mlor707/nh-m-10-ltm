# TrustFlow - Hệ thống Truyền tải Tài liệu Nội bộ An toàn
## 1. Định hướng làm đề tài của nhóm:
*   **Mục tiêu dự án:** Xây dựng hệ thống Client-Server truyền tải tài liệu nội bộ an toàn tuyệt đối bằng giao thức HTTPS (REST API) kết hợp tính năng Chunked Upload và mã hóa luồng dữ liệu.
*   **Thị trường và Tệp khách hàng hướng tới:** Ứng dụng được thiết kế linh hoạt để phục vụ các tổ chức có yêu cầu bảo mật dữ liệu ở mức độ cao nhất, bao gồm:
    *   **Khối Ngân hàng & Tài chính:** Chống rò rỉ hồ sơ tín dụng, báo cáo giao dịch mật, tuân thủ chuẩn an toàn thông tin PCI DSS.
    *   **Hệ thống Y tế & Bệnh viện lớn:** Bảo vệ hồ sơ bệnh án điện tử, kết quả xét nghiệm.
    *   **Văn phòng Luật sư & Kiểm toán:** Bảo mật hợp đồng M&A, sổ sách kế toán, thỏa thuận NDA.
*   **Định hướng kỹ thuật cốt lõi:** Áp dụng kiến trúc "Zero-Knowledge" (Không tri thức), sử dụng mã hóa đầu cuối (End-to-End Encryption - E2EE). Máy chủ backend chỉ làm trạm trung chuyển qua cổng 443, hoàn toàn không thể đọc được nội dung file được mã hóa từ Client.

## 2. Các Project tham khảo + Link github của các project đó
*   **Send (Fork của Mozilla Send)**
    *   *Link GitHub:* [timvisee/send](https://github.com/timvisee/send)
    *   *Mô tả:* Hệ thống chia sẻ file E2EE, mã hóa trực tiếp phía Client (Client-side) bằng Web Crypto API trước khi tải lên máy chủ.
*   **YeetFile**
    *   *Link GitHub:* [timvisee/send](https://github.com/benbusby/yeetfile)
    *   *Mô tả:* Nền tảng tự lưu trữ chia sẻ file mã hóa qua REST API, hỗ trợ phân quyền người dùng độc lập.
*   **Magic-Wormhole**
    *   *Link GitHub:* [timvisee/send](https://github.com/magic-wormhole/magic-wormhole)
    *   *Mô tả:* Ứng dụng truyền tải ngang hàng sử dụng giao thức PAKE để trao đổi khóa giải mã an toàn mà không bị rò rỉ qua mạng.
## 3. Tóm tắt Nhóm sẽ làm thêm hay phát triển thêm những gì mà các Project tham khảo chưa có hay chưa hay
*   **Tích hợp Dynamic Watermarking (Đóng dấu động):** Các dự án tham khảo không chống được việc chụp màn hình. Nhóm sẽ phát triển chế độ "View-Only", tự động chèn watermark (Tên nhân viên, IP, Thời gian) chìm lên tài liệu để truy vết nếu có rò rỉ.
*   **Data Hashing xác thực toàn vẹn (SHA-256):** Tự động đối chiếu mã băm ở cả Client và Server trong từng HTTP Request, đảm bảo báo cáo giao dịch hoặc bằng chứng số không bị sai lệch dù chỉ một byte.
*   **Quản lý luồng tải (Rate Limiting) qua API:** Thiết lập hàng rào giới hạn số lượng request tải xuống theo giờ dựa trên JWT, chặn đứng rủi ro nhân viên cố tình tải hàng loạt dữ liệu ra ngoài.
*   **Hủy dữ liệu vật lý (Secure Wipe):** Thay vì chỉ xóa đường dẫn trong CSDL, hệ thống sẽ có luồng chạy ngầm ghi đè dữ liệu rác lên vùng nhớ ổ cứng chứa file gốc trước khi xóa hoàn toàn khỏi server sau 24 giờ.
