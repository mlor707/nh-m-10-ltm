# Dựng máy chủ SSH để thử SCP, SFTP, rsync

Ba giao thức SCP, SFTP và rsync cùng chạy trên SSH, nên chỉ cần **một máy chủ OpenSSH** là thử được cả ba.
Chọn **một** trong hai cách dưới đây.

## Cách A – Docker (nhanh nhất, khuyên dùng)

Cần cài Docker Desktop (Windows/macOS) hoặc Docker Engine (Linux).

```bash
# 1. Tạo cặp khóa SSH cho dự án (đăng nhập bằng khóa, không dùng mật khẩu)
python -m securetransfer.devssh keygen

# 2. Thêm vào file .env (lệnh trên đã in sẵn đúng 5 dòng này)
#    ST_SSH_HOST=127.0.0.1
#    ST_SSH_PORT=2222
#    ST_SSH_USER=transfer
#    ST_SSH_KEY_FILE=data/ssh_dev/id_ed25519
#    ST_REMOTE_DIR=.

# 3. Bật máy chủ SSH
docker compose up -d --build

# 4. Kiểm tra đăng nhập được
ssh -i data/ssh_dev/id_ed25519 -p 2222 transfer@127.0.0.1 echo ok
```

Dừng: `docker compose down`. Xem file đã nhận: `docker compose exec sshd ls -l /home/transfer`.

## Cách B – Máy ảo hoặc WSL Ubuntu

```bash
sudo apt update && sudo apt install -y openssh-server rsync
sudo systemctl enable --now ssh
python -m securetransfer.devssh keygen        # chạy trên máy dev
# Chép nội dung data/ssh_dev/id_ed25519.pub vào ~/.ssh/authorized_keys của user trên máy ảo
```
Trong `.env` đặt `ST_SSH_HOST` là IP máy ảo, `ST_SSH_PORT=22`, `ST_SSH_USER` là user trên máy ảo,
`ST_REMOTE_DIR` là một thư mục có quyền ghi (ví dụ `/home/user/inbox`, tạo trước bằng `mkdir`).

## Thử ngay sau khi dựng xong

```bash
# Gửi qua SCP, nhận lại bằng SCP
python -m securetransfer.cli send --user alice --level SECRET --scenario admin hopdong.pdf
python -m securetransfer.cli receive --user alice --level SECRET --scenario admin hopdong.pdf ra.pdf

# Gửi qua rsync (scenario sync) hoặc SFTP (scenario baseline)
python -m securetransfer.cli send --user alice --scenario sync hopdong.pdf

# So sánh tốc độ ba giao thức
python -m securetransfer.cli benchmark --size-mb 5 --protocols scp sftp rsync
```
Hoặc mở giao diện web, tab **So sánh giao thức**.

## Lưu ý theo hệ điều hành

- **Windows:** lệnh `rsync` không có sẵn. Cách dễ nhất là cài WSL2 (Ubuntu), rồi chạy cả dự án trong WSL
  (`sudo apt install rsync`). SCP và SFTP chạy được trực tiếp trên Windows vì dùng thư viện Python.
- **macOS/Linux:** thường có sẵn `rsync`; nếu thiếu thì cài bằng `brew install rsync` hoặc `apt install rsync`.

## Gặp lỗi?

| Lỗi | Nguyên nhân thường gặp | Cách xử lý |
|-----|------------------------|-----------|
| `Permission denied (publickey)` | Sai user hoặc sai file khóa | Kiểm tra `ST_SSH_USER`, `ST_SSH_KEY_FILE`; chạy lại `keygen` rồi `docker compose up -d --force-recreate` |
| `Connection refused` | Máy chủ chưa chạy hoặc sai cổng | `docker compose ps`; kiểm tra `ST_SSH_PORT=2222` |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` (rsync) | Đã xóa volume nên khóa máy chủ đổi | `ssh-keygen -R "[127.0.0.1]:2222"` |
| `Không tìm thấy lệnh 'rsync'` | Máy dev chưa cài rsync | Xem mục Windows ở trên |
| `Missing privilege separation directory: /run/sshd` (chạy test trên Linux) | Chưa có thư mục của sshd | `sudo mkdir -p /run/sshd` |

## Test tự động với sshd thật

`python -m pytest -q` tự khởi động một sshd tạm (cổng ngẫu nhiên) để kiểm thử SCP/SFTP/rsync.
Nếu máy không có `sshd`, `rsync` hoặc `scp`, các test này được **bỏ qua** (skip) chứ không báo lỗi.
Trên Windows hãy chạy test trong WSL để các test này được chạy.

## Tình trạng kiểm chứng

- Các test SCP/SFTP/rsync **đã chạy thật** với sshd (OpenSSH) trên Linux: gửi/nhận đúng nội dung, từ chối khóa sai, báo lỗi khi thiếu file, luồng gateway đầu-cuối.
- File `docker-compose.yml` và thư mục `docker/` **chưa được chạy thử** (môi trường viết code không có Docker). Cấu hình tương đương đã được thử bằng sshd chạy tay; nếu Docker báo lỗi, hãy ghi lại thông báo để sửa.
