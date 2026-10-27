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

# 4. Chẩn đoán tự động: kiểm tra cấu hình, cổng, đăng nhập, thư mục đích, rồi thử SCP/SFTP/rsync
python -m securetransfer.cli ssh-check
```
Lệnh `ssh-check` in `[OK]` hoặc `[LỖI]` cho từng bước, mỗi lỗi kèm gợi ý cách sửa. Khi tất cả đều `[OK]` là máy chủ đã sẵn sàng.

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
# Chẩn đoán trước (nếu có bước nào lỗi, đọc dòng gợi ý bên dưới nó)
python -m securetransfer.cli ssh-check

# Gửi qua SCP, nhận lại bằng SCP
python -m securetransfer.cli send --user alice --level SECRET --scenario admin hopdong.pdf
python -m securetransfer.cli receive --user alice --level SECRET --scenario admin hopdong.pdf ra.pdf

# Gửi qua rsync (scenario sync) hoặc SFTP (scenario baseline)
python -m securetransfer.cli send --user alice --scenario sync hopdong.pdf

# So sánh tốc độ ba giao thức (in bảng và ghi file CSV; mỗi lần đo xong, file thử trên máy chủ được xóa)
python -m securetransfer.cli benchmark --sizes 1 10 50 --repeat 3 --protocols scp sftp rsync --csv data/benchmark.csv
```
Hoặc mở giao diện web, tab **So sánh giao thức**.

## Bật chế độ nghiêm ngặt (strict host key)

Mặc định (chế độ dev) ứng dụng tự chấp nhận máy chủ SSH lạ ở lần kết nối đầu, tiện khi thử nhưng **không chống được
kẻ giả mạo máy chủ**. Khi demo hoặc chạy thật, hãy bật chế độ strict: chỉ kết nối tới máy chủ đã được tin cậy.

```bash
# 1. Tin cậy máy chủ (hiện vân tay để bạn đối chiếu rồi mới lưu)
python -m securetransfer.devssh trust-host
#    Đối chiếu vân tay in ra với máy chủ thật:
#    docker compose exec sshd ssh-keygen -lf /hostkeys/ssh_host_ed25519_key.pub

# 2. Thêm vào .env
#    ST_SSH_STRICT_HOST_KEY=true
#    ST_SSH_KNOWN_HOSTS=data/ssh_dev/known_hosts

# 3. Kiểm tra lại
python -m securetransfer.cli ssh-check
```
Khi bật strict: máy chủ chưa tin cậy bị từ chối, và nếu khóa máy chủ **thay đổi** so với lúc đã lưu thì bị chặn kèm cảnh báo
(có thể đang bị tấn công giữa đường). Lệnh `trust-host` cũng từ chối ghi đè khóa cũ bằng khóa khác.
Biến `ST_SSH_TIMEOUT` (giây, mặc định 20) đặt thời gian chờ kết nối cho cả ba giao thức.

## Lưu ý theo hệ điều hành

- **Windows:** lệnh `rsync` không có sẵn. Cách dễ nhất là cài WSL2 (Ubuntu), rồi chạy cả dự án trong WSL
  (`sudo apt install rsync`). SCP và SFTP chạy được trực tiếp trên Windows vì dùng thư viện Python.
- **macOS/Linux:** thường có sẵn `rsync`; nếu thiếu thì cài bằng `brew install rsync` hoặc `apt install rsync`.

## Gặp lỗi?

| Lỗi | Nguyên nhân thường gặp | Cách xử lý |
|-----|------------------------|-----------|
| `Máy chủ chưa được tin cậy (chế độ strict)` | Chưa chạy `trust-host` | `python -m securetransfer.devssh trust-host` |
| `KHÓA MÁY CHỦ ĐÃ THAY ĐỔI` | Máy chủ cài lại (volume Docker bị xóa) hoặc đang bị giả mạo | Đối chiếu vân tay với máy chủ thật. Nếu đúng là cài lại: xóa dòng cũ trong `data/ssh_dev/known_hosts` rồi chạy lại `trust-host` |
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

- Các test SCP/SFTP/rsync, chế độ strict, trust-host, timeout và `ssh-check` **đã chạy thật** với sshd (OpenSSH) trên Linux.
- `docker/entrypoint.sh` và `docker/10-securetransfer.conf` đã được chạy thử với sshd thật (dựng lại đúng nội dung image):
  đăng nhập bằng khóa, `ssh-check` đạt cả SCP/SFTP/rsync, strict mode và tình huống đổi khóa máy chủ đều đúng.
- **Chưa kiểm chứng:** bước `docker compose build/up` (môi trường viết code không có Docker). Nếu Docker báo lỗi,
  hãy ghi lại thông báo để sửa `Dockerfile` hoặc `docker-compose.yml`.
