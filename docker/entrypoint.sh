#!/bin/sh
set -e
mkdir -p /hostkeys /run/sshd
# Khóa máy chủ lưu trong volume để không đổi mỗi lần khởi động lại
[ -f /hostkeys/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N "" -f /hostkeys/ssh_host_ed25519_key

if [ ! -f /keys/authorized_keys ]; then
  echo "Thiếu /keys/authorized_keys. Hãy chạy:  python -m securetransfer.devssh keygen" >&2
  exit 1
fi
mkdir -p /home/transfer/.ssh
install -m 600 -o transfer -g transfer /keys/authorized_keys /home/transfer/.ssh/authorized_keys
chown transfer:transfer /home/transfer/.ssh && chmod 700 /home/transfer/.ssh

echo "sshd sẵn sàng. Người dùng: transfer (chỉ đăng nhập bằng khóa)"
exec /usr/sbin/sshd -D -e
