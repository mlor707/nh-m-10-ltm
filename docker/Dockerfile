# Máy chủ SSH dùng để thử SCP / SFTP / rsync (CHỈ DÙNG KHI PHÁT TRIỂN)
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server rsync \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash transfer \
 && usermod -p '*' transfer
COPY 10-securetransfer.conf /etc/ssh/sshd_config.d/10-securetransfer.conf
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
