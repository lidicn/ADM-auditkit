FROM python:3.11-slim

# 装 openssh-server + git（git 用于审计时跑 git log 等）
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server git \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /home/auditbot/.ssh /workspace /audit-out \
    && useradd -m -s /bin/bash auditbot \
    && chown auditbot:auditbot /home/auditbot/.ssh /audit-out \
    && chmod 700 /home/auditbot/.ssh

# sshd 加固：禁 root、禁密码、只允许 auditbot、只允许公钥
RUN sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config \
    && grep -q '^AllowUsers' /etc/ssh/sshd_config \
       && sed -i 's/^AllowUsers.*/AllowUsers auditbot/' /etc/ssh/sshd_config \
       || echo 'AllowUsers auditbot' >> /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
COPY authorized_keys /home/auditbot/.ssh/authorized_keys
RUN chmod 600 /home/auditbot/.ssh/authorized_keys \
    && chown auditbot:auditbot /home/auditbot/.ssh/authorized_keys \
    && chmod +x /entrypoint.sh

# 连通性验证标记：元宝 SSH 进来读这个，确认真连到容器（不是路由陷阱）
RUN echo "AUDITKIT_CONTAINER_ALIVE_$(date +%s)" > /home/auditbot/CANARY \
    && chown auditbot:auditbot /home/auditbot/CANARY

EXPOSE 22
HEALTHCHECK --interval=60s --timeout=10s --retries=3 --start-period=10s \
    CMD pgrep sshd >/dev/null || exit 1

CMD ["/entrypoint.sh"]
