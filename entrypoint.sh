#!/bin/bash
set -e

# 生成 host key（首次启动时）
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi

echo "[entrypoint] starting sshd on :22 ..."
/usr/sbin/sshd -D &
SSHD_PID=$!

echo "[entrypoint] sshd started (pid $SSHD_PID), waiting..."
wait $SSHD_PID
