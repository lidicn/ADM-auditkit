#!/bin/bash
# run_audit.sh —— 一键跑一轮审计 + 生成报告 + 投递开发者路径
#
# 在 NAS 宿主机跑。串联三步：
#   1. 容器内跑 auditkit round（产物落 /audit-out 可写卷）
#   2. 容器内跑 core/report.py 生成 markdown 报告
#   3. 宿主机 deliver_report.sh 投递到目标项目 doc/审计报告/
#
# 用法:
#   run_audit.sh <project> <round_num>
#   例: run_audit.sh doubao-butler 1
#
# 前置：auditkit 容器已启动（docker ps | grep auditkit）
set -euo pipefail

PROJECT="${1:?用法: run_audit.sh <project> <round_num>}"
ROUND="${2:?需要 round 编号}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROUND_DIR_NUM=$(printf "round-%03d" "$ROUND")

echo "── 1/3 容器内跑 auditkit round $PROJECT round-$ROUND"
docker exec -e AUDITKIT_PROJECTS_DIR=/audit-out/projects auditkit \
    sh -c "cd /workspace && python3 auditkit round $PROJECT --path /targets/$PROJECT --round $ROUND" \
    || { echo "[run_audit] round 失败"; exit 1; }

echo "── 2/3 生成 markdown 报告"
docker exec auditkit sh -c \
    "cd /workspace && python3 core/report.py /audit-out/projects/$PROJECT/$ROUND_DIR_NUM $PROJECT" \
    || { echo "[run_audit] 报告生成失败"; exit 1; }

echo "── 3/3 投递到开发者路径"
bash "$HERE/deliver_report.sh" "$PROJECT" "$ROUND"

echo ""
echo "── 完成。报告已投递到 /vol1/1000/docker/$PROJECT/doc/审计报告/"
