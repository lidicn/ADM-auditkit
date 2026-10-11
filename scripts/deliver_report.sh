#!/bin/bash
# deliver_report.sh —— 把 auditkit round 产出的 report.md 投递到目标项目 doc/审计报告/
#
# 在 NAS 宿主机跑（不在容器内，因为 /targets 是只读挂载）。
# 从 docker volume 宿主路径读 report.md，拷到目标项目的 doc/审计报告/<项目>_第N轮机器审计.md
#
# 用法:
#   deliver_report.sh <project> <round_num>
#   例: deliver_report.sh doubao-butler 1
#
# 目录约定（遵循开发规范 §1：NAS 是运行环境，产物落可读区）：
#   源: /vol1/docker/volumes/adm-auditkit_audit-out/_data/projects/<project>/round-<NNN>/report.md
#   目标: /vol1/1000/docker/<project>/doc/审计报告/<project>_第<NNN>轮机器审计.md
set -euo pipefail

PROJECT="${1:?用法: deliver_report.sh <project> <round_num>}"
ROUND="${2:?需要 round 编号}"
ROUND_DIR_NUM=$(printf "round-%03d" "$ROUND")

VOL_BASE="/vol1/docker/volumes/adm-auditkit_audit-out/_data"
SRC_DIR="$VOL_BASE/projects/$PROJECT/$ROUND_DIR_NUM"
SRC="$SRC_DIR/report.md"

TARGET_DIR="/vol1/1000/docker/$PROJECT/doc/审计报告"
TARGET="$TARGET_DIR/${PROJECT}_第${ROUND}轮机器审计.md"

if [ ! -f "$SRC" ]; then
    echo "[deliver] 报告不存在: $SRC"
    echo "  先在容器里跑: docker exec -e AUDITKIT_PROJECTS_DIR=/audit-out/projects auditkit \\"
    echo "    sh -c 'cd /workspace && python3 auditkit round $PROJECT --path /targets/$PROJECT --round $ROUND'"
    exit 1
fi

mkdir -p "$TARGET_DIR"
cp "$SRC" "$TARGET"
echo "[deliver] $SRC"
echo "       → $TARGET"
echo "  $(wc -l < "$TARGET") 行"
