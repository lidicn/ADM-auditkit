#!/usr/bin/env bash
# auditkit 一键运行脚本
#
# 用法:
#   ./run_all.sh <repo_path> <out_dir>
#
# 说明:
#   沙盒/受限环境下一次跑完全部 26 个阶段容易超时。
#   本脚本按批次调用 audit.py，利用「累积式 summary」保证结果不丢失。
#   跑完后自动执行回归检查。

set -u
REPO="${1:-/data/workspace/audit/doubao-butler-main}"
OUT="${2:-/data/workspace/audit/out}"
AUDIT="$(cd "$(dirname "$0")" && pwd)/audit.py"

mkdir -p "$OUT"

# 批次划分：快的先跑，重的（graph/runtime/tests）放后面
BATCH1="bootstrap atomicity concurrency deploycontract dupfiles errpath falsyzero"
BATCH2="httpcontract identity kwcontract lifecycle multisource secrets successclaim"
BATCH3="timeunit dupimpl contract mqtt cycles deadcall graph"
BATCH4="runtime orphans"
BATCH5="tests"

run_batch () {
    local label="$1"; shift
    echo "==================== $label ===================="
    for st in "$@"; do
        printf '  [%s] ' "$st"
        timeout 280 python3 "$AUDIT" "$st" --repo "$REPO" --out "$OUT" 2>&1 \
            | grep -E "^    " | head -1
    done
}

run_batch "批次 1/5" $BATCH1
run_batch "批次 2/5" $BATCH2
run_batch "批次 3/5" $BATCH3
run_batch "批次 4/5" $BATCH4
run_batch "批次 5/5" $BATCH5

echo ""
echo "==================== 回归检查 ===================="
python3 "$(cd "$(dirname "$0")" && pwd)/regression/check_regression.py"

echo ""
echo "汇总: $OUT/audit_summary.json"
