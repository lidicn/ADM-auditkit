#!/usr/bin/env bash
# AutoForge 安全审计工作流 — 单轮编排
# 用法: af_audit.sh [round_name] [--force]
#   --force: 即使无仓库变更也执行全量阶段
set -uo pipefail
ulimit -f unlimited 2>/dev/null

export PATH=/opt/audit/pylibs/bin:/usr/local/bin:$PATH
export PYTHONPATH=/opt/audit/pylibs
PY=python3

AUDIT_ROOT=${AUDIT_ROOT:-/data/workspace/audit}
SRC=${AUDIT_ROOT}/src
PKG="$SRC/src/autoforge"; [[ -d "$PKG" ]] || PKG="$SRC/autoforge"
TESTS="$SRC/tests"; [[ -d "$TESTS" ]] || TESTS="$SRC"
WF=${AUDIT_ROOT}/workflow
ROUND=${1:-$(ls -1 "$AUDIT_ROOT/rounds" 2>/dev/null | grep -c '^round-' | awk '{printf "round-%03d", $1+1}')}
FORCE=${2:-}
RDIR="$AUDIT_ROOT/rounds/$ROUND"
PY=python3

mkdir -p "$RDIR"/{sast,secrets,deps,graph,skill,state} "$AUDIT_ROOT"/{baseline,state}
LOG="$RDIR/run.log"
: >"$LOG"

say(){ echo "[$(TZ=CST-8 date +%H:%M:%S)] $*" | tee -a "$LOG"; }

# P0：自检门禁 —— 开工前先验证 20 个分析器**没有静默失效**。
# 过去十九轮里，多次出现「规则坏了但看上去像『代码很干净』」（PITFALLS N1）。
# 例：rmw_consistency 在 dirty 样本上 0 命中，根因是 _chain 对 BinOp receiver 返回空。
# 没有这道门禁，这种失效会以「本轮 0 缺陷」的形式被误报成好消息。
if [[ -f "$AUDIT_ROOT/selftest/run_selftest.py" && "${SKIP_SELFTEST:-}" != "1" ]]; then
  say "P0 selftest"
  if $PY "$AUDIT_ROOT/selftest/run_selftest.py" >"$AUDIT_ROOT/selftest/last.json" 2>&1; then
    say "P0 selftest ok（20 分析器均有召回，clean 无回归）"
  else
    say "P0 selftest FAIL —— 有分析器静默失效，本轮结论不可信"
    $PY -c "import json;d=json.load(open('$AUDIT_ROOT/selftest/last.json'));[print(' ',f) for f in d.get('failures',[])]" 2>/dev/null
    exit 3
  fi
fi

say "=== ROUND $ROUND start (PID $$) ==="

# ---------- Phase 0: 快照 / 增量 ----------
say "P0 snapshot"
if $PY "$WF/lib/fetch_snapshot.py" "$AUDIT_ROOT" >>"$LOG" 2>&1; then
  CHANGED=$(cat "$AUDIT_ROOT/state/changed" 2>/dev/null || echo unknown)
  say "P0 changed=$CHANGED"
  if [[ "$CHANGED" == "false" && "$FORCE" != "--force" ]]; then
    say "P0 无仓库变更且非 --force → 仅执行轻量阶段（skill+graph）；重型阶段复用基线"
    LITE=1
  else
    LITE=0
  fi
else
  say "P0 快照失败（离线？）→ 使用现有 src，按 --force 处理"
  LITE=0
fi

# ---------- Phase 1: SBOM / 依赖 / 供应链 ----------
if [[ "$LITE" == "0" ]]; then
  say "P1 supply-chain"; $PY "$WF/lib/dep_audit.py" "$SRC" "$RDIR/deps" >>"$LOG" 2>&1 || say "P1 FAIL"
else
  say "P1 skipped (lite)"
fi

# ---------- Phase 2: SAST ----------
if [[ "$LITE" == "0" ]]; then
  CONFIGS=("$WF/lib/rules/autoforge-agentic.yml")
  [[ -d /opt/audit/3rd/tob-rules/python ]] && CONFIGS+=(/opt/audit/3rd/tob-rules/python)
  [[ -d /opt/audit/3rd/0xdea-rules/rules ]] && CONFIGS+=(/opt/audit/3rd/0xdea-rules/rules)
  say "P2 semgrep (${#CONFIGS[@]} configs)"
  timeout 1500 semgrep scan --config "${CONFIGS[@]}" "$PKG" \
    --sarif --output "$RDIR/sast/semgrep.sarif" --metrics=off --quiet \
    --timeout 60 --max-memory 6000 --exclude 'test*' --exclude '*_test.py' >>"$LOG" 2>&1 \
    && say "P2 ok" || say "P2 semgrep 退出码非0（可能部分规则报错，见 log）"
  [[ -s "$RDIR/sast/semgrep.sarif" ]] || echo '{"runs":[]}' >"$RDIR/sast/semgrep.sarif"
  sarif-tools stats "$RDIR/sast/semgrep.sarif" 2>/dev/null | tee -a "$LOG" || true
else
  say "P2 skipped (lite)"
fi

# ---------- Phase 3: secrets ----------
if [[ "$LITE" == "0" ]]; then
  say "P3 detect-secrets"
  $PY -m detect_secrets scan --all-files --force-use-all-plugins "$SRC/src" >"$RDIR/secrets/detect-secrets.raw.json" 2>>"$LOG" || say "P3 FAIL"
  $PY - "$RDIR/secrets" <<'PYEOF' 2>>"$LOG" || true
import json,sys
from pathlib import Path
d=Path(sys.argv[1])
raw=d/"detect-secrets.raw.json"
f=[]
if raw.exists():
    j=json.loads(raw.read_text())
    for path,items in j.get("results",{}).items():
        for it in items:
            f.append({"type":it.get("type"),"severity":"high" if it.get("type") in
                      ("PrivateKeyDetector","AWSKeyDetector","GitHubTokenDetector") else "medium",
                      "file":path,"line":it.get("line_number",0),"message":f"疑似密钥: {it.get('type')}"})
(d/"detect-secrets.json").write_text(json.dumps({"findings":f},ensure_ascii=False,indent=2))
print(len(f))
PYEOF
else
  say "P3 skipped (lite)"
fi

# ---------- Phase 4: 图谱 ----------
say "P4 graph"
$PY "$WF/lib/graph/build_graph.py" "$PKG" "$RDIR/graph" >>"$LOG" 2>&1 && say "P4 ok" || say "P4 FAIL"
$PY "$WF/lib/graph/paths_to_findings.py" "$RDIR/graph" >>"$LOG" 2>&1 || say "P4 paths FAIL"

# ---------- Phase 5: agentic / skill 面 ----------
say "P5 skill-scan"
$PY "$WF/lib/skill_scan.py" "$SRC" "$RDIR/skill" >>"$LOG" 2>&1 || say "P5 FAIL"

# ---------- Phase 5.5: 专题分析器（纯 stdlib，不依赖 semgrep）----------
# 轮次专题：state_defects（状态一致性/崩溃恢复）、concurrency_defects（并发/异步正确性）
# 两者都不依赖外部工具，沙箱内 semgrep 损坏时仍可跑，因此不受 LITE 限制。
say "P5.5 topic analyzers"
if [[ -f "$WF/lib/state_defects.py" ]]; then
  $PY "$WF/lib/state_defects.py" "$PKG" "$RDIR/state" >>"$LOG" 2>&1 \
    && say "P5.5 state ok" || say "P5.5 state FAIL"
fi
if [[ -f "$WF/lib/concurrency_defects.py" ]]; then
  $PY "$WF/lib/concurrency_defects.py" "$PKG" "$RDIR/concurrency" >>"$LOG" 2>&1 \
    && say "P5.5 concurrency ok" || say "P5.5 concurrency FAIL"
fi
if [[ -f "$WF/lib/boundary_defects.py" ]]; then
  $PY "$WF/lib/boundary_defects.py" "$PKG" "$RDIR/boundary" >>"$LOG" 2>&1 \
    && say "P5.5 boundary ok" || say "P5.5 boundary FAIL"
fi
if [[ -f "$WF/lib/controlflow_defects.py" ]]; then
  $PY "$WF/lib/controlflow_defects.py" "$PKG" "$RDIR/controlflow" >>"$LOG" 2>&1 \
    && say "P5.5 controlflow ok" || say "P5.5 controlflow FAIL"
fi
if [[ -f "$WF/lib/deadcode_defects.py" ]]; then
  $PY "$WF/lib/deadcode_defects.py" "$PKG" "$RDIR/deadcode" >>"$LOG" 2>&1 \
    && say "P5.5 deadcode ok" || say "P5.5 deadcode FAIL"
fi
if [[ -f "$WF/lib/time_numeric_defects.py" ]]; then
  $PY "$WF/lib/time_numeric_defects.py" "$PKG" "$RDIR/time_numeric" >>"$LOG" 2>&1 \
    && say "P5.5 time_numeric ok" || say "P5.5 time_numeric FAIL"
fi
if [[ -f "$WF/lib/input_defects.py" ]]; then
  $PY "$WF/lib/input_defects.py" "$PKG" "$RDIR/input" >>"$LOG" 2>&1 \
    && say "P5.5 input ok" || say "P5.5 input FAIL"
fi
if [[ -f "$WF/lib/consistency_defects.py" ]]; then
  $PY "$WF/lib/consistency_defects.py" "$PKG" "$RDIR/consistency" >>"$LOG" 2>&1 \
    && say "P5.5 consistency ok" || say "P5.5 consistency FAIL"
fi
if [[ -f "$WF/lib/serialization_defects.py" ]]; then
  $PY "$WF/lib/serialization_defects.py" "$PKG" "$RDIR/serialization" >>"$LOG" 2>&1 \
    && say "P5.5 serialization ok" || say "P5.5 serialization FAIL"
fi
if [[ -f "$WF/lib/errorhandling_defects.py" ]]; then
  $PY "$WF/lib/errorhandling_defects.py" "$PKG" "$RDIR/errorhandling" >>"$LOG" 2>&1 \
    && say "P5.5 errorhandling ok" || say "P5.5 errorhandling FAIL"
fi
if [[ -f "$WF/lib/observability_defects.py" ]]; then
  $PY "$WF/lib/observability_defects.py" "$PKG" "$RDIR/observability" >>"$LOG" 2>&1 \
    && say "P5.5 observability ok" || say "P5.5 observability FAIL"
fi
if [[ -f "$WF/lib/config_compat_defects.py" ]]; then
  $PY "$WF/lib/config_compat_defects.py" "$PKG" "$RDIR/config" >>"$LOG" 2>&1 \
    && say "P5.5 config ok" || say "P5.5 config FAIL"
fi
if [[ -f "$WF/lib/testgap_defects.py" ]]; then
  $PY "$WF/lib/testgap_defects.py" "$PKG" "$RDIR/testgap" "$TESTS" >>"$LOG" 2>&1 \
    && say "P5.5 testgap ok" || say "P5.5 testgap FAIL"
fi
if [[ -f "$WF/lib/api_contract_defects.py" ]]; then
  $PY "$WF/lib/api_contract_defects.py" "$PKG" "$RDIR/apicontract" >>"$LOG" 2>&1 \
    && say "P5.5 apicontract ok" || say "P5.5 apicontract FAIL"
fi
if [[ -f "$WF/lib/resource_defects.py" ]]; then
  $PY "$WF/lib/resource_defects.py" "$PKG" "$RDIR/resource" >>"$LOG" 2>&1 \
    && say "P5.5 resource ok" || say "P5.5 resource FAIL"
fi
if [[ -f "$WF/lib/semantic_defects.py" ]]; then
  $PY "$WF/lib/semantic_defects.py" "$PKG" "$RDIR/semantic" >>"$LOG" 2>&1 \
    && say "P5.5 semantic ok" || say "P5.5 semantic FAIL"
fi
if [[ -f "$WF/lib/rmw_consistency.py" ]]; then
  $PY "$WF/lib/rmw_consistency.py" "$PKG" "$RDIR/rmw" >>"$LOG" 2>&1 \
    && say "P5.5 rmw ok" || say "P5.5 rmw FAIL"
fi
if [[ -f "$WF/lib/auth_defects.py" ]]; then
  $PY "$WF/lib/auth_defects.py" "$PKG" "$RDIR/auth" >>"$LOG" 2>&1 \
    && say "P5.5 auth ok" || say "P5.5 auth FAIL"
fi
if [[ -f "$WF/lib/pattern_propagation.py" ]]; then
  $PY "$WF/lib/pattern_propagation.py" "$PKG" "$RDIR/patterns" >>"$LOG" 2>&1 \
    && say "P5.5 patterns ok" || say "P5.5 patterns FAIL"
fi

# ---------- Phase 6: 历史缺陷回归复核 ----------
say "P6 backlog"
$PY "$WF/lib/backlog.py" "$AUDIT_ROOT" "$RDIR" >>"$LOG" 2>&1 \
  && say "P6 backlog ok" || say "P6 backlog FAIL"

# ---------- Phase 7: 聚合 ----------
say "P6 aggregate"
$PY "$WF/lib/aggregate.py" "$RDIR" "$AUDIT_ROOT/baseline/findings.json" 2>>"$LOG" | tee -a "$LOG"

say "=== ROUND $ROUND done → $RDIR/report.md ==="
