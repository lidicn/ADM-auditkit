#!/usr/bin/env bash
# 在本机（能直连 GitHub 的机器）执行，把审计工具箱推送到目标仓库。
#
# 用法：
#   ./scripts/push.sh <git@github.com:OWNER/REPO.git> [分支名]
#
# 例：
#   ./scripts/push.sh git@github.com:lidicn/ADM-auditkit.git main
#
# 说明：本脚本只做 git 操作，不碰任何凭据。
# 认证依赖你本机已配好的 SSH key（你给的那把 nas-haier 就是在你本机生效的）。
set -euo pipefail

REMOTE=${1:?需要Git远程地址, git@github.com:OWNER/REPO.git}
BRANCH=${2:-main}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

# 0) 先自检：确认没有把密钥/大文件混进来
echo "── 推送前检查"
if command -v git-secrets >/dev/null 2>&1; then
  git-secrets --scan || { echo "发现疑似密钥，已中止"; exit 1; }
fi

# 1) 初始化（若已是 git 仓库则跳过）
if [[ ! -d .git ]]; then
  git init -q
  git checkout -q -b "$BRANCH"
else
  git checkout -q "$BRANCH" 2>/dev/null || git checkout -q -b "$BRANCH"
fi

# 2) 忽略运行产物
cat > .gitignore <<'EOF'
__pycache__/
*.pyc
projects/*/round-*/findings/
*.zip
selftest/last.json
EOF

# 3) 提交
git add -A
if git diff --cached --quiet; then
  echo "── 无变更可提交"
else
  git -c user.name=auditkit -c user.email=auditkit@localhost \
      commit -q -m "auditkit: 多项目审计工作流（21 分析器 + CLI + 自检门禁）"
fi

# 4) 推送
echo "── 推送 → $REMOTE ($BRANCH)"
git remote remove origin 2>/dev/null || true
git remote add origin "$REMOTE"
git push -u origin "$BRANCH"

echo "── 完成"
