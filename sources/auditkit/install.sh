#!/usr/bin/env bash
# auditkit 依赖安装脚本
# 用法: bash install.sh
#
# 注意：沙盒/容器环境会重置，每次新会话需重跑。
#       pycg 必须装 onecode-pycg（pip install pycg 装出的是空壳）。

set -uo pipefail

echo "==> [1/3] pip 安装"
python3 -m pip install --quiet --disable-pip-version-check \
  pytest pytest-asyncio \
  ruff bandit vulture pyflakes pylint mypy \
  onecode-pycg \
  paho-mqtt "starlette==0.37.2" aiohttp httpx \
  edge-tts apscheduler coverage \
  python-multipart pillow 2>&1 \
  | grep -vE "WARNING: Running pip|already satisfied" || true

echo "==> [2/3] 校验命令行工具"
for t in ruff bandit vulture pylint mypy pycg; do
  if command -v "$t" >/dev/null 2>&1; then echo "    OK   $t"; else echo "    MISS $t（该阶段结果不可信）"; fi
done

echo "==> [3/3] 校验 Python 模块"
python3 - <<'PY'
import importlib
mods = ["pytest", "paho.mqtt.client", "starlette", "aiohttp", "httpx",
        "coverage", "pycg", "edge_tts", "apscheduler"]
for m in mods:
    try:
        importlib.import_module(m); print(f"    OK   {m}")
    except Exception as e:
        print(f"    MISS {m}: {type(e).__name__}")
PY

echo "==> 完成。若某项 MISS，对应阶段会自动标记 ⚠️ 工具不可用（不会误报为'无问题'）"
