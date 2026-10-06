#!/usr/bin/env bash
# 一键装齐 bug-hunter 工作流所需的全部依赖。
#
# 为什么需要这个：沙箱会在会话间重置，依赖全部丢失。
# 过去十三轮里因此中断过至少 6 次，每次都表现为
# "ModuleNotFoundError: No module named pytest" —— 而按纪律①
# （工具故障 ≠ 无问题），这若被误读成"缺陷消失"就是灾难。
#
# 用法：bash skills/bug-hunter/scripts/bootstrap.sh
set -u
PY=$(command -v python3 || command -v python)
echo "==> python: $PY  $($PY -V 2>&1)"

# 分两组：核心（缺了整条流水线跑不动）/ 可选（缺了对应阶段降级）
# 核心：缺了整条流水线跑不动
CORE="pytest pytest-asyncio hypothesis"
# 可选：缺了对应阶段降级（--stages 会打印降级提示）
OPT="radon vulture ruff aiohttp starlette paho-mqtt mutmut pylint mypy bandit"
# 测试增强（第十三轮补）：
#   pytest-xdist        并行，大套件提速
#   pytest-timeout      防用例挂死（V23 曾让反测自己陪葬）
#   pytest-rerunfailures 抖动重试
#   pytest-randomly     随机顺序，暴露用例间污染（V4 那种）
#   deal / icontract    契约式：前置/后置/不变量声明
#   faker               真实感随机数据
EXTRA="pytest-xdist pytest-timeout pytest-rerunfailures pytest-randomly deal icontract faker"

echo "==> 安装核心依赖"
$PY -m pip install -q $CORE 2>&1 | tail -2

echo "==> 安装可选依赖"
$PY -m pip install -q $OPT 2>&1 | tail -2

echo "==> 安装测试增强依赖"
$PY -m pip install -q $EXTRA 2>&1 | tail -2

echo "==> 验证"
$PY - <<'PYEOF'
import importlib
need = ["pytest", "hypothesis", "radon", "vulture", "ruff", "mutmut",
        "deal", "icontract", "xdist", "pytest_timeout", "faker"]
have, miss = [], []
for m in need:
    try:
        importlib.import_module(m); have.append(m)
    except Exception:
        miss.append(m)
print("  已就绪:", " ".join(have))
if miss:
    print("  缺失  :", " ".join(miss), "（对应阶段会降级，看 --stages 输出）")
PYEOF
echo "==> done"
