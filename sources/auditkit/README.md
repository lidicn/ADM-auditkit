# auditkit · doubao-butler 审计工作流

版本 **v2.4** · 26 个阶段 · 自研 Python AST + 调用图 + 桩件驱动执行 + 项目自带测试 + 已知缺陷回归集

```bash
# 全量（沙盒建议分批跑，见第六节）
python3 auditkit/audit.py all \
  --repo /data/workspace/audit/doubao-butler-main \
  --out  /data/workspace/audit/out

# 单阶段 / 多阶段
python3 auditkit/audit.py atomicity,concurrency,timeunit --repo ... --out ...

# 回归检查（改判据后必跑，命中率不得下降）
python3 auditkit/regression/check_regression.py
```

---

## 一、阶段清单（26）

| # | 阶段 | 方法 | 检出什么 |
|---|---|---|---|
| 1 | `bootstrap` | 规范化副本 | 剥 BOM、隔离产物 |
| 2 | `static` | ruff/bandit/vulture/pyflakes/pylint/mypy | 通用静态告警 |
| 3 | `graph` | PyCG 调用图 | 节点/边、不可达 |
| 4 | `tests` | **跑项目自带 pytest** + 环境/真实失败分类 | 真实失败（最高信噪比） |
| 5 | `secrets` | 正则 + `_env` 覆盖分析 | 硬编码内网地址/凭据 |
| 6 | `httpcontract` | AST 出站响应绑定 | 未检查状态码 **+ 响应完全丢弃** |
| 7 | `mqtt` | 主题常量求解（含 f-string） | 发布/订阅不配对 |
| 8 | `dupimpl` | AST 结构指纹 Jaccard | 跨文件重复实现 |
| 9 | `multisource` | 字面量序列 + dict-list | **多真源漂移**（最高频根因） |
| 10 | **`successclaim`** | try/except 后继控制流 | **谎报成功**（最高频失效形态） |
| 11 | **`deploycontract`** | 必需环境变量 vs 部署清单 | **全新部署必崩** |
| 12 | `atomicity` | AST 写调用 + 锁区间 | 非原子写 / 固定 tmp / 锁外写 / 无 fsync |
| 13 | `concurrency` | AST 并发模式 | create_task 丢弃 / 双检无锁 / async 阻塞 IO / 跨线程连接 |
| 14 | `timeunit` | AST 时间 API | naive-aware 混用 / 秒毫秒混用 / **wall-monotonic 混用** |
| 15 | `identity` | token 收割 + 逻辑行过滤 | 判定逻辑硬编码身份 |
| 16 | `lifecycle` | 双通道资源扫描 | 模块级/实例属性资源无释放 |
| 17 | `errpath` | 作用域可见性分析 | except 分支引用未定义名 |
| 18 | `kwcontract` | kwarg vs 函数签名 | 传了不存在的 kwarg |
| 19 | `falsyzero` | `X or <常量>` + 字段词表 | 0 被 falsy 吞掉 |
| 20 | `runtime` | drive.py 桩件驱动 + coverage | 真实执行覆盖 |
| 21 | `dupfiles` | 四道过滤 | 分叉孤儿模块 |
| 22 | `orphans` | 图谱 + AST 双通道 | 零调用者（advisory） |
| 23 | `deadcall` | 成员定义比对 + 白名单 | 调用未定义成员 |
| 24 | `cycles` | 模块级 SCC | 循环依赖 |
| 25 | `contract` | AST 签名比对 | 前后端/调用不匹配 |
| 26 | `verify` | findings.json | 对照实验复现 |

---

## 二、v2.4 实测数据（最终轮）

| 阶段 | 结果 |
|---|---|
| atomicity | **35 处（high 33）** |
| concurrency | **45 处** — C1 create_task 丢弃 17 / C2 双检无锁 11 / C4 async 阻塞 5 / C5 跨线程 12 |
| dupimpl | **24 对** |
| multisource | **18 对（high 10 已漂移）** |
| httpcontract | **28 处** — 响应完全丢弃 12 / 未检查状态码 16 |
| kwcontract | **4 处（全真）** |
| falsyzero | 15 处（high 5） |
| timeunit | 10 处 — T1 4 / T2 4 / **T3 2** |
| identity | 12 处（high 4） |
| lifecycle | 11 处 high（模块级 10 / 实例属性 1） |
| secrets | 36 处硬编码（8 不可覆盖） |
| errpath | 2 处 |
| dupfiles | **6 个孤儿模块** |
| deadcall | 249 处（**4 处被 hasattr 保护 → 静默失效**） |
| successclaim | 3 处（high 1） |
| deploycontract | 2 处必需变量未在清单声明 |
| graph | 709 节点 / 1661 边（6.8s） |
| tests | **586 通过 / 7 真实失败** |
| **回归集** | **29 / 29（100%）** |

---

## 三、覆盖矩阵（18 类缺陷）

| 类 | 状态 | 由谁覆盖 |
|---|---|---|
| A 空引用/未定义名 | ✅ | errpath, deadcall |
| B 参数/契约不匹配 | ✅ | contract, mqtt, **kwcontract** |
| **C 逻辑错误** | ❌ **空白** | **无（原理上不可静态检测）** |
| D 并发/竞态 | ✅ | concurrency |
| E 异常处理缺陷 | ✅ | errpath |
| F 资源生命周期 | 🔶 | lifecycle（只认 SQLite/HTTP/文件） |
| G 死代码/孤儿 | ✅ | dupfiles, orphans, dupimpl |
| H 契约/主题 | ✅ | mqtt, contract |
| I 硬编码/配置 | ✅ | secrets, identity, **deploycontract** |
| J 依赖缺失/环境 | 🔶 | tests（已做环境/真实分类） |
| K 超时/阻塞 | ✅ | httpcontract, concurrency(C4) |
| L 安全 | 🔶 | secrets |
| M 数据完整性 | ✅ | atomicity |
| N 数值/单位/时区 | ✅ | timeunit, **falsyzero** |
| O 状态机 | 🔶 | 无专项 |
| P 部署/环境 | ✅ **v2.4 新增** | **deploycontract** |
| Q 性能 | 🔶 | 无专项 |
| R 多真源漂移 | ✅ **v2.4 强化** | multisource（含 dict-list）, dupimpl |

**空白 4 → 1（仅剩 C 逻辑错误）**

---

## 四、已知缺陷回归集（防退化）

`regression/fixtures.json` 收录 29 条历史已确认缺陷，每条标注应由哪个阶段捕获。

```bash
python3 auditkit/regression/check_regression.py
```

**改任何阶段判据后必须跑，命中率不得下降。** 这是防止"改了工具却不知道改坏"的唯一手段。

### 三次因回归集而发现的自身 bug

1. **累积式 summary** —— 原实现每次运行覆盖 `audit_summary.json`，分批跑（沙盒唯一可行方式）会互相抹掉，回归首测仅 **7%** 命中。改为每阶段单写 `stage_results/<stage>.json` 再合并 → 83%
2. **匹配器结构归一化** —— 各阶段返回字段名不统一（`items` / `lan_high` / 文件级无行号），只认 `items` 导致 `lifecycle`、`secrets` 明明命中却报未命中 → 93%
3. **fixture 行号修正** —— `lifecycle` 对 `PresenceStore` 只报文件级，原 fixture 写 `line:26` 永不匹配 → **100%**

---

## 五、工具选型决策记录

### semgrep —— **放弃**（沙盒限制，非选型问题）

- **阻塞原因**：沙盒存在 **200MB 单文件硬上限**（实测 `dd` 写 250MB 被截断为 209715200 字节）
- semgrep 核心是 OCaml 编译的 `semgrep-core` 二进制，**必然超 200MB**，任何安装方式都会被截断
- 实测：pip wheel 70.8MB 可下载，但解压出的 `semgrep-core` 恰为 209715200 字节 → 无法执行

### 替代方案：继续自研 AST

本项目高价值缺陷**高度项目特定**（`hasattr` 保护、`s.member_by_name` 未用、`sdd/notify` 死主题、角色白名单三份副本）—— semgrep 通用规则库一条都覆盖不到。

### 外部静态工具在沙盒不可用

`ruff`/`bandit`/`vulture`/`pylint`/`mypy` 会**间歇性消失**（`/usr/local/bin/ruff` 存在但 `subprocess` 报 `FileNotFoundError`）。

**已加保护**：工具不可用时标记 `TOOL_UNAVAILABLE` 并在输出打 ⚠️，**绝不显示为"0 行"**——避免把"查不了"误读成"查过了没问题"。

---

## 六、环境注意事项

- **沙盒会重置**，依赖清单：
  ```
  pytest pytest-asyncio paho-mqtt starlette==0.37.2 aiohttp httpx
  edge-tts apscheduler coverage onecode-pycg python-multipart pillow
  ruff bandit vulture pylint mypy pyflakes
  ```
- **`pycg` 必须装 `onecode-pycg`**（`pip install pycg` 装出的是空壳）
- **Python 3.10 vs 项目要求 3.11** —— `homesdk` 需 `PYTHONPATH=vendor/homesdk/src`
- bash 默认 60s 超时，**命令内 `timeout` 无效**，须传工具参数（毫秒）
- **建议分批跑**（一次全量易超时），累积式 summary 保证结果不丢：
  ```bash
  for st in bootstrap atomicity concurrency deploycontract dupfiles errpath falsyzero; do
      python3 auditkit/audit.py $st --repo <repo> --out <out>
  done
  ```
- 修改前先备份：`cp audit.py audit.py.bak`

---

## 七、已知局限（诚实）

1. **C 类（逻辑错误）完全空白** —— "代码能跑、类型对、无异常但做的事是错的"（如 HA 空 payload = 全屋）必须依赖领域语义，静态分析原理上做不到。本项目 7 个 P0 中有多个属此类，靠人工深挖得来
2. **`runtime` 覆盖约 22%** —— `orphans` 的 731 条仍是 advisory-only
3. **`dupimpl` 抓不到"同概念不同风格"** —— P1-38 那对连续三轮未命中
4. **`deadcall` 不解析接收者类型** —— 249 处中多数是标准库成员误报
5. **`errpath` 的 6 轮调参可能过拟合** —— 未做跨项目泛化测试
6. **外部静态工具不可用** —— 其结论不可信，已标记

---

## 八、版本历史（关键迭代）

| 版本 | 新增/修复 |
|---|---|
| v1.9 | `atomicity` / `concurrency` / `timeunit`（填补三个空白类别） |
| v2.0 | `multisource`（多真源漂移，最高频根因） |
| v2.1 | `kwcontract`（kwarg vs 签名，一次扫描复现 P0-10 与 P1-44） |
| v2.2 | `falsyzero` + `timeunit` T3（时钟混用，含下标传播与别名解析） |
| v2.3 | `multisource` 支持 dict-list（复现第十五轮 P1-43） |
| **v2.4** | **`successclaim`（谎报成功）+ `deploycontract`（部署契约）+ 回归集 + 累积式 summary + 工具不可用标记 + 测试环境/真实分类** |
