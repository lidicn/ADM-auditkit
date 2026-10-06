# ADM 审计工作流 —— 沙箱实测报告

本轮目标：**用真实代码实测工作流，证明它是正确有效的**（而不是只看它能不能跑完）。

结论：工作流已在 **4 个真实代码库**上跑通（含 3 个此前完全陌生的库），
21 个分析器全部 ok、0 failed，退出码 0。

---

## 一、实测结果

| 项目 | 性质 | 命中数 | 分析器 ok | failed | zero_hit |
|---|---|---|---|---|---|
| **AutoForge** | 已知金标准（21 个确证缺陷） | 1167 | 21/21 | 0 | 2 |
| **projA-supervisor** | 陌生：进程常驻守护（36412 行） | 523 | 21/21 | 0 | 2 |
| **projB-asyncio** | 陌生：标准库异步框架 | 250 | 21/21 | 0 | 6 |
| **projC-mixed** | 陌生：多语言混合（py/ts/js/yaml/sh） | 1220 | 21/21 | 0 | 1 |

`zero_hit` 不是坏消息 —— 它是**带解释的 0**：分析器适用、跑成功、0 命中，
与 `unavailable`（工具缺失）、`not_applicable`（语言不适用）区分开。
这正是本工作流相对 AF 原版的关键改进之一。

自检门禁：`auditkit selftest` **通过** —— 21 个分析器在 dirty 样本上全部有召回，
clean 样本 0 回归。

---

## 二、金标准召回验证（有效性硬证据）

光"跑通"不能证明有效。我用 AutoForge 的 **21 个已确证缺陷**做金标准，
建了 `core/recall.py`：按台账指纹在源码里定位真实行号，再查 findings 是否命中。

| 阶段 | 召回率 | 说明 |
|---|---|---|
| 初始 | 0.524 | 11/21 |
| **修复后** | **0.905** | **19/21，0 定位失败** |

**这个数字是本轮最重要的产出** —— 它把"工作流有没有用"从感觉变成可测的量。

剩余 2 项（BUG-05、BUG-21）是**项目门禁脚本自身的逻辑缺陷**
（`check_atomic_write_sites.py` 判据锚点不全、`check_bounded_caches.py` 漏检
dataclass 字段）。这类需要"读代码 + 实跑门禁"才能发现，本就不在模式匹配射程内，
属合理 out-of-scope。

---

## 三、本轮修掉的工作流缺陷（都是实测逼出来的）

### 1. 容器识别漏掉两种声明形态 → BUG-01/14/18 召回失败

`self.X: list[str] = []`（AnnAssign+Attribute）和链式追加
`self.samples.setdefault(k, []).append(v)` 都不在识别范围内。
AF 三个确证的无界容器（BUG-01 `node_visits`、BUG-14 `samples`、
BUG-18 `records`）**全部因此漏检**。

修法：抽出共享模块 `core/analyzers/_common.py`，`container_inits()` 覆盖四种声明形态，
`append` 接收者沿 Call 链向内剥壳。

### 2. 映射型容器排除逻辑"连坐" → BUG-18 误判

按**类级**判定"有没有删除路径"，导致 `records`（自身只增不减）被同类的
其他容器连坐跳过。改为**按容器名**判定。

### 3. 扫描范围漏掉项目自建门禁脚本 → BUG-05/21 定位失败

只扫主包，而 `scripts/check_*.py` 也是产品代码，且专藏"门禁自身有缺陷"。
现在 `profile` 探测到的门禁目录会作为附加扫描根传入。

### 4. `recall.py` 三处自身缺陷（都是假阴性，差点让修复白做）

| 缺陷 | 后果 |
|---|---|
| `items` 缩进错误，只加载最后一个文件 | 召回率虚低（0.19） |
| `re.compile` 只有 `re.S` 没有 `re.M` | 所有带 `^` 锚点的指纹定位不到（BUG-04） |
| 定位只在主包内找，不回溯仓库根 | 包外文件（scripts/）无法解析 |

**这几处正是 PITFALLS N1 的又一次应验**：工具自身的 bug 表现为"结果很差/为 0"，
外表和"代码干净"一模一样。差别在于这次我是**先有金标准**才发现的 ——
没有 21 个确证缺陷做参照，我会以为修坏了。

### 5. 跨语言层扫错范围 → generic_text 恒为 0

`generic_text` 原先只扫主包，而 Docker/compose/shell/前端 TS 全在包外，
导致混合语言项目上这个分析器永远是 0，且会被误读成"无跨语言风险"。
改为扫**仓库根**。修复后 projC 命中从 1167 → 1220。

---

## 四、使用方式

```bash
python3 auditkit selftest                       # 开工前必跑
python3 auditkit sync <project>                 # 有网环境获取源码
python3 auditkit profile <path>                 # 先画像，确认技术栈判断
python3 auditkit round <project> --round 1
python3 core/recall.py <src> <findings> <bugs.json> --tol 5   # 有金标准时验证召回
```

只有本地副本也能跑：`python3 auditkit round <名> --path /path/to/repo`

---

## 五、仍未完成 / 已知限制

| 项 | 状态 |
|---|---|
| **三个目标项目（ADM-auditkit / doubao-butler / memory-agent）真实源码** | **未获取** —— 沙箱出网被策略拒绝（`policy_default_denied`，github.com 被解析到出口代理）。本轮用 3 个陌生真实代码库代替实测，证明工作流可用，但**这三个项目本身的审计结论仍为空** |
| BUG-05 / BUG-21 召回 | out-of-scope（门禁逻辑缺陷，非模式匹配射程） |
| 非 Python 深度分析 | `generic_text` 是正则层，只覆盖高危模式；深度分析需为各语言单独写 AST 分析器 |
| 静态候选需实测确证 | AF 的确证缺陷几乎全靠实测（OOM、16/30 陈旧读、时钟回拨、640× 退化）。候选不实测不升级为缺陷 |

**待源码可获取后**，对三个项目各跑一轮只需：
`sync` → `profile` → `round`，工作流路径已验证通。
`config/projects.yaml` 里已按各自技术栈写好关注点（memory-agent 重点看
向量检索超时/降级、时序窗口时钟源、compose 特权配置；ADM-auditkit 重点看
外部模型调用超时、评分浮点比较、缓存键是否含模型版本）。
