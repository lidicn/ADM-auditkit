# ADM-auditkit 审计工作流 Skill

> 这是一个**审计平台**，不是固定规则扫描器。
> 你的角色是**审计 agent**：发现盲区 → 写新规则 → 递交提案。
> 平台哲学：**探索负责发明模式，工作流负责复印模式，台账负责记住裁决。**

---

## 〇、连接方式（先连到 NAS）

审计容器跑在 NAS 上，先 SSH 连进去：

```bash
# SSH 配置（本机 ~/.ssh/config 里已配好）
Host nas
    HostName 192.168.2.200
    User lidicn
    IdentityFile ~/.ssh/id_ed25519
    Port 22

# 连接
ssh nas
```

连上后，所有审计命令通过 `docker exec` 执行。

---

## 一、平台架构

```
L0 基础设施：Python 运行时、git、文件系统
L1 多模式引擎：画像探测、AST 分派、汇总、报告生成
L2 项目适配：AutoForge / doubao-butler / memory-agent
L3 规则层：你写的新规则放这里
```

**你的工作在 L3**：不断写新规则，覆盖更多缺陷类型。

---

## 二、完整工作流（R0 探索 → R1 基线 → R2+ 回归）

```
R0 轻装探索轮（假设驱动、按模块切片、不看机器命中行号）
     ↓【沉淀出口·规定动作】可机械化的发现 → 当场起草规则 + 回归护栏
R1 基线轮（全景 round，校准新规则，建立噪音地图）
     ↓ triage：探索 ∪ 轮次 去重合并
R2+ 回归轮（delta/regression 模式，三项目并扫，分钟级守夜）
```

### 为什么要 R0 探索轮？

**工作流消费经验，不生产经验。** 规则库是过往发现的化石，只能机械放大"已经有人想过的缺陷类"。新缺陷类的唯一来源是手动探索。

---

## 三、命令速查

### 基础命令

| 命令 | 说明 |
|---|---|
| `auditkit profile <path>` | 探测项目画像 |
| `auditkit list` | 列出已配置项目 |
| `auditkit selftest` | 跑分析器自检门禁 |
| `auditkit rules list` | 列出已加载规则 |
| `auditkit rules test <rule_id>` | 单独跑某规则的 dirty/clean 自检 |

### 审计命令

| 命令 | 说明 |
|---|---|
| `auditkit round <project> --round N` | 对某项目执行一轮审计 |
| `auditkit round-all --round N` | **批量并行扫描多个项目**（扫描并行，triage 分批） |
| `auditkit status <project>` | 查看项目缺陷台账 |
| `auditkit pack <project>` | 打包项目审计产物 |

### 迭代命令（新增）

| 命令 | 说明 |
|---|---|
| `auditkit scout <project>` | **手猎轮**：初始化四件套（假设/方言/规则草案/四问） |
| `auditkit reconcile <project> --round N` | **对账**：手猎结论 vs 工具结论，输出差异表 |
| `auditkit diff <project> <a> <b>` | **命中集 diff**：对比两轮命中集（规则变更后验证 added/removed） |
| `auditkit triage accept/reject --rule R --file F --line L --reason "..."` | **裁决落盘**：按 (rule, file, line) 记录裁决 |
| `auditkit triage list <project>` | 列出裁决记录 |
| `auditkit triage apply <project> --round N` | 标记某轮中已裁决的命中，输出增量 |
| `auditkit triage bugs <project>` | 查看缺陷台账（bugs.json） |
| `auditkit propose create --type rule --name xxx` | 生成变更提案包 |

---

## 四、轮次模式（P1-3）

`auditkit round` 支持 `--mode` 参数：

| 模式 | 说明 | 适用场景 |
|---|---|---|
| `full` | 全量规则 + 全量文件 | 首扫、建立基线 |
| `delta` | 只审 git diff 涉及文件 | 活跃仓库增量守夜 |
| `targeted` | 只跑指定规则（`--rules`） | 验证单条规则效果 |
| `regression` | 仅确证 bug 对应规则（从 bugs.json 读取） | 验证修复效果 |

```bash
# 全量首扫
ssh nas "docker exec auditkit python3 /app/auditkit round AutoForge --round 1 --mode full"

# 增量守夜（只审变更文件）
ssh nas "docker exec auditkit python3 /app/auditkit round AutoForge --round 2 --mode delta"

# 回归验证（只跑确证 bug 对应规则）
ssh nas "docker exec auditkit python3 /app/auditkit round AutoForge --round 3 --mode regression"
```

---

## 五、批量并行扫描（round-all）

**扫描可以并行，triage 必须分批。**

```bash
# 并行跑三个项目（默认全部已配置项目）
ssh nas "docker exec auditkit python3 /app/auditkit round-all --round 1"

# 指定项目
ssh nas "docker exec auditkit python3 /app/auditkit round-all --round 1 --projects AutoForge,doubao-butler"

# 用 delta 模式并行守夜
ssh nas "docker exec auditkit python3 /app/auditkit round-all --round 2 --mode delta"
```

### 为什么 triage 要分批？

一次囤 3×500+ 条待裁决是反模式，注意力稀释后哪个项目都收敛不了。

**正确姿势**：
1. 批量扫描：一条命令三个 round，分钟级
2. 分批裁决：按 criticality 排队（AutoForge > memory-agent > doubao-butler）
3. 洞察回灌：fixed-tmp 一条规则在 AutoForge 命中 6 处，同一洞察直接复扫另两项目

---

## 六、手猎轮（scout）+ 对账（reconcile）

### R0 手猎轮

```bash
# 初始化四件套
ssh nas "docker exec auditkit python3 /app/auditkit scout AutoForge"
```

会在 `projects/AutoForge/scout/` 创建四个模板文件：

| 文件 | 内容 |
|---|---|
| `hypotheses.md` | 手猎假设清单（每条带「可证伪预测」） |
| `vocabulary.yaml` | 项目方言表（本项目用哪些 API / 惯用法 / 约定） |
| `rule_drafts.md` | 候选规则草案（从手猎假设反推） |
| `focus.md` | 项目「四问」：构造/残留/耗尽/并发 |

**手猎轮的核心原则**：
- 探索必须在"看机器 findings 之前"——防止自动化偏见
- 沉淀出口必须是规定动作——探索结束后强制回答"这批发现里哪些可机械化？"
- 按 criticality 排期，不做三项目齐步走

### 对账（reconcile）

```bash
# 手猎结论 vs 工具结论对账
ssh nas "docker exec auditkit python3 /app/auditkit reconcile AutoForge --round 1"
```

对账输出三分类：

| 分类 | 说明 | 行动 |
|---|---|---|
| **工具漏报** | 手动确证但工具 0 命中 | 最强信号——写新规则或修复失效规则 |
| **手动盲区** | 工具报了但手动没确证 | 次强信号——补充手猎假设 |
| **共同盲区** | 两者都没找到 | 需人工深入分析 |

---

## 七、Triage 裁决落盘（P1-1）

**人工裁决不落盘，下轮重报。** canary:103、flock:132 这类"语义不成立"的 FP，这次裁了，下个 agent 还得重裁。

### 记录裁决

```bash
# 不采纳（误报）
ssh nas "docker exec auditkit python3 /app/auditkit triage reject AutoForge \
  --rule py.except_return_failopen --file src/af_canary.py --line 103 \
  --reason 'return True 语义是有漂移需回滚，是 fail-closed 设计'"

# 已知未修（真 bug，进缺陷台账）
ssh nas "docker exec auditkit python3 /app/auditkit triage accept AutoForge \
  --rule py.unbounded_container --file src/af_history.py --line 42 \
  --reason '进程级单例，无界增长，确证'"
```

### 应用裁决到某轮

```bash
# 标记某轮中已裁决的命中，输出增量（未裁决的新命中）
ssh nas "docker exec auditkit python3 /app/auditkit triage apply AutoForge --round 2"
```

### 查看裁决和缺陷台账

```bash
# 列出裁决记录
ssh nas "docker exec auditkit python3 /app/auditkit triage list AutoForge"

# 查看缺陷台账（bugs.json）
ssh nas "docker exec auditkit python3 /app/auditkit triage bugs AutoForge"
```

---

## 八、规则意图标签（P1-4）

规则加 `intent` 字段，区分两种意图：

| intent | 说明 | 0 命中含义 |
|---|---|---|
| `discovery` | 发现新缺陷（默认） | 需要排查——可能规则失效或真干净 |
| `regression` | 验证已修复缺陷 | **成功**——豁免零命中自检，不进 triage 队列 |

```python
class CrossFuncUndefinedNameRule(BaseRule):
    id = "py.cross_func_undefined_name"
    intent = "regression"  # 给已修复历史缺陷写的规则，0 命中是成功
    ...
```

---

## 九、命中集 diff（P0-2）

规则或共享判据变更后，不用整轮重跑 553 条，直接对比两轮的命中集：

```bash
# 对比 round-5 和 round-6 的命中集
ssh nas "docker exec auditkit python3 /app/auditkit diff AutoForge 5 6"
```

输出：
- 各规则 added/removed 数量
- 新增命中详情（rule, file, line）
- 移除命中详情

---

## 十、写新规则

规则有两种格式：

### 格式 A：YAML 规则（简单模式）

适合：正则就能描述的语法模式。

```yaml
# rules/generic/your_new_rule.yaml
id: py.your_new_rule
name: 规则名称
description: 详细描述这个规则检测什么、为什么重要
applies_to: []  # 空数组=通用，或写 ["AutoForge"] 限定项目
mode: static_ast
severity: low  # low / medium / high
status: active
version: "1.0.0"
intent: discovery  # discovery / regression
match:
  type: [ExceptHandler]
  regex: ["except\\s+Exception\\s*:"]
tests:
  dirty:
    - name: 样本名
      code: |
        def foo():
            try:
                pass
            except Exception:
                pass
  clean:
    - name: 样本名
      code: |
        def foo():
            try:
                pass
            except (OSError, ValueError):
                pass
```

### 格式 B：Python 规则（复杂 AST 分析）

适合：需要跨语句分析、数据流追踪的场景。

```python
# rules/generic/your_new_rule.py
"""规则描述：检测什么缺陷、来源（哪轮发现的）。"""
from __future__ import annotations
import ast
from engine.base import BaseRule, Finding, node_source


class YourNewRule(BaseRule):
    id = "py.your_new_rule"
    name = "规则名称"
    description = "规则描述"
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.0.0"
    intent = "discovery"  # discovery / regression

    tests = {
        "dirty": [{"name": "样本名", "code": "def foo():\n    pass"}],
        "clean": [{"name": "样本名", "code": "def foo():\n    pass"}],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                out.append(Finding(
                    rule_id=self.id, file=str(tree.path), line=node.lineno,
                    severity=self.severity, title=self.name,
                    detail="缺陷描述", evidence=node_source(tree, node.lineno)[:200],
                ))
        return out
```

---

## 十一、自检与验证

### 规则自检

```bash
# 跑全部规则的 dirty/clean 自检
ssh nas "docker exec auditkit python3 /app/auditkit selftest"

# 单独跑某规则
ssh nas "docker exec auditkit python3 /app/auditkit rules test py.your_new_rule"
```

### 端到端验证

```bash
# 跑一轮真实项目
ssh nas "docker exec auditkit python3 /app/auditkit round AutoForge --round 2"

# 看报告
ssh nas "docker exec auditkit cat /app/projects/AutoForge/round-002/report.md"
```

### 命中集对比（规则变更后验证）

```bash
ssh nas "docker exec auditkit python3 /app/auditkit diff AutoForge 1 2"
```

---

## 十二、递交提案

如果新规则表现良好（命中合理、误报不高），把它打包成提案：

```
提案包结构：
├── rules/generic/your_new_rule.py   或 .yaml
├── CHANGE.yaml                       变更说明
└── README_提交说明.md                 为什么要加这条规则
```

```bash
# 自动生成提案包（收集改动文件 + 跑测试 + 生成 CHANGE.yaml）
ssh nas "docker exec auditkit python3 /app/auditkit propose create \
  --type rule --name your_new_rule --title '新规则标题' --summary '改了什么、为什么改'"
```

维护者审核后会合入 GitHub。

---

## 十三、完整迭代循环

```
R0 手猎 → 找盲区 → 写新规则 → 自检 → R1 基线 → triage 裁决 → 递交提案
   ↑                                                    ↓
   └────────────────────────────────────────────────────┘
         R2+ 回归轮（delta/regression 模式，增量守夜）
```

**目标**：跑 20 轮后，缺陷收敛——新规则命中越来越少，说明覆盖得差不多了。

---

## 十四、注意事项

1. **先跑 selftest**：每次写新规则前，先确认现有规则没坏
2. **零命中 ≠ 干净**：规则 0 命中时，先检查是不是静默失效（看 PITFALLS.md）
3. **候选不是确证**：报告里的命中是机器候选，需要人工确证才算真缺陷
4. **判据局部性**：规则只检测它该检测的，不要越界（见 criterion-locality-proposal.md）
5. **可移植性**：规则尽量通用，不要写死项目路径（见 rule-portability-proposal.md）
6. **扫描并行，triage 分批**：不要一次囤 3×500+ 条待裁决
7. **裁决必须落盘**：用 `auditkit triage` 记录，不要只在脑子里记
8. **探索轮先手猎**：新项目首轮不要直接上工作流，先手猎建立坐标系
