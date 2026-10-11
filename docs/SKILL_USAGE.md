# ADM-auditkit 审计工作流 Skill

> 这是一个**审计平台**，不是固定规则扫描器。
> 你的角色是**审计 agent**：发现盲区 → 写新规则 → 递交提案。

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

## 二、第一步：跑基线审计

```bash
# 跑一轮基线，看现有规则命中了什么
ssh nas "docker exec auditkit python3 /app/auditkit round AutoForge --round 1"

# 看报告
ssh nas "docker exec auditkit cat /app/projects/AutoForge/round-001/report.md"
```

### 报告里要找什么

| 信号 | 说明 |
|---|---|
| **零覆盖盲区** | 规则在该项目 0 命中——可能静默失效，也可能不适用 |
| **Top 规则** | 哪类缺陷最多？还有没有类似但没覆盖的？ |
| **Top 文件** | 哪个文件命中最多？还有没有类似文件没扫到？ |
| **零命中的模块** | 报告说"零覆盖盲区"的，是不是真的没问题？ |

---

## 三、第二步：写新规则

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
match:
  type: [ExceptHandler]  # AST 节点类型
  regex: ["except\\s+Exception\\s*:"]  # 匹配正则
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
import re
from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk


class YourNewRule(BaseRule):
    id = "py.your_new_rule"
    name = "规则名称"
    description = "规则描述"
    applies_to = []
    mode = "static_ast"
    severity = "medium"
    status = "active"
    version = "1.0.0"

    tests = {
        "dirty": [
            {"name": "样本名", "code": "def foo():\n    pass"},
        ],
        "clean": [
            {"name": "样本名", "code": "def foo():\n    pass"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        out = []
        for node in ast.walk(tree):
            # 你的检测逻辑
            if isinstance(node, ast.Call):
                out.append(Finding(
                    rule_id=self.id, file=str(tree.path), line=node.lineno,
                    severity=self.severity, title=self.name,
                    detail="缺陷描述", evidence=node_source(tree, node.lineno)[:200],
                ))
        return out
```

---

## 四、第三步：自检

写完规则后，**必须**跑自检，确认规则没静默失效：

```bash
ssh nas "docker exec auditkit python3 /app/auditkit selftest"
```

自检会跑你的 dirty/clean 样本，确认：
- dirty 样本能命中
- clean 样本不误报

如果自检失败，说明规则有 bug，先修好再递交。

---

## 五、第四步：端到端验证

```bash
# 跑一轮真实项目，看新规则命中了多少
ssh nas "docker exec auditkit python3 /app/auditkit round AutoForge --round 2"

# 看报告里你的新规则命中了什么
ssh nas "docker exec auditkit cat /app/projects/AutoForge/round-002/report.md | grep your_new_rule"
```

---

## 六、第五步：递交提案

如果新规则表现良好（命中合理、误报不高），把它打包成提案：

```
提案包结构：
├── rules/generic/your_new_rule.py   或 .yaml
├── CHANGE.yaml                       变更说明
└── README_提交说明.md                 为什么要加这条规则
```

维护者审核后会合入 GitHub。

---

## 七、完整迭代循环

```
跑基线 → 找盲区 → 写新规则 → 自检 → 端到端验证 → 递交提案
   ↑                                                    ↓
   └────────────────────────────────────────────────────┘
```

**目标**：跑 20 轮后，缺陷收敛——新规则命中越来越少，说明覆盖得差不多了。

---

## 八、注意事项

1. **先跑 selftest**：每次写新规则前，先确认现有 21 个分析器没坏
2. **零命中 ≠ 干净**：规则 0 命中时，先检查是不是静默失效（看 PITFALLS.md）
3. **候选不是确证**：报告里的命中是机器候选，需要人工确证才算真缺陷
4. **判据局部性**：规则只检测它该检测的，不要越界（见 criterion-locality-proposal.md）
5. **可移植性**：规则尽量通用，不要写死项目路径（见 rule-portability-proposal.md）
