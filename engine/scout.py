#!/usr/bin/env python3
"""scout —— 手猎轮。

P1（建议书）：审计工作流是经验的消费者，不是生产者。新项目首轮应插入「手猎」阶段，
其产出不是报告，而是下一轮规则的输入。

强制产出四件套：
  ① 手猎假设清单（每条带「可证伪预测」）
  ② 项目方言表（本项目用哪些 API / 惯用法 / 约定，供规则适配）
  ③ 候选规则草案（从手猎假设反推，落为 rules/ 或 adapter）
  ④ 该项目「四问」：能不能构造 / 崩溃后残留 / 资源耗尽 / 并发下是否正确

用法：
  auditkit scout <project>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
PROJECTS_DIR = ROOT / "projects"


HYPOTHESES_TEMPLATE = """# 手猎假设清单 —— {project}

> 每条假设必须带「可证伪预测」：如果成立，应该观察到什么。
> 这是经验生产的核心——工作流只能消费已有经验，不能生产新经验。

## 假设 1：<标题>

- **假设**：<描述>
- **可证伪预测**：如果成立，应该观察到 <什么>
- **验证方法**：<怎么验证>
- **状态**：待验证 / 已确证 / 已证伪
- **确证证据**：<文件:行号 或 复现步骤>

## 假设 2：...

"""

VOCABULARY_TEMPLATE = """# 项目方言表 —— {project}

> 本项目用哪些 API / 惯用法 / 约定，供规则适配。
> 规则可移植性的铁证：DO 规则假设 AutoForge 的 atomic_write_text，
> 而 doubao-butler 用 write_json_atomic，匹配不上 ⇒ 规则安静地 0 命中。

## 原子写入
- <项目用的原子写入 API>：<用法示例>

## 日志
- <项目用的日志 API>：<用法示例>

## 配置
- <项目用的配置 API>：<用法示例>

## 缓存
- <项目用的缓存 API>：<用法示例>

## 其他惯用法
- ...

"""

RULE_DRAFTS_TEMPLATE = """# 候选规则草案 —— {project}

> 从手猎假设反推，落为 rules/ 或 adapter。
> 工作流运行规则，不写规则。新规则的原料只能从手动推理中来。

## 规则 1：<规则 ID>

- **来源假设**：<对应假设 1>
- **判据**：<什么形态算命中>
- **误报风险**：<什么形态会误报>
- **建议位置**：rules/generic/ 或 rules/project/{project}/
- **草案代码**：

```python
# 规则草案
```

## 规则 2：...

"""

FOCUS_TEMPLATE = """# 项目「四问」—— {project}

> 每个项目的 focus / 专题规划。
> 这四个问题是稳定性缺陷的高发区。

## 1. 能不能构造？
- <是否存在不可信输入构造对象/状态的路径>
- <验证方法>

## 2. 崩溃后残留？
- <异常路径是否留下不一致状态/半写文件/锁未释放>
- <验证方法>

## 3. 资源耗尽？
- <是否存在无界增长/泄漏/死锁>
- <验证方法>

## 4. 并发下是否正确？
- <竞态/原子性/可见性问题>
- <验证方法>

"""


def cmd_scout(project: str) -> int:
    scout_dir = PROJECTS_DIR / project / "scout"
    scout_dir.mkdir(parents=True, exist_ok=True)

    files = {
        "hypotheses.md": HYPOTHESES_TEMPLATE,
        "vocabulary.yaml": VOCABULARY_TEMPLATE,
        "rule_drafts.md": RULE_DRAFTS_TEMPLATE,
        "focus.md": FOCUS_TEMPLATE,
    }

    print(f"=== 手猎轮初始化: {project} ===")
    print(f"目录: {scout_dir}")
    print()

    for filename, template in files.items():
        f = scout_dir / filename
        if f.exists():
            print(f"  已存在，跳过: {filename}")
        else:
            f.write_text(template.format(project=project), encoding="utf-8")
            print(f"  已创建: {filename}")

    print()
    print("四件套说明:")
    print("  1. hypotheses.md   —— 手猎假设清单（每条带可证伪预测）")
    print("  2. vocabulary.yaml —— 项目方言表（供规则适配）")
    print("  3. rule_drafts.md  —— 候选规则草案（从假设反推）")
    print("  4. focus.md        —— 项目「四问」（构造/残留/耗尽/并发）")
    print()
    print("下一步: 由 agent 轻装读代码，填写四件套。完成后运行 auditkit reconcile 对账。")

    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    return cmd_scout(sys.argv[1])


if __name__ == "__main__":
    sys.exit(main())
