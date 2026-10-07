# ADM-auditkit 规则编写指南

> 本文档指导元宝（网络沙箱 AI）如何编写适合提交的 L3 规则文件。
> 最后更新：2026-10-07

---

## 一、规则是什么

L3 规则是四层架构的最上层，是**可插拔的检测逻辑单元**。每条规则：

- 声明自己适用的**审计模式**（8 种之一）
- 声明自己适用的**项目**（通用或指定项目）
- 自带 **dirty/clean 测试样本**（注册时自动验证）
- 运行时产出 `Finding`（缺陷候选）

规则有**两种形态**，按需选择：

| 形态 | 适用场景 | 文件格式 |
|---|---|---|
| **YAML 声明式** | 简单模式匹配（调用名/属性名/类型/正则） | `.yaml` |
| **Python 插件式** | 复杂逻辑（跨函数分析/调用图/状态机） | `.py` |

**原则：能 YAML 就不 Python。** YAML 规则更易审核、更易维护、注册期校验更严格。

---

## 二、目录结构

```
rules/
├── generic/                    # 通用规则（所有项目适用）
│   ├── __init__.py
│   ├── py_dynamic_code_exec.yaml   # YAML 规则示例
│   └── example_rule.py             # Python 插件规则示例
└── project/                    # 项目专属规则
    ├── __init__.py
    ├── AutoForge/
    │   ├── __init__.py
    │   └── af_mcp_tool_no_timeout.yaml
    ├── doubao-butler/
    │   └── __init__.py
    └── memory-agent/
        └── __init__.py
```

**放置规则：**
- 检测逻辑与项目无关 → 放 `rules/generic/`
- 检测逻辑依赖特定项目的代码结构/命名约定 → 放 `rules/project/<项目名>/`
- 文件名用小写蛇形，与规则 id 对应（如 `py.dynamic_code_exec` → `py_dynamic_code_exec.yaml`）

---

## 三、YAML 规则格式

### 3.1 完整示例

```yaml
# rules/generic/py_dynamic_code_exec.yaml
id: py.dynamic_code_exec
name: 动态代码执行
description: 使用 eval/exec 执行动态构造的代码，可能导致任意代码执行漏洞
applies_to: []              # 空列表 = 所有项目
mode: static_ast
severity: high
status: active
version: "1.0.0"
match:
  call: [eval, exec]        # 单条件组
tests:
  dirty:
    - name: eval-call
      code: result = eval(user_input)
    - name: exec-call
      code: exec(dynamic_code)
  clean:
    - name: safe-eval-variable
      code: eval_fn = my_custom_eval
    - name: math-eval-method
      code: result = obj.evaluate(expr)
```

### 3.2 字段说明

| 字段 | 必填 | 类型 | 说明 |
|---|---|---|---|
| `id` | ✅ | string | 规则唯一标识，格式见 §五 |
| `name` | ✅ | string | 规则中文名（展示用） |
| `match` | ✅ | dict/list | 匹配条件，见 §3.3 |
| `description` | ❌ | string | 规则描述（会出现在 Finding detail 里） |
| `applies_to` | ❌ | list | 适用项目列表，空列表=所有项目。如 `["AutoForge"]` |
| `mode` | ❌ | string | 审计模式，默认 `static_ast`。8 种可选见 §六 |
| `severity` | ❌ | string | 严重度：`critical`/`high`/`medium`/`low`/`info`，默认 `medium` |
| `status` | ❌ | string | 状态：`active`/`testing`/`draft`/`deprecated`/`broken`，默认 `active` |
| `version` | ❌ | string | 语义化版本，默认 `"1.0.0"` |
| `tests` | ❌ | dict | dirty/clean 测试样本，见 §四。**强烈建议必须提供** |

### 3.3 match 语义（核心）

match 支持 **5 种判据**：

| 判据 | 匹配对象 | 示例 |
|---|---|---|
| `call` | 函数调用的末段名 | `call: [eval, exec]` 匹配 `eval(x)`、`exec(x)` |
| `attr` | 属性访问的属性名 | `attr: [timeout]` 匹配 `obj.timeout` |
| `name` | 节点名（函数名/类名/变量名） | `name: [handle_request]` |
| `type` | AST 节点类型 | `type: [Call, FunctionDef]` |
| `regex` | 源码行正则（纯正则组按行扫） | `regex: ["TODO.*fix", "HACK"]` |

**组合规则：**

```yaml
# 单条件组：组内多判据 AND，判据内多模式 OR
match:
  call: [requests.get, requests.post]   # 调用 requests.get OR requests.post
  attr: [timeout]                         # AND 访问了 .timeout
# 含义：调用了 requests.get/post 且访问了 .timeout

# 多条件组（列表）：组间 OR
match:
  - call: [eval]
  - call: [exec]
# 含义：调用了 eval OR 调用了 exec（等价于 call: [eval, exec]）

# 纯正则组：按行扫描，不依赖 AST
match:
  regex: ["TODO.*fixme", "HACK"]
```

**注意：**
- `call` 匹配的是**末段名**，`requests.get` 会匹配 `a.b.requests.get()` 吗？不会——`call` 只取末段 `get`。要匹配全名用 `regex`。
- `regex` 组如果是纯组（组内只有 regex 判据），按行扫描源码；否则按 AST 节点扫描。
- 所有判据值可以是字符串或字符串列表。

---

## 四、测试样本（dirty/clean）

每条规则**必须**自带测试样本，注册时自动验证：
- **dirty 样本**：必须命中规则（至少 1 条 Finding）
- **clean 样本**：必须不命中规则（0 条 Finding）

如果 dirty 不命中或 clean 命中，规则会被标记为 `broken`，**不会进入注册表**（fail-closed）。

### 格式

```yaml
tests:
  dirty:
    - name: 简短描述      # 必填，用于失败时定位
      code: |              # 必填，Python 源码（多行用 |）
        def f():
            eval(user_input)
  clean:
    - name: 简短描述
      code: |
        def f():
            safe_eval = my_eval
```

**编写要点：**
- dirty 样本要**最小化**：只包含触发规则的必要代码，不要引入无关逻辑
- clean 样本要**形似而神不似**：看起来像缺陷但实际安全（如变量名含 eval 但不是调用）
- 每个样本的 `name` 要能描述测试意图
- 样本代码必须是**合法 Python**（能被 ast.parse 解析）

---

## 五、规则命名规范（id）

```
<语言前缀>.<规则名>          # 通用规则
<项目缩写>.<规则名>           # 项目专属规则
```

| 前缀 | 含义 | 示例 |
|---|---|---|
| `py.` | Python 通用 | `py.dynamic_code_exec`、`py.unbounded_container` |
| `ts.` / `js.` | TypeScript/JavaScript | `ts.await_no_timeout` |
| `af.` | AutoForge 专属 | `af.mcp_tool_no_timeout` |
| `ma.` | memory-agent 专属 | `ma.llm_call_no_timeout` |
| `db.` | doubao-butler 专属 | `db.plugin_sandbox_escape` |

**规则名**用小写蛇形，描述检测目标，如 `unbounded_container`、`dynamic_code_exec`、`mcp_tool_no_timeout`。

---

## 六、审计模式（mode）

8 种模式，规则通过 `mode` 字段选择适用的模式：

| mode | 说明 | 规则形态 |
|---|---|---|
| `static_ast` | 静态 AST 分析（Python 语法树） | YAML + Python |
| `cross_lang_text` | 跨语言文本分析（Dockerfile/yaml/shell/TS/JS） | Python |
| `graph_reachability` | 图谱可达性分析（调用图/数据流图） | Python |
| `contract_verify` | 契约验证（从 docstring 提取不变式） | Python |
| `dynamic_injection` | 动态注入（失败注入/超时模拟） | Python |
| `mutation_test` | 变异测试（注入缺陷验证规则有效性） | Python |
| `dep_supply_chain` | 依赖供应链（CVE/许可证/版本比对） | Python |
| `config_audit` | 配置面审计（env/docker-compose/部署配置） | Python |

**当前只有 `static_ast` 模式完整实现**，其他模式为骨架。写规则时优先用 `static_ast`。

---

## 七、Python 插件规则格式

当 YAML 的 match 语义不够用时（需要跨函数分析、调用图、状态机等），写 Python 插件。

### 7.1 完整示例

```python
# rules/generic/example_rule.py
"""示例规则：无界累加容器检测。

检测 self.container.append/extend 等增长操作后，没有对应的移除路径（pop/remove/clear/del）。
"""
from __future__ import annotations

import ast
import re
from engine.base import BaseRule, Finding, node_source
from engine.helpers import own_walk, call_name, full_unparse  # 可用原语

_GROWTH_RE = r"self\.{name}\.(append|extend|add|insert|update|setdefault)\b"


class UnboundedContainerRule(BaseRule):
    # ── 元数据（必须填写）──
    id = "py.unbounded_container"
    name = "无界累加容器"
    description = "容器只增不减，可能导致内存无限增长"
    applies_to = []              # 所有项目
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.0"

    # ── 测试样本（必须提供）──
    tests = {
        "dirty": [
            {"name": "append-only", "code": "class C:\n    def f(self):\n        self.items.append(x)"},
        ],
        "clean": [
            {"name": "append-and-pop", "code": "class C:\n    def f(self):\n        self.items.append(x)\n        self.items.pop()"},
        ],
    }

    def run(self, tree, profile, adapter) -> list[Finding]:
        """核心检测逻辑。

        Args:
            tree: ParsedUnit（含 .ast / .source / .path）
            profile: ProjectProfile（项目画像，可查语言/框架）
            adapter: ProjectAdapter（项目适配，可查 extra_roots/focus）

        Returns:
            list[Finding]：缺陷候选列表
        """
        out = []
        for node in own_walk(tree.ast):          # 作用域感知遍历
            if not isinstance(node, ast.ClassDef):
                continue
            for attr in self._container_attrs(node):
                if self._has_growth(node, attr) and not self._has_removal(node, attr):
                    out.append(Finding(
                        rule_id=self.id,
                        file=str(tree.path),
                        line=node.lineno,
                        severity=self.severity,
                        title=self.name,
                        detail=f"self.{attr} 只增不减",
                        evidence=node_source(tree, node.lineno)[:200],
                    ))
        return out

    def _container_attrs(self, cls_node) -> list[str]:
        # ... 辅助方法 ...
        return []

    def _has_growth(self, cls_node, attr) -> bool:
        return bool(re.search(_GROWTH_RE.format(name=attr), full_unparse(cls_node)))

    def _has_removal(self, cls_node, attr) -> bool:
        removal = rf"self\.{attr}\.(pop|remove|clear|discard)|del self\.{attr}"
        return bool(re.search(removal, full_unparse(cls_node)))
```

### 7.2 必须实现的内容

| 项 | 说明 |
|---|---|
| 继承 `BaseRule` | `from engine.base import BaseRule` |
| 类属性 `id`/`name` | 同 YAML 字段，见 §三/§五 |
| 类属性 `tests` | dict，格式 `{"dirty": [...], "clean": [...]}`，见 §四 |
| 方法 `run(tree, profile, adapter)` | 返回 `list[Finding]`，**必须实现**，否则注册报错 |

### 7.3 Finding 结构

```python
from engine.base import Finding

Finding(
    rule_id=str,        # 规则 id（必填）
    file=str,           # 文件路径（必填，用 str(tree.path)）
    line=int,           # 行号（必填）
    severity=str,       # 严重度（必填，用 self.severity）
    title=str,          # 缺陷标题（必填，用 self.name）
    detail=str,         # 详细描述（必填）
    evidence=str,       # 证据代码片段（可选，建议用 node_source(tree, lineno)）
)
```

### 7.4 可用的引擎原语（engine.helpers）

```python
from engine.helpers import (
    full_unparse,    # 存在性判定用：完整源码，不截断
    code_unparse,    # 顺序/区间判定用：剥离 docstring 后 unparse
    brief,           # 展示用：截断，禁止用于判定
    own_walk,        # 作用域感知遍历：不穿透嵌套函数
    all_walk,        # 穿透遍历：ast.walk 的别名
    call_name,       # 取调用末段名：a.b.c() → "c"
    call_full,       # 取调用全名：a.b.c() → "a.b.c"
    calls_in,        # 作用域内是否调用了某函数
    CallGraph,       # 函数索引 + 跨函数传递闭包
    has_trace,       # 留痕四叉判定：日志/raise/计数/状态标志
    handlers_of,     # 取作用域内的 except handler
    load_files,      # 加载源码（BOM 感知，不静默吞错）
    rel_path,        # 路径脱敏
    SEV_ORDER,       # 严重度排序字典
    iter_funcs,      # 遍历 (path, fn, full_body)
)
```

**每条原语都对应一次真实事故**，使用前请读原语函数的 docstring。

### 7.5 run() 方法的参数

```python
def run(self, tree, profile, adapter) -> list[Finding]:
```

- `tree`：`ParsedUnit` 对象，属性：
  - `tree.ast`：`ast.Module`（AST 根节点）
  - `tree.source`：源码字符串
  - `tree.path`：文件路径（`Path` 对象）
- `profile`：`ProjectProfile` 对象，可查：
  - `profile.languages`：语言分布
  - `profile.frameworks`：框架列表
  - `profile.has_python`：是否有 Python
- `adapter`：项目适配器，可查：
  - `adapter.extra_roots(repo)`：附加扫描根
  - `adapter.focus()`：关注规则列表
  - `adapter.focus_rules()`：关注规则 id 列表

---

## 八、提交流程

### 8.1 编写后本地验证

```bash
# 1. 列出所有规则，确认你的规则被加载且状态正确
python auditkit rules list

# 预期输出：
# id                               mode         status     severity  applies_to
# py.my_new_rule                   static_ast   active     high      *

# 2. 单独跑你的规则的 dirty/clean 自测
python auditkit rules test py.my_new_rule

# 预期输出：
# rule: py.my_new_rule
#   dirty: 2/2 命中 ✅
#   clean: 2/2 不命中 ✅
#   status: active

# 3. 跑全部测试（确保没有破坏其他规则）
python -u tests/run_all.py
# 预期：total=85+ ... failed=0
```

### 8.2 生成提案包

```bash
# 生成标准化变更提案包
python auditkit propose create \
  --type rule \
  --name py_my_new_rule \
  --title "新增规则：检测 XXX 缺陷" \
  --summary "检测 XXX 场景下的 YYY 问题，来源于 ZZZ 项目确证缺陷" \
  --risk low

# 预期输出：
# 提案包已生成: proposals/20261007_140235_py_my_new_rule
#   CHANGE.yaml: ...
#   files/: 1 个变更文件
#   evidence/: 2 个验证证据
```

### 8.3 提案包内容

```
proposals/<时间戳>_<名称>/
├── CHANGE.yaml      # 提案元数据（title/type/risk/verify_cmd/summary/验证结果）
├── files/           # 所有改动文件的副本（自包含）
│   └── rules/generic/py_my_new_rule.yaml
├── changes.patch    # git diff（如有）
└── evidence/        # 自动验证证据
    ├── test_output.txt   # 全部测试输出
    └── rules_list.txt    # 规则列表输出
```

### 8.4 发给维护者

把整个提案包目录（或打包成 zip）发给维护者。维护者会：
1. 审核 `CHANGE.yaml` 的摘要和风险
2. 查看 `files/` 里的规则代码
3. 运行 `CHANGE.yaml` 里的 `verify_cmd` 确认测试通过
4. 合入 git 并推送

---

## 九、常见错误和排查

### 9.1 规则没有出现在 `rules list` 里

**原因**：注册期 fail-closed，规则有问题被拒绝。

**排查**：
```bash
python -c "from engine.loader import load_rules; r = load_rules(); print(r.broken)"
```
查看 `broken` 字典里的错误信息。

**常见原因**：
- 缺少必填字段（`id`/`name`/`match`）
- `match` 用了未知判据（只能是 call/attr/name/type/regex）
- dirty 样本不命中（规则逻辑有问题或样本写错了）
- clean 样本命中了（规则太宽泛，有假阳性）
- Python 插件的 `run()` 方法抛异常

### 9.2 dirty 样本不命中

**排查步骤**：
1. 确认样本代码是合法 Python（能被 ast.parse）
2. YAML 规则：确认 `match` 判据正确（`call` 匹配末段名，不是全名）
3. Python 规则：在 `run()` 里加 print 调试，确认 AST 遍历到了目标节点
4. 用 `python auditkit rules test <rule_id> --json` 看详细输出

### 9.3 clean 样本命中了（假阳性）

**这是最常见的问题**，说明规则太宽泛。

**优化方向**：
- YAML：增加更多 AND 条件（如同时要求 `call` 和 `attr`）
- Python：用 `own_walk` 替代 `ast.walk`（不穿透嵌套函数）
- Python：增加上下文判断（如只在类方法内检测，不检测模块级）
- 参考 `legacy/analyzers/` 里的旧分析器降噪技巧

### 9.4 Python 插件的 `run()` 抛异常

**注意**：执行期是 fail-open 的——单文件异常不会阻断整个审计，但会被记录到 diagnostics。

**排查**：
- 确认 `tree.ast` / `tree.source` / `tree.path` 属性存在
- 确认 `Finding` 的参数类型正确（`line` 是 int，不是 None）
- 用 `try/except` 包裹可能失败的代码，异常时返回空列表

---

## 十、参考资源

| 资源 | 路径 | 说明 |
|---|---|---|
| YAML 规则示例 | `rules/generic/py_dynamic_code_exec.yaml` | 最简单的 YAML 规则 |
| Python 插件示例 | `rules/generic/example_rule.py` | 完整的 Python 插件，含降噪逻辑 |
| 项目专属规则示例 | `rules/project/AutoForge/af_mcp_tool_no_timeout.yaml` | 项目专属规则 |
| 旧分析器参考 | `legacy/analyzers/` | 22 个旧分析器，可参考检测逻辑和降噪技巧 |
| 引擎原语 | `engine/helpers.py` | 公共 AST 原语，每条对应一次真实事故 |
| 规则加载器 | `engine/loader.py` | YAML 解析和校验逻辑 |
| 引擎基类 | `engine/base.py` | BaseRule/Finding/BaseAuditMode 定义 |

---

## 十一、检查清单（提交前必过）

- [ ] 规则 `id` 符合命名规范（`py.xxx` / `af.xxx` / `ma.xxx` / `db.xxx`）
- [ ] 规则放在正确的目录（`rules/generic/` 或 `rules/project/<项目>/`）
- [ ] YAML 规则的 `match` 只用了 5 种合法判据
- [ ] Python 插件继承了 `BaseRule`，实现了 `run()` 方法
- [ ] 提供了 dirty 样本（至少 1 个，必命中）
- [ ] 提供了 clean 样本（至少 1 个，必不命中）
- [ ] `python auditkit rules test <rule_id>` 全部通过
- [ ] `python -u tests/run_all.py` 全部通过（没有破坏其他规则）
- [ ] `python auditkit propose create` 生成提案包成功
- [ ] CHANGE.yaml 的 summary 写清了"改了什么、为什么改、来源"
