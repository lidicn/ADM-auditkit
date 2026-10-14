# Echo —— 跨过程「沉默链」检测器

> 代码知道它失败了，它只是没说。Echo 让沉默本身发不出声。

## 一、它解决什么

现有可观测性工具都是「你埋什么我看什么」。Echo 回答另一个问题：

> **你没埋的地方，哪里该埋？**

它不问「这个 except 里有没有 logger」，它问：

> **这个失败信号沿调用图往上传播，最后有没有变成任何一个可观测决策？**

没有 —— 就是**断链**。

## 二、与现有规则正交（不是重复造轮子）

| 能力 | 粒度 | 判什么 |
|---|---|---|
| `py.silent_except_no_trace` | 单 handler | 留痕**有无**（`print` 也算留痕） |
| `py.print_trace_not_logger` | 单 handler | 留痕**质量**（print 是弱通道） |
| `core/graph/build_graph.py` | 模块级 | 入口 → sink **信任边界** |
| **Echo** | **函数级 + 跨过程** | 失败信号**是否转化为可观测** |

前三条都只看**一个函数体内的代码形态**。Echo 看的是**跨函数、跨文件的数据流**。
所以它独立成子命令，而非第 34 条 L3 规则。

## 三、判据链

```
失败出口（except 内 return 空值 / 裸 pass / continue / 降级赋值 / 异常存变量）
  │
  ├─ 出口已发声？（logger / raise / 记账毒化）→ 是：不算沉默，终止
  │   ⚠ print 不算发声（不进日志系统，与成功同形）
  │
  └─ 出口沉默 → 沿调用图向上传播
       调用方"接住"了吗？（检查返回值 + 告警）
         ├─ 接住 → 链终止
         └─ 没接住 → 沉默继续上溯
              └─ 到顶层仍无人发声 → ★断链★
```

### 失败出口八类形态（按真缺陷样本归纳）

| kind | 形态 | 样本 |
|---|---|---|
| `empty_return` | `return {}` / `[]` / `None` / `False` | MA52 / MA75 / MA76 / MA77 |
| `degraded_dict` | `return {flag:False, ...}`（门禁 fail-open） | MA89 |
| `default_return` | `return "split"`（安全默认值） | MA83 |
| `degrade_assign` | `x = None` / `[]` / `{}` 后继续 | MA54 / MA58 / MA66 / MA79 |
| `swallow_pass` | `except: pass` | MA59 |
| `swallow_continue` | `except: continue` | MA55 / MA63 / MA85 |
| `print_only_swallow` | except 内只 print，无显式出口 | MA74 / MA87 / MA88 |
| `err_capture_retry` | `last_err = exc` 后重试（重试期零留痕） | MA86 |

## 四、用法

```bash
# 已知阳性自检（dirty 必中 / clean 必不中）
./auditkit echo --selftest

# 扫一个项目
./auditkit echo /path/to/project/src --out chains.json

# 或直接跑
python3 core/echo/echo_scan.py /path/to/src out.json
```

输出 JSON：`stats` + `chains`（每条带 `exit` / `path` / `hops` / `severity`）。

## 五、已验证（不空想，有 ground truth）

| 验证 | 结果 |
|---|---|
| 已知阳性自检 | **5/5 PASS**（2 dirty 命中 + 3 clean 不命中） |
| memory-agent 第五期真缺陷 | **19/19 沉默类命中**（MA52…MA89） |
| 跨项目（doubao-butler） | 175 文件 / 163 沉默出口 / **135 断链**，抽样质量真实 |

> Echo 相对空想工具的最大优势：它有 42 条真缺陷做 ground truth。
> 验证器：`core/echo/verify_ma.py`。

**召回率演进**（每轮修的都是假阴性，不是调参）：

| 版本 | 命中 | 修了什么 |
|---|---|---|
| v1 | 9/20 (45%) | — |
| v2 | 17/19 (89%) | 补降级字典 / 默认常量 / 降级赋值 / print-only 四类形态 |
| v3 | 18/19 (95%) | 补**嵌套函数收集**（全仓 1159 个，MCP 工具常在工厂函数内定义） |
| v4 | **19/19 (100%)** | 补 `err_capture_retry` 形态 |

## 六、局限（必须说清）

**精确率未完整评估。** MA 上 353 条断链只抽样 13 条人工看过（质量真实），
**未经完整 triage**。它是 discovery 工具，产出是候选，不是结论。

**已知假阳性来源：**

1. **调用图按函数名全仓保守匹配** —— `self.foo()` / `obj.foo()` 一律按 attr 名连全仓同名函数。
   同名函数跨文件会误连（如 `get_history` 在 `ha_client` 与 `ha_db` 各有一份）。
   这是刻意取舍：**宁可连错（假阳性），不可漏连（假阴性）**。
2. **只扫 except handler** —— `try` 块内的判空返回（如 `_read_skill_meta` 的
   `if not txt.startswith("---"): return {}`）不在射程内。
3. **深 6 跳截断** —— 更长路径不报。

**设计边界（不覆盖）：**

- 崩溃面（异常外抛，如 MA78 `activity_rules` 整表外抛）——信号是**有的**，只是形态不对
- 语义 / 单位口径分裂（MA64、MA81、MA82）——不是沉默问题
- 路由遮蔽（MA53 / MA62）、SSRF（MA57）——不是数据流断链

## 七、方向性原则（继承 PITFALLS）

- **假阴性比假阳性危险** ⇒ 保守匹配、从严判定"是否接住"，偏向多报
- **不自动降 severity**（同 `dead_code_hint` 的处理原则），只做可见标记
- **阴性结论必须配覆盖度 + 已知阳性自检**（N14）

## 八、文件

| 文件 | 作用 |
|---|---|
| `echo_scan.py` | 核心引擎（收集 / 出口 / 调用图 / 传播 / 自检） |
| `verify_ma.py` | MA 真缺陷 ground truth 验证器 |
| `README.md` | 本文档 |
