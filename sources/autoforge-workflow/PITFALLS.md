# 审计工作流陷阱清单 PITFALLS

> 十九轮审计中**分析器自身踩过的坑**。写新规则前必读，能省下大量重复调试。
> 分两类：**假阴性**（规则静默失效，报 0 但代码有问题）比假阳性危险得多——
> 假阳性浪费时间，假阴性会让你写出"此处无缺陷"的错误结论。

---

## 一、假阴性：规则静默失效（最危险）

报 0 命中时**必须**先自检（见 `selftest/`），以下全是真实发生过的事故。

### N1. 遍历节点类型与取值函数不匹配 —— RES-01/02/03/04 全灭

```python
for n in ast.walk(fn):
    if not isinstance(n, ast.Call): continue
    names = _assigned_names(n)      # ← 该函数只认 Assign/AugAssign，永远 []
    if not names: continue          # ← 于是所有 fd/句柄/临时资源全部跳过
```
**症状**：第十六轮首版在 AutoForge 上报 0，差点写出"资源管理无缺陷"的结论。
合成样例自检发现 5 个已知缺陷只检出 2 个。
**修法**：要取"赋值目标"，就遍历 `Assign` 节点，从 `.value` 里取 `Call`。

### N2. `ast.unparse` 的装饰器**不含 `@`**

```python
re.search(r"@\w+\.(get|post)\(", ast.unparse(decorator))   # ← 永远不匹配
```
**症状**：第十八轮 AUTH-01（路由无鉴权）首版 0 命中，81 个路由全漏。
**修法**：正则去掉 `^@`。

### N3. 只认 `ast.Name`，漏掉 `self.xxx`（`ast.Attribute`）

**症状**：第十八轮 AUTH-04 首版 0 命中——凭证字段在 `__init__` 里写作 `self._tokens`（Attribute），
而规则只收集 `ast.AnnAssign` + `ast.Name`。
**修法**：凡涉及"实例属性"的收集，**必须同时处理 Name 与 Attribute**（取 `.attr`）。

### N4. 正则中常量位置假设过强 —— CFG-02

**症状**：第十三轮只匹配"常量在比较符左侧"，`payload.get("version") != MODEL_VERSION`（常量在右）漏报。
**修法**：比较类规则一律做**双向**匹配。

### N5. 正则括号不平衡导致 `re.error` —— RMW-02

**症状**：第十九轮 RMW-02 抛 `re.error`，5 个模块被 try/except 静默跳过（`[warn]` 刷屏但没人看）。
**修法**：复杂正则改为**分步简单匹配**；并把 `[warn]` 计数纳入退出码，别让它静默。

### N6. 台账指纹里 `[str]` 是字符类

**症状**：BUG-19 首次复核判 `unknown`——指纹 `list[str]` 的 `[str]` 在正则里是字符类，匹配不到字面量。
**修法**：指纹里避免裸方括号，或 `re.escape` 后再拼。

---

## 二、假阳性：规则过宽

### P1. `ast.walk` 会下降进**嵌套函数**（高频！）

**症状**：第十五轮 API-08 报 8 条"注解非 Optional 却返回 None"——
实际是 `ast.walk(fn)` 把内层 `def _walk()` / `def dep()` 的 `return None` 算到了外层函数头上。
**修法**：凡分析"本函数的 return / 语句"，用**不下降进嵌套 def/class** 的专用遍历器
（见各分析器里的 `_stms()` / `_own_returns()`）。

### P2. 生成器函数的裸 `return` 是"结束迭代"，不是返回 None

**症状**：`Iterator[dict]` 注解的函数里 `return` 表示 yield 结束（如 `if not path.exists(): return`），是正确写法。
**修法**：含 `Yield`/`YieldFrom` 的函数整体排除。

### P3. `os.open()` 返回 fd，不涉及文本编码

**症状**：第十七轮 SEM-08 把 5 处 `os.open()` 判为"未指定 encoding"。
**修法**：`os.*` 前缀整体排除；`opener.open()`/`resp.*` 是网络响应（字节流），也排除。

### P4. `sum(整数列表) == 0` 不是浮点比较

**症状**：`af_predict.py:658` 的 `sum(hist) == 0`（hist 是 int 直方图）被判浮点相等。
**修法**：只认**明确浮点证据**（字面量小数点 / `float(` 调用 / 浮点后缀变量），
并排除 `sum(`/`len(`/`int(`/`count(` 开头的整数表达式。

### P5. `except` 里的 `logger.*` 永不抛出

**症状**：第十七轮 PAT-06 首版 73 条，绝大多数是 `logger.warning()`。
标准库日志设计上不抛异常，不是 BUG-13 同类。
**修法**：排除 `logging.*` / `logger.*` / `warnings.warn` / `print`。

### P6. 被调方自带兜底时，调用点无需再包 try（**最重要的一条**）

**症状**：PAT-06 二轮修正。`af_version._audit()` 内部就有 `try: ... except: pass`
（注释明写"审计是旁路 fail-open"）；而 BUG-13 的真身 `_audit_degraded()` 没有。
**两者调用点形状完全相同**，唯一区别在被调方内部。
**修法**：建"被调方是否自带兜底"索引（见 `pattern_propagation.build_self_protected`）。

> **通则**：判断"这个调用要不要防护"，**判据在被调方的语义里，不在调用点的语法里**。
> 第十轮 `default=str`（持久化路径是 bug、日志路径是合理降级）也是同一条原则。

### P7. 抽象方法与具体方法

**症状**：第十五轮 API-05 把基类 `DeviceSM` **已实现的** `drain_followups`/`reset`
当成"子类必须重写"，8 个子类全误报。
**修法**：只有 `@abstractmethod` 才是必须实现的；子类继承具体方法即可。

### P8. 断言写法有两套：pytest 与 unittest

**症状**：第十四轮 TST-06 报 139 条"无断言测试"——项目用 `self.assertEqual(...)`，
而规则只认裸 `assert` 和 `pytest.raises`。
**修法**：同时识别 `assert*`、`fail`、`raises` 方法名与 `self.assertXxx`。

### P9. 有界容器的写法不止 `deque(maxlen=)`

**症状**：第十二轮 OBS 把 `if len(self.X) > self.max_X: del self.X[:...]` 判为无界。
**修法**：`_is_bounded()` 需同时认 `deque(maxlen=)`、类内 `max_*` 字段、尾部裁剪表达式。

### P10. `Attribute` 的 attr 名匹配造成张冠李戴

**症状**：第十一轮 ERRH-03 把 `json.JSONDecodeError` 取 attr 后变成裸 `JSONDecodeError` 判"未定义"；
`def pop()` 里的 `self._store.pop()` 被判成递归（第五轮）。
**修法**：限定性判定时用**完整链**（`_chain()`）而非末段 attr。

### P11. 导入名也是"已定义"

**症状**：第十一轮 `from json import JSONDecodeError` 后使用 `JSONDecodeError`，被判"未定义异常名"。
**修法**：已知名字集合必须并入 `ImportFrom` 的 `names`。

### P12. Python 语义陷阱
- `False == 0` → 第二轮把 `return False` 误判成"返回 0 伪装成功"
- `or` 的 falsy → BUG-02 是真缺陷，但 `if x or default` 多数场景是有意的
- `StreamingResponse(async_gen())` 是合法用法，不是"丢失 await"
- `FileLock` 是**跨进程锁**，IO 必须在锁内，不是"持锁 IO"（第三轮 12 条全误报）

### P13. 动态注册扫不到
`af_cli.py` 的 CLI 子命令、FastAPI 的 `add_typer` 均为运行时注册，
静态分析下的"未被引用"多为假阳性（第五轮 DEAD-03）。

---

## 三、工具与流程自身的事故

| 事故 | 教训 |
|---|---|
| `fetch_snapshot.py` 算出增量判定但**没落盘** | 编排脚本永远读不到 `state/changed` → "无变更时只跑轻量轮"从未生效。落盘后要**端到端验证** |
| semgrep 在沙箱反复装坏（pip 中断导致缺 `semdep.parsers.util`） | 主力分析改用**纯 stdlib AST**，不依赖外部工具 |
| 混合返回分析器首版 92 条 → 修正终止性判断后 19 条 → 抽样 6 条全误报 | 精度不足的产物**不应采纳进结论**，如实写进报告 |
| 第十九轮 RMW-02 `re.error` 静默跳过 5 个模块 | `[warn]` 不能只打印，要计入退出码 |

---

## 四、方法论通则（十九条）

1. **报 0 必须先自检**。第十五、十六轮都用合成样例抓住了"检测器坏了"。
   第十六轮那次若不自检，就会写出假结论。
2. **静态给候选，实测给确定性**。确证缺陷几乎都靠实测（BUG-06 OOM、BUG-08 16/30、
   BUG-09 回拨、BUG-19 640×、BUG-20 配对失败）。候选不实测不升级为缺陷。
3. **判据在被调方语义里**（见 P6）。
4. **规则要判"不一致"而非"缺失"**。第十九轮 RMW-01 判"同类内有的写盘方法重读、有的不"，
   而不是"缺 `_load()`"——自动区分"有意都不重读"与"漏了一个"，从源头压假阳性。
5. **命中要 triage**。否则同一条位置每轮重复报（实测重复率 91%），虚高计数并浪费核验精力。
6. **零覆盖文件 ≠ 干净文件**。第十九轮发现 6 个生产模块从未被任何规则命中，
   这是真盲区，需人工确认。
7. 误报修完后，把修正写进本文件——**同一个坑我踩过不止一次**（嵌套函数、生成器、`or` 默认值）。

---

## 本轮（第十九轮后·工作流盲区修补）新增

### 假阴性（续）

**N7｜`_chain()` 对非 Name receiver 返回空串 —— 跨 10 个分析器的共性漏检**
十个分析器（`api_contract`/`auth`/`config_compat`/`consistency`/`errorhandling`/
`observability`/`pattern_propagation`/`resource`/`rmw_consistency`/`semantic`）
都各自定义了同名 `_chain()`，实现统一为：
`func` 是 Name 或 Attribute 链且**末端必须是 Name** 才返回调用名，否则返回 `""`。
于是 `(p / "new.json").write_text(...)`、`arr[0].save()`、`get(x).close()` 这类
**receiver 是表达式**的调用被整体丢弃，规则静默失效。

- 真实后果：`consistency_defects` 的 TX-04（先删后写）在样本上 0 命中，
  定位到 `_chain` 返回 `''`；修复后同一规则恢复 4 条命中。
- 修法：末端非 Name 时**不再返回空串**，改为返回已收集的属性链
  （`(p/"x").write_text()` → `"write_text"`），至少能匹配方法名。
- 通则：**跨文件复制的 helper，一处有缺陷等于处处有缺陷。** 应抽成共享模块。

**N8｜容器识别只认「注解」和「Call 形态」，漏掉字面量初始化**
`observability_defects` 的 OBS-02 只把 `self.X: list[...]`（AnnAssign）和
`self.X = field(default_factory=list)`（Call）当作容器，而 `self.X = []` /
`self.X = {}` 是 `ast.List` / `ast.Dict` **字面量，不是 Call** → 全部漏检。
这是最常见的容器初始化形态，属重大盲区。修法：同时接受
`isinstance(n.value, (ast.List, ast.Dict, ast.Set, ast.ListComp))`。

### 假阳性（续）

**P14｜OBS-02 把「映射型容器」当成「累加型遥测」**
`self._codes = {}` + `create()` 写 + `consume()` 里 `pop()` 删除——条目有进有出，
不是单调增长，但 OBS-02 只看「有 append/下标写 + 无裁剪」就报。
修法：若类内存在 `pop/popitem/clear/remove/discard/del self.X[...]` 任一删除路径，
该容器判为映射型，不参与「无界累加」判定。
- 效果：clean 归零，dirty 召回从 5 降到 4（未丢真缺陷）。

**P15｜CONC-08 无法区分「漏加锁」与「有意只锁写段」**
读-改-写模式中 `_load()` 在锁外、`_persist()` 在锁内属**正确**形态
（先加载快照，再持锁改并写盘），但 CONC-08 报「锁覆盖不全」。
此类语义判定规则无法完成，已记入 clean 白名单并附理由，交人工判。

### 事故（续）

| # | 现象 | 根因 | 处置 |
|---|---|---|---|
| A9 | `run_selftest.py` 中 `expect.json` 路径写为 `CASES/` 而实际在 `selftest/` | 建文件与引用位置不一致 | 改为 `ROOT / "expect.json"` |
| A10 | `ccnt_eff` 在赋值后才定义 → `UnboundLocalError` | 插入白名单逻辑时未调整语句顺序 | 把白名单计算移到 `result[name] =` 之前 |
| A11 | 白名单 `allow_on_clean` 实际是 dict（规则名→理由），脚本按 list 处理 → `dict has no attribute append` | 未先读结构再改 | 先 `json.loads` 判类型再写 |
| A12 | helper 被重复定义（旧版覆盖新版，依赖不存在的 `_parent_try`） | 多次 patch 插入同名函数 | 删除重复定义；**patch 后必须确认无同名函数** |

### 方法论通则（续）

8. **「0 命中」必须自证。** 已建成 `selftest/` 套件：dirty 样本（34 个已知缺陷）上
   每个分析器**必须至少命中 1 条**，否则判 FAIL；clean 样本（正确写法）上命中数
   与 golden 快照比对，新增即红警。这是把「PITFALLS N1（规则静默失效）」
   从人肉抽查变成**每轮自动门禁**。
9. **白名单必须带理由。** `expect.json` 的 `allow_on_clean` 是 dict：
   规则名 → 为什么这条在正确代码上命中仍属良性。没有理由的白名单等于放弃召回。
10. **优先修规则，其次才加白名单。** 本轮 P14 先尝试修规则成功（clean 归零且
    dirty 未丢），P15 确实无法用规则表达才进白名单。顺序反了会积累技术债。
