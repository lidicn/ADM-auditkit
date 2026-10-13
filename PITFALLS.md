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
| A13 selftest 全 20 分析器 dirty 0 命中（但 golden 全绿） | 样本带 BOM + `read_text(errors="ignore")` 不带 encoding → BOM 字符让 ast.parse 抛 SyntaxError → `except SyntaxError: continue` 三重静默。防静默失效的门禁自己静默失效了。收口到 `_common.read_source()` 用 `utf-8-sig` 去 BOM，解析失败打 `[warn]` 计入 FAIL；门禁加三态（tools_missing/ok_but_no_hit/ok） |

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

**N9｜`read_text(errors="ignore")` 不带 encoding → BOM 致全分析器静默 0 命中**
20 个 legacy 分析器统一用 `ast.parse(p.read_text(errors="ignore"))` + `except SyntaxError: continue`。
当源文件带 UTF-8 BOM（`EF BB BF`）时：
- `read_text` 不带 encoding 走 `locale.getpreferredencoding()`
- BOM 字节经解码变成 `U+FEFF` 字符进入源文本
- `ast.parse` 抛 `SyntaxError: invalid non-printable character U+FEFF`（**跨平台一致**，Python 行为非 OS 行为）
- `except SyntaxError: continue` 静默吞掉 → 该文件 0 命中

**最讽刺的后果**：防静默失效的门禁（selftest）自己静默失效了——全 20 分析器 dirty 0 命中，
但 golden 全绿，drift 报 51 条"规则消失"红警。PITFALLS N1（头号事故）的现实复现。
- 修法：收口到 `_common.read_source()` 用 `encoding="utf-8-sig"`（自动去 BOM），
  解析失败返回 error 而非 `except: continue`；调用方打 `[warn]` 到 stderr，
  `run_selftest.py` 统计 warn_count 做三态诊断（tools_missing/ok_but_no_hit/ok）。
- 通则：**`errors="ignore"` 是静默失效的温床，凡用必配 `encoding="utf-8-sig"`，
  且失败必须打印 `[warn]` 而非静默 continue。**
  `engine/helpers.py:load_files()` 早已是正确范本，legacy 层漏改。

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

---

## 本轮（2026-10-12 · memory-agent round-003 + deepseek-studio round-003）新增

### 假阴性（续）

**N10｜嵌套副本污染：全局 skip_dirs 与项目级排除是两级，不能混**
memory-agent 的 `.qoder/tmp-*`（Qoder 工具整库快照）进引擎 `DEFAULT_SKIP_DIRS`
是对的——它是**通用暂存约定**。但 deepseek-studio 的 `deepseek-pp/` 是仓库内
**上游解包子目录，是该项目私有目录名**：写进引擎全局 skip_dirs 违反判据
可移植性（别的项目没有这个目录，白添一条永不命中的配置）。
实证代价：deepseek-studio round-003 的 5,268 条命中里 **4,346 条（82%）**
来自该副本，studio 自身真实信号只有 922 条。
- 修法：全局 `DEFAULT_SKIP_DIRS` 只收通用约定（.git/.qoder/workorders/tmp/
  node_modules/dist…）；**项目私有副本名写 `config/projects.yaml` 该项目的
  排除项**。两级边界：换一个项目还成立的才配进全局。
- **【2026-10-12 已落地】**：引擎此前根本不消费 `config/projects.yaml` 的
  `defaults.skip_dirs`——skip 用的是 `engine/profile.py:17` 与 `core/lang/
  generic_text.py:27` 的**硬编码** `SKIP_DIRS`，且无项目级覆盖通道。本次实现：
  `engine/profile.py` 的 `ProjectProfile` 加 `skip_dirs` 字段（from_dict 读取）；
  `static_ast_mode.py:iter_sources` 合并 `prof.skip_dirs`；
  `core/lang/generic_text.py:main` 接受 `--skip-dirs` 并合并到 walk；
  `engine/runner.py` 的 `run_round`/`run_generic_text` 透传；`auditkit:cmd_round`
  从**项目配置段**（非画像 JSON）取 `skip_dirs` 注入。
  **根因坑**：`cmd_round` 里的 `profile` 是画像 JSON（`core/profile.py` 探测输出），
  不含项目配置键——必须单独 `load_projects().projects[name]` 取。
  效果：deepseek-studio 加 `skip_dirs: [deepseek-pp]` 后，round-006 总命中
  5,268 → 557，deepseek-pp 路径命中 4,269 → **0**，独立项目 `deepseek-pp` 因
  skip 走项目级而**不受影响**。

**N11｜「双传输路径口径漂移」——同一功能两条实现，护栏只装了一条**
deepseek-studio `mcp-controller.ts`：stdio 传输的 `sendRequest` 有 30s 超时，
**HTTP/SSE 传输的 `fetch` 什么都没有**；`connectStdio` 有 `shell: isWin`，
`testConnection` 没有（Windows 上测试 `.cmd` 命令恒失败）。单看任一条路径
都"没有缺失"——缺陷在**两条路径的口径差**里。
- 修法：这类判据要按「同类外部调用点集合」比对参数（超时/清理/转义），
  报告口径从"这里缺 X"改为"这两个调用点一个有 X 一个没有"。
  与通则 4（判不一致而非缺失）同族，但这是**跨实现路径**的不一致。

**N12｜跨语言盲区：超时/定时器类规则此前全是 Python AST**
C3（MCP HTTP fetch 无超时）漏报的根因不是没想到，是**所有超时类规则
（`py.outbound_call_no_timeout` / `py.http_timeout_disabled` / `py.requests_no_timeout`）
都只解析 Python**；`generic_text` 正则层没有任何 fetch/XHR 超时模式。
一个 TS 项目里"外部调用无超时"这一类缺陷 100% 不可见。
- 修法：v1.2.0 已在 generic_text 补 `TS-07/JS-06-fetch-no-timeout` 与
  `TS-08/JS-07-settimeout-no-clear`（行首裸 `setTimeout` 未保存句柄——
  返回值没保存就无从 clearTimeout，判据结构上可靠）。
- 通则：**每加一条 Python 专属规则，问一句"这个缺陷类在别的语言里长什么样"**。

### 假阳性（续）

**P16｜TS 方法签名被当作调用（`types.ts:41` 实测）**
`TS-08` 判据是"行首裸 setTimeout"，但 TS 接口里的
`setTimeout(callback: () => void, delayMs: number): ReturnType<typeof setTimeout>;`
同样是行首 `setTimeout(`——**`) : 类型` 是签名特征不是调用**。
- 修法：行级排除 `\)\s*:\s*[\w<]`（TS 方法签名/类型声明形态）。

**P17｜innerHTML 的静态赋值（`innerHTML = ''` / 无插值模板串）**
`tool-card-ui.ts:245` 把静态骨架赋给 innerHTML 被 TS-01 报——右侧是纯字符串
字面量时没有任何可注入数据。收敛：右侧不含 `${` 且整体是字符串字面量才排除；
含插值、`+` 拼接、函数调用或裸标识符的一律仍报（确证 C1 就是
`buildCardHtml(...)` 这种函数调用形态）。
- 教训：形状判据收敛时，"排除"的边界要划在**数据可信度**上（有没有外部数据
  进入），不是划在"像不像坏味道"上。

**P18｜TS-03 过宽是"正则层无法判别返回值是不是 Promise"的慢性病**
`TS-03-unhandled-promise` 的正则是 `^\s*(?!await|return|//)[\w.]+\([^)]*\)\s*;?\s*$`——
它只匹配"行尾直接结束的调用"，**完全不管这调用返回的是不是 Promise**。
于是 `res.setHeader(...)`/`res.end()`/`buckets.set()`/`process.exit()`/
`fs.mkdirSync()`/`el.appendChild()`/`emitter.emit()` 这些**同步/非 Promise 调用**
全被误判为"未 await 的 Promise"。
- 实证：deepseek-studio round-003 全量 5,268 命中里 **4,973 条（94%）是 TS-03**，
  其中 studio 自身 837 条、嵌套副本 4,135 条。这是"P4（targeted 模式不过滤
  generic_text 噪音）"长期挂账的实质——单条规则就淹没了所有真实信号。
- **【2026-10-12 收敛】**：叠加两道白名单——① `TS03_OK_HINT`（行内有
  `.catch(`/`await `/`void `/`console.`/`logger.`/`expect(` 或边界正则匹配
  `await|void|return|it|test|describe` 调用，即"已被处理/常规忽略"）；② 扩大
  `TS03_SYNC_WHITELIST` 到 HTTP/Node/DOM 同步 API（`.setHeader(`/`.writeHead(`/
  `.end(`/`.exit(`/`process.exit(`/`Sync(`/`.appendChild(`/`.addEventListener(`/
  `.removeEventListener(`/`.setAttribute(`/`.emit(`/`.delete(`/`.add(`/`.remove(`/
  `.replace(`）。
- 效果：TS-03 studio 自身 **837 → 455**（降噪 46%），叠加 N10 项目级 skip 后
  全量 **5,268 → 557**（降噪 89%），455 条剩余多为 `fetch`/全局函数/可能 Promise 的
  `close`/`start`/`kill`，作为 info 级（NEEDS_REVIEW）清单可接受。
- 根治方向：**AST 语义分析**（解析调用目标类型是否返回 Promise），正则白名单是
  治标——每加一个框架 API 就维护一次黑名单不可持续。短期把 TS-03 维持 info 级、
  当"人工过一遍"清单即可，不要据此写"此处无缺陷"结论。

---

## 本轮（2026-10-13 · AutoForge 第四期 103 轮元分析）新增

> 来源：元宝 watcher 对 `lidicn/AutoForge` 第 1–103 轮审计汇总包。核心结论——
> "没找到多少 bug"是**判据噪声淹没信号**：483 条台账里确证约 86、假阳性/证伪 45+ 组、
> 判据缺口 40、流程事故 41。该沉淀的不是那 86 条（属被审方的债，应合补丁），
> 是下面这些**审计方自身**可复用的教训。

### 假阴性（续）

**N13｜审计自指陷阱：清点的分母取自"报告提没提过族名"**
watcher 判断"还剩多少没核"历经 4 版，每版分母都取自"报告文本是否提过该族"——
而"写报告、登记台账"这两个动作**本身就会把零覆盖变成已覆盖**（AF-SCOPE-080）。
且 18 条 rule 对受审语料 `src/` 零贡献，历轮却一直在给这些"零覆盖族"做分诊。
- 修法：分母必须 **machine-computed**（rule × 子树实际命中，如 W186/W187），
  清点脚本**不得读自己的报告/台账文本**；先确认 rule 在受审作用域内有信号再分诊。

### 假阳性（续）

**P19｜静态形状判据不认"外部约束层 / 下一行防御 / 实参来源"**
103 轮 45+ 组假阳性的共同根因：判据只看代码形状，不看形状之外的约束——
`check_*` 不抛即通过但 `src/` 内**零调用方**；DO 族"读不出来⇒整档覆盖"但五处写侧
**紧邻落盘那行都装了 refuse 护栏**；PAT-07"无界容器"但项目有 **105 项豁免登记表**；
`json.loads(resp.text)`/`json.loads(stdin.read())` 被当"文件损坏"但实参**根本不源自
文件读**（23 个"真无痕"站点里 9 个不读文件，可砍 39% 假阳性）。
- **【2026-10-13 已落地 · AFS-04】**：`state_defects.check_unguarded_load` 加两道降噪——
  ① **站点级去重**：`json.loads(x.read_text())` 读链上 json.loads 与 read_text 双报改为
  由外层 json.loads 代表整链（AutoForge 副本实测 20→12 站点）；② **认实参来源**
  （`_arg_is_file_read`）：json.loads 实参若非本函数文件读（排除 stdin/HTTP/SSE/socket
  receiver 的 `.read()`），"文件损坏"判词不适用 → 降 info 不派单。
- 通则：形状判据收敛时，"排除"的边界要划在**终点语义**（读路径终点 vs 写侧有护栏）
  与**实参来源**上，不是划在"像不像坏味道"上。

**P20｜rule 编号"族号 vs 全名"口径不一，护栏全量误报**
`core/recall.py` 的 `RULE_FAMILY` 用**族号**（`AFS-04`）做 key，而 findings 的 `rule`
字段是**全名**（`AFS-04-unguarded-load`）。用全名精确匹配族号 key → 把已登记规则全量
误报为"未登记"（本次自测即暴露）。
- **【2026-10-13 已落地】**：`engine/hit_set_diff.unregistered_rules` 改为**族号前缀匹配**
  （`rule.startswith(fam + "-")`）。通则：跨模块对 rule 名做集合运算前，先统一口径
  （族号 / 全名），否则"对不上的都算未登记"。

### 事故（续）

**M7｜PoC / 复测"假绿灯"族（41 条流程事故里最危险的一组）**
- 门禁双侧复跑循环里没 `cd`，两次都从补丁副本启动 ⇒ 两侧 rc=1、条数行号全同，
  "看起来像补丁没引入漂移"，**实际跑的是同一棵树**（差点交付假绿灯）。
- PoC 直接调内层函数，**绕过捕获它的 `except: continue` 循环** ⇒ 26 组全 SAME，是假的。
- 盘面构造末尾无条件 `chmod 777` 把刚设的权限改回去 ⇒ "双侧同失败"被误读为"补丁失效"。
- 清理动作覆盖了被测盘面；判据用子串匹配（`"summary"` 是 `"project_summary"` 子串）恒真却"跑通"。
- 补丁路径写成基线树而非 patched 树，与"补丁失效"完全同形。
- 修法：① 双侧必须 `from` **不同树**并断言根路径；② PoC 走**真实入口**不能绕过捕获循环；
  ③ 清理只清临时产物、**绝不触及被测盘面**；④ 判据先做正/负自检再信 rc；
  ⑤ 打补丁前后 `git apply --check` + 与 full/ 逐字节比对。

### 方法论通则（续）

**通则 A｜证据可信度必须显式标注：测试无回归背书 ⇒ "双侧一致 = 同形 ≠ 全绿"**
AutoForge 项目自带测试因 `homesdk` 缺失两侧同样 collection error——所有"patched 后
双侧一致"只是**两侧同样跑不起来**，不是全绿。门禁多道自述"读不出 git 索引的降级档"，
`rc=0 ≠ CI 一定绿`。
- 通则：审计结论必须带**回归背书状态**（有无可跑通的测试基线）；无背书时"一致"
  只能表述为"同形"，并显式声明"未获回归背书"。

**通则 B｜族级计数 ≠ 站点数，键级差 ≠ 工作量**
实测族级计数与 `(file,line)` 去重后站点数**差 42%**；`hit_set_diff` 键级
（rule,file,line）差集 775 vs rule 级净额 +25，**差 30 倍**（行号漂移 + rule 改名被
放大成新增/移除）。历轮"还有 54 条没核"系统性高估工作量。
- **【2026-10-13 已落地】**：`engine/hit_set_diff.py` 增加**三档口径分层**
  （键级 / 站点级(file,line 去重) / rule 级净额）+ **rule 编号稳定性护栏**
  （两轮 rule 名集合 diff，新增/消失提示"可能是改名而非增删"）+ 召回护栏。
- 通则：报"还剩多少没核"必须给站点级或 rule 级净额，并标注键级差被放大的风险。

**通则 C｜射程声明：扫描面之外不下结论**
本次受审语料只有 `src/`（103 个 `.py`），`tests/` 与 `scripts/` 不在射程；18 条 rule
对语料零贡献（如 AFS-03 信号 100% 落在 tests/scripts）。5 个 GitHub 链接全程解析失败，
远端最新情况未确认。
- 通则：报告必须带**射程边界**（扫了哪些路径、哪些 rule 对该语料零信号、哪些外部
  依赖未验证）；射程外的"0 命中"不得读成"无缺陷"。
