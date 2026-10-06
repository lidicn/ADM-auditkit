# 已证实的反模式与不变量清单

全部来自 doubao-butler 五轮审计的实锤发现。每条注明来源，供新项目复用。

---

## 一、静态反模式（S1，模式匹配）

| ID | 反模式 | 来源 | 为什么是坑 |
|---|---|---|---|
| P1 | `run_coroutine_threadsafe` 的 Future 从不 `.result()` | V13 | 协程异常存在 Future 里，调用线程 try/except 落空 → **失败被记成 mark_success** |
| P2 | async 函数内阻塞调用（`time.sleep` / `subprocess.run` / 同步 `httpx`） | V18 | 阻塞整个事件循环。排除 `run_in_executor` / `to_thread` 包裹 |
| P3 | `asyncio.create_task` 返回值未保存 | V6 | asyncio 只持弱引用，Task 可能在完成前被 GC |
| P4 | `except: pass` / `except Exception: pass` | 系统性 | 故障静默。本项目 55 处，门禁基线 42 条豁免 |
| P5 | 状态文件非原子写（直接 `open(w)` + `json.dump`，无 `os.replace`） | T-2 | 写一半进程被杀 → 重启后 json 解析失败 → 降级路径静默 → **防护消失** |

P5 在 doubao-butler 上最新命中 4 处（我五轮都没读过这些文件）：
`api/push_routes.py:151`、`core/cron_task.py:110`、`core/fast_routes.py:43`、`memory/feeder.py:53`——4 个文件 `os.replace` 计数均为 0。

---

## 二、不变量（S3，属性断言——唯一自动发现层）

不变量的价值不在复现已知 bug，而在**发现没预料到的形状**。写新不变量前先问：它超出源发现还能抓到什么？

### INV-1 async 纯净
**声明**：async 函数体内不得出现阻塞调用。
**源起**：V18（docker_tools 的 `time.sleep`）。
**超出**：能抓到任何 async 路径上的同步 IO，不必事先知道它叫什么。
**误报控制**：排除 `run_in_executor` / `asyncio.to_thread` 包裹的同步 helper。

### INV-2 状态文件耐久
**声明**：写 JSON 状态文件必须走 `tmp` + `os.replace` 原子替换。
**源起**：T-2（trigger 冷却文件非原子写，重启后冷却表静默归零 → 触发风暴）。
**超出**：项目里 `config_routes`、`skills/store`、`triggers/store`、`deps` 会话文件**都实现了原子写**，唯独漏了最该耐久的冷却文件——说明这是**遗漏而非无知**，同类遗漏大概率还有第二处。S3 首次运行即证实：另有 4 处同类遗漏。

### INV-3 失败可观测
**声明**：捕获异常后不得无条件返回成功态。
**源起**：V13 + 系统性（`{"ok": True}` 常量返回）。
**超出**：覆盖所有"咽下异常再报成功"的写法，不局限于调度层。

### INV-4 异常可见
**声明**：异常处理分支不得引用未定义符号。
**源起**：P0-3（`config_routes.py:23` 的 `except` 分支引用未定义的 `logger`）。
**超出**：降级路径里的 `NameError` 是本项目系统性病灶——"兜底代码自己崩了"。ruff F821 早已报出但项目未修。

### INV-5 副作用守恒
**声明**：同一操作的多个执行路径，副作用集合必须一致。
**源起**：T-1（`dialog.speak` 走队列后提前 return，`dedup.record` / `repo.add_turn` / `_publish_dialog` 三个副作用全丢）。
**超出**：这个形状**极其通用**——任何"if 快路径: return"都可能漏副作用，是提前 return 类缺陷的通杀检测。当前 doubao-butler 上 0 命中，属正常（需人工标注路径对才能生效）。

---

## 三、复杂度与缺陷密度的关系

在 doubao-butler 上实证：

| 函数 | CC | 我独立发现的缺陷数 |
|---|---|---|
| `on_wakeup` | 63 | 3 |
| `enqueue_item` | 32 | 2 |
| `speak` | 高 | 1 |

**复杂度热点与缺陷落点高度重合**。所以 S2 的优先级地图不是装饰——它直接告诉你下一轮该读哪里。

**⚠ 但第六轮证伪了这个推断的外推**：CC=93 的 `dispatch_tool` 实测**干净**——
15 个被调函数同步/异步一致性 0 处不一致、未知工具名有兜底、异常有边界。
它是扁平 if-链查表分发器，每个分支都是 `name == X → 调 Y` 的单行映射，
**无状态、无副作用交错**。

修正后的判据：
- **适用**：函数内含状态与副作用交错（on_wakeup、enqueue_item 均属此类）
- **不适用**：纯查表式分发器、扁平路由表、配置映射

教训：复杂度是**必要不充分**条件。S2 给的是"值得读"，不是"一定有 bug"——
两者混同会把审计变成按分数抄答案。

---

## 四、反测设计要点

反测证明"报告里给的修法确实有效"，比正测更有价值（正测只证明缺陷存在）。

- **不是 mock**：用 `rebind()` 取真实函数源码、改目标几行后重新编译绑定，全局符号仍解析到真模块。
- **`keep_original`**：注入副作用后仍要保留原 `return`，否则控制流穿透、副作用执行两次（V7 反测踩过）。
- **`swallow_continuation`**：替换续行开头会留下孤儿行 → `IndentationError`（V8/V9 反测踩过）。
- **`_MISSING` 哨兵**：恢复"原先不存在的属性"要 `delattr` 而非 `setattr`（V10 反测踩过）。
- **断言要精确**：只盯单个名字/行为，不做宽泛扫描（V18 反测曾因 `or True` 假通过）。


---

## 五、信号分 ≠ 缺陷密度（第九轮实证）

第九轮审计了 core 第 2、3 名（`mcp/server.py` 640 行、`api/skill_routes.py` 1061 行），
**零新缺陷**。三条疑点全部核实为无问题：

| 疑点 | 核实结果 |
|---|---|
| 52 端点是否有未授权访问 | 53/56 函数带 guard，无 guard 的 3 个全是内部 helper |
| LLM 调用无 wait_for 包裹 | `httpx.AsyncClient(timeout=llm_timeout)` 已兜底，默认 30s |
| async 内同步调 validate_skill | 实测 0.004ms 且零 IO，阻塞可忽略 |

**结论**：Phase A 的信号分预测的是"值得读"，不是"一定有 bug"。
这与第六轮"CC≠缺陷"是同一教训的第二次实证——**高信号密度区 ≠ 高缺陷密度区**。

### 混合聚焦（应对办法）

单纯按信号分会反复把已读烂的文件推进 core。已改为**未读文件 ×1.6 权重**，
让盲区能与危险区竞争。这是"探索 vs 利用"的权衡。

---

## 六、产出递减与下一步（九轮复盘）

新缺陷产出：14 → 4 → 3 → 2 → 1 → 0（递减）
证伪产出：稳定

**静态分析已达边际收益上限。** 继续扩大扫描范围是在已排除风险的地方重复投入。
建议转向：
- **A. 运行时验证**：把 lifespan 跑起来，专攻并发类缺陷（SQLite 跨线程至今未证实）
- **B. 属性测试**：hypothesis 随机输入打边界，突破静态分析上限


---

## 七、同类扩散排查（第十轮新增，产出递减的解法）

R8→R9 产出递减到 0，一度判断"静态分析触顶"。第十轮加 `propagate.py` 后
**产出回到 2**——说明递减不是"缺陷挖完"，而是**方法触顶**。

已实现 5 个形状：

| 形状 | 源 | 状态 |
|---|---|---|
| `new-loop` | V23 跨循环挂死 | ✅ done @R10：34 处 → 坐实 V24、证伪 runner.py:450 |
| `direct-speak` | V15 绕过 TTSQueue | ✅ done @R11：27 处 → 坐实 V26 |
| `success-err` | V13 失败报成功 | ⬜ TODO |
| `blocking` | V18 async 内阻塞 | ⬜ TODO |
| `nonatomic` | T-2/V20 非原子写 | 🔶 partial @R6 |

**剩余 3 个形状未排查**，是 R12+ 最直接的产出来源。

### 扩散层的经验：对照组是判据的关键

R11 找到 V26，靠的是**比较 5 处同形状调用点**：
4 处都传了 `device_id`（绑定通过），唯独 `anomaly.py:371` 没传且多传了 `priority`。
**同形状之间的横向差异，比单点的绝对判断可靠得多**——
单看 anomaly 那行代码，很容易误判成"大概能播吧"。

### 关于懒初始化（V25 通用教训）

```python
if _x is None:          # 锁外检查
    c = create()
    with lock:
        _x = c          # 先发布
    init(c)             # 后初始化  ← 其他线程可能拿到未初始化的对象
```

**加双重检查不够。** 正确做法：`with lock: if _x is None: c=create(); init(c); _x=c`
——**初始化完成后再发布**。反测实测：仅加双重检查 7 次半初始化，正确改法 0 次。


---

## 第十四轮备查：新工具（第十三轮安装）

| 工具 | 状态 | 用途 | 备注 |
|---|---|---|---|
| pytest-xdist | ✅ | 并行 | `-n auto` |
| pytest-timeout | ✅ | 防用例挂死 | **V23 反测曾把自己陪葬**，必须有 timeout |
| pytest-randomly | ✅ | 随机顺序 | 能暴露 V4 那类用例间污染 |
| pytest-rerunfailures | ✅ | 抖动重试 | |
| deal | ✅ | 契约式（pre/post/inv） | 与 hypothesis 集成 |
| icontract | ✅ | 契约式（含继承） | 违规信息最详细 |
| faker | ✅ | 真实感随机数据 | |
| mutmut | ✅ | 变异测试 | **第十四轮首选**：验证 641 个测试里有多少真在测东西 |
| crosshair | ⚠️ | 符号执行 | 需重装，第十四轮若可用优先于 hypothesis |

### 第十四轮建议顺序

1. **mutmut 变异测试** —— 当前证据最弱的一项：641 passed 里有多少能真正抓住缺陷？
2. **crosshair 符号执行** —— 比重跑 hypothesis 更聪明地找边界反例
3. 剩余 3 个扩散形状：`success-err` / `blocking` / `nonatomic`
4. 未读枢纽：`config.py`(39) / `store/`(26) / `skills/runner_types.py`(17)
