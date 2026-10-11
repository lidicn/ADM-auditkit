# 跨项目审计经验总结 · round-008

- **总结人**：Claude Code · ADM-auditkit 审计 agent
- **日期**：2026-10-12
- **范围**：10 个项目（AutoForge / doubao-butler / memory-agent / ADM-auditkit / deepseek-pp / deepseek-studio / DeskPilot / TVPilot / xiaotiancai / PosterWall）

---

## 一、这批发现里哪些可机械化？（沉淀出口·规定动作）

### 已机械化（本提案 3 条新规则）

| 模式 | 规则 | 来源项目 | 跨项目复现度 |
|---|---|---|---|
| async def 内同步阻塞调用 | py.async_def_sync_block | DeskPilot | doubao-butler 生产 62 命中（FastAPI 项目通用） |
| open() 不用 with 传 Popen 不关句柄 | py.open_no_close_to_popen | DeskPilot | 守护进程模式通用 |
| while True 调 C SDK 无总超时 | py.sdk_while_no_timeout | DeskPilot | C SDK 集成场景通用 |

### 可机械化但本提案未做（需后续规则）

| 模式 | 来源项目 | 为什么没做 |
|---|---|---|
| JS/TS 裸 fetch 无 AbortSignal | deepseek-pp | auditkit 是 Python AST，JS/TS 需 generic_text 或专用分析器 |
| HttpURLConnection 未 disconnect | xiaotiancai (Kotlin) | Kotlin AST，auditkit 不支持 |
| Node http.request 无 error 监听 | DeskPilot (JS) | 同上 |
| Vue onUnmounted 在 async 内注册 | DeskPilot (Vue) | 框架特定，需专用规则 |
| MutationObserver 永不 disconnect | PosterWall (JS) | 同上 |
| Rust sidecar 进程树不级联杀 | deepseek-studio (Rust) | Rust AST，auditkit 不支持 |

**结论**：auditkit 当前能力边界是 Python AST。JS/TS/Rust/Kotlin 的缺陷模式目前只能人工 agent 审计，无法机械化复扫。若要覆盖，需扩展 auditkit 到 generic_text 或多语言 AST。

---

## 二、跨语言通则（不依赖具体语法）

以下是跨语言、跨项目的稳定性通则，人工 agent 审计时应逐条对照，不依赖 auditkit 规则：

### 通则 1：网络/IO 调用必须设底层 timeout

| 语言 | 错误形态 | 正确形态 |
|---|---|---|
| Python | `requests.get(url)` 无 timeout | `requests.get(url, timeout=10)` |
| JS/TS | `fetch(url)` 无 AbortSignal | `fetch(url, {signal: AbortSignal.timeout(10000)})` |
| Kotlin | `HttpURLConnection` 无 connectTimeout/readTimeout | `conn.connectTimeout = 10000; conn.readTimeout = 10000` |
| Node | `http.request({timeout:30000})` 不绑 'timeout' 事件 | `req.on('timeout', () => req.destroy())` |
| Rust | `Command::spawn` 无 stdin 读取超时 | 用 `tokio::time::timeout` 包装 |

**关键**：timeout 必须在**底层**（调用层），不能只在调用方的 barrier 层。deepseek-pp 的 recovery barrier 有 10s 超时但底层 fetch 无 AbortSignal——barrier 超时后 fetch 仍挂起。DeskPilot 的 Node http 设了 `timeout:30000` 选项但没绑事件监听器——等于没设。

### 通则 2：资源必须释放（语言无关）

| 资源 | 必须释放 | 跨项目复现 |
|---|---|---|
| 网络连接 | HttpURLConnection.disconnect() / fetch 的 AbortController | xiaotiancai、deepseek-pp |
| 文件句柄 | open() 用 with / 显式 close / 传 Popen 后父进程关 | DeskPilot、PosterWall |
| 进程 | Job Object 级联杀 / try_wait 轮询 / 不得 fire-and-forget | deepseek-studio |
| 监听器 | addEventListener 必有配对 removeEventListener（同引用） | DeskPilot、PosterWall |
| MutationObserver | observe 必有配对 disconnect | PosterWall |
| MediaPlayer | setOnError + onCompletion 双路径 release | xiaotiancai |

### 通则 3：错误路径必须复位状态

异常 catch 后，状态机必须恢复到一致态。三个反例：
- deepseek-pp：storage 失败时"永远刷新永远失败"循环无错误表面化
- deepseek-studio：loadConfig 静默吞错，回退默认覆盖原配置
- PosterWall：download 冷却在 qB 失败路径不复位（阻止用户重试）

### 通则 4：C SDK / 外部库不可信

while True 循环依赖 SDK 返回值退出 = 把可靠性押在 SDK 上。SDK 状态机卡死时循环永久挂起。**应在循环外加总超时/最大迭代守卫，而非依赖 SDK 自身正确性。**

### 通则 5：长期运行进程的容器必须有淘汰策略

"只进不出"的模块级容器（session 表、去重 set、缓存、历史）必须有 LRU/TTL/容量上限，否则内存随进程寿命单调上涨。跨 6 个项目复现（DeskPilot、AutoForge、memory-agent、TVPilot、doubao-butler、PosterWall）。

### 通则 6：读失败不能当成"没有数据"

AutoForge 20 轮审计的核心结论：读路径的失败被当成"没有数据"是 6 项缺陷的共同根因。doubao-butler 的 atomic_json 调用方同理——若忽略 `unreadable=True`，残缺数据当完整数据覆盖。修复通则：**读失败必须留痕，写侧在 unreadable=True 时拒绝整份覆盖**。

---

## 三、auditkit 能力边界与扩展方向

### 当前能覆盖

- Python AST 规则（21 条）覆盖：读失败降级、异常放行、无界容器、动态代码、SQL 拼接、JSON 未保护、固定 tmp 并发、环境变量裸转换、出站无 timeout 等
- 本提案新增 3 条覆盖：async 阻塞、Popen 句柄泄漏、SDK 循环无超时

### 不能覆盖（需人工 agent 或扩展）

- JS/TS：fetch 无 timeout、http 无 error 监听、innerHTML XSS、MutationObserver 泄漏、Vue 生命周期钩子误用
- Rust：进程树不级联杀、主线程 sleep 阻塞
- Kotlin：HttpURLConnection 不 disconnect、协程异常、lateinit NPE
- 跨语言文本（Dockerfile/shell/yaml）：部分由 generic_text 分析器覆盖，但能力有限

### 扩展建议

1. **generic_text 分析器扩展**：JS/TS 的 fetch 无 AbortSignal、http 无 error 监听可用正则覆盖（不依赖 AST）
2. **多语言 AST**：长期看需支持 JS/TS/Rust AST，但工程量大
3. **数据流分析**：ctypes 经中间变量赋值的形态需数据流追踪，当前 Python AST 规则无法覆盖

---

## 四、审计方法论经验

### 4.1 双路径审计（auditkit + agent）

10 个项目分两条路径：
- Python 项目用 auditkit AST 扫描（机器候选 → 人工 triage）
- 非 Python 项目用并行 agent 人工审读

**经验**：auditkit 适合"已知模式的批量复扫"，agent 适合"未知模式的首次发现"。两者互补，不可替代。本提案 3 条规则就是把 agent 发现的模式机械化回灌 auditkit。

### 4.2 triage 比扫描重要

round-008 机器候选 5577 条（4 项目合计），经 triage 后真实缺陷约 13 项（待核）。**扫描并行，triage 分批**——一次囤 3×500+ 条待裁决是反模式。

### 4.3 假阳性必须记录回灌

本轮发现 4 处假阳性（unbounded_container 漏认界化、rmw_silent_empty 误判局部变量、fixed_tmp 误判有意设计、mcp_tool_no_timeout 越界）。这些是 PITFALLS P6 通则的延续：**判据在被调方语义里，不在调用点语法里**。

### 4.4 临时副本噪音

memory-agent 扫描含 `.qoder/tmp-*` 临时副本，93% 命中是噪音。**下次审计前必须清理扫描对象的临时副本目录**，否则噪音淹没真信号。

---

## 五、分歧记录（与 DeepSeek++ 提案）

| 项 | 本提案（Claude Code） | DeepSeek++ 提案 |
|---|---|---|
| atomic_json.py 固定名 | 假阳性（有意设计） | 真缺陷（X-2，改 mkstemp） |
| 依据 | docstring 明写固定名防孤儿；风险在调用方 | 固定 tmp + os.replace 并发交错 |
| 建议动作 | 核查调用方 unreadable 处理 | 改 atomic_json 本身 |

两份提案并存，供维护者裁决。本提案立场：PITFALLS P6——判据在被调方语义里，atomic_json 的固定名是有意设计，不应改工具本身。

---

**署名**：Claude Code · ADM-auditkit 审计 agent
**日期**：2026-10-12
