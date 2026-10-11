# AutoForge 审计报告 · auditkit round-005

> **审计日期**：2026-10-11
> **审计工具**：ADM-auditkit（NAS 容器 `auditkit`，SSH 到 `192.168.2.200`）
> **审计对象**：AutoForge —— NAS 容器内 `/data/workspace/audit/src`（bind mount `/vol1/1000/docker/autoforge`）
> **轮次**：round-005
> **方法**：auditkit 静态 AST + 文本规则扫描 → 547 条机器候选 → 6 组并行人工 triage（逐条读源码核验）

---

## ⚠ 审计范围声明

**本次审计的是 NAS 容器内的 AutoForge 源码，不是本地最新工作区。**

容器源码（`/vol1/1000/docker/autoforge`）比本地 `E:\NAS\AutoForge` 落后——本地今天刚改过但未同步进 NAS 的文件**不在本次审计范围内**：

| 文件 | 容器版本 | 本地版本 | 差距 |
|---|---|---|---|
| `src/autoforge/af_atomic.py` | 55 行（10-07） | 144 行（10-11 19:10） | 容器旧 |
| `src/autoforge/af_config.py` | 217 行（10-08） | 233 行（10-11 18:56） | 容器旧 |
| `src/autoforge/af_persist.py` | 249 行（10-07） | 257 行（10-11 18:58） | 容器旧 |
| `src/autoforge/af_api.py` | 1486 行（10-09） | 1450 行（10-09） | 容器版本行数更多（可能有未同步的本地删改） |

**结论适用范围**：本报告结论仅覆盖上述容器版本（截至 2026-10-09 那批改动）。`af_atomic`/`af_config`/`af_persist` 的最新本地改动需另行审计——建议同步后重跑一轮。

---

## 一、门禁前置：selftest

| 指标 | 值 |
|---|---|
| selftest 结果 | **通过** |
| 分析器数 | 21 |
| 状态分布 | `ok: 21` |
| 0 命中（规则失效） | 无 |
| clean 误报 | 无 |

**结论**：21 个分析器全绿、0 静默失效。round-005 的命中是真实命中而非规则坏了（PITFALLS N1 头号事故已排除）。

---

## 二、扫描汇总

| 指标 | 值 |
|---|---|
| 命中总数 | **547** |
| 严重度分布 | high 47 · medium 77 · low 423 |
| 规则数 | 17 active + 1 broken = 18 loaded |
| 分析器 | 2/2 ok |
| 画像 | python 333 文件/91371 行；框架 docker, fastapi, homeassistant, mqtt, pytest |

### 命中规则 Top 15

| 规则 | 命中数 | 严重度 |
|---|---|---|
| `py.silent_except_no_trace` | 316 | low |
| `py.except_broad_swallow` | 98 | low |
| `py.unbounded_container` | 35 | high |
| `TS-03-unhandled-promise` | 33 | medium |
| `py.periodic_claim_no_loop` | 17 | medium |
| `GEN-01-hardcoded-secret` | 9 | high |
| `TS-04-any-abuse` | 9 | medium |
| `py.outbound_call_no_timeout` | 7 | medium |
| `py.urlopen_direct` | 4 | medium |
| `YAML-04-no-resource-limit` | 4 | medium |
| `SH-04-no-shellcheck` | 4 | medium |
| `py.dynamic_import_string` | 3 | low |
| `py.except_return_failopen` | 2 | high |
| `py.env_numeric_unguarded` | 2 | medium |
| `YAML-02-latest-tag` | 2 | medium |

### 命中文件 Top 10

| 文件 | 命中数 |
|---|---|
| `src/autoforge/af_service.py` | 39 |
| `src/autoforge/af_evo.py` | 32 |
| `src/autoforge/af_conflict_runtime.py` | 26 |
| `src/autoforge/af_version.py` | 18 |
| `src/autoforge/af_api.py` | 17 |
| `src/autoforge/af_catalog.py` | 17 |
| `src/autoforge/af_runtime_plugins.py` | 16 |
| `scripts/verify_adm_window.py` | 15 |
| `src/autoforge/af_auth.py` | 13 |
| `src/autoforge/af_conflict.py` | 13 |

---

## 三、Triage 结论

### 3.1 确证的稳定性/功能性 Bug

**本次审计确证 3 条真 bug，全部来自 low 级静默吞抽样（详见第四节）。high+medium 124 条候选确证 0 条真 bug。**

5 个 agent 并行逐条读容器内源码核验 high+medium；1 个 agent 抽样核验 low 级 100 条无留痕宽捕。结论如下：

| 规则组 | 候选数 | 真 bug | 误报 | 质量问题 |
|---|---|---|---|---|
| `py.unbounded_container`（无界容器） | 35 | 0 | 35 | 0 |
| `py.except_return_failopen` + `json_parse_unguarded` + `outbound_call_no_timeout` + `env_numeric_unguarded` | 10 | 0 | 10 | 0 |
| `py.periodic_claim_no_loop`（周期声称无循环） | 17 | 0 | 17 | 0 |
| TS-03 + TS-04 + GEN-06（前端） | 43 | 0 | 34 | 9 |
| urlopen_direct + hardcoded-secret + shellcheck + YAML | 23 | 0 | 9 | 14 |
| **high+medium 小计** | **124** | **0** | **105** | **19** |
| low 级静默吞抽样（`except_broad_swallow`） | 100 | **3** | ~48 | — |
| **合计（抽样口径）** | **224** | **3** | **~153** | **~19** |

**3 条确证 bug 速览**（详见第四节）：

| 编号 | 危险 | 位置 | 缺陷 |
|---|---|---|---|
| **BUG-L1** | 中 | `af_api.py:676` | pending_asks 读失败静默返回 `asks:[]`，提问被丢失；写侧有留痕、读侧无——读写对称性缺口 |
| **BUG-L2** | 轻 | `af_runtime_plugins.py:331,340` | API 端点注册失败 `except: pass` 无 logger，缺失端点排障困难（两个实例） |

#### 3.1.1 无界容器（35 条，全误报）

全部误报，三类判据：

1. **单次 scan/单次请求临时集合**（P14 同类）：`check_outbound_guard.py` 的 `Visitor` 字段、`af_nl_parse._Builder` 的 nodes/edges、`af_evo.GraphView.warnings`、各测试装配器（`MockAdapter`/`FakeHAAdapter`/`FaultPlan`）——随 scan/测试结束即回收。
2. **有裁剪/有上限/有进有出**（P9/P14）：`af_bus.emitted` 是 `deque(maxlen=1000)`；`af_health._history` 有 `history_max=4096` + `del rows[:n]` 尾部裁剪；`af_conflict._release_log` 有时间窗裁剪 + 清空；`af_scheduler._queues` 有 `popleft` 消费；`af_scheduler._time_fired` 按天清理；`af_vhass/action_queue._pending` 有进有出 + 清理；`af_vhass/device_sm.attributes` 是 update/替换非 append。
3. **键集受图规模封顶**：`af_auth._revoked`（吊销黑名单，受 `MAX_ISSUED=10000` 约束）、`af_conflict._circuits`/`af_health.extra_ids`/`af_intervention.managed`/`af_runtime._exec_stats`/`af_scene._groups`（键=automation_id/entity_id，图内有限集）。

**两个边界项**（`af_pretrigger._events`、`af_proposal.order`）随运行时间 append 无显式上限，但靠 `_load()`/`load()` 从磁盘重置（重启安全）、语义上是需保留的台账/历史。不构成运行期内存泄漏 bug，但可作"加 max_* 上限"加固候选（与已有 `BUG-18` 修复模式对齐）。

#### 3.1.2 fail-open / 裸 JSON / 无超时 / env 裸转（10 条，全误报）

- **`py.except_return_failopen`（2 条）**：`af_canary.py:103` 和 `af_flock.py:132` 两处 `except → return True`，True 的语义是"有问题/有竞争"（告警方向），属 **fail-closed** 不是 fail-open。规则只看布尔值没区分 True 的语义方向。
- **`py.json_parse_unguarded`（1 条）**：`af_cli.py:1062` 的 `json.loads` 是 for 循环的**可迭代表达式**（循环开始前一次性解析整个文件），非循环体内逐条解析，不存在"一条脏数据中断整批"。且是 CLI metrics 命令非生产批量路径。
- **`py.outbound_call_no_timeout`（7 条）**：5 条在 `scripts/` 下一次性审计脚本（非生产路径）；`af_orchestrator.py:2323` 的 `session.ir.get("id")` 是内存 dict 查找（规则误识别为外部调用）；`af_service.py:2448` 的 `subprocess.Popen` 构造器本身非阻塞、不接受 timeout（timeout 应在 `.wait()`/`.communicate()` 上，此处未调用）。
- **`py.env_numeric_unguarded`（2 条）**：`af_catalog.py:260` 有 `os.getenv(X, "10")` 默认值；`af_service.py:1152` 既有默认值又有 try-except + clamp 负数 + warning，完全防护。

#### 3.1.3 周期声称无循环（17 条，全误报）

三类：
1. **被外部主循环/周期回调反复调用**（正确架构 P13）：`af_runtime.tick`（被 `af_live.py` 守护线程 `while not stop.is_set(): runtime.tick()` 调用）、`af_runtime_ext.tick`/`af_shadow.compare_due`（被 `later(3600.0, _tick)` 周期回调驱动）、`af_scheduler.tick`/`af_vhass/action_queue.flush`（被 tick 链路调用）。
2. **函数体实际有 for 循环**（规则触发条件不成立）：`sweep_orphans`/`runtime_plugins.tick`/`scheduler.tick`/`compare_due`/`register_device_services`。
3. **纯函数/一次性动作**（名字带周期含义但本不该自循环）：`verify`/`_emit`/`suspend`/`attach`/`restore_instance`/`wall_after`/`jump`/`parse_duration`/`advance`。

#### 3.1.4 TS 前端（43 条，0 真 bug）

- **TS-03 未 await Promise（33 条，全误报）**：工具把同步调用误判为漏 await——`localStorage`/`Map`/`Array.push`/`Vue app.use/mount`/`void` 返回的辅助函数都不是 Promise。所有 `async function` 内的 await 链（`api.login`/`api.logout`/`refresh`）均正确 await，标记的行只是同步副作用调用。
- **TS-04 any 滥用（9 条，质量问题非 bug）**：均为 API 响应体 `any` 类型标注，字段访问处均有 `|| ''`/`?? []`/`!!` 运行时兜底，不产生运行时类型错误。
- **GEN-06 日志泄敏（1 条，误报）**：`gh_ci_status.py:120` 的 token 只用作 `Authorization` 头，从不进入 `print`；还实现 `_NoRedirects` 在 302 前摘掉 Authorization 防泄露。

#### 3.1.5 脚本/shell/凭据/YAML（23 条，0 真 bug）

- **`GEN-01-hardcoded-secret`（9 条，全误报）**：全部是 tests/ 目录下的假 token 样本（`"SEKRIT-9f2c41be"`/`"tok-nope"`/`"supersecret12345"` 等），是测试断言对象非真凭据。
- **`py.urlopen_direct`（4 条，质量问题）**：全部在 `scripts/` 下一次性 CI/运维脚本，均传了 timeout，访问 GitHub API/本地端点，无敏感数据经手。
- **`SH-04-no-shellcheck`（4 条，质量问题）**：`gates.sh`/`metrics_push_cron.sh`/`preflight.sh`/`rollback.sh` 均有 `set -uo pipefail`，无 shell 陷阱，仅缺 shellcheck 指令注解。
- **YAML 类（6 条，质量问题）**：`docker-compose.api.yml`/`api-test.yml` 用 `image: ...:latest` 且未设 `deploy.resources.limits`，无直接 OOM 场景。

---

## 四、低级候选（low 423 条）抽样核验

low 级 423 条里 `py.silent_except_no_trace`(316) + `py.except_broad_swallow`(98) + `py.dynamic_import_string`(3) + `py.except_broad_swallow`(其余)。规则 message 自身声明"它本身不是缺陷，是 CWE-390 读失败被当没数据族的必要前兆"——这是**前兆标记**非确证。

按"message 提到 logger/留痕 = 良性"筛出 100 条无留痕宽捕，逐条读 except 块体核验（6 个 agent 分文件覆盖）。

### 4.1 真吞可疑（3 条，确证为稳定性/功能性缺陷）

#### BUG-L1（中危）：pending_asks 读失败静默吞，提问被丢失

**位置**：`src/autoforge/af_api.py:676`
**代码**：
```python
@app.get("/api/asks/pending", dependencies=[Depends(_read)])
def api_asks_pending() -> dict[str, Any]:
    ...
    try:
        data = json.loads(sc.read_text(encoding="utf-8"))
        return {"ok": True, "asks": data.get("asks", []), "ts": data.get("ts", 0)}
    except Exception:
        return {"ok": True, "asks": []}   # ← 无 logger，把读失败当"无待答"
```
**缺陷**：`pending_asks.json` 是 watch 进程写出的 sidecar，供 DB/butler 轮询发现挂起 ask。文件存在但 JSON 损坏/权限错误时，读侧静默返回 `asks: []`，调用方认为"没有待答提问"——**提问被静默丢失**。

**读写对称性缺口**（确证证据）：写侧 `af_live.py` 明确有 `logger.warning("pending_asks 原子写入失败...")` 且注释"R14-01/R14-03 修复：写失败不得静默吞掉，否则 butler 永远读不到待答而静默丢失提问"。但**读侧没有对等的留痕**——写失败有人管，读失败静默吞。

**影响**：但ler/DB 查询 `/api/asks/pending` 得到空列表，已挂起的提问被静默丢弃，用户无感知。与此前确证的 F8/F9/F10（读失败被当没数据族）同族。

**建议修复**：except 块加 `logger.warning("pending_asks 读失败...", exc_info=True)`，并返回 `{"ok": False, "asks": [], "error": "read_failed"}` 让调用方能区分"无待答"与"读失败"。

#### BUG-L2（轻）：API 端点注册失败静默吞，排障困难

**位置**：`src/autoforge/af_runtime_plugins.py:331` 和 `:340`（同一问题两个实例）
**代码**：
```python
# conf 分级引擎端点（:331）
try:
    ...install_api(app, ...)
    mounted = True
except Exception:
    pass
# 冲突仲裁器端点（:340）
try:
    from autoforge.af_conflict_runtime import install_api as _conflict_install
    _conflict_install(app, ext.conflict)
    mounted = True
except Exception:
    pass
```
**缺陷**：conf 分级引擎或冲突仲裁器的 API 端点注册失败时，`except: pass` 无 logger，服务照常启动但缺少端点。`mounted` 可能因另一端点装上而仍为 True，注册失败完全无痕迹。

**影响**：WebUI 调用缺失端点时 404，但用户无法从日志得知"注册阶段就失败了"（以为是路由配错或端点被删）。排障难度增加。影响较轻——缺失会被前端 404 发现，但定位成本高。

**建议修复**：两处 except 加 `logger.warning("...端点注册失败...", exc_info=True)`，保留诊断痕迹。

### 4.2 良性（约 48 条已核验，其余 323 条按前兆标记处理）

抽样 100 条无留痕宽捕中，除上述 3 条真吞可疑外，其余约 48 条逐条读源码确认为良性，分四类：

- **有留痕（~20 条）**：except 块体内有 `logger.warning/error/debug/exception` 或 `runtime.audit.append(...)`。典型：`af_runtime_plugins.py` 的 tick/observe 钩子（`:83/92/106` logger.debug）、`af_conflict_runtime.py:501/509`（bridge 未接线 warning）、`af_live.py` 的 ticker/inbox 循环（`:333/457/493/567/570` 全有 logger.exception）。
- **有意识降级（~25 条）**：except 返回安全默认值且 docstring/注释说明意图。典型：`af_adapters/ha.py` 的 get_state/all_states（docstring "失败返回 None/{}"）、`af_catalog.py:782/794`（经验库失败降级为不生效）、`af_closedloop/history.py:41`（跳过坏行并计数 `skipped += 1`）、`af_orchestrator.py:1092`（LLM 解析失败 fallback 到 HeuristicIntentParser）。
- **fail-closed（3 条）**：except 里 re-raise 或按最坏情况处理。典型：`af_conflict_runtime.py:346`（`except BaseException: self._safe_release(...); raise`）、`af_service.py:240/269`（探测失败按"不能写"处理）。
- **非命中（1 条）**：`af_api.py:1334` 该行实际在 docstring 内，非 except 块（规则行号偏移误报）。

### 4.3 整体评价

`src/autoforge/` 在异常处理维度整体质量相当高——绝大多数宽捕 Exception 都有留痕或有意识降级，不少还带 docstring 说明 fail-closed/fail-open 语义。3 条真吞是少数漏网，其中 BUG-L1（pending_asks 读侧）有明确的读写对称性缺口证据，应优先修复。

---

## 五、附带发现（非规则确证，需人工确认）

以下两项不在规则命中清单内，由 triage agent 读源码时发现，需人工确认：

### 5.1 疑似真凭据硬编码

**位置**：`docker/docker-compose.api-test.yml:14`
**内容**：`MQTT_PASSWORD=e181b6538e54b1e7f0668e1036213d53`（32 位十六进制串）

GEN-01 规则未标记此文件（可能因非 tests/ 目录的扫描范围）。但这条比测试源码里的假 token 更接近真凭据——32 位十六进制串符合 MQTT broker 口令特征。主 compose `docker-compose.api.yml` 已正确示范从宿主机 env/secrets 注入敏感值，这份 test compose 没跟进。

**建议**：确认是否真实 MQTT broker 口令。若是，迁移到 `.env` 或 docker secrets（与主 compose 做法对齐）。

### 5.2 疑似死代码

**位置**：`src/autoforge/af_executor.py:442` `sweep_orphans`
**现象**：docstring 声称"定期调用（如每次 tick 后）"，但 grep 全仓无任何调用点。

**建议**：确认是否废弃。若是，删除或补调用点；若是有意保留的应急接口，补注释说明。

### 5.3 加固候选（非 bug）

两个无界容器边界项可加 `max_*` 上限加固：
- `src/autoforge/af_pretrigger.py:65` `TriggerHistory._events` —— 随触发频率 append 无显式上限（靠磁盘重置兜底）
- `src/autoforge/af_proposal.py:200` `ProposalManager.order` —— 随提案提交率 append 无显式上限（靠磁盘重置兜底）

与已有 `BUG-18` 修复模式（`demote_errors_max`/`max_records`）对齐，加上限更稳。

---

## 六、规则改进建议（写给 auditkit 维护者）

triage 过程发现若干规则系统性误报模式，建议改进：

| 规则 | 误报根因 | 建议改进 |
|---|---|---|
| `py.except_return_failopen` | 只看 `return True` 的布尔值，未区分 True 的语义方向（告警 vs 放行） | 增加语义判据：True=告警方向（canary/flock）不算 fail-open |
| `py.outbound_call_no_timeout` | 把 `session.ir.get()`（内存 dict 查找）误识别为外部调用 | 排除 `.get(`/`[...]` 等 dict/映射访问 |
| `py.outbound_call_no_timeout` | 把 `subprocess.Popen`（非阻塞构造器）当作需 timeout 的调用 | Popen 本身非阻塞，timeout 只适用于 `.wait()`/`.communicate()` |
| `py.unbounded_container` | 漏识别 `dict[key]=整体替换`（非累加）和"键集受图规模封顶" | 增加"整体替换"识别；键集为有限 entity_id 的 dict 降级 |
| `py.json_parse_unguarded` | 把 for 循环可迭代表达式的一次性解析当作循环内逐条解析 | 区分 `for x in json.loads(...)` vs `for x in items: json.loads(...)` |
| `TS-03-unhandled-promise` | 把 localStorage/Map/Array/Vue 同步 API 误判为未 await Promise | 增加同步 API 白名单（localStorage/Map/Set/Array/Vue app.use/mount） |

---

## 七、方法论与局限

1. **候选不是确证**（PITFALLS 通则 2）：547 条全是机器候选，本次 triage 逐条读源码核验后才定论。
2. **零覆盖盲区**：`generic_text` 模式 0 命中——该模式可能不适用于 AutoForge（文本规则仍产出 17.6K findings），需人工确认不是静默失效。
3. **审计范围局限**：见上方"审计范围声明"——容器源码落后于本地，`af_atomic`/`af_config`/`af_persist` 最新改动未覆盖。
4. **low 级未全量核验**：423 条 low 中抽样核验 100 条无留痕宽捕（见第四节），其余 323 条按规则 message 自身声明"它本身不是缺陷"处理（前兆标记非确证）。
