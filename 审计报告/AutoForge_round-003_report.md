# AutoForge 审计报告 · round-003

> 由 auditkit 自动生成。本报告是**机器候选**，非确证缺陷——
> 候选不实测不升级为缺陷（proposal-1 方法论）。

## 画像

- 主语言: python  文件数: {'python': 333, 'shell': 4, 'typescript': 36, 'yaml': 4, 'javascript': 70}  行数: {'python': 91371, 'shell': 572, 'typescript': 3304, 'yaml': 328, 'javascript': 6512}
- 框架: docker, fastapi, homeassistant, mqtt, pytest

## 汇总

| 指标 | 值 |
|---|---|
| 命中总数 | **547** |
| 严重度分布 | high 47 · medium 77 · low 423 |
| 规则数 | 17 |
| 分析器 | 2/2 ok |
| 引擎 active 规则 | 18 |

## ⚠ 零覆盖盲区（规则在该项目 0 命中）

> 零命中 ≠ 干净。可能是规则不适用，也可能是规则静默失效（PITFALLS N1）。需人工确认。

- `generic_text`

## 命中规则 Top 15

| 规则 | 命中数 |
|---|---|
| `py.silent_except_no_trace` | 316 |
| `py.except_broad_swallow` | 98 |
| `py.unbounded_container` | 35 |
| `TS-03-unhandled-promise` | 33 |
| `py.periodic_claim_no_loop` | 17 |
| `GEN-01-hardcoded-secret` | 9 |
| `TS-04-any-abuse` | 9 |
| `py.outbound_call_no_timeout` | 7 |
| `py.urlopen_direct` | 4 |
| `YAML-04-no-resource-limit` | 4 |
| `SH-04-no-shellcheck` | 4 |
| `py.dynamic_import_string` | 3 |
| `py.except_return_failopen` | 2 |
| `py.env_numeric_unguarded` | 2 |
| `YAML-02-latest-tag` | 2 |

## 命中文件 Top 10

| 文件 | 命中数 |
|---|---|
| `/data/workspace/audit/src/src/autoforge/af_service.py` | 39 |
| `/data/workspace/audit/src/src/autoforge/af_evo.py` | 32 |
| `/data/workspace/audit/src/src/autoforge/af_conflict_runtime.py` | 26 |
| `/data/workspace/audit/src/src/autoforge/af_version.py` | 18 |
| `/data/workspace/audit/src/src/autoforge/af_api.py` | 17 |
| `/data/workspace/audit/src/src/autoforge/af_catalog.py` | 17 |
| `/data/workspace/audit/src/src/autoforge/af_runtime_plugins.py` | 16 |
| `/data/workspace/audit/src/scripts/verify_adm_window.py` | 15 |
| `/data/workspace/audit/src/src/autoforge/af_auth.py` | 13 |
| `/data/workspace/audit/src/src/autoforge/af_conflict.py` | 13 |

## 高危缺陷明细（critical + high，共 47 条，列前 50）

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/scripts/check_outbound_guard.py:84`
- 说明: Visitor.self.raw 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class Visitor(ast.NodeVisitor):
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/scripts/check_outbound_guard.py:85`
- 说明: Visitor.self.exempt 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class Visitor(ast.NodeVisitor):
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/scripts/check_outbound_guard.py:86`
- 说明: Visitor.self.guarded 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class Visitor(ast.NodeVisitor):
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/scripts/check_outbound_guard.py:87`
- 说明: Visitor.self.openers 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class Visitor(ast.NodeVisitor):
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/scripts/check_outbound_guard.py:88`
- 说明: Visitor.self.findings 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class Visitor(ast.NodeVisitor):
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_adapters/mock.py:31`
- 说明: MockAdapter.self.calls 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class MockAdapter:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_auth.py:154`
- 说明: TokenRegistry.self._revoked 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class TokenRegistry:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_bus.py:179`
- 说明: EventBus.self.emitted 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class EventBus:
  ```

### py.except_return_failopen · `high`
**异常分支返回放行值**
- 位置: `/data/workspace/audit/src/src/autoforge/af_canary.py:103`
- 说明: except 返回 `True`（语义：放行 / 命中 / 通过）且无留痕 ⇒ fail-open

### py.json_parse_unguarded · `high`
**循环内裸 JSON 解析**
- 位置: `/data/workspace/audit/src/src/autoforge/af_cli.py:1062`
- 说明: `_metrics_snapshot` 循环内 JSON 解析未受保护：一条脏数据将中断整批

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_conflict.py:178`
- 说明: ConflictArbiter.self._release_log 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class ConflictArbiter:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_conflict.py:181`
- 说明: ConflictArbiter.self._circuits 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class ConflictArbiter:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_evo.py:289`
- 说明: GraphView.self.warnings 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class GraphView:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_evo.py:841`
- 说明: EvoScanner.self.warnings 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class EvoScanner:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_fault.py:232`
- 说明: FaultPlan.self.specs 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class FaultPlan:
  ```

### py.except_return_failopen · `high`
**异常分支返回放行值**
- 位置: `/data/workspace/audit/src/src/autoforge/af_flock.py:132`
- 说明: except 返回 `True`（语义：放行 / 命中 / 通过）且无留痕 ⇒ fail-open

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_health.py:455`
- 说明: HealthEngine.self.extra_ids 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class HealthEngine:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_health.py:463`
- 说明: HealthEngine.self._history 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class HealthEngine:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_insight_queue.py:90`
- 说明: InsightQueue.self.unreadable 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class InsightQueue:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_intervention.py:148`
- 说明: InterventionDetector.self.managed 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class InterventionDetector:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_nl_parse.py:1040`
- 说明: _Builder.self.nodes 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class _Builder:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_nl_parse.py:1041`
- 说明: _Builder.self.edges 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class _Builder:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_pretrigger.py:65`
- 说明: TriggerHistory.self._events 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class TriggerHistory:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_proposal.py:200`
- 说明: ProposalManager.self.order 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class ProposalManager:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_runtime.py:59`
- 说明: Runtime.self._exec_stats 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class Runtime:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_runtime_ext.py:68`
- 说明: ConfGrading.self.restore_corrupt 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class ConfGrading:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_scene.py:132`
- 说明: SceneManager.self._groups 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class SceneManager:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_scheduler.py:76`
- 说明: Scheduler.self._queues 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class Scheduler:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_scheduler.py:78`
- 说明: Scheduler.self._time_fired 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class Scheduler:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_vhass/action_queue.py:34`
- 说明: ActionQueue.self._pending 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class ActionQueue:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_vhass/bridge.py:62`
- 说明: HassAdapter.self.calls 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class HassAdapter:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_vhass/device_sm.py:68`
- 说明: DeviceSM.self.attributes 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class DeviceSM(ABC):
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_vhass/fake.py:273`
- 说明: FakeHAAdapter.self.calls 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class FakeHAAdapter:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_vhass/fake.py:277`
- 说明: FakeHAAdapter.self.unmodeled 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class FakeHAAdapter:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_vhass/high_fidelity.py:126`
- 说明: HighFidelityHA.self._attributes 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class HighFidelityHA:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_vhass/high_fidelity.py:243`
- 说明: HighFidelityAdapter.self.calls 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class HighFidelityAdapter:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_vhass/high_fidelity.py:245`
- 说明: HighFidelityAdapter.self.unmodeled 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class HighFidelityAdapter:
  ```

### py.unbounded_container · `high`
**无界累加容器**
- 位置: `/data/workspace/audit/src/src/autoforge/af_vhass/sse_stream.py:26`
- 说明: FakeSSEStream.self._emitted_ids 只进不出：无 pop/clear/del，也无 maxlen/max_* 界化证据
- 代码:
  ```
  class FakeSSEStream:
  ```

### GEN-01-hardcoded-secret · `high`
****
- 位置: `tests/contract/test_af_ma_metrics_contract.py:101`
- 说明: 疑似硬编码凭据；应走环境变量/密钥管理
- 代码:
  ```
  res = Ingester(buffer_dir=tmp_path).push(_snapshot(), ma_url="http://ma.invalid", token="butler-tok-123", http_post=cap.
  ```

### GEN-01-hardcoded-secret · `high`
****
- 位置: `tests/unit/test_access_log_token_mask.py:34`
- 说明: 疑似硬编码凭据；应走环境变量/密钥管理
- 代码:
  ```
  SECRET = "SEKRIT-9f2c41be"
  ```

### GEN-01-hardcoded-secret · `high`
****
- 位置: `tests/unit/test_sse_pair_request_stream.py:141`
- 说明: 疑似硬编码凭据；应走环境变量/密钥管理
- 代码:
  ```
  assert live.status(token="tok-nope") == 403
  ```

### GEN-01-hardcoded-secret · `high`
****
- 位置: `tests/unit/test_sse_pair_request_stream.py:162`
- 说明: 疑似硬编码凭据；应走环境变量/密钥管理
- 代码:
  ```
  response, content_type = live.open_stream(token="tok-reporter")
  ```

### GEN-01-hardcoded-secret · `high`
****
- 位置: `tests/unit/test_sse_pair_request_stream.py:185`
- 说明: 疑似硬编码凭据；应走环境变量/密钥管理
- 代码:
  ```
  response, _ = live.open_stream(token="tok-reporter", header=True)
  ```

### GEN-01-hardcoded-secret · `high`
****
- 位置: `tests/unit/test_v1_4_credentials.py:15`
- 说明: 疑似硬编码凭据；应走环境变量/密钥管理
- 代码:
  ```
  cfg.update_credentials(ha_token="supersecret12345")
  ```

### GEN-01-hardcoded-secret · `high`
****
- 位置: `tests/unit/test_v1_4_credentials.py:64`
- 说明: 疑似硬编码凭据；应走环境变量/密钥管理
- 代码:
  ```
  cfg.update_credentials(ha_token="valid_token")
  ```

### GEN-01-hardcoded-secret · `high`
****
- 位置: `tests/unit/test_v1_4_credentials.py:76`
- 说明: 疑似硬编码凭据；应走环境变量/密钥管理
- 代码:
  ```
  cfg.update_credentials(ha_token="valid_token_123")
  ```

### GEN-01-hardcoded-secret · `high`
****
- 位置: `ui-user-mimo/tests/store.test.mjs:16`
- 说明: 疑似硬编码凭据；应走环境变量/密钥管理
- 代码:
  ```
  const CREDS = { username: 'owner', password: 'non-empty-session' }
  ```

---

## 关于本报告

- 本报告由 auditkit 静态分析自动生成，是**候选命中**，不是确证缺陷。
- 静态命中有假阳性（详见 PITFALLS.md），需人工 triage + 实测确证。
- 原始数据: `findings/*.json` / `all-findings.json` / `summary.json`
