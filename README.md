# auditkit —— 多项目审计工作流

从 AutoForge 二十轮审计的工作流**通用化**而来：把单项目硬编码的
`bash af_audit.sh round-020 --force` 改造为可同时维护多个仓库的统一入口。

```
auditkit profile  <path|project>    探测画像（语言 / 框架 / 入口 / 自建门禁）
auditkit sync     [project]         克隆或更新仓库（离线会**明确失败**，不假装成功）
auditkit round    <project> --round N   执行一轮审计
auditkit status   <project>         查看缺陷台账
auditkit selftest                   跑分析器自检门禁
auditkit pack     <project>         导出该项目审计产物
```

---

## 一、为什么需要通用化（AF 原工作流的四处硬编码）

| AF 原状 | 通用化改造 |
|---|---|
| 路径写死 `src/src/autoforge` | `profile.py` 探测主语言与 Python 包路径，`registry.py` 按画像分派 |
| 只支持 Python（AST） | 新增 `core/lang/generic_text.py`：跨语言通用规则 10 条 + ts/js/go/shell/yaml 专属规则 |
| semgrep / detect-secrets / 绘图缺失即 FAIL | `probe_tools()` 探测外部工具，**缺失标 `unavailable` 不算失败**（沙箱里 semgrep 反复装坏过） |
| 单项目、靠记忆调用 | `config/projects.yaml` 登记 + `auditkit` CLI 统一入口 |

另外补上了 AF 工作流里两处"静默失效"的坑，见 `PITFALLS.md`：

- `fetch_snapshot.py` 算出的增量判定**没落盘** → "无变更只跑轻量轮"从未生效
- 台账指纹含 `[str]`（正则字符类）→ 缺陷被误判 `unknown`

---

## 二、目录结构

```
adm-auditkit/
├── auditkit                 统一 CLI 入口
├── config/projects.yaml     项目登记表（repo / path / 已知技术栈 / 关注点）
├── core/
│   ├── profile.py           画像探测：语言、框架、测试、自建门禁、入口
│   ├── registry.py          分析器分派 + 外部工具能力探测 + 汇总
│   ├── aggregate.py         命中汇总
│   ├── backlog.py           缺陷台账回归复核
│   ├── fetch_snapshot.py    快照 / 增量
│   ├── dep_audit.py         依赖审计
│   ├── skill_scan.py        skill 扫描
│   ├── analyzers/           20 个专题分析器（纯 stdlib AST）
│   └── lang/generic_text.py 跨语言规则层
├── selftest/                自检门禁：dirty / clean 双样本 + golden 快照
├── projects/<项目>/round-NNN/   各项目各轮产物
├── scripts/                 辅助脚本
└── PITFALLS.md              21 轮踩坑清单（假阴性 8 / 假阳性 15 / 事故 12）
```

---

## 三、快速开始

```bash
# 0) 开工前必跑：验证 21 个分析器没有静默失效
python3 auditkit selftest

# 1) 获取源码（离线会明确报错，不要跳过）
python3 auditkit sync <project>

# 2) 先画像，确认技术栈判断正确（尤其是未知项目）
python3 auditkit profile <path>

# 3) 跑一轮
python3 auditkit round <project> --round 1

# 4) 看台账
python3 auditkit status <project>
```

**只有本地副本、没登记也能跑**：`python3 auditkit round <任意名> --path /path/to/repo`

---

## 四、接入新项目

1. `config/projects.yaml` 加一项：

```yaml
  my-project:
    repo: https://github.com/xxx/my-project
    path: /data/workspace/repos/my-project
    known_stack: 未知则写"未知"，先跑 profile 探测
    focus:
      - 该项目的特有风险（例如"外部模型调用无超时"）
```

2. `python3 auditkit sync my-project`
3. `python3 auditkit profile my-project`（确认 `主语言` 与 `Python 包` 判定正确）
4. `python3 auditkit round my-project --round 1`

**技术栈未知的项目不要凭猜测写规则**：先 `profile` 看真实文件构成。
`doubao-butler` 就是这种情况——配置里已标注"未知，按通用化处理"。

---

## 五、20 个专题分析器

| 主题 | 分析器 | 主题 | 分析器 |
|---|---|---|---|
| 稳定性/功能性 | `ast_defects` | 序列化往返 | `serialization_defects` |
| 状态持久化 | `state_defects` | 错误处理与降级 | `errorhandling_defects` |
| 并发与异步 | `concurrency_defects` | 可观测性 | `observability_defects` |
| 资源上限/复杂度 | `boundary_defects` | 配置兼容性 | `config_compat_defects` |
| 控制流与异常契约 | `controlflow_defects` | 测试缺口 | `testgap_defects` |
| 死代码与缓存契约 | `deadcode_defects` | 内部 API 契约 | `api_contract_defects` |
| 时间与数值边界 | `time_numeric_defects` | 语义正确性 | `semantic_defects` |
| 外部输入与信任边界 | `input_defects` | 资源生命周期 | `resource_defects` |
| 事务边界 | `consistency_defects` | 模式泛化 | `pattern_propagation` |
| 鉴权与权限边界 | `auth_defects` | 读写一致性 | `rmw_consistency` |
| 跨语言（非 Python） | `generic_text` | | |

---

## 六、自检门禁（最重要的一块）

**为什么必须有**：二十轮里至少三次差点把"规则坏了"当成"代码干净"。
规则失效不会报错，只会安静地报 0 —— 外表和"项目很干净"完全一样。

门禁逻辑：

- `selftest/cases/dirty/` —— 34 个已知缺陷（含 ts / sh / yaml 样本）
  每个分析器**必须至少命中 1 条**，0 命中即判 FAIL 并阻止本轮
- `selftest/cases/clean/` —— 全部是正确写法
  命中数与 `golden.json` 比对，新增即红警（规则变宽 → 假阳性回归）
- `selftest/expect.json` —— 确属良性的命中白名单，**每条必须附理由**

写新规则时请先读 `PITFALLS.md`，里面记录了嵌套函数、生成器裸 return、
`False == 0`、`or` 默认值、`FileLock` 跨进程锁等十余个反复踩到的坑。

---

## 七、已知限制

| 限制 | 说明 |
|---|---|
| 非 Python 语言覆盖较浅 | `generic_text` 是正则层，只覆盖高危模式（密钥硬编码 / SQL 拼接 / eval / TLS 关闭 / CORS 通配 / 特权容器）。要做深度分析需为该语言单独写 AST 分析器 |
| 静态分析候选需实测确证 | AF 的 21 个确证缺陷几乎全靠实测（OOM、16/30 陈旧读、时钟回拨、640× 退化、配对流程失败）。**候选不实测不升级为缺陷** |
| `pytest` 不可用 | 标 `unavailable`，与 `clean` 区分，不算通过 |
| 依赖 CVE 比对需联网 | 离线标 `unavailable` |

---

## 八、与 AutoForge 审计结果的关系

AutoForge 的 21 个确证缺陷及二十轮报告保留在 `../audit/`（已导出
`autoforge-audit-workflow.zip`）。本目录的 `projects/AutoForge/` 是
用通用化工作流**重跑**的结果，可作为两版工作流的对照。
