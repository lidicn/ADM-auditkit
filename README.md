# ADM AuditKit · 通用审计工作流整合方案

> 目标：将 4 份高度重复的审计工作流整合为一套 ADM 通用审计工具，一套代码跑 DB/AF/MA/DP 四个项目。
> 维护者：元宝（整合执行）
> 来源：E:\NAS\QA 下 4 份 zip 工作流

---

## 一、4 份原始工作流盘点

| 工作流 | 大小 | 定位 | 通用度 | 核心资产 |
|---|---|---|---|---|
| **auditkit** | 62KB | 轻量审计引擎 | 高 | `audit.py` (121KB 单核检测引擎) + `drive.py` + regression 回归测试 |
| **autoforge-audit-workflow** | 6MB（含AF源码） | 重量级 20 轮多维度审计 | 核心高 | `workflow/lib/` 30 个检测模块 + `workflow/af_audit.sh` 驱动 + `selftest/` 自测试 + 20 轮审计方法论 |
| **bug-hunter-workflow** | 119KB | 通用 bug 狩猎 | 高 | `scripts/` 14 个脚本（变异测试/属性测试/不变量/扫描排序）+ `project-suite/audit_helpers.py` (128KB) |
| **memory-agent_正规化审计全套** | 167KB | MA 项目专用 | 低（结果导向） | 7 份审计报告方法论 + 3 个专项测试（到达时间/设备匹配/身份融合） |

**已剔除**：autoforge 包中的 AF 完整源码（~5MB，被审计对象非工具）、memory-agent 的 127KB 结果 zip。

---

## 二、重复度分析

### 高度重复（必须整合）

**缺陷检测维度完全一致**——4 份工作流覆盖的检测维度几乎相同：

| 维度 | autoforge lib/ | bug-hunter | auditkit | MA |
|---|---|---|---|---|
| 并发/异步 | `concurrency_defects.py` | `concurrency.py` | ✅ | ✅ |
| 状态一致性 | `state_defects.py` | `invariants.py` | ✅ | ✅ |
| 错误处理 | `errorhandling_defects.py` | `core.py` | ✅ | ✅ |
| 鉴权/权限 | `auth_defects.py` | — | ✅ | ✅ |
| 资源泄漏 | `resource_defects.py` | `mutation.py` | ✅ | — |
| 死代码 | `deadcode_defects.py` | — | ✅ | — |
| 可观测性 | `observability_defects.py` | — | ✅ | — |
| 配置兼容 | `config_compat_defects.py` | — | ✅ | — |
| 测试缺口 | `testgap_defects.py` | `property_tests.py` | ✅ | ✅ |
| API契约 | `api_contract_defects.py` | — | ✅ | ✅ |
| 序列化 | `serialization_defects.py` | — | ✅ | — |
| 时间/数值 | `time_numeric_defects.py` | — | ✅ | — |
| 外部输入 | `input_defects.py` | — | ✅ | — |
| 数据一致性 | `consistency_defects.py` | — | ✅ | ✅ |
| 控制流 | `controlflow_defects.py` | `pipeline.py` | ✅ | — |
| 边界 | `boundary_defects.py` | `fast_core.py` | ✅ | — |
| 模式泛化 | `pattern_propagation.py` | `patterns.md` | ✅ | — |
| 依赖供应链 | `dep_audit.py` | — | ✅ | ✅ |
| 读写一致性 | `rmw_consistency.py` | — | ✅ | — |
| 语义 | `semantic_defects.py` | — | ✅ | — |

**结论**：autoforge 的 `workflow/lib/` 已经覆盖了全部 20 个维度，是最完整的检测引擎。bug-hunter 和 auditkit 的检测能力是其子集。

### 项目特有（不可整合，保留为参考）

- autoforge 的 20 轮审计报告（`rounds/round-0XX/审计报告-*.md`）—— 是 AF 项目的审计结果
- memory-agent 的 A1-A7 报告 —— 是 MA 项目的审计结果
- 每个项目的 semgrep 规则中有少量项目特定规则

---

## 三、整合方案

### 3.1 目标架构

```
adm-auditkit/
├── README.md                    # 本文档
├── sources/                     # 4份原始工作流（保留供参考，不修改）
│   ├── auditkit/
│   ├── autoforge-workflow/
│   ├── bug-hunter/
│   └── memory-agent/
├── core/                        # 【整合产物】通用检测引擎
│   ├── dimensions/              # 20个维度检测模块（从autoforge lib/去AF化）
│   │   ├── concurrency.py
│   │   ├── state.py
│   │   ├── auth.py
│   │   ├── errorhandling.py
│   │   ├── resource.py
│   │   ├── deadcode.py
│   │   ├── observability.py
│   │   ├── config.py
│   │   ├── testgap.py
│   │   ├── api_contract.py
│   │   ├── serialization.py
│   │   ├── time_numeric.py
│   │   ├── input.py
│   │   ├── consistency.py
│   │   ├── controlflow.py
│   │   ├── boundary.py
│   │   ├── pattern.py
│   │   ├── dep_audit.py
│   │   └── rmw.py
│   ├── rules/                   # 通用 semgrep 规则
│   │   ├── python-security-core.yml
│   │   ├── stability.yml
│   │   └── state.yml
│   ├── mutation.py              # 变异测试（来自bug-hunter）
│   ├── property_tests.py        # 属性测试（来自bug-hunter）
│   ├── graph/                   # 调用图构建+风险路径（来自autoforge）
│   │   ├── build_graph.py
│   │   └── paths_to_findings.py
│   └── aggregate.py             # 结果聚合（来自autoforge）
├── adapters/                    # 【整合产物】项目适配器
│   ├── db.yml                   # 豆包管家
│   ├── af.yml                   # AutoForge
│   ├── ma.yml                   # memory-agent
│   └── dp.yml                   # DeskPilot
├── report/                      # 【整合产物】统一报告生成器
│   └── generator.py
├── selftest/                    # 自测试（clean/dirty 样本）
│   ├── cases/clean/sample.py
│   └── cases/dirty/sample.py
├── audit.sh                     # 【整合产物】统一入口脚本
└── docs/
    └── 整合执行细案.md
```

### 3.2 整合步骤（分 3 阶段）

#### 阶段 1：以 autoforge workflow 为主体，去 AF 化（1-2 天）

**核心动作**：把 `sources/autoforge-workflow/workflow/lib/` 的 30 个模块复制到 `core/dimensions/`，逐个剥离 AF 硬编码。

**AF 硬编码类型**（需要替换为配置注入）：
1. 源码路径硬编码（如 `src/autoforge/`）→ 改为从 adapter 配置读取
2. AF 特定模块名（如 `af_orchestrator`、`af_mcp`）→ 改为通用模式匹配
3. AF 特定规则（`rules/autoforge-*.yml`）→ 移到 `adapters/af.yml` 的 rules 段
4. AF 特定导入（如 `from autoforge.af_conf import ...`）→ 改为可选导入，失败时降级

**验收**：`core/dimensions/` 每个模块 `import` 不依赖 AF 源码；用 `sources/selftest/cases/dirty/sample.py` 能检出已知缺陷。

#### 阶段 2：吸收 bug-hunter 的变异/属性测试（1 天）

**核心动作**：
1. 把 `sources/bug-hunter/bug-hunter/scripts/mutation.py` 和 `property_tests.py` 整合到 `core/`
2. 把 `sources/bug-hunter/project-suite/audit_helpers.py` (128KB) 的通用辅助函数提取到 `core/helpers.py`
3. 不变量检测（`invariants.py`）作为新维度 `core/dimensions/invariants.py`

**验收**：`audit.sh --mutation` 能对任意项目跑变异测试；`audit.sh --property` 能跑属性测试。

#### 阶段 3：统一报告 + 项目适配器 + 入口脚本（1 天）

**核心动作**：
1. 写 `adapters/db.yml` / `af.yml` / `ma.yml` / `dp.yml`，每个包含：
   ```yaml
   project: doubao-butler
   source_roots: ["butler"]
   exclude_paths: ["butler/static", "butler/graphify-out"]
   rules: ["python-security-core", "stability"]
   dimensions: ["all"]  # 或指定子集
   output_format: "markdown"
   ```
2. 写 `audit.sh` 统一入口：
   ```bash
   ./audit.sh --project db --dimensions concurrency,state,auth --output report.md
   ./audit.sh --project af --all --mutation
   ./audit.sh --project ma --selftest
   ```
3. 写 `report/generator.py` 统一输出格式（Markdown + JSON）

**验收**：`./audit.sh --project db --dimensions concurrency` 能对豆包管家跑并发检测并生成报告。

### 3.3 不整合的部分

- `sources/` 下 4 份原始工作流**原样保留**，作为参考和回退
- autoforge 的 20 轮审计报告（AF 项目结果）
- memory-agent 的 A1-A7 报告（MA 项目结果）
- auditkit 的 `最终审计报告.md`（特定项目结果）

---

## 四、关键设计决策

### 4.1 为什么以 autoforge workflow 为主体？

- 覆盖维度最全（20 个，其余 3 份都是子集）
- 最成熟（经过 20 轮审计迭代验证）
- 已有 selftest 框架（clean/dirty 样本）
- 已有调用图构建+风险路径分析（graph/）
- 已有 semgrep 规则体系（rules/）

### 4.2 为什么保留 bug-hunter？

- 变异测试（mutation testing）和属性测试（property-based testing）是 autoforge 没有的
- `audit_helpers.py` (128KB) 有大量通用辅助函数
- 不变量检测（invariants）是独特维度

### 4.3 为什么保留 auditkit？

- `audit.py` (121KB) 是单核轻量引擎，启动快，适合 CI 快速扫描
- `regression/` 有完整的回归测试框架
- 可作为 `core/` 的轻量替代方案

### 4.4 项目适配器模式

不把项目配置硬编码在检测模块里，而是通过 `adapters/*.yml` 注入。新增项目只需加一个 yml 文件（5 分钟），不需要改核心代码。

---

## 五、验收标准

整合完成后，以下命令必须全部通过：

```bash
# 1. 自测试
./audit.sh --selftest
# 预期：clean 样本 0 缺陷，dirty 样本检出已知缺陷

# 2. 对豆包管家跑核心维度
./audit.sh --project db --dimensions concurrency,state,auth,errorhandling
# 预期：生成 report.md，包含缺陷列表+严重程度+代码位置

# 3. 对 AutoForge 跑全维度
./audit.sh --project af --all
# 预期：生成报告，维度覆盖≥18个

# 4. 变异测试
./audit.sh --project db --mutation --target butler/core/dialog.py
# 预期：生成变异体存活率报告

# 5. 新增项目（模拟）
cp adapters/db.yml adapters/test.yml
# 修改 source_roots
./audit.sh --project test --dimensions deadcode
# 预期：无需改核心代码，直接可用
```

---

## 六、风险与注意事项

1. **AF 硬编码剥离不彻底**：autoforge 的 30 个模块可能有隐藏的 AF 依赖（如特定异常类、配置键名），需要逐个 `import` 测试
2. **semgrep 规则兼容性**：autoforge 的规则可能依赖 AF 特定的代码结构，通用化时需要拆分通用规则和项目规则
3. **报告格式统一**：4 份工作流的报告格式不同，统一时需要保留各份的优点（如 autoforge 的维度分类、bug-hunter 的变异存活率）
4. **不要删除 sources/**：原始工作流保留为参考，整合过程中随时可以回查
5. **渐进式整合**：先让 autoforge workflow 能通过 adapter 配置跑 DB 项目，再逐步吸收 bug-hunter 和 auditkit 的能力

---

## 七、文件索引

| 路径 | 说明 |
|---|---|
| `sources/auditkit/` | 轻量审计引擎（audit.py 121KB） |
| `sources/autoforge-workflow/workflow/lib/` | 30 个检测模块（整合主体） |
| `sources/autoforge-workflow/workflow/af_audit.sh` | 驱动脚本参考 |
| `sources/autoforge-workflow/workflow/lib/rules/` | semgrep 规则 |
| `sources/autoforge-workflow/selftest/` | 自测试框架 |
| `sources/bug-hunter/bug-hunter/scripts/` | 变异/属性/不变量测试 |
| `sources/bug-hunter/project-suite/audit_helpers.py` | 128KB 通用辅助函数 |
| `sources/memory-agent/` | MA 审计方法论+专项测试 |

---

—— ADM AuditKit 整合方案 · 2026-10-06
