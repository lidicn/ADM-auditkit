# 工作流迭代提案：让规则**跨项目可复用**

> 来源：doubao-butler 连续二十轮审计（`lidicn/doubao-butler`）
> 作者：元宝
> 日期：2026-10-08

---

## 背景：一个尴尬的实测结果

我们在 AutoForge 上做了二十轮，攒下 24 个分析器、数十条规则，门禁全绿。
换到 doubao-butler 的**第一轮**，就出现了这个：

```
DO（破坏性覆盖）规则命中：0
```

而 doubao-butler 里**确确实实存在**最标准的 DO-01 形态（D2：role_state.json
读失败返空 → 写入覆盖 → 全部会话丢失，我们人工实测复现了）。

规则一条没报。**它不是坏了，也不是没跑——它安静地输出了 0。**

根因：DO 规则的「写盘 API 别名表」里写的是 AutoForge 用过的
`atomic_write_text` / `_atomic_write_text`，而 doubao-butler 用的是自定义的
`write_json_atomic`。匹配不上 ⇒ 0 命中。

**规则内嵌了源项目的假设。**

这不是个例。二十轮里同类事件至少六次，见 `evidence/known_portability_failures.md`。

---

## 为什么这件事值得单独提

auditkit 是**通用**工具。一条规则在 A 项目上验证通过，不代表它在 B 项目上
还能用——而且**失效时不报错**，只表现为"命中变少/变多"。

更麻烦的是失效方向有两个，都会骗人：

| 方向 | 表现 | 危害 |
|---|---|---|
| 漏报 | "本项目没有这类缺陷" | 真缺陷被跳过（D2 差点就这么漏了） |
| 误报 | 一堆命中 | 挤占分诊预算，真信号被淹没 |

我们二十轮里两个方向都栽过，且**都是靠人工实测才发现的**。

---

## 九项建议（按优先级）

### 1. 规则不得内嵌源项目假设（最高优先）

把"写盘 API 名""项目包名""断言函数名"这类东西从规则里抽出去，改成：
- 可配置（规则声明里带一个 `assumptions` 段）
- 或自适应（像 ASM-01 后来做的：从 `src_root` 推断项目包名，从
  `requirements.txt` / `pyproject.toml` 读依赖名）

实测证据：
- **W50**：写盘 API 名不对 ⇒ DO 规则 0 命中（真缺陷 D2 被跳过）
- **W79d**：包名写死 `butler` ⇒ 门禁 dirty 样本 0 命中 ⇒ **门禁 FAIL**
- **W79f**：包名→导入名未映射（pillow/PIL、beautifulsoup4/bs4、
  pycryptodome/Crypto、paho-mqtt/paho、python-multipart/multipart **5/5 全中**）
  ⇒ 5 个已声明依赖被当成装配缺失
- **W91**：PoC 适配器按项目硬编码 ⇒ 换项目时回退跑**别的项目**的探针
  ⇒ 输出 `{"unavailable": 2}`，与"本项目无可测目标"无法区分

### 2. `type` 判据必须覆盖 async 变体（引擎层，一条修复惠及所有规则）

实测：**`issubclass(ast.AsyncWith, ast.With)` 是 `False`。**
async 节点**不是**同步节点的子类。

后果：我们 10 处 `isinstance(x, ast.With)` **全部漏掉 `async with`**。
doubao-butler 是 async 重度项目（httpx.AsyncClient、aiohttp、asyncio 锁全用
async with）⇒ 一整条因果链判错，MIXED-RETURN 的 high 从 11 虚高到被修后 1。

同一条规则里，`FunctionDef` 要配 `AsyncFunctionDef` 这件事规则作者是**知道的**
（几乎每条规则都写了那个元组），但 `With`/`For` 同样需要这件事，**10 处全漏**。

⇒ 建议引擎侧把 `type: [With]` 语义定义为"含 AsyncWith"，或至少在文档里
显式列出所有需要配对的节点组，并加一条 lint 检查"写了 With 没写 AsyncWith"。

### 3. 判据要表达「失败是否可见」，而不是「有没有 try/except」

我们有一条规则（AFS-04）把 **fail-closed 判成了缺陷**：

```python
if self.path.is_file():
    self._codes = json.loads(self.path.read_text(encoding="utf-8"))
```

判为 medium："未包裹异常处理；文件损坏会让加载直接抛异常，无降级路径"。

**但抛异常正是我们十六轮来一直推荐的正确写法。** 而"降级"（静默返回空）
恰恰是本项目 22 项确证缺陷里 10 项的共同根因。

这条规则会**把修复后的正确写法判成缺陷**。

正确判据是三态：
- 无 try（异常冒泡）⇒ 可见 ⇒ 不报
- except + `raise` / `logger.*` ⇒ 可见 ⇒ 不报
- except + 纯 pass/return 无日志 ⇒ **无痕** ⇒ 报

### 4. 同一族缺陷会分散在多个分析器，PoC 输入要按族聚合

实测 doubao-butler 上"递归无预算"这一族：
- `boundary_defects` → `RSC-02-recursion-no-budget`
- `guard_order_defects` → `GOD-02-unguarded-recursion`（含 D12）

只从一个分析器拿 findings ⇒ 只喂一半给 PoC ⇒ **最关键那条可能根本没测**。
已改为多分析器合并 + 按 `(file, line, rule)` 去重。

### 5. PoC 无适配器时显式报 `no_adapter`，绝不回退跑别的项目探针

见建议 1 的 W91。`unavailable` 与"没适配器"是两回事，混在一起会让报表
完全失真。

### 6. `unavailable` / `no_write` 归因标准化，且**多字段取原因**

不同 PoC 把原因放不同字段：
- `poc_state` → `reason`
- `poc_failopen` → `detail`

首版只读 `reason` ⇒ 2 条判成"归因不明"，而 `detail` 里明明写着
`No module named 'autoforge'` ⇒ **错过了一个"探针在跑别的项目"的真问题**。

归因表建议内置：

| reason 关键词 | 归因 | 正确解读 |
|---|---|---|
| `seed-not-observable` | 探针观测不到状态文件 | **被测代码可能有问题，是探针到不了** |
| `No module named` / `ModuleNotFoundError` | 环境缺口 | 不是被测代码的问题 |
| `is not defined` | 样本/补丁自身问题 | 多半是我们自己写错了 |
| （空，`no_write`） | 没触发写入 | **不代表安全** |

**关键纪律：`unavailable`（测不到）与 `safe`（没问题）在报表里长得一模一样，
必须严格分开。**

### 7. FAIL 消息必须带根因，不能只说"规则可能失效"

两次共享样本污染（W80b：顶层裸 `import pkgcore.*`；W85：样例引用了模块级
不存在的 `_u`）都让状态 PoC 判 `unavailable`，而 FAIL 消息只说
"探针可能已静默失效" ⇒ **诊断方向错了** ⇒ 每次都要手工查。

已改为：reason 里出现 `is not defined` / `No module named` 时，直接提示
"**像共享样本自身有问题**"，并附上首条 reason。

### 8. 共享样本的每一次改动，都是对其他所有分析器的一次回归测试

标着"缺陷写法"的样本（ASM 样例故意 import 不存在的模块）因为写成了裸 import，
把**别的**分析器的 PoC 打挂了。

镜像的一例：第十三轮发现标着"正确写法"的样本**自己复刻了缺陷**，
靠规则的漏报维持绿色十几年。

⇒ 样本不是私有的。加东西之前要问的是"它会不会让别人测不了或测错"。

### 9. 扫描范围需要项目可声明，且默认排除一次性脚本

doubao-butler 里 `scripts/audit_1002/` 有 **100 个上一轮审计留下的一次性脚本**，
一直被当成产品代码扫描：

| 指标 | 收口前 | 收口后 |
|---|---|---|
| 扫描文件 | 311 | 211 |
| RSC-03 命中 | **95** | **4** |

那 95 条几乎全来自 `patch_ledger_*` / `probe_*` / `mutate_*`。
它们占满分诊榜、消耗人工核验预算，还让"命中总量"看起来很大，
造成"覆盖很充分"的错觉。

⇒ 建议支持项目根下 `audit-exclude.txt`（每行一个相对路径前缀）。

---

## 一条贯穿始终的纪律

累计二十余次**工具/探针/样本/环境静默失效**，失效源位置一路外移：

```
我们写的分析器 → 补丁 → 外部工具 → 环境 → 探针自身 → 共享样本 → 调用方式
```

**共同点无一例外：表现为"命中变多/变少"或"看起来正常运行"，而不是报错。**

唯一有效的对策：

> **任何"看起来修好了"或"看起来在测"，都先怀疑工具与环境，再相信结论。**

而要让这条纪律可执行，靠的不是人的警觉，是**双向样本（dirty + clean）+ drift
检测 + 失败即报**。第十九轮那次"逻辑反转"就是靠 clean 样本上报出
`ast`/`json`/`os` 才暴露的——如果只跑 dirty，会看到 7 条命中、觉得规则在工作。

---

## 附：本次同时提交的规则与判据缺口

- 规则：`py.dynamic_import_string`（动态导入字符串清单，见 l3_rules 提案）
- 判据缺口：gap-3（async 节点）、gap-4（跨函数数据流）、gap-5（项目假设内嵌）
