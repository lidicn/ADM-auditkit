# 判据的「局部性」边界

> AutoForge 第二期 20 轮的工作流提案。不新增规则，全部是判据修正。

## 一句话

静态规则的判据天生是**局部**的——它只看一个函数、一个节点的形态。
而缺陷是否成立，条件往往是**跨函数、跨模块**的。
第二期 20 轮里，连续 6 轮的实质产出都是判据修正而非新缺陷，
且这些修正**全部是同一类根因的不同表现**。

---

## 一、证据：六轮连续出同一类缺口

| 轮次 | 缺口 | 根因 |
|---|---|---|
| 16 | W145 `replace` 多态名 | 只看调用点名字，不看接收者语义 |
| 17 | W146 SER-01 前提不判 | message 说了前提，判据不验证 |
| 18 | W147 IN-03 前提不判 | 同上 |
| 18 | **W147b 有校验 ≠ 判据正确** | **规则问错了问题** |
| 19 | **W148 有 try ≠ 异常会逃逸** | **规则问错了问题** |
| 20 | W149 返回 None 的语义方向 | 第四次的同族 |

**W147b 和 W148 是分水岭**：前几条是"规则说了前提却不验证"，
这两条是**规则问的问题本身就是错的**。

---

## 二、三个具体案例

### AF19 · 有防护，但防护的判据错了

```python
# 看起来三重检查，很完备
candidate = (dist / full_path).resolve()
if full_path and candidate.is_file() and str(candidate).startswith(str(dist)):
    return FileResponse(str(candidate))
```

`str(candidate).startswith(str(dist))` **没有分隔符边界**：

```
dist      = /x/uidist
candidate = /x/uidist2/secret.txt
"/x/uidist2/secret.txt".startswith("/x/uidist") == True   ❌
```

向上逃逸（`/etc/passwd`）挡得住，**同层兄弟**挡不住。
端到端：`GET /%2e%2e/uidist2/secret.txt` → 200 + `TOP-SECRET`。

> 原规则问"有没有校验 `..`/斜杠"——AF19 两者都不缺。

### AF20 · 有 try，但异常照样逃逸

```python
def _read(name, default):
    try:
        return json.load(fh)      # ← try 只包这一句
    except ...:
        logger.warning(...); self.restore_corrupt.append(name); return default

self.canary.load(_read("canary_state.json", {}))   # ← load() 在 try 之外
```

`canary_state.json` 里一个 `since:"abc"` ⇒ `float("abc")` 抛 ValueError
⇒ `restore()` 抛 ⇒ `install()` 抛 ⇒ 被 `af_runtime.py:105` 兜住
⇒ **`grading = None`，整套 conf_grading 静默停用，`restore_corrupt` 为空**。

而 `_read` 的注释明写"降级 + 留痕……**但绝不静默**"。
**留痕机制本身被绕过**——这比数据丢失更难发现。

### AF21 · 返回 None，但调用方把 None 读成了别的意思

```python
# af_shadow.py install() 里的 _do
if band == "shadow":
    runner.run_do(instance, node)
    return None          # ← 契约是"出边集合"，None 意为"失败且无兜底边"
```

`NodeExecutor.run()`：

```python
kinds = self._execute(instance, node)
if kinds is None:  # 已终止（失败且无兜底边）
    return instance
```

对照实测（a1 → d1 → p1）：

| | 经过节点 | 终态 | 停在 |
|---|---|---|---|
| 原仓库 | a1, d1 | **created（未终止）** | d1 |
| 补丁（返回 `{"then"}`） | a1, d1 | **done** | p1 |

两个后果：
1. **回放不完整** —— 多动作自动化只能记录第一个 do，而 shadow 的产出正是转正证据
2. **实例挂起** —— 非终态，24h 后才由 `expire_stale()` 清掉

> 注意 ask 档返回 None 是**对的**（`open_ask` 内部会 suspend）。
> 同一个返回值，两个语义。**规则无法区分，人也不能想当然。**

---

## 三、为什么"局部判据"修不完

每一条修法都只是**补一个特例**：

- W145 排除 `str.replace` → 下次遇到 `dict.get` 又要补（W100b）
- W147 判"变量是路由参数" → 嵌套函数就失效（gap-10）
- W146 判"同模块有 restore_*" → 跨模块就失效（gap-11）

**这不是实现没写好，是判据形态本身的边界。**

建议方向（按性价比）：

1. **低成本**：把"前提"从 message 里删掉，或明确标注"（本规则不验证该前提）"
   —— 现在的写法会误导分诊者以为判据已经考虑过了
2. **中成本**：给常见跨函数模式建索引（装饰器→函数、模块→restore 函数、
   调用点→调用方是否有兜底），供多条规则共用
3. **高成本**：引擎支持上下文判据（能表达"这个 except 是否就包在护栏那一行外"）

---

## 四、两条流程纪律（比判据更重要）

### ① 改完判据后，"数字没变"是最危险的信号

本轮 W147 + W147b 修完，IN-03 仍是 44 条、2 medium——**数字完全没变**。
但那 2 条现在精确指向 AF19 现场（`unbounded_prefix_compare=True`），
其余 42 条 message 写明"未发现外部来源与非边界比较"。

**如果只看数字，会以为这两条修正毫无价值。**

### ② 每次改判据都必须跑负向测试

W145 第一版把 `re.compile` 插在 `import re` 之前 ⇒ NameError，
而分析器有宽泛异常兜底，结果不是崩溃，是**静默少了 3 条命中**（17 vs 20）。

只跑真实语料看到"19→10、假阳性消失"会以为修好了
——**实际是 3 条真命中被自己的 NameError 吞掉**。

同类事故（本轮 20 轮内共 4 次）：
W138d 缩进错误、W143c 正则写了 `sleep\(` 但输入不含括号、
W144b 把变量名传给类型判断、W144c `ast.unparse` 保留注解。

**共同特征：失效表现为"数字变好了"，不会报错。**
