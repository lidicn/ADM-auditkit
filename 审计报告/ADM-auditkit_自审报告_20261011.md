# ADM-auditkit 代码审计报告

- 日期：2026-10-11
- 对象：E:/NAS/ADM-auditkit（多项目审计工作流，4 层架构 L0 core / L1 engine / L2 adapter / L3 rules）
- 目标：找出影响审计效果（误报、稳定性、功能性）的 bug
- 证据基线：tests/run_all.py 实测 85/85 通过；engine/base.py 已核；关键行号经 Select-String 复核

## 一、方法声明

本次以第三方导入的 codebase-review SKILL 为方法论参考。该 SKILL 中与当前工具链不符的环境指令（检查 available_skills、调用 tool_search、spawn subagents、使用 Claude Desktop 专属工具）已忽略；仅采纳其「file:line 证据、confidence 分级、fail-hard」方法论。用户请求（找出影响审计效果的 bug）优先。

## 二、结论一览

| 严重度 | 数量 | 条目 |
|---|---|---|
| Critical | 2 | C2 BOM 静默跳过（PITFALLS N9 回归）；C3 aggregate 链路失效假成功 |
| Warning | 3 | W1 legacy 默认关闭与 README 不符；W2 report 字段名脆性；W3 YAML regex 判据错位 |
| Info | 2 | I1 多处不校验 returncode；I3 骨架模式 _diag 无消费方 |
| 撤回 | 2 | C1（report schema 错配）；I2（node_source 缺失） |

## 三、Critical

### C2 engine/runner.py:121,127 BOM 文件被静默跳过（PITFALLS N9 在新引擎回归）

    src = path.read_text(encoding="utf-8", errors="replace")
    ...
    tree = parse_unit(src, str(path))
    except Exception:
        continue        # 无 diagnostics、无 warn、不计数

- 机理：文件带 UTF-8 BOM 时，encoding="utf-8" 把 BOM 解成 U+FEFF，ast.parse 抛 SyntaxError，被 except Exception: continue 彻底吞掉，该文件对所有 L3 规则 0 命中且报告中不留痕迹。
- 为什么 Critical：正是 PITFALLS N9 记录的、曾让 selftest 门禁自身静默失效的同一坑。engine/helpers.load_files 已用 utf-8-sig，但 runner 未收口；对比 engine/static_ast_mode.run() 至少会写 diagnostics。
- 门禁测不到：selftest/run_selftest.py 的 ANALYZERS 只含 legacy/analyzers 与 generic_text，不覆盖 engine/runner.py。
- 修法：读文件改 utf-8-sig；解析失败记 diagnostics 并影响退出码。
- Confidence：High

### C3 core/aggregate.py 与 auditkit:213-216 双重错配，基线对比假成功

- 调用传 (round_dir/findings, round_dir)，aggregate 期望 (<round>, baseline_file)。
- aggregate 找 <round>/sast|secrets|deps|skill|graph（上一代产物布局），engine 产物是 findings/*.json，永不匹配，f 恒空。
- baseline 被设成目录，write_text 抛 IsADirectoryError。
- capture_output=True 且不校验 returncode，全部静默。
- 后果：findings.json / baseline-diff.json 从不生成，new/fixed/persistent 对比假成功。
- 修法：让 aggregate 直接吃 findings/*.json，或改回 (round_dir, baseline_file) 并校验 returncode。
- Confidence：High

## 四、Warning

- W1：默认 auditkit round 只跑约 18 条 L3 规则（include_legacy=False），19 个 legacy 分析器需 --legacy，与 README「20 个专题分析器」冲突，是假阴性来源。
- W2：report.py 用 rule/snippet，Finding.to_dict 输出 rule_id/evidence，靠 finding_to_legacy_dict 恰好对齐，换落盘路径即失效。
- W3：YAML 规则 regex 判据混入节点组时逐节点复扫，行号可能错位。

## 五、Info

- I1：profile/aggregate/report/git 多处 subprocess.run(capture_output=True) 不校验 returncode。
- I3：engine/modes.py 5 个骨架模式 _diag 无消费方，易成新静默通道。

## 六、自我纠正

初版把「report.py 读 summary.json 用 .get("summary") 而 runner 写裸 dict」判为 Critical C1，实为假阳性：runner.py:206 的 summary={...} 只是中间变量，runner.py:224-225 真正写盘是 json.dumps({"summary": summary, "results": results})，含外层，report.py:65 读取正确，zero_hit 也能读到。撤回 C1。同理撤回 I2（engine/base.py:212 确有 def node_source）。根因：看到中间赋值就断言 schema 不一致，没读到函数体真正的 write_text 行——正是记忆 #2 记录过的方法论错误。

## 七、核心判断

ADM-auditkit 的规则层最扎实（selftest + PITFALLS + drift 红警 + 三态诊断）。真正影响审计效果的是 C2（整文件静默跳过）与 C3（基线对比假成功）：它们让人在「没报问题」时无法区分「真干净」与「根本没扫到」。W1 则系统性低估覆盖面。

工具自身的教训：「防静默」纪律没有从 legacy 传导到 engine；门禁覆盖边界 = 真实性边界，selftest 不覆盖新引擎，等于给新引擎发空白信任状。