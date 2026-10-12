#!/usr/bin/env python3
"""跨语言通用危险模式层 —— 补上 AF 工作流最大的空白。

AF 的 18 个分析器全是 **Python AST**。拿去扫一个 TypeScript / Go / Shell 项目，
结果必然是全 0 命中。而"0 命中"在静态分析里是最危险的信号 ——
它可能只是"规则不适用于这种语言"，却会被读成"代码很干净"（PITFALLS N1）。

本层用正则做**语言无关**的危险模式匹配，覆盖 Python AST 够不到的所有语言。
定位是**兜底不是替代**：精度不如 AST，但保证任何语言都有基线覆盖，
并且**显式声明覆盖率**，让报告里的 0 有解释。

规则分两类：
  - ANY：所有语言通用（密钥、SQL 拼接、eval、TLS 关闭、CORS 通配...）
  - 语言专属：ts/js（innerHTML、命令注入模板串）、go（err 忽略、panic 在库里）、
              shell（未引用变量、rm -rf）、yaml（特权容器、latest 标签）

用法: generic_text.py <root> <outdir>
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist",
             "build", ".mypy_cache", ".pytest_cache", "vendor", "target",
             ".ruff_cache", "site-packages", ".qoder", "workorders", "tmp",
             ".wxt", ".svelte-kit", ".nuxt", ".next", ".angular"}

SCANNABLE = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go",
             ".rs", ".java", ".sh", ".bash", ".yml", ".yaml", ".sql", ".rb",
             ".php", ".c", ".cpp", ".h"}

# ── 通用规则（所有语言） ────────────────────────────────────────────
RULES_ANY = [
    ("GEN-01-hardcoded-secret", "high",
     r"""(?i)(api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*["'][^"'${\s]{8,}["']""",
     "疑似硬编码凭据；应走环境变量/密钥管理"),
    ("GEN-02-sql-concat", "high",
     # v1.1.0（2026-10-12 memory-agent round-003 收敛）：行首加 (?!.*\?) 负向预查——
     # 同一行出现 ? 占位符说明该语句走参数化绑定（拼接的只是代码内部片段，
     # 如 `sql = "SELECT COUNT(*) FROM t WHERE " + " AND ".join(where)` + params），
     # 无注入路径。实测该项目生产 4 处命中全为此形态（round-003 后全部 triage reject）。
     # 已知残留局限：跨行拼接（SQL 与绑定分处多行）单行正则看不见 ?，仍会误报。
     r"""(?i)^(?!.*\?).*(select|insert|update|delete)\s+.*(\+\s*[\"'`]|\$\{|%\s*\(|\|\s*format|\.format\(|f["'])""",
     "SQL 由字符串拼接/格式化构造 → 注入风险；应使用参数化查询"),
    ("GEN-03-eval-dynamic", "high",
     r"""(?i)\b(eval|exec|new\s+Function|setTimeout\s*\(\s*["'`]|setInterval\s*\(\s*["'`])\s*\(""",
     "动态求值/执行字符串 → 代码注入；应改为显式调用"),
    ("GEN-04-tls-disabled", "high",
     r"""(?i)(rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|ssl_verify\s*=\s*False)""",
     "TLS 校验被关闭 → 中间人可替换服务端；除非显式测试用途否则必改"),
    ("GEN-05-cors-wildcard", "medium",
     r"""(?i)(Access-Control-Allow-Origin\s*[:=]\s*['"]?\*|allow_origins\s*=\s*\[?\s*['"]\*['"]|origins\s*=\s*\[\s*['"]\*['"])""",
     "CORS 通配 → 任意站点可读响应"),
    ("GEN-06-log-sensitive", "medium",
     r"""(?i)(console\.log|print|logger\.|log\.|println).{0,40}(password|passwd|secret|token|api[_-]?key|authorization)""",
     "日志可能输出凭据；应脱敏"),
    ("GEN-07-unsafe-random", "medium",
     r"""(?i)(Math\.random\s*\(\s*\)|random\.random\s*\(\s*\)).{0,80}(token|secret|key|salt|nonce|session|password)""",
     "用非密码学随机源生成安全敏感值"),
    ("GEN-08-credential-eq", "medium",
     r"""(?i)(token|secret|password|signature|api[_-]?key)\s*(===?|!==?)\s*[a-z_][\w.]*\s*(?:$|\)|;|&&|\|\|)""",
     "凭据用 ==/=== 比较 → 时序侧信道；应恒定时间比较"),
    ("GEN-09-todo-security", "low",
     r"""(?i)(TODO|FIXME|XXX|HACK).{0,60}(security|auth|password|secret|token|encrypt|sanitize|escape|validate)""",
     "安全相关的未完成项"),
    ("GEN-10-disabled-check", "medium",
     r"""(?i)(disable|skip|bypass|ignore)[_-]?(ssl|tls|auth|authentication|certificate|verify|validation)""",
     "安全校验被禁用/跳过"),
]

# ── 语言专属 ────────────────────────────────────────────────────────
RULES_BY_LANG = {
    "typescript": [
        ("TS-01-innerhtml", "high", r"""(?i)\.innerHTML\s*=|dangerouslySetInnerHTML""",
         "直接写 innerHTML → XSS；应转义或用 textContent"),
        ("TS-02-cmd-injection", "high",
         r"""(?i)(exec|execSync|spawn|child_process)\s*\([^)]*(\$\{|`[^`]*\$\{)""",
         "命令由模板串拼出 → 命令注入；应传数组参数并白名单"),
        ("TS-03-unhandled-promise", "medium",
         r"""^\s*(?!await|return|//)[\w.]+\([^)]*\)\s*;?\s*$""",
         "疑似未 await 的 Promise 调用（需人工确认）"),
        ("TS-04-any-abuse", "low", r""":\s*any\b|as\s+any\b""",
         "any 类型绕过类型检查"),
        # v1.2.0（2026-10-12 deepseek-studio round-003）：跨语言「外部调用无超时」盲区。
        # 此前所有超时类规则（py.outbound_call_no_timeout 等）都是 Python AST，
        # TS/JS 的 fetch/axios 完全无覆盖——该项目 MCP HTTP 传输
        # （mcp-controller.ts:304）stdio 有 30s 超时、HTTP 路径什么都没有，
        # server 挂起即 callTool 永久 pending、agent loop 卡死（确证 C3）。
        ("TS-07-fetch-no-timeout", "medium",
         r"""(?i)\b(?:fetch|axios\.(?:get|post|put|delete|request|create))\s*\(""",
         "外部 HTTP 调用行未见超时（signal/timeout/AbortSignal）——对端挂起会卡死调用方"),
        # v1.2.0：行首裸 setTimeout（未赋值给变量）结构上不可能被 clearTimeout——
        # 返回值没保存就无从取消。正是 Promise.race 竞速模式
        # （mcp-controller.ts:287/365、testConnection:519）的泄漏形态。
        ("TS-08-settimeout-no-clear", "medium",
         r"""^\s*setTimeout\s*\(""",
         "裸 setTimeout 未保存句柄 → 无法 clearTimeout；竞速/延迟模式会持续泄漏定时器"),
        # v1.3.0（2026-10-12 deepseek-studio round-001）：.catch(() => 空值) 吞错模式——
        # 跨项目通则"读失败不能当没有数据"的 TS 实例（配置损坏被当首次运行覆盖、
        # stat 失败被当文件不存在）。正则会话删 err 参数并返回空字面量（null/undefined/{}/''/[]），
        # 多行 catch 块（catch { stored = {} }）与可辨识降级（.catch(() => fallback())）不匹配。
        ("TS-09-catch-swallows-error", "medium",
         r"""\.catch\(\s*\(\s*\)\s*=>\s*(?:null|undefined|\{\s*\}|''|""|\[\s*\]|\(\s*\{\s*\}\s*\))""",
         "Promise .catch 丢弃 err 并返回空字面量 → 读/解析失败被静默降级为'空结果'（应区分 ENOENT 与真正异常，或至少记录 err）"),
    ],
    "javascript": [
        ("JS-01-innerhtml", "high", r"""(?i)\.innerHTML\s*=|dangerouslySetInnerHTML""",
         "直接写 innerHTML → XSS；应转义或用 textContent"),
        ("JS-06-fetch-no-timeout", "medium",
         r"""(?i)\b(?:fetch|axios\.(?:get|post|put|delete|request|create))\s*\(""",
         "外部 HTTP 调用行未见超时（signal/timeout/AbortSignal）——对端挂起会卡死调用方"),
        ("JS-07-settimeout-no-clear", "medium",
         r"""^\s*setTimeout\s*\(""",
         "裸 setTimeout 未保存句柄 → 无法 clearTimeout；竞速/延迟模式会持续泄漏定时器"),
        # v1.3.0（2026-10-12）：与 TS-09 对称的 JS 版 catch 吞错模式
        ("JS-09-catch-swallows-error", "medium",
         r"""\.catch\(\s*\(\s*\)\s*=>\s*(?:null|undefined|\{\s*\}|''|""|\[\s*\]|\(\s*\{\s*\}\s*\))""",
         "Promise .catch 丢弃 err 并返回空字面量 → 读/解析失败被静默降级为'空结果'"),
        ("JS-02-cmd-injection", "high",
         r"""(?i)(exec|execSync|spawn)\s*\([^)]*(\$\{|`[^`]*\$\{)""",
         "命令由模板串拼出 → 命令注入"),
        ("JS-03-require-nonliteral", "medium", r"""require\s*\(\s*[^"'`\s]""",
         "动态 require → 可能加载不可控模块"),
    ],
    "go": [
        ("GO-01-err-ignored", "medium", r"""\b\w+\s*,\s*_?\s*:?=\s*\w+\.\w+\([^)]*\)""",
         "疑似忽略返回的 error（需人工确认）"),
        ("GO-02-panic-in-lib", "medium", r"""^\s*panic\s*\(""",
         "库代码 panic → 调用方无法恢复；应返回 error"),
        ("GO-03-sql-fmt", "high", r"""fmt\.Sprintf\([^)]*(SELECT|INSERT|UPDATE|DELETE)""",
         "SQL 由 fmt.Sprintf 构造 → 注入风险"),
    ],
    "shell": [
        ("SH-02-rm-rf-var", "high", r"""(?i)rm\s+-rf?\s+[^/\s]*\$\{?\w""",
         "rm -rf 作用于变量 → 变量为空时可能删根目录"),
    ],
    "yaml": [
        ("YAML-01-privileged", "high", r"""(?i)privileged\s*:\s*true""",
         "容器以 privileged 运行 → 等同宿主机 root"),
        ("YAML-02-latest-tag", "low", r"""(?i)image\s*:\s*[\w./-]+:latest""",
         "镜像用 latest 标签 → 不可复现、可能拉到意外版本"),
        ("YAML-03-host-network", "medium", r"""(?i)hostNetwork\s*:\s*true|network_mode\s*:\s*["']?host""",
         "容器共用宿主网络栈"),
    ],
}

EXT_LANG = {
    ".py": "python", ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".go": "go", ".sh": "shell", ".bash": "shell",
    ".yml": "yaml", ".yaml": "yaml",
    ".rs": "rust",
}

# 语言专属规则是否"较宽、需人工确认" —— 这些默认降为 info，避免刷屏
#: 文件级规则：对**整个文件**跑一次，而不是逐行。
#: 首版把「脚本未 set -e」写成逐行正则 `^(?!.*set\s+-)` → 几乎匹配每一行，
#: 一个 10 行脚本刷出 8 条 info。这类"文件属性"判据必须文件级（PITFALLS P16）。
FILE_RULES = {
    "shell": [
        ("SH-03-no-set-e", "low", r"""(?m)^\s*set\s+[-+]?[euxo]""",
         "脚本未设置 `set -e/-u` → 命令失败会静默继续（需人工确认是否刻意）",
         "negate"),
        ("SH-04-no-shellcheck", "info", r"""(?m)^\s*#\s*shellcheck\s+(shell|enable|disable)""",
         "未见到 shellcheck 指令注解", "negate"),
    ],
    # v1.3.0（2026-10-12 deepseek-studio round-001）：Rust 用 Command::new 拉起子进程树
    # （如 cmd /c npx tsx），关闭时 child.kill()/TerminateProcess 只杀直接子进程，孙进程成孤儿。
    # 正确做法：Windows 用 Job Object（CREATE_JOB_OBJECT + KILL_ON_JOB_CLOSE）级联杀，
    # 或子进程侧孤儿防护。coexist 模式＝文件同时出现「spawn」与「只 kill 单 PID」且
    # 没有 libc::kill/Job Object 级联缓解。testing：需端到端验证噪音后在报告中转 active。
    "rust": [
        ("RS-01-spawn-no-kill-tree", "medium",
         (r"Command::new", r"\.kill\(\)|child\.kill"),
         (r"libc::kill", r"CREATE_JOB_OBJECT|JobObject|KILL_ON_JOB"),
         "coexist",
         "Command::new 拉起子进程树 + child.kill()/TerminateProcess 只杀直接子进程，"
         "孙进程成孤儿；应级联杀（Job Object KILL_ON_JOB_CLOSE）或子进程侧孤儿防护"),
    ],
    "yaml": [
        ("YAML-04-no-resource-limit", "low", r"""(?im)^\s*resources\s*:\s*$""",
         "容器未声明 resources → 可耗尽节点资源", "negate"),
    ],
}

NEEDS_REVIEW = {"TS-03-unhandled-promise", "GO-01-err-ignored",
                "SH-03-no-set-e", "SH-01-unquoted-var", "TS-04-any-abuse",
                # v1.2.0：跨语言 fetch 无超时。跨行参数是已知盲区，只出清单不派单
                "TS-07-fetch-no-timeout", "JS-06-fetch-no-timeout"}

# TS-03 同步 API 白名单：这些是同步操作，不是 Promise，不应判未 await
# GEN-02 内部片段白名单（v1.1.0 收敛，2026-10-12 memory-agent round-003）：
# SQL 与绑定参数分处多行时，行首 (?!.*\?) 负向预查看不见 ?；但拼接另一侧是
# 常量分隔符 join（`" AND ".join(conds)`）说明拼的是代码内部条件片段、
# 用户值全走参数绑定，无注入路径。实测该项目生产 4 处命中全为此形态。
GEN02_INTERNAL_JOIN = ('" and ".join', '" or ".join', '", ".join', '" where " +')

# TS-07/JS-06 白名单（v1.2.0，2026-10-12）：行内出现这些即视为「已设超时」。
# fetch(url, { signal }) / axios.get(url, { timeout }) 是正确形态。
# 已知局限：参数跨行时单行看不见（与 GEN-02 同族的跨行盲区），故该规则定
# NEEDS_REVIEW（info 级），只做「必须人工过一遍」的清单，不直接派单。
FETCH_TIMEOUT_KEYS = ("signal:", "signal ", "abortsignal", "abortcontroller", "timeout")

# TS-01/JS-01 收敛（v1.2.0，2026-10-12 deepseek-studio round-003）：
# 右侧是纯字符串字面量（空串/无 ${ 插值的模板串）时无任何可注入数据——
# `innerHTML = ''` 清空与静态骨架模板不该报。含 ${ 插值、+ 拼接、
# 函数调用或裸标识符的一律仍报（确证 C1 就是 buildCardHtml(...) 形态）。
_LITERAL_ONLY_RE = re.compile(r"""^\s*(['"`])(?:(?!\1).)*\1\s*;?\s*$""")

# TS-03 同步 API 白名单：这些是同步操作，不是 Promise，不应判未 await
TS03_SYNC_WHITELIST = (
    "localStorage.", "sessionStorage.",
    ".setItem(", ".getItem(", ".removeItem(", ".clear(",
    "Map.", "Set.",
    ".push(", ".pop(", ".shift(", ".unshift(", ".splice(",
    ".slice(", ".concat(", ".filter(", ".map(", ".reduce(",
    ".forEach(", ".find(", ".findIndex(", ".includes(", ".indexOf(",
    ".join(", ".sort(", ".reverse(", ".keys(", ".values(", ".entries(",
    "app.use(", "app.mount(", "app.config.",
    # v1.2.2 收敛（2026-10-12 deepseek-studio round-006）：HTTP/Node/DOM 常见同步或
    # 非 Promise API 被正则误判为"未 await 的 Promise"——这些返回值不是 Promise，
    # 排除它们可显著降噪（实测 studio 自身 TS-03 837 条里大量是这类）。
    # 注意：正则层无法判别"调用目标是否返回 Promise"，这是 TS-03 过宽的根因；
    # 长期应改为 AST 语义分析，此处仅按"已知同步 API"治标。
    ".setHeader(", ".writeHead(", ".end(", ".exit(", "process.exit(", "Sync(",
    # DOM/集合/事件 同步方法（deepseek-studio 这类 Tauri 桌面应用前端代码大量出现）
    ".appendChild(", ".addEventListener(", ".removeEventListener(", ".setAttribute(",
    ".emit(", ".delete(", ".add(", ".remove(", ".replace(",
)

# TS-03 收敛（v1.2.2，2026-10-12 deepseek-studio round-003）：
# 行内出现这些标记说明 Promise 已被处理或属于常规忽略，不作"未处理"报——
# 否则 deepseek-studio 单项目 233 条 TS-03（占全量 94%）几乎全是噪音。
# 这些标记不会出现在真正裸调用未处理的行里（裸调用行只有 `foo()`），
# 故排除它们不漏真缺陷。
#   - 子串集：.catch( 已接 then 链 / await / void 显式丢弃 / console/logger 日志 /
#     expect( 断言
#   - 正则集：(?<![\w.]) 边界避免 split(/wait(/respect( 等被 "it("/"expect(" 子串误伤
TS03_OK_HINT = (".catch(", "await ", "void ", "console.", "logger.", "expect(")
TS03_OK_HINT_RE = re.compile(r"(?<![\w.])(?:await|void|return|it|test|describe)\s*\(")


def scan_file(path: Path, rel: str) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
    except OSError:
        return []
    lang = EXT_LANG.get(path.suffix.lower())
    rules = list(RULES_ANY)
    if lang in RULES_BY_LANG:
        rules += RULES_BY_LANG[lang]
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 800:
            continue
        for rid, sev, pat, msg in rules:
            if rid in NEEDS_REVIEW:
                sev = "info"
            try:
                if re.search(pat, line):
                    # TS-03 同步 API 白名单：排除 localStorage/Map/Array 等同步操作
                    if rid == "TS-03-unhandled-promise":
                        if any(sync in line for sync in TS03_SYNC_WHITELIST):
                            continue
                        if any(h in line for h in TS03_OK_HINT) or TS03_OK_HINT_RE.search(line):
                            continue
                    if rid == "GEN-02-sql-concat":
                        low = line.lower()
                        if any(seg in low for seg in GEN02_INTERNAL_JOIN):
                            continue
                    if rid in ("TS-07-fetch-no-timeout", "JS-06-fetch-no-timeout"):
                        low = line.lower()
                        if any(k in low for k in FETCH_TIMEOUT_KEYS):
                            continue
                    if rid in ("TS-01-innerhtml", "JS-01-innerhtml"):
                        rhs = line.split("=", 1)[1] if "=" in line else ""
                        if "${" not in rhs and _LITERAL_ONLY_RE.match(rhs):
                            continue
                    if rid in ("TS-08-settimeout-no-clear", "JS-07-settimeout-no-clear"):
                        # v1.2.1：TS 方法签名/类型声明（`setTimeout(cb: () => void, d: number): ReturnType<...>;`）
                        # 不是调用——`) : 类型` 是签名特征。types.ts:41 实测误报。
                        if re.search(r"\)\s*:\s*[\w<]", line):
                            continue
                    out.append({
                        "rule": rid, "severity": sev, "file": rel, "line": lineno,
                        "function": "<line>", "language": lang or path.suffix,
                        "message": msg, "snippet": line.strip()[:120],
                    })
            except re.error:
                continue
    # 文件级规则
    for entry in FILE_RULES.get(lang or "", []):
        rid, sev, pat, msg, mode = entry[0], entry[1], entry[2], entry[3], entry[4]
        exclude = entry[5] if len(entry) > 5 else ()
        eff_sev = "info" if rid in NEEDS_REVIEW else sev
        hit = False
        if mode == "negate":
            hit = not re.search(pat, text)
        elif mode == "coexist":
            reqs = pat if isinstance(pat, (tuple, list)) else (pat,)
            excls = exclude if isinstance(exclude, (tuple, list)) else ((exclude,) if exclude else ())
            hit = (all(re.search(rq, text) for rq in reqs)
                   and not any(re.search(ex, text) for ex in excls))
        if hit:
            out.append({
                "rule": rid, "severity": eff_sev, "file": rel, "line": 1,
                "function": "<file>", "language": lang or path.suffix, "message": msg,
                "snippet": f"<整个文件 {len(text.splitlines())} 行>",
            })
    return out


def main() -> int:
    args = sys.argv[1:]
    # 项目级遍历排除（N10）：`--skip-dirs a b c` 合并到 SKIP_DIRS。
    # 嵌套副本（如 deepseek-studio/deepseek-pp/）不进全局 SKIP_DIRS，由调用方按项目传入。
    skip_set = set(SKIP_DIRS)
    if "--skip-dirs" in args:
        i = args.index("--skip-dirs")
        extra, j = [], i + 1
        while j < len(args) and not args[j].startswith("--"):
            extra.append(args[j]); j += 1
        skip_set |= set(extra)
    root = Path(args[0] if args else ".")
    outdir = Path(args[1] if len(args) > 1 else ".")
    outdir.mkdir(parents=True, exist_ok=True)

    findings, files, by_lang = [], 0, Counter()
    for dirpath, dirnames, filenames in __import__("os").walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_set]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() not in SCANNABLE:
                continue
            rel = str(p.relative_to(root))
            files += 1
            by_lang[EXT_LANG.get(p.suffix.lower(), p.suffix)] += 1
            findings += scan_file(p, rel)

    sev = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda x: (sev.get(x["severity"], 9), x["file"], x["line"]))
    (outdir / "generic-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({
        "files_scanned": files,
        "by_language": dict(by_lang),
        "total": len(findings),
        "by_severity": dict(Counter(f["severity"] for f in findings)),
        "by_rule": dict(Counter(f["rule"] for f in findings)),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
