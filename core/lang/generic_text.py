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
             ".ruff_cache", "site-packages"}

SCANNABLE = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go",
             ".rs", ".java", ".sh", ".bash", ".yml", ".yaml", ".sql", ".rb",
             ".php", ".c", ".cpp", ".h"}

# ── 通用规则（所有语言） ────────────────────────────────────────────
RULES_ANY = [
    ("GEN-01-hardcoded-secret", "high",
     r"""(?i)(api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*["'][^"'${\s]{8,}["']""",
     "疑似硬编码凭据；应走环境变量/密钥管理"),
    ("GEN-02-sql-concat", "high",
     r"""(?i)(select|insert|update|delete)\s+.*(\+\s*[\"'`]|\$\{|%\s*\(|\|\s*format|\.format\(|f["'])""",
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
    ],
    "javascript": [
        ("JS-01-innerhtml", "high", r"""(?i)\.innerHTML\s*=|dangerouslySetInnerHTML""",
         "直接写 innerHTML → XSS"),
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
    "yaml": [
        ("YAML-04-no-resource-limit", "low", r"""(?im)^\s*resources\s*:\s*$""",
         "容器未声明 resources → 可耗尽节点资源", "negate"),
    ],
}

NEEDS_REVIEW = {"TS-03-unhandled-promise", "GO-01-err-ignored",
                "SH-03-no-set-e", "SH-01-unquoted-var", "TS-04-any-abuse"}


def scan_file(path: Path, rel: str) -> list[dict]:
    try:
        text = path.read_text(errors="ignore")
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
                    out.append({
                        "rule": rid, "severity": sev, "file": rel, "line": lineno,
                        "function": "<line>", "language": lang or path.suffix,
                        "message": msg, "snippet": line.strip()[:120],
                    })
            except re.error:
                continue
    # 文件级规则
    for rid, sev, pat, msg, mode in FILE_RULES.get(lang or "", []):
        if mode == "negate":
            if not re.search(pat, text):
                out.append({
                    "rule": rid, "severity": "info" if rid in NEEDS_REVIEW else sev,
                    "file": rel, "line": 1, "function": "<file>",
                    "language": lang or path.suffix, "message": msg,
                    "snippet": f"<整个文件 {len(text.splitlines())} 行>",
                })
    return out


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else ".")
    outdir.mkdir(parents=True, exist_ok=True)

    findings, files, by_lang = [], 0, Counter()
    for dirpath, dirnames, filenames in __import__("os").walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
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
