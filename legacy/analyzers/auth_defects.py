#!/usr/bin/env python3
"""第十八轮专题：鉴权与权限边界（纯 stdlib AST）。

前十七轮覆盖稳定性、持久化、并发、复杂度、控制流、缓存、时间数值、输入边界、
事务边界、序列化、错误处理/降级、可观测性、配置兼容性、测试缺口、API 契约、
资源生命周期、模式泛化。本轮看**谁被允许做什么，以及鉴权本身会不会拖垮系统**：

  AUTH-01 路由/处理函数无鉴权依赖却执行敏感动作（签发令牌/撤销/写数据）
  AUTH-02 凭据用 == / != 比较（应恒定时间 hmac.compare_digest）
  AUTH-03 鉴权路径 fail-open（except 后放行 / 解析失败当"无限制"）
  AUTH-04 凭证集合只增不减（注册表/黑名单无裁剪）→ 鉴权开销线性增长
  AUTH-05 持锁做磁盘 IO（锁内 read-modify-write 全量文件）
  AUTH-06 权限判定表缺省放行（未知 scope / 未知 subject 走 else 分支放行）

设计原则：安全类判定极易假阳性（很多"无鉴权"是健康检查/静态资源）。
命中一律标注 **sensitive**（是否执行敏感动作）与 **reachable**，便于人工判定。

用法: auth_defects.py <src_root> <outdir>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

# 敏感动作：签发/撤销凭据、写盘、执行
SENSITIVE = re.compile(
    r"(?i)(issue|revoke|grant|token|credential|secret|password|passwd|auth|"
    r"write_text|write_bytes|\.write\(|atomic_write|delete|remove|deploy|exec|apply)")
SAFE_ROUTE = re.compile(r"(?i)(health|ping|ready|static|favicon|robots|docs|openapi|redoc|spa_fallback)")

CRED_HINT = re.compile(r"(?i)(token|secret|password|passwd|credential|api_key|apikey|signature|hmac|cookie)")


def _chain(n: ast.Call) -> str:
    if isinstance(n.func, ast.Name):
        return n.func.id
    if isinstance(n.func, ast.Attribute):
        parts = []
        cur = n.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
        return ".".join(reversed(parts))
    if parts:
            return ".".join(reversed(parts))
    return ""


def _fn_src(fn) -> str:
    try:
        return ast.unparse(fn)
    except Exception:
        return ""


def _decorators(fn) -> list[str]:
    return [ast.unparse(d) for d in fn.decorator_list]


# ────────────────────────────────────────────────────────────────────
# AUTH-01 路由无鉴权依赖却执行敏感动作
# ────────────────────────────────────────────────────────────────────
def check_route_without_auth(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decs = _decorators(fn)
        # 是路由处理器？
        # 注意：ast.unparse(装饰器) **不含 '@' 前缀**；首版正则写了 ^@ → AUTH-01 全漏
        is_route = any(re.match(r"\w+\.(get|post|put|delete|patch|websocket)\s*\(", d)
                       for d in decs)
        if not is_route:
            continue
        route = "".join(re.findall(r'"(/[^"]*)"', " ".join(decs))) or "<unknown>"
        if SAFE_ROUTE.search(fn.name) or SAFE_ROUTE.search(route):
            continue
        # 有鉴权依赖？
        has_dep = any(re.search(r"dependencies\s*=|Depends\(", d) for d in decs)
        # 形参里是否有依赖注入的鉴权项
        params = ast.unparse(fn.args)
        has_param_dep = "Depends(" in params
        if has_dep or has_param_dep:
            continue
        src = _fn_src(fn)
        hits = sorted({m.group(0) for m in SENSITIVE.finditer(src)})
        if not hits:
            continue
        # 函数体内自行做鉴权（调 authenticate / 查 registry）→ 不是漏挂，降级
        manual = bool(re.search(r"(?i)(registry\.authenticate|\bauthenticate\s*\(|requires\s*\()", src))
        out.append({
            "rule": "AUTH-01-route-no-auth",
            "severity": "low" if manual else "high",
            "manual_auth": manual,
            "file": rel, "line": fn.lineno, "function": fn.name,
            "message": (f"路由 {route}（{fn.name}）无 dependencies/Depends 鉴权，"
                        f"但函数内出现敏感动作 {hits[:5]}"),
            "route": route, "sensitive": hits[:5],
        })
    return out


# ────────────────────────────────────────────────────────────────────
# AUTH-02 凭据用 == 比较（非恒定时间）
# ────────────────────────────────────────────────────────────────────
def check_credential_equality(tree, rel):
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Compare):
            continue
        if not any(isinstance(o, (ast.Eq, ast.NotEq)) for o in n.ops):
            continue
        parts = [ast.unparse(n.left)] + [ast.unparse(c) for c in n.comparators]
        # 首版只要求"任一侧含凭据字样"→ 把 `tokens[2] == '->'`（语法解析）、
        # `os.environ.get('AUTO...') == '1'`（开关判定）全判成凭据比对。
        # 收紧：两侧都必须是**标识符**（非字面量、非调用），且都命中凭据词。
        ident = re.compile("^[A-Za-z_][\w.\[\]'\"]*$")
        if not all(ident.match(p.strip()) for p in parts):
            continue
        if not all(CRED_HINT.search(p) for p in parts):
            continue
        # 排除与 None / 布尔 / 空串 的比较（那是存在性判定，不是凭据比对）
        if any(re.match(r"^(None|True|False|''|\"\")$", p.strip()) for p in parts):
            continue
        # 排除 len() / 类型比较
        if any(p.strip().startswith(("len(", "type(", "isinstance")) for p in parts):
            continue
        out.append({
            "rule": "AUTH-02-credential-eq", "severity": "medium",
            "file": rel, "line": n.lineno, "function": "<module>",
            "message": (f"凭据相关比较 `{' == '.join(p[:24] for p in parts)}` 使用 == / !=；"
                        f"应按恒定时间比较（hmac.compare_digest）防时序侧信道"),
        })
    return out


# ────────────────────────────────────────────────────────────────────
# AUTH-03 鉴权路径 fail-open
# ────────────────────────────────────────────────────────────────────
ALLOW_HINT = re.compile(r"(?i)(allow|permit|grant|authorized|ok\s*=\s*True|return\s+True)")


def check_auth_failopen(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        src = _fn_src(fn)
        if not re.search(r"(?i)(auth|scope|permission|credential|token)", fn.name + src):
            continue
        for t in ast.walk(fn):
            if not isinstance(t, ast.Try):
                continue
            for h in t.handlers:
                hsrc = ast.unparse(ast.Module(body=h.body, type_ignores=[]))
                # except 里返回 True / 放行
                if re.search(r"return\s+True", hsrc) or re.search(
                        r"(?i)(allow|permit|grant)\w*\s*=\s*True", hsrc):
                    out.append({
                        "rule": "AUTH-03-auth-failopen", "severity": "high",
                        "file": rel, "line": h.lineno, "function": fn.name,
                        "message": (f"{fn.name}() 的 except 分支返回 True/放行："
                                    f"鉴权过程出错时**默认允许**（fail-open），应为 fail-closed"),
                        "handler": hsrc[:60],
                    })
                # except 里静默 pass（鉴权函数内）
                elif re.match(r"\s*pass\s*$", hsrc.strip()) and re.search(
                        r"(?i)(auth|scope|permission|credential|verify|check)", fn.name):
                    out.append({
                        "rule": "AUTH-03-auth-failopen", "severity": "medium",
                        "file": rel, "line": h.lineno, "function": fn.name,
                        "message": (f"{fn.name}() 的 except 分支仅 pass；"
                                    f"鉴权过程中的异常被静默吞掉（需确认是否等于放行）"),
                    })
    return out


# ────────────────────────────────────────────────────────────────────
# AUTH-04 凭证集合只增不减
# ────────────────────────────────────────────────────────────────────
CRED_CONTAINER = re.compile(r"(?i)(_tokens|_revoked|tokens|revoked|blacklist|_sessions|_codes|issued)")


def check_credential_growth(tree, rel):
    out = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        src_cls = ast.unparse(cls)
        methods = {m.name: m for m in cls.body
                   if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
        # 凭证集合字段
        fields = {}
        for n in ast.walk(cls):
            if isinstance(n, ast.AnnAssign):
                tgt = n.target
                nm = tgt.id if isinstance(tgt, ast.Name) else (
                    tgt.attr if isinstance(tgt, ast.Attribute) else None)
                if nm and CRED_CONTAINER.search(nm):
                    fields[nm] = n.lineno
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
                for t in n.targets:
                    if isinstance(t, ast.Attribute) and CRED_CONTAINER.search(t.attr):
                        fields.setdefault(t.attr, n.lineno)
        if not fields:
            continue
        for mname, m in methods.items():
            msrc = _fn_src(m)
            for n in ast.walk(m):
                added = None
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                        and isinstance(n.func.value, ast.Attribute) \
                        and isinstance(n.func.value.value, ast.Name) \
                        and n.func.value.value.id == "self" \
                        and n.func.attr in ("add", "append", "update"):
                    added = n.func.value.attr
                elif isinstance(n, ast.Assign) and isinstance(n.value, ast.Dict) is False:
                    # self.X[k] = v
                    for t in n.targets:
                        if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Attribute) \
                                and isinstance(t.value.value, ast.Name) \
                                and t.value.value.id == "self":
                            added = t.value.attr
                if not added or added not in fields:
                    continue
                # 是否有裁剪/上限
                trimmed = bool(re.search(
                    rf"(?i)(del\s+self\.{re.escape(added)}|self\.{re.escape(added)}\.clear|"
                    rf"self\.{re.escape(added)}\.pop|maxlen|max_)", src_cls))
                if trimmed:
                    continue
                # 该集合是否参与线性扫描（for ... in self.X）
                scanned = bool(re.search(
                    rf"for\s+\w+\s+in\s+(self\.)?{re.escape(added)}\b", src_cls))
                out.append({
                    "rule": "AUTH-04-credential-growth", "severity": "high" if scanned else "medium",
                    "file": rel, "line": n.lineno, "class": cls.name, "function": mname,
                    "message": (f"{cls.name}.{mname}() 向凭证集合 self.{added} 添加条目，"
                                + ("类内未见裁剪；且该集合被 `for ... in` 线性扫描 → "
                                   "鉴权开销随条目数线性增长" if scanned else "类内未见裁剪")),
                    "container": added,
                })
    return out


# ────────────────────────────────────────────────────────────────────
# AUTH-05 持锁做磁盘 IO
# ────────────────────────────────────────────────────────────────────
IO_HINT = re.compile(r"(?i)(write_text|write_bytes|read_text|read_bytes|\.write\(|json\.dump|json\.load|open\(|atomic_write|os\.replace|unlink|remove)")


def check_lock_with_io(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # 找 with self._lock: / with lock:
        for w in ast.walk(fn):
            if not isinstance(w, ast.With):
                continue
            ctxs = [ast.unparse(it.context_expr) for it in w.items]
            if not any(re.search(r"(?i)(lock|_lock|mutex|semaphore)", c) for c in ctxs):
                continue
            body = ast.Module(body=w.body, type_ignores=[])
            for x in ast.walk(body):
                if isinstance(x, ast.Call):
                    c = _chain(x)
                    if IO_HINT.search(c) or IO_HINT.search(ast.unparse(x)[:60]):
                        out.append({
                            "rule": "AUTH-05-lock-with-io", "severity": "medium",
                            "file": rel, "line": x.lineno, "function": fn.name,
                            "message": (f"{fn.name}() 在 `with {ctxs[0]}` 内做磁盘 IO "
                                        f"`{c}()`；锁持有时间随 IO 延长，"
                                        f"高频路径上会串行化所有调用"),
                            "lock": ctxs[0],
                        })
                        break
    return out


# ────────────────────────────────────────────────────────────────────
# AUTH-06 权限判定缺省放行
# ────────────────────────────────────────────────────────────────────
def check_default_allow(tree, rel):
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not re.search(r"(?i)(scope|permission|allow|authoriz|can_|check_)", fn.name):
            continue
        src = _fn_src(fn)
        # if/elif 链后跟 else: return True
        for n in ast.walk(fn):
            if not isinstance(n, ast.If) or not n.orelse:
                continue
            # else 块（不是 elif）
            orelse = n.orelse
            if len(orelse) == 1 and isinstance(orelse[0], ast.If):
                continue   # elif，不是 else
            else_src = ast.unparse(ast.Module(body=orelse, type_ignores=[]))
            if re.search(r"return\s+True", else_src) and not re.search(
                    r"return\s+False", else_src):
                out.append({
                    "rule": "AUTH-06-default-allow", "severity": "medium",
                    "file": rel, "line": orelse[0].lineno, "function": fn.name,
                    "message": (f"{fn.name}() 的条件链以 `else: return True` 收尾；"
                                f"未覆盖到的情况**默认放行**（应为默认拒绝）"),
                })
    return out


CHECKS = [
    check_route_without_auth,
    check_credential_equality,
    check_auth_failopen,
    check_credential_growth,
    check_lock_with_io,
    check_default_allow,
]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit/src/src/autoforge")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/data/workspace/audit/rounds/round-018/auth")
    outdir.mkdir(parents=True, exist_ok=True)

    findings, files = [], 0
    for p in sorted(root.rglob("*.py")):
        if any(x.startswith("test") for x in p.parts):
            continue
        try:
            tree = ast.parse(p.read_text(errors="ignore"))
        except SyntaxError:
            continue
        rel = str(p.relative_to(root))
        files += 1
        for c in CHECKS:
            try:
                findings += c(tree, rel)
            except Exception as e:  # noqa: BLE001
                print(f"[warn] {c.__name__} on {rel}: {e}", file=sys.stderr)

    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: (sev.get(x["severity"], 9), x["file"], x["line"]))
    (outdir / "auth-findings.json").write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    print(json.dumps({"files": files, "total": len(findings),
                      "by_severity": dict(Counter(f["severity"] for f in findings)),
                      "by_rule": dict(Counter(f["rule"] for f in findings))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
