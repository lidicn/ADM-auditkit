#!/usr/bin/env python3
"""auditkit —— 图谱化代码审计工作流（Graph-Augmented Audit Workflow）

设计原则（来自七轮实战复盘）：
  1. 可执行 > 可推断：跑不通的不进报告
  2. 交叉验证：图谱结论必须与 grep/AST 结论对撞，单方结论不采信
  3. 规范化前置：BOM/编码问题会让静态工具静默失效
  4. 入口点决定图谱有效性：孤儿检测必须用全部真实入口点

阶段:
  bootstrap  规范化源码（剥离 BOM，生成 .norm 副本）
  static     静态扫描（ruff/bandit/vulture/pylint/mypy）
  graph      构建调用图（PyCG）
  orphans    孤儿函数（定义但无人调用）—— 图谱 + grep 交叉验证
  deadcall   调用未定义方法/属性（by_room 类硬伤）
  cycles     循环依赖
  contract   签名契约 + 前后端路由契约
  verify     运行时验证（需自备场景脚本）
  all        串行跑完除 verify 外的全部阶段

用法:
  python3 audit.py <阶段> --repo <仓库路径> [--out <输出目录>]
"""
from __future__ import annotations

import argparse, ast, json, os, re, shutil, subprocess, sys, time
from collections import defaultdict
from pathlib import Path

TOOL_VERSION = "1.1"

# 外部/标准库/第三方接收者 —— 其方法不是本项目定义的，一律跳过
EXTERNAL_RECEIVERS = {
    "os","sys","io","json","time","re","ast","hashlib","hmac","secrets","socket",
    "uuid","logging","pathlib","Path","asyncio","threading","subprocess","shutil",
    "tempfile","collections","itertools","functools","datetime","random","base64",
    "html","urllib","requests","httpx","aiohttp","PIL","Image","img","np","pd",
    "sqlite3","zipfile","tarfile","csv","configparser","argparse","traceback",
    "inspect","importlib","types","typing","dataclasses","enum","copy","pickle",
    "request","response","img","ev","loop","task","session","client","conn","cur",
}

# 内置类型/标准库方法 —— deadcall 检测需排除，否则全是噪声
BUILTIN_METHODS = {
    "get","set","append","extend","insert","pop","remove","clear","copy","update",
    "keys","values","items","sort","reverse","index","count","find","join","split",
    "strip","lstrip","rstrip","replace","startswith","endswith","format","encode",
    "decode","lower","upper","title","isdigit","isalpha","read","write","close",
    "open","seek","flush","readlines","writelines","read_text","write_text","exists",
    "mkdir","unlink","rename","glob","rglob","iterdir","is_dir","is_file","resolve",
    "with_suffix","with_name","relative_to","as_posix","parts","suffix","stem","name",
    "group","search","match","sub","splitlines","rjust","ljust","zfill","hexdigest",
    "hex","new","uuid4","uuid1","now","fromtimestamp","strftime","strptime","astimezone",
    "timestamp","isoformat","weekday","sleep","time","monotonic","total_seconds",
    "add_done_callback","cancel","done","result","exception","set_result","set_exception",
    "to_thread","create_task","gather","wait_for","run_until_complete","get_event_loop",
    "get_running_loop","run_coroutine_threadsafe","call_later","call_soon","shield",
    "setdefault","fromkeys","popitem","difference","intersection","union","issubset",
    "add_argument","parse_args","error","exit","getLogger","debug","info","warning",
    "is_set","set","clear","wait","token_urlsafe","compare_digest","partition",
    "dirname","basename","abspath","environ","md5","sha1","sha256","pbkdf2_hmac",
    "thumbnail","convert","verify","BytesIO","form","json","loads","dumps","urlparse",
    "error","exception","critical","log","fetchone","fetchall","execute","commit",
    "executemany","executescript","close","rowcount","lastrowid","description",
}

# ── 通用工具 ────────────────────────────────────────────────────────
# 沙盒实测（第二十轮）：pip 安装的 CLI 工具在调用之间会**间歇性消失**
# （/usr/local/bin/ruff 存在但 subprocess 报 FileNotFoundError）。
# 原实现静默返回 -2 → 报告显示"0 行"，极易被误读为"无问题"。
# 现改为：① 找不到时尝试 `python3 -m` ② 仍失败则返回明确的 TOOL_UNAVAILABLE 标记
_RC_UNAVAILABLE = -2


def sh(cmd: list[str], cwd: str | None = None, timeout: int = 900) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, f"TIMEOUT after {timeout}s"
    except FileNotFoundError:
        # 退路 1：同名的 python -m 形式
        mod = cmd[0]
        if mod not in ("python3", "python"):
            try:
                p = subprocess.run(["python3", "-m", mod, *cmd[1:]],
                                   cwd=cwd, capture_output=True, text=True, timeout=timeout)
                combined = (p.stdout or "") + (p.stderr or "")
                # 第二十轮：rc!=0 且报 "No module named" == 该 python 没装，
                # **不能**当作成功返回（否则把错误信息当成扫描结果）
                if not ("No module named" in combined and p.returncode != 0):
                    return p.returncode, combined
            except FileNotFoundError:
                pass
            except subprocess.TimeoutExpired:
                return -1, f"TIMEOUT after {timeout}s"
        # 退路 2：绝对路径
        for base in ("/usr/local/bin", "/usr/bin"):
            cand = f"{base}/{cmd[0]}"
            if os.path.exists(cand):
                try:
                    p = subprocess.run([cand, *cmd[1:]],
                                       cwd=cwd, capture_output=True, text=True, timeout=timeout)
                    return p.returncode, (p.stdout or "") + (p.stderr or "")
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
        return _RC_UNAVAILABLE, f"TOOL_UNAVAILABLE: {cmd[0]}"

def pyfiles(root: Path, excludes=(".git", "__pycache__", "vendor", ".norm", "node_modules")) -> list[Path]:
    out = []
    for r, ds, fs in os.walk(root):
        ds[:] = [d for d in ds if d not in excludes]
        for f in fs:
            if f.endswith(".py"):
                out.append(Path(r) / f)
    return sorted(out)

def read(p: Path) -> str:
    raw = p.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")

# ── Stage 0: bootstrap ──────────────────────────────────────────────
def stage_bootstrap(repo: Path, out: Path) -> dict:
    """剥离 BOM 生成规范化副本。PyCG/ruff 遇 BOM 会 SyntaxError 或静默跳过文件。"""
    norm = repo / ".norm"
    if norm.exists():
        sh(["rm", "-rf", str(norm)], timeout=120)
        if norm.exists():
            shutil.rmtree(norm, ignore_errors=True)
    n_bom = 0
    for p in pyfiles(repo):
        rel = p.relative_to(repo)
        dst = norm / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        raw = p.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            n_bom += 1
            raw = raw[3:]
        dst.write_bytes(raw)
    return {"normalized_to": str(norm), "bom_files": n_bom,
            "note": "后续所有静态/图谱分析一律基于 .norm 副本"}

# ── Stage 1: static ─────────────────────────────────────────────────
STATIC = {
    "ruff":      (["ruff", "check", "--output-format=concise", "."], 300),
    "bandit":    (["bandit", "-r", ".", "-f", "txt", "-q"], 400),
    "vulture":   (["vulture", ".", "--min-confidence", "80"], 300),
    "pyflakes":  (["python3", "-m", "pyflakes", "."], 300),
    "pylint":    (["pylint", "--disable=all", "--enable=E,unused-import,undefined-variable",
                   "--recursive=y", "."], 600),
    "mypy":      (["mypy", "--ignore-missing-imports", "--no-error-summary", "."], 900),
}

def stage_static(repo: Path, out: Path) -> dict:
    norm = repo / ".norm"
    target = norm if norm.exists() else repo
    res = {}
    for name, (cmd, to) in STATIC.items():
        t0 = time.time()
        rc, txt = sh(cmd, cwd=str(target), timeout=to)
        lines = [l for l in txt.splitlines() if l.strip()][:400]
        unavailable = (rc == _RC_UNAVAILABLE)
        res[name] = {"rc": rc, "seconds": round(time.time() - t0, 1),
                     "lines": len(lines), "sample": lines[:60],
                     "unavailable": unavailable}
        (out / f"static_{name}.txt").write_text("\n".join(lines), encoding="utf-8")
        tag = "  ⚠️ 工具不可用（结果不可信，非'无问题'）" if unavailable else ""
        print(f"    {name:<10} rc={rc:<3} {len(lines):>4} 行  {res[name]['seconds']}s{tag}")
    return res

# ── Stage 2: graph ──────────────────────────────────────────────────
def discover_entrypoints(repo: Path) -> list[str]:
    """真实入口点 = 应用装配 + 全部路由模块（缺任一都会产生假孤儿）。"""
    eps = []
    app = repo / "butler" / "app.py"
    if app.exists():
        eps.append(str(app))
    api = repo / "butler" / "api"
    if api.exists():
        eps += [str(p) for p in sorted(api.glob("*_routes.py"))]
    return eps

def stage_graph(repo: Path, out: Path) -> dict:
    norm = repo / ".norm"
    src = norm if norm.exists() else repo
    eps = discover_entrypoints(repo)
    eps_norm = [str(src / Path(e).relative_to(repo)) for e in eps]
    if not eps_norm:
        return {"error": "未发现入口点"}
    cg = out / "callgraph.json"
    t0 = time.time()
    rc, txt = sh(["pycg", "--max-iter", "1", "--package", str(src),
                  *eps_norm, "-o", str(cg)], timeout=900)
    if not cg.exists():
        return {"error": f"pycg 失败 rc={rc}", "stderr": txt[-800:]}
    g = json.loads(cg.read_text(encoding="utf-8"))
    n_nodes = len(g)

    def succ(v):
        # PyCG 各版本输出不同：list 或 {"successors": [...]}
        return v if isinstance(v, list) else (v.get("successors", []) if isinstance(v, dict) else [])

    n_edges = sum(len(succ(v)) for v in g.values())
    # 反查索引
    callers: dict[str, set[str]] = defaultdict(set)
    for caller, info in g.items():
        for callee in succ(info):
            callers[callee].add(caller)
    (out / "callers.json").write_text(
        json.dumps({k: sorted(v) for k, v in callers.items()}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    print(f"    节点 {n_nodes} / 边 {n_edges} / 耗时 {round(time.time()-t0,1)}s")
    return {"nodes": n_nodes, "edges": n_edges, "entrypoints": len(eps_norm),
            "seconds": round(time.time() - t0, 1), "graph": str(cg)}

# ── Stage 3a: orphans（交叉验证）────────────────────────────────────
def stage_orphans(repo: Path, out: Path) -> dict:
    """孤儿 = 图谱零调用者 且 grep 零调用点。
    单凭图谱会误报：函数内 import + 工厂函数返回会让 PyCG 丢失类型。"""
    callers_f = out / "callers.json"
    if not callers_f.exists():
        return {"error": "请先跑 graph"}
    callers = json.loads(callers_f.read_text(encoding="utf-8"))
    g = json.loads((out / "callgraph.json").read_text(encoding="utf-8"))

    # 收集所有定义（模块级函数 + 类方法）
    defs: dict[str, list[tuple[str, int, bool]]] = defaultdict(list)
    for p in pyfiles(repo):
        try:
            t = ast.parse(read(p))
        except SyntaxError:
            continue
        rel = str(p.relative_to(repo))
        for n in ast.walk(t):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if n.name.startswith("__"):
                    continue
                cls = ""
                for parent in ast.walk(t):
                    if isinstance(parent, ast.ClassDef) and n in list(ast.walk(parent)):
                        cls = parent.name
                        break
                defs[n.name].append((rel, n.lineno, bool(cls)))

    # 常见名 = 与标准库/内置方法名冲突，grep 命中不可信，需人工确认
    COMMON = {
        "match","get","set","add","save","load","run","close","update","delete","format",
        "join","split","find","count","index","pop","append","insert","remove","sort",
        "keys","values","items","copy","clear","start","stop","wait","send","read",
        "write","open","flush","seek","encode","decode","strip","replace","search",
        "group","sub","parse","dump","has_key","values","call","bind","init","check",
        "push","pull","next","prev","iter","len","str","int","float","bool","dict",
        "list","tuple","all","any","max","min","sum","abs","round","filter","map",
    }
    cand = [k for k in g if not callers.get(k)]
    confirmed, likely, graph_only = [], [], []
    for node in cand:
        short = node.split(".")[-1]
        if short in ("__init__", "main") or short.startswith("_"):
            continue
        rc, txt = sh(["grep", "-rn", rf"\.{re.escape(short)}\s*\(", "--include=*.py", "butler/"],
                     cwd=str(repo))
        hits = [l for l in txt.splitlines() if l.strip()]
        real = [l for l in hits if f"def {short}" not in l]
        rec = {"node": node, "name": short, "grep_hits": len(real),
               "sample": real[0][:110] if real else ""}
        if real:
            graph_only.append(rec)                      # 图谱误报（PyCG 丢类型）
        elif short in COMMON:
            likely.append(rec)                          # 名字冲突，需人工确认
        else:
            confirmed.append(rec)                       # 高置信真孤儿
    confirmed.sort(key=lambda x: x["name"])
    likely.sort(key=lambda x: x["name"])
    print(f"    候选 {len(cand)} → 确认孤儿 {len(confirmed)} / 待确认 {len(likely)}"
          f" / 图谱误报 {len(graph_only)}")
    # ── 补充通道：AST 全量定义 + grep ──
    # 必要性：PyCG 只覆盖入口点可达代码，且把工厂函数返回的方法命名为
    #   factory.method（如 get_alias_store.list_aliases），
    #   完全未被调用的方法可能根本不出图 → 图检测存在覆盖空洞。
    ast_orph = []
    all_defs: dict[str, list[tuple[str, str, int]]] = defaultdict(list)  # name -> (file, cls, line)
    for p in pyfiles(repo):
        try:
            t = ast.parse(read(p))
        except SyntaxError:
            continue
        rel = str(p.relative_to(repo))
        for cls in [n for n in ast.walk(t) if isinstance(n, ast.ClassDef)]:
            for b in cls.body:
                if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)) and not b.name.startswith("__"):
                    all_defs[b.name].append((rel, cls.name, b.lineno))
    # 预先缓存：每个文件是否「可能持有该类实例」
    # 判据：文件文本中出现 类名 或 该模块的工厂/单例访问器名
    file_text: dict[str, str] = {}
    for p in pyfiles(repo):
        file_text[str(p.relative_to(repo))] = read(p)
    # 模块 -> 工厂访问器（get_xxx_store / get_xxx / init_xxx）
    # 只在「本模块定义的工厂/单例访问器」里取，避免抓到泛用的 get_runtime
    accessors: dict[str, set[str]] = defaultdict(set)
    for f, txt in file_text.items():
        mod = f.removesuffix(".py").replace("/", ".")
        for m in re.finditer(r"^\s*def\s+(get_\w+|init_\w+|build_\w+|make_\w+)\s*\(", txt, re.M):
            accessors[mod].add(m.group(1))

    checked = 0
    for name, locs in all_defs.items():
        if name.startswith("_"):        # 私有方法通常由 self 调用，噪声大
            continue
        checked += 1
        for f, cls, ln in locs:
            mod = f.removesuffix(".py").replace("/", ".")
            keys = ({cls} | accessors.get(mod, set())) - {"get_runtime", "get_logger",
                                                          "get_settings", "init_logging"}
            # 只在这些「可能持有实例」的文件里找调用点
            plausible = [g for g, t in file_text.items()
                         if any(k in t for k in keys) and g != f]
            if not plausible:
                ast_orph.append({"cls": cls, "method": name, "file": f, "line": ln,
                                 "reason": "无任何文件引用该类/工厂"})
                continue
            found = None
            for g in plausible:
                for i, line in enumerate(file_text[g].splitlines(), 1):
                    if re.search(rf"\.{re.escape(name)}\s*\(", line) and f"def {name}" not in line:
                        found = f"{g}:{i}"
                        break
                if found:
                    break
            if not found:
                tight = len(plausible) <= 10
                ast_orph.append({"cls": cls, "method": name, "file": f, "line": ln,
                                 "plausible_n": len(plausible),
                                 "confidence": "high" if tight else "low",
                                 "reason": f"{len(plausible)} 个可能文件内均无 .{name}() 调用"})
    hi = [x for x in ast_orph if x.get("confidence") == "high"]
    ast_orph.sort(key=lambda x: (x.get("plausible_n", 0), x["file"], x["line"]))

    # ── 第三通道：用 runtime 真实执行覆盖剔除误报 ──
    rt_f = out / "runtime_coverage.json"
    eliminated, remaining = [], ast_orph
    if rt_f.exists():
        rt = json.loads(rt_f.read_text(encoding="utf-8"))
        alive = set(rt.get("alive", []))
        remaining, eliminated = [], []
        for x in ast_orph:
            q = f"{x['file']}::{x['cls']}.{x['method']}"
            (eliminated if q in alive else remaining).append(x)
        print(f"    runtime 通道：{len(alive)} 个方法被真实执行 → "
              f"剔除 {len(eliminated)} 个 AST 误报，剩 {len(remaining)} 个")
    else:
        print("    runtime 通道：未运行（先跑 runtime 阶段可自动剔除误报）")

    print(f"    AST 通道：检查 {checked} 个类名方法 → 零调用 {len(ast_orph)} 个"
          f"（高置信 {len(hi)}）")

    return {"candidates": len(cand),
            "confirmed_orphans": confirmed,
            "likely_orphans_needing_review": likely,
            "graph_false_positive": graph_only[:80],
            "ast_orphans": remaining,
            "ast_orphans_all": ast_orph,
            "ast_eliminated_by_runtime": eliminated[:200],
            "ast_checked": checked,
            "methodology": ("双通道：①图谱=0 且 grep=0（仅覆盖入口可达代码）"
                            " ②AST 全量定义 + grep=0（补图覆盖空洞）。"
                            "名称冲突者单列待人工确认")}

# ── Stage 3b: deadcall（调用未定义成员）─────────────────────────────
def stage_deadcall(repo: Path, out: Path) -> dict:
    """obj.method() —— 若 method 名称在全仓无 def，即为疑似硬伤（by_room 类）。"""
    defined = set()
    for p in pyfiles(repo):
        try:
            t = ast.parse(read(p))
        except SyntaxError:
            continue
        for n in ast.walk(t):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined.add(n.name)
            if isinstance(n, ast.ClassDef):
                for b in n.body:
                    if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        defined.add(b.name)
                for g in n.bases:
                    defined.add(ast.unparse(g) if hasattr(ast, "unparse") else "")

    # 已知属性集合（dataclass field / property）
    hits = []
    for p in pyfiles(repo):
        try:
            src = read(p); t = ast.parse(src)
        except SyntaxError:
            continue
        rel = str(p.relative_to(repo))
        for n in ast.walk(t):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            if not isinstance(f, ast.Attribute):
                continue
            name = f.attr
            if name.startswith("__") or name in defined:
                continue
            # 排除内置/常用方法（这些不是本项目定义的，报出来全是噪声）
            if name in BUILTIN_METHODS:
                continue
            val = f.value
            vname = ast.unparse(val) if hasattr(ast, "unparse") else ""
            if vname in ("self","cls","os","sys","json","time","Path","logger","repo",
                         "asyncio","ast","re","Path"):
                continue
            root = re.match(r"[A-Za-z_][A-Za-z0-9_]*", vname)
            root = root.group(0) if root else ""
            if root in EXTERNAL_RECEIVERS:
                continue
            # hasattr 保护 = 静默降级信号
            guarded = "hasattr" in "".join(
                src.splitlines()[max(0, n.lineno-6):n.lineno])
            hits.append({"file": rel, "line": n.lineno, "expr": f"{vname}.{name}",
                         "hasattr_guarded": guarded,
                         "kind": "方法/属性名疑似未定义"})
    # 去重并按是否有 hasattr 保护排序（被保护的更危险：静默失效）
    seen, uniq = set(), []
    for h in hits:
        k = (h["file"], h["line"])
        if k in seen:
            continue
        seen.add(k); uniq.append(h)
    uniq.sort(key=lambda x: (not x["hasattr_guarded"], x["file"]))
    print(f"    疑似调用未定义成员 {len(uniq)} 处（其中 {sum(1 for x in uniq if x['hasattr_guarded'])} 处被 hasattr 保护 → 静默失效）")
    return {"count": len(uniq), "items": uniq[:120],
            "note": "hasattr 保护项最危险：错误被降级为静默短路"}

# ── Stage 3c: cycles ────────────────────────────────────────────────
def stage_cycles(repo: Path, out: Path) -> dict:
    norm = repo / ".norm"
    src = norm if norm.exists() else repo
    rc, txt = sh(["pydeps", str(src), "--max-bacon", "2", "--show-cycles", "--no-show"],
                 cwd=str(repo), timeout=600)
    cycles = [l.strip() for l in txt.splitlines() if "->" in l and "import" not in l.lower()]
    # 用 AST 自建模块级循环检测兜底
    imp: dict[str, set[str]] = defaultdict(set)
    for p in pyfiles(repo):
        try:
            t = ast.parse(read(p))
        except SyntaxError:
            continue
        mod = str(p.relative_to(repo)).replace("/", ".").removesuffix(".py")
        for n in ast.walk(t):
            if isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                imp[mod].add(n.module.split(".")[-1])
            elif isinstance(n, ast.Import):
                for a in n.names:
                    imp[mod].add(a.name.split(".")[-1])
    found, visiting = [], set()
    def dfs(m, path):
        if m in path:
            found.append(" -> ".join(list(path[path.index(m):]) + [m])); return
        if m in visiting:
            return
        visiting.add(m)
        for nx in imp.get(m, ()):
            if nx in imp:
                dfs(nx, path + [m])
    for m in list(imp):
        dfs(m, [])
    uniq = sorted(set(found))
    print(f"    模块级循环 {len(uniq)} 处")
    return {"ast_cycles": uniq[:40], "pydeps_cycles": cycles[:20]}

# ── Stage 4: contract ───────────────────────────────────────────────
def stage_contract(repo: Path, out: Path) -> dict:
    """(a) self.method 调用 vs 定义签名  (b) 后端路由 vs 前端 fetch"""
    res = {}

    # (a) 签名
    defs: dict[str, list[dict]] = defaultdict(list)
    for p in pyfiles(repo):
        try:
            t = ast.parse(read(p))
        except SyntaxError:
            continue
        for n in ast.walk(t):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = n.args
                defs[n.name].append({
                    "file": str(p.relative_to(repo)), "lineno": n.lineno,
                    "pos": [x.arg for x in a.posonlyargs + a.args],
                    "kwonly": [x.arg for x in a.kwonlyargs],
                    "defaults": len(a.defaults),
                    "vararg": a.vararg is not None, "kwarg": a.kwarg is not None,
                })
    bad = []
    for p in pyfiles(repo):
        try:
            t = ast.parse(read(p))
        except SyntaxError:
            continue
        f1 = str(p.relative_to(repo))
        for n in ast.walk(t):
            if not isinstance(n, ast.Call):
                continue
            fn = n.func
            if not (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                    and fn.value.id == "self"):
                continue
            cands = [d for d in defs.get(fn.attr, []) if d["file"] == f1]
            if not cands:
                continue
            c = cands[0]
            pos = [x for x in c["pos"] if x not in ("self", "cls")]
            req = set(pos[:len(pos) - c["defaults"]]) if c["defaults"] else set(pos)
            provided = set(pos[:len(n.args)]) | {k.arg for k in n.keywords if k.arg}
            # **kwargs 解包：AST 看不到内容，无法静态判定，跳过（避免误报）
            if any(k.arg is None for k in n.keywords):
                continue
            missing = req - provided
            unknown = [k.arg for k in n.keywords
                       if k.arg and k.arg not in pos and k.arg not in c["kwonly"] and not c["kwarg"]]
            if missing or unknown:
                bad.append({"file": f1, "line": n.lineno, "method": fn.attr,
                            "missing": sorted(missing), "unknown_kw": unknown,
                            "def_line": c["lineno"]})
    res["signature_mismatch"] = {"count": len(bad), "items": bad[:60]}

    # (b) 路由
    routes = set()
    for p in pyfiles(repo):
        for m in re.finditer(r'Route\(\s*"([^"]+)"', read(p)):
            routes.add(m.group(1))
    calls = set()
    for pat in ("butler/static/**/*.js", "butler/dashboard_pwa/**/*.js"):
        for jp in Path(repo).glob(pat):
            s = read(jp)
            for m in re.finditer(r'''(?:fetch|api\.\w+)\s*\(\s*[`'"]([^`'"]+)''', s):
                calls.add(m.group(1))
            for m in re.finditer(r'`(/api/[^`]*)`', s):
                calls.add(m.group(1))
    def segs(u):
        """切分为路径段；前端模板插值 ${...} 归一为参数标记 {}"""
        # 先消解 ${...}（其内部可能含 ?，必须先于 query 切分），再切 query
        u = re.sub(r"\$\{[^}]*\}", "{}", u)
        u = u.split("?")[0]
        return [x for x in u.strip("/").split("/") if x]
    def is_param(x):
        # Starlette 转换器 {id:int} / {skill_id} / 前端插值归一后的 {} / 含 {} 后缀
        return x.startswith("{") or "{}" in x
    def match(u):
        a = segs(u)
        if "/" + "/".join(a) in routes:
            return True
        for r in routes:
            b = [x for x in r.strip("/").split("/") if x]
            if len(a) == len(b) and all(x == y or is_param(x) or is_param(y)
                                        for x, y in zip(a, b)):
                return True
        return False
    missing = sorted({u for u in calls if u.startswith("/api") and not match(u)})
    res["route_mismatch"] = {"backend_routes": len(routes),
                             "frontend_calls": len(calls),
                             "frontend_only": missing}
    print(f"    签名不匹配 {len(bad)} / 前端调用后端无路由 {len(missing)}")
    return res

# ── Stage: secrets（硬编码地址/凭据扫描）───────────────────────────
PRIVATE_URL_RE = re.compile(r'"https?://(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)[\d./:]+')
SECRET_ASSIGN_RE = re.compile(
    r'''(?i)(token|key|password|secret)\s*[:=]\s*["'][^"']{6,}["']''')

def _collect_env_overridden_fields(repo: Path) -> set[str]:
    """从 config.py 的 Settings.load() 收集所有被 _env("X") 显式覆盖的字段名。

    必要性（第十轮教训）：dataclass 字段默认值写成字面量（如 ha_url="http://192.168..."），
    但 load() 里用 _env("HA_URL") 覆盖 → 用户配环境变量即可生效，不算 high。
    只看字段默认值会把 config.py 的 13 处全部误标为 high。
    """
    fields: set[str] = set()
    cfg = repo / "butler" / "config.py"
    if not cfg.exists():
        return fields
    try:
        txt = cfg.read_text(encoding="utf-8-sig")
    except Exception:
        return fields
    # 形如  field_name=_env("ENV_VAR", ...)
    for m in re.finditer(r"""(\w+)\s*=\s*_env\s*\(\s*["']([A-Z0-9_]+)["']""", txt):
        fields.add(m.group(1))
        fields.add(m.group(2).lower())
    return fields


def stage_secrets(repo: Path, out: Path) -> dict:
    """扫描硬编码：① 内网地址 ② 疑似硬编码凭据。

    severity 判据（第十轮修正）：
      同行出现 _env(/os.environ/getenv                      → low
      或 该行赋值目标字段名属于 Settings.load() 的 _env 覆盖集合 → low
      否则（纯字面量，用户不改源码就无法使用）              → high
    """
    overridden = _collect_env_overridden_fields(repo)
    lan, sec = [], []
    for p in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm",
                                     "node_modules", "tests")):
        try:
            content = p.read_text(encoding="utf-8-sig")
        except Exception:
            continue
        rel = str(p.relative_to(repo))
        for i, ln in enumerate(content.splitlines(), 1):
            for m in PRIVATE_URL_RE.finditer(ln):
                overridable = bool(re.search(r"_env\(|os\.environ|getenv", ln))
                if not overridable:
                    # 该行是否形如 `字段名: type = "http://..."` 且字段名在 _env 覆盖集合内
                    fm = re.search(r"""^\s*(\w+)\s*:\s*[^=]*=\s*["']https?://""", ln)
                    if fm and fm.group(1) in overridden:
                        overridable = True
                lan.append({"file": rel, "line": i, "url": m.group(0).strip('"'),
                            "env_overridable": overridable,
                            "severity": "low" if overridable else "high"})
            if SECRET_ASSIGN_RE.search(ln):
                if re.search(r"(?i)(_env|environ|getenv|None)", ln):
                    continue
                sec.append({"file": rel, "line": i, "snippet": ln.strip()[:110]})
    hi = [x for x in lan if x["severity"] == "high"]
    print(f"    硬编码内网地址 {len(lan)} 处（{len(hi)} 处无法用环境变量覆盖）"
          f" / 疑似硬编码凭据 {len(sec)} 处")
    return {"lan_urls": lan, "lan_high": hi, "hardcoded_secrets": sec}


# ── Stage: dupfiles（影子/孤儿模块检测）────────────────────────────
def stage_dupfiles(repo: Path, out: Path) -> dict:
    """检测「同名模块多份并存」+「零精确引用」，找出分叉的孤儿副本。

    四道过滤（缺一不可，避免误删）：
      ① 精确引用（全仓非 .md 文本，含 Dockerfile/yml/toml/sh）
      ② 括号导入 `from X import (a, b, ...)`（app.py 注册 25+ 路由模块的形式）
      ③ coverage 存活（执行过 ⇒ 动态加载，如 skills/engines/*/engine.py）
      ④ 排除同 stem twin 文件（logger 名碰撞）+ importlib 精确模块名
    """
    pkg = repo / "butler"
    if not pkg.exists():
        return {"skipped": "无 butler/ 包"}

    by_stem: dict[str, list] = defaultdict(list)
    for p in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        by_stem[p.stem].append(p)

    alive: set = set()
    rt_f = out / "runtime_coverage.json"
    if rt_f.exists():
        alive = set(json.loads(rt_f.read_text(encoding="utf-8")).get("alive", []))

    # 不含 .md：文档对文件名的**提及**不构成代码引用
    EXTS = {".py", ".yml", ".yaml", ".toml", ".sh", ".txt", ".cfg", ".ini", ".json", ""}
    SKIP_DIRS = {".git", "__pycache__", "vendor", ".norm", "node_modules",
                 ".ruff_cache", ".mypy_cache", ".pytest_cache", ".venv", ".idea"}
    # 第十六轮教训：ref_files **必须排除 tests/** —— 否则
    # tests/test_http_contract_top5.py 里 "butler.schema 是死副本" 这句
    # **点名文字**会被误计为引用，导致漏报孤儿（P1-45 的 schema.py）。
    # 讽刺的是：恰恰是证明它已死的注释救了它。
    ref_files: list = []
    for r, ds, fs in os.walk(repo):
        ds[:] = [d for d in ds if d not in SKIP_DIRS and not d.startswith(".cache")]
        if "tests" in Path(r).parts:
            continue
        for f in fs:
            if f.startswith(".") and f not in (".env.example", ".gates.toml"):
                continue
            fp = Path(r) / f
            if fp.suffix in EXTS or f in ("Dockerfile", "Makefile", "Procfile"):
                ref_files.append(fp)
    texts: dict = {}
    for p in ref_files:
        try:
            texts[str(p)] = p.read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            texts[str(p)] = ""

    results = []
    for stem, paths in sorted(by_stem.items()):
        if len(paths) < 2 or stem == "__init__":
            continue
        for p in paths:
            rel = str(p.relative_to(repo))
            mod = rel[:-3].replace("/", ".")
            short = mod.rsplit(".", 1)[-1]
            pat = re.compile(
                r"{mod}\b|from \.{short} import|from \.\.\s*import\s*{short}\b"
                r"|importlib\.import_module\([\"']{mod}[\"']|{rel}".format(
                    mod=re.escape(mod), short=re.escape(short), rel=re.escape(rel)))
            parent = mod.rsplit(".", 1)[0] if "." in mod else ""
            parent_pat = (re.compile(rf"from\s+{re.escape(parent)}\s+import\s*\(")
                          if parent else None)
            refs = []
            for q in ref_files:
                if q == p or q.stem == stem:
                    continue
                rel_q = str(q.relative_to(repo))
                body = texts[str(q)]
                for i, ln in enumerate(body.splitlines(), 1):
                    if pat.search(ln) and not ln.strip().startswith("#"):
                        refs.append(f"{rel_q}:{i}")
                if parent_pat:
                    la = body.splitlines()
                    for i, ln in enumerate(la):
                        if not parent_pat.search(ln):
                            continue
                        for j in range(i, min(i + 60, len(la))):
                            nm = re.match(r"\s*([A-Za-z_][\w]*)\s*,?\s*$", la[j])
                            if nm and nm.group(1) == short:
                                refs.append(f"{rel_q}:{j+1}")
                            if la[j].rstrip().endswith(")"):
                                break
            if refs:
                continue
            alive_n = sum(1 for a in alive if a.startswith(rel + "::"))
            if alive_n > 0:
                continue
            diff_n, twin = 0, ""
            for q in paths:
                if q == p:
                    continue
                try:
                    d = subprocess.run(["diff", str(p), str(q)],
                                       capture_output=True, text=True).stdout
                except Exception:
                    d = ""
                n = len([l for l in d.splitlines() if l[:1] in ("<", ">")])
                if n > diff_n:
                    diff_n, twin = n, str(q.relative_to(repo))
            try:
                lines_n = len(p.read_text(encoding="utf-8-sig").splitlines())
            except Exception:
                lines_n = 0
            results.append({"file": rel, "stem": stem, "lines": lines_n,
                            "exact_refs": 0, "alive_methods": alive_n,
                            "twin": twin, "diff_lines": diff_n,
                            "twin_files": [str(q.relative_to(repo)) for q in paths if q != p]})
    results.sort(key=lambda x: -x["diff_lines"])
    print(f"    影子/孤儿模块 {len(results)} 个（同名并存 + 零精确引用）")
    for r in results[:8]:
        print(f"      {r['file']}  ({r['lines']} 行, 与 {r['twin'] or '-'} 差异 {r['diff_lines']})")
    return {"count": len(results), "items": results}


# ── Stage: httpcontract（出站请求契约）─────────────────────────────
RESP_METHODS = re.compile(r"(session|c|client|s)\.(get|post|put|delete|request|patch)\(")
STATUS_CHECK = {"status", "status_code", "raise_for_status", "ok", "is_success"}


def stage_httpcontract(repo: Path, out: Path) -> dict:
    """检测出站 HTTP 响应是否在解析前检查状态码（第九轮 P0-14 的人工发现固化）。"""
    findings = []
    for p in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            src = p.read_text(encoding="utf-8-sig")
            tree = ast.parse(src)
        except SyntaxError:
            continue
        rel = str(p.relative_to(repo))
        srclines = src.splitlines()
        for node in ast.walk(tree):
            resp, lineno = None, None
            if isinstance(node, ast.AsyncWith):
                for it in node.items:
                    if isinstance(it.optional_vars, ast.Name):
                        expr = ast.unparse(it.context_expr) if hasattr(ast, "unparse") else ""
                        if RESP_METHODS.search(expr):
                            resp, lineno = it.optional_vars.id, node.lineno
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Await):
                if isinstance(node.targets[0], ast.Name):
                    expr = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
                    if RESP_METHODS.search(expr):
                        resp, lineno = node.targets[0].id, node.lineno
            if not resp:
                continue
            chunk = "\n".join(srclines[lineno - 1: lineno + 24])
            uses = re.findall(rf"\b{re.escape(resp)}\.(\w+)", chunk)
            parsed = [u for u in uses if u in ("json", "text")]
            checked = [u for u in uses if u in STATUS_CHECK]
            if parsed and not checked:
                findings.append({"file": rel, "line": lineno, "resp": resp,
                                 "uses": sorted(set(uses))[:6],
                                 "kind": "出站响应解析前未检查状态码"})
        # ── 判据 2：响应**完全丢弃**（第十九轮 P1-48 暴露的盲区）─────────
        # 原判据依赖 `resp.json()` / `resp.text` 存在（parsed 非空）。
        # 而 execute_device_command 的 7 处 `await client.post(...)` 结果
        # **连变量都不赋**，parsed 为空 → 完全逃逸。
        # 形态：HTTP 方法调用出现在 Expr 语句中（Await 或普通 Call）。
        for node in ast.walk(tree):
            n = None
            if isinstance(node, ast.Expr):
                if isinstance(node.value, ast.Await):
                    n = node.value.value
                elif isinstance(node.value, ast.Call):
                    n = node.value
            if not isinstance(n, ast.Call):
                continue
            callee = ast.unparse(n.func) if hasattr(ast, "unparse") else ""
            if not re.search(r"\.(post|put|patch|delete)\s*$", callee):
                continue  # 只管写操作；get 丢弃结果通常是查询失败可接受
            # 是否已被赋给变量
            assigned = False
            for anc in ast.walk(tree):
                if isinstance(anc, ast.Assign) and anc.value is (node.value if isinstance(node.value, ast.Await) else node):
                    assigned = True
            if assigned:
                continue
            findings.append({"file": rel, "line": node.lineno, "resp": "<discarded>",
                             "uses": [callee.split(".")[-1]],
                             "kind": "出站响应完全丢弃（不赋值、不检查状态码）"})
    # 去重
    seen, uniq = set(), []
    for f in findings:
        k = (f["file"], f["line"], f["kind"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    by = {}
    for x in uniq:
        by[x["kind"]] = by.get(x["kind"], 0) + 1
    print(f"    出站请求未检查状态码 {len(uniq)} 处 {by}")
    for x in uniq[:6]:
        print(f"      {x['file']}:{x['line']}  {x['kind'][:40]}")
    return {"count": len(uniq), "by_kind": by, "items": uniq}


# ── Stage: mqtt（发布/订阅主题契约）────────────────────────────────
def stage_mqtt(repo: Path, out: Path) -> dict:
    """MQTT 主题契约：发布 vs 订阅配对检查。"""
    subs: dict = {}
    pubs: dict = {}

    consts: dict = {}
    tp0 = repo / "butler" / "bus" / "topics.py"
    if tp0.exists():
        try:
            tt0 = ast.parse(tp0.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            tt0 = None
        if tt0:
            for n in tt0.body:
                if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name):
                    v = n.value
                    if isinstance(v, ast.Constant) and isinstance(v.value, str):
                        consts[n.targets[0].id] = v.value
                    elif isinstance(v, ast.JoinedStr):
                        parts = []
                        for x in v.values:
                            if isinstance(x, ast.Constant) and isinstance(x.value, str):
                                parts.append(x.value)
                            elif isinstance(x, ast.FormattedValue):
                                e = x.value
                                if isinstance(e, ast.Name):
                                    parts.append(consts.get(e.id, "{" + e.id + "}"))
                                elif isinstance(e, ast.Constant):
                                    parts.append(str(e.value))
                        consts[n.targets[0].id] = "".join(parts)

    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm",
                                      "node_modules", "tests")):
        try:
            tree = ast.parse(pr.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            continue
        rel = str(pr.relative_to(repo))
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            fn = n.func
            name = (fn.attr if isinstance(fn, ast.Attribute)
                    else (fn.id if isinstance(fn, ast.Name) else ""))
            if name not in ("subscribe", "publish", "mqtt_publish", "pub",
                            "publish_json", "publish_raw"):
                continue
            if not n.args:
                continue
            a0 = n.args[0]
            val = None
            if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                val = a0.value
            elif isinstance(a0, ast.JoinedStr):
                val = "".join(x.value for x in a0.values if isinstance(x, ast.Constant))
            elif isinstance(a0, ast.Name) and a0.id in consts:
                val = consts[a0.id]
            if not val:
                continue
            loc = f"{rel}:{n.lineno}"
            (subs if name == "subscribe" else pubs).setdefault(val, []).append(loc)

    if tp0.exists():
        try:
            tt = ast.parse(tp0.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            tt = None
        if tt:
            for n in tt.body:
                if (isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                        and n.targets[0].id.endswith("TOPICS")
                        and isinstance(n.value, (ast.Tuple, ast.List))):
                    for el in n.value.elts:
                        if isinstance(el, ast.Name) and el.id in consts:
                            subs.setdefault(consts[el.id], []).append(
                                f"butler/bus/topics.py:{el.lineno}(via {n.targets[0].id})")
                        elif isinstance(el, ast.Constant) and isinstance(el.value, str):
                            subs.setdefault(el.value, []).append(
                                f"butler/bus/topics.py:{el.lineno}(via {n.targets[0].id})")

    def topic_match(pattern, topic):
        pp, tp = pattern.split("/"), topic.split("/")
        for i, seg in enumerate(pp):
            if seg == "#":
                return True
            if i >= len(tp):
                return False
            if seg == "+":
                continue
            if seg != tp[i]:
                return False
        return len(pp) == len(tp)

    orphan_sub = [{"topic": s, "sub_at": l} for s, l in subs.items()
                  if not any(topic_match(s, p) for p in pubs)]
    orphan_pub = [{"topic": p, "pub_at": l} for p, l in pubs.items()
                  if not any(topic_match(s, p) for s in subs)]
    near_miss = []
    import difflib
    for s, sl in subs.items():
        for p, pl in pubs.items():
            if topic_match(s, p) or s == p:
                continue
            if s.replace("/", "") == p.replace("/", "") or \
                    difflib.SequenceMatcher(None, s, p).ratio() > 0.85:
                near_miss.append({"sub": s, "pub": p, "sub_at": sl, "pub_at": pl})
    print(f"    订阅 {len(subs)} / 发布 {len(pubs)} → "
          f"无人发布 {len(orphan_sub)} / 无人订阅 {len(orphan_pub)} / 近似未匹配 {len(near_miss)}")
    return {"sub_topics": len(subs), "pub_topics": len(pubs),
            "orphan_sub": orphan_sub, "orphan_pub": orphan_pub, "near_miss": near_miss}


# ── Stage: dupimpl（重复实现检测）──────────────────────────────────
def _func_fingerprint(fn):
    calls, attrs, consts = [], [], []
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Attribute):
                calls.append(f.attr)
            elif isinstance(f, ast.Name):
                calls.append(f.id)
        elif isinstance(n, ast.Attribute):
            attrs.append(n.attr)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) > 2:
            consts.append(n.value)
    return tuple(calls), tuple(sorted(set(attrs))), tuple(sorted(set(consts)))


def _jaccard(a, b):
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def stage_dupimpl(repo: Path, out: Path) -> dict:
    """跨文件结构性重复实现检测。按「常量差异」降序 → 常量不同 = 已漂移。"""
    funcs = []
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm",
                                      "node_modules", "tests")):
        try:
            tree = ast.parse(pr.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            continue
        rel = str(pr.relative_to(repo))
        for n in ast.walk(tree):
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            bl = (getattr(n, "end_lineno", n.lineno) or n.lineno) - n.lineno
            if bl < 8:
                continue
            calls, attrs, consts = _func_fingerprint(n)
            if len(calls) < 4:
                continue
            funcs.append({"file": rel, "line": n.lineno, "name": n.name,
                          "calls": calls, "attrs": attrs, "consts": consts, "len": bl})
    pairs = []
    for i in range(len(funcs)):
        for j in range(i + 1, len(funcs)):
            a, b = funcs[i], funcs[j]
            if a["file"] == b["file"]:
                continue
            sc = _jaccard(a["calls"], b["calls"])
            sa = _jaccard(a["attrs"], b["attrs"])
            sk = _jaccard(a["consts"], b["consts"])
            if sc >= 0.6 and sa >= 0.6 and sk >= 0.5:
                pairs.append({
                    "a": f"{a['file']}:{a['line']} {a['name']}",
                    "b": f"{b['file']}:{b['line']} {b['name']}",
                    "sim_calls": round(sc, 3), "sim_attrs": round(sa, 3),
                    "sim_consts": round(sk, 3), "drift": round(1.0 - sk, 3),
                    "consts_only_in_a": sorted(set(a["consts"]) - set(b["consts"]))[:6],
                    "consts_only_in_b": sorted(set(b["consts"]) - set(a["consts"]))[:6]})
    pairs.sort(key=lambda x: -x["drift"])
    seen, uniq = set(), []
    for x in pairs:
        ka = x["a"].rsplit(" ", 1)[0]
        kb = x["b"].rsplit(" ", 1)[0]
        if ka in seen or kb in seen:
            continue
        seen.add(ka); seen.add(kb)
        uniq.append(x)
    print(f"    跨文件重复实现 {len(uniq)} 对（阈值: 调用≥0.6 属性≥0.6 常量≥0.5）")
    for x in uniq[:6]:
        print(f"      drift={x['drift']:.2f}  {x['a']}  ≈  {x['b']}")
    return {"count": len(uniq), "pairs": uniq[:60], "scanned": len(funcs)}


# ── Stage: falsyzero（or-默认值的 falsy 吞值）─────────────────────
# 动因：第十七轮 P2-14 / P2-15 ——
#   `s["success_rate"] or 1`   → 0.0 变 1，最差技能被排到最优位置
#   `brain.get('temperature') or 0.7` → 用户设 0.0（确定性解码）被改成 0.7
#   共同形态：`X or <默认值>`，当 X 的合法取值包含 0/0.0/False/"" 时被静默吞掉。
#   难点：0 是否合法取值**取决于语义**，工具只能排序优先级，不能自动判定。
# 0 是**合法且有语义**的取值 → `or 默认` 会吞掉它（真缺陷）
ZERO_MEANINGFUL = {
    # 采样/比率类：0 表示确定性或零值，是常见配置
    "temperature", "top_p", "top_k", "repetition_penalty", "presence_penalty",
    "frequency_penalty", "threshold", "confidence", "weight", "score",
    "rate", "ratio", "success_rate", "fail_rate", "similarity", "sim",
    # 物理/表现量：0 表示静音、最暗、无延迟，合法
    "speed", "volume", "brightness", "delay", "interval", "offset",
    "retry", "max_retries",
}
# 0 **无意义**，`or 默认` 是合理兜底 → 明确排除，避免噪声
# （第十七轮教训：初版把 max_chars/days/limit/count 放进 ZERO_MEANINGFUL，
#   产生 13 处 high 中约 8 处是假阳性；这些字段取 0 无实际语义）
ZERO_MEANINGLESS = {
    "max_chars", "max_tokens", "days", "hours", "minutes", "seconds",
    "limit", "count", "total", "size", "width", "height", "page", "page_size",
}


def stage_falsyzero(repo: Path, out: Path) -> dict:
    """检测 `X or <常量>` 形式的 falsy 吞值。

    分级（需人工确认，不自动定级为缺陷）：
      FZ-high  ：变量/键名在 ZERO_MEANINGFUL 集合（比率、温度、阈值、计数）
                → 0 是合法取值，`or` 会吞掉
      FZ-low   ：其他，可能是合理兜底
    同时报告**右值**以便人工判断（如 `or 1` 对成功率字段尤其危险）
    """
    findings = []
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            src = pr.read_text(encoding="utf-8-sig")
            tree = ast.parse(src)
        except SyntaxError:
            continue
        rel = str(pr.relative_to(repo))
        for n in ast.walk(tree):
            if not isinstance(n, ast.BoolOp) or not isinstance(n.op, ast.Or):
                continue
            last = n.values[-1]
            if not isinstance(last, ast.Constant) or isinstance(last.value, bool):
                continue
            if not isinstance(last.value, (int, float)) or last.value == 0:
                continue  # `x or 0` 无害
            code = ast.unparse(n)
            # 从左值抽取字段名：a.b.c / d['k'] / d.get('k')
            field = ""
            first = n.values[0]
            if isinstance(first, ast.Subscript) and isinstance(first.slice, ast.Constant):
                field = str(first.slice.value)
            elif isinstance(first, ast.Call) and isinstance(first.func, ast.Attribute) \
                    and first.func.attr == "get" and first.args \
                    and isinstance(first.args[0], ast.Constant):
                field = str(first.args[0].value)
            elif isinstance(first, ast.Attribute):
                field = first.attr
            elif isinstance(first, ast.Name):
                field = first.id
            fl = field.lower()
            # MEANINGLESS 优先（明确排除 > 模糊命中）
            hit = fl in ZERO_MEANINGFUL and fl not in ZERO_MEANINGLESS
            findings.append({
                "file": rel, "line": n.lineno, "field": field,
                "default": last.value, "expr": code[:80],
                "severity": "high" if hit else "low",
                "note": (f"字段 '{field}' 的 0 是合法取值，`or {last.value}` 会吞掉"
                         if hit else "0 可能无意义，需人工确认"),
            })
    hi = [x for x in findings if x["severity"] == "high"]
    print(f"    `X or <常量>` {len(findings)} 处（high {len(hi)}）")
    for x in hi[:10]:
        print(f"      [high] {x['file']}:{x['line']}  {x['field']} or {x['default']}")
    return {"count": len(findings), "high": len(hi), "items": findings}


# ── Stage: kwcontract（关键字参数 vs 函数签名）─────────────────────
# 动因：第十六轮 P1-44 —— quarantine.py:177 调
#       `rt.bark.push(..., reason="技能隔离")`，而 Bark.push **无 reason 参数**
#       → TypeError；但因 create_task 丢弃 + 协程异常延迟抛出，**完全静默**。
#       该形态 100% 可静态检测，本轮固化为阶段。
#       注意：与 stage_contract 不同 —— contract 只查**必填参数缺失**，
#              kwcontract 查**传入了不存在的参数名**（多余 kwarg）。


def _collect_defs(repo: Path) -> dict:
    """收集全仓函数/方法定义名 → (参数名集合, 是否有 **kwargs, 文件:行)"""
    defs: dict = {}
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            tree = ast.parse(pr.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            continue
        rel = str(pr.relative_to(repo))
        for n in ast.walk(tree):
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = n.args
            names = [a.arg for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)]
            has_kw = args.kwarg is not None
            defs.setdefault(n.name, []).append({
                "params": set(names), "has_kwargs": has_kw,
                "loc": f"{rel}:{n.lineno}",
            })
    return defs


# 外部库同名函数的合法 kwarg（用于消除 `get(timeout=)` / `run(cwd=)` / `format(x=)` 类噪声）
# 第十七轮：初版 43 处中 34 处为此类噪声（httpx.get / subprocess.run / str.format /
# asyncio.create_task），仅 3 处为真实缺陷。
EXTERNAL_KWARGS = {
    "get": {"params", "headers", "timeout", "cookies", "auth", "json", "data",
            "follow_redirects", "allow_redirects", "verify", "proxies", "files",
            "content", "stream", "max_redirects"},
    "post": {"params", "headers", "timeout", "cookies", "auth", "json", "data",
             "follow_redirects", "files", "content"},
    "put": {"params", "headers", "timeout", "json", "data", "content"},
    "patch": {"params", "headers", "timeout", "json", "data"},
    "delete": {"params", "headers", "timeout"},
    "request": {"params", "headers", "timeout", "json", "data", "method", "url"},
    "run": {"args", "cwd", "env", "timeout", "capture_output", "shell", "check",
            "text", "input", "stdout", "stderr", "encoding", "universal_newlines"},
    "create_task": {"name", "coro", "loop", "context"},
    "format": set(),  # str.format(**kwargs) 任意 kwarg 合法 → 整名跳过
    "Popen": {"args", "cwd", "env", "shell", "stdout", "stderr", "text"},
}
# 整名跳过：这些名字在本仓有定义，但调用点几乎必然是外部库/内建
SKIP_CALLEE = {"format", "get", "post", "put", "patch", "delete", "request",
               "run", "create_task", "Popen", "Session", "ClientSession"}


def stage_kwcontract(repo: Path, out: Path) -> dict:
    """检测「传入了目标函数不存在的 kwarg」。

    判据（四层，逐层收紧以控噪）：
      ① 调用点带关键字参数
      ② 能在本仓找到**同名**定义（否则是外部库，跳过）
      ③ **所有**同名定义都不接受该 kwarg，且**都无 **kwargs**（若有任一接受则为合法重载）
      ④ 排除 self/cls 等显式排除项、排除 **kwargs 解包调用
    """
    defs = _collect_defs(repo)
    # 本地类名 → 其实例方法调用需特殊处理（obj.method(...)）
    findings = []
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            src = pr.read_text(encoding="utf-8-sig")
            tree = ast.parse(src)
        except SyntaxError:
            continue
        rel = str(pr.relative_to(repo))
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call) or not n.keywords:
                continue
            f = n.func
            if isinstance(f, ast.Attribute):
                callee = f.attr
            elif isinstance(f, ast.Name):
                callee = f.id
            else:
                continue
            cands = defs.get(callee)
            if not cands:
                continue  # 外部库函数，跳过
            # 噪声过滤：该 kwarg 是外部同名 API 的合法参数 → 跳过
            ext = EXTERNAL_KWARGS.get(callee)
            for kw in n.keywords:
                if kw.arg is None:
                    continue  # **kwargs 解包
                if ext is not None and (ext == set() or kw.arg in ext):
                    continue
                ok = False
                for c in cands:
                    if c["has_kwargs"] or kw.arg in c["params"]:
                        ok = True
                        break
                if ok:
                    continue
                findings.append({
                    "file": rel, "line": n.lineno, "callee": callee, "kwarg": kw.arg,
                    "candidates": [c["loc"] for c in cands][:3],
                    "accepted": sorted(list(cands[0]["params"]))[:14],
                    "kind": f"调用 {callee}() 传入不存在的 kwarg '{kw.arg}' → TypeError",
                })
    seen, uniq = set(), []
    for f in findings:
        k = (f["file"], f["line"], f["callee"], f["kwarg"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    uniq.sort(key=lambda x: (x["file"], x["line"]))
    print(f"    kwarg 不匹配 {len(uniq)} 处")
    for x in uniq[:8]:
        print(f"      {x['file']}:{x['line']}  {x['callee']}(... {x['kwarg']}= ...)")
    return {"count": len(uniq), "items": uniq}


# ── Stage: successclaim（谎报成功）────────────────────────────────
# 动因：**本项目最高频的失效形态**，历史 ≥5 条结论同源，却完全无阶段覆盖：
#   P1-48  execute_device_command  HTTP 401/404/500 → 仍记 {"success": True}
#   P1-44  quarantine 通知         TypeError → 因 create_task 丢弃，无人知晓
#   P1-46  anomaly 告警播报        TypeError → 被 logger.warning 吞
#   第五轮 inbox                   入队成功 → 先扣预算、再记 INBOX_DONE 成功
#   第五轮 dialog                  入队成功 → 返回 {"spoken": True}
#   第九轮 deskpilot.health()      403 → 报 ok: True
# 共同形态：**发生失败后，控制流仍走到"成功"分支**（返回 ok / 记 success=True /
#   返回 True / 不 re-raise）。因为不抛异常，日志里没有任何 ERROR。
# 可静态检测：扫 try/except 之后无条件出现的成功标记。

SUCCESS_TOKENS = {
    # 字面量成功标记
    "ok", "success", "done", "true", "passed", "healthy",
}
SUCCESS_KEYWORDS = {
    "ok", "success", "spoken", "delivered", "sent", "played", "accepted",
    "completed", "finished", "healthy", "passed",
}


def stage_successclaim(repo: Path, out: Path) -> dict:
    """检测「失败后仍声明成功」。

    **精确判据**（第十九轮教训：只看 except handler 本身会产生大量误报——
    decision_routes.py:85 的 except 后是重试循环并最终 return False；
    auto_switch.py:157 的 except 后直接 return False。二者都是正确写法）。

    真正的问题是 **except 之后的控制流是否落到成功分支**：
      SC-2  try/except 之后的**下一条语句**是成功返回（return True / {"ok": True}）
      SC-4  except 分支是 bare pass 且后续仍走成功路径
      SC-3  调用结果未赋值（连成败都无法判定）
    实现：定位 Try 节点在其父 block 中的位置，取其后继语句。
    """
    findings = []
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            src = pr.read_text(encoding="utf-8-sig")
            tree = ast.parse(src)
        except SyntaxError:
            continue
        rel = str(pr.relative_to(repo))
        for fn in [f for f in ast.walk(tree)
                   if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            fname = fn.name.lower()
            if re.search(r"^(try_|safe_|_maybe|maybe_|_optional|best_effort|_probe)", fname):
                continue
            # 建立「父 block → 语句序列」索引，用于取 Try 的后继
            blocks = []
            for n in ast.walk(fn):
                for attr in ("body", "orelse", "finalbody"):
                    b = getattr(n, attr, None)
                    if isinstance(b, list) and any(isinstance(x, ast.Try) for x in b):
                        blocks.append(b)
            for n in ast.walk(fn):
                if not isinstance(n, ast.Try):
                    continue
                swallowed = []
                for h in n.handlers:
                    hb = h.body
                    if not hb:
                        continue
                    if any(isinstance(x, ast.Raise) for x in ast.walk(
                            ast.Module(body=hb, type_ignores=[]))):
                        continue  # re-raise，不吞
                    bare_pass = len(hb) == 1 and isinstance(hb[0], ast.Pass)
                    only_log = all(isinstance(x, ast.Expr) and isinstance(x.value, ast.Call)
                                   and _is_logger_call(x.value) for x in hb)
                    if bare_pass or only_log:
                        swallowed.append((h.lineno, "SC-4" if bare_pass else "SC-2"))
                if not swallowed:
                    continue
                # 取 Try 在其父 block 中的后继语句
                succ = None
                for b in blocks:
                    for i, st in enumerate(b):
                        if st is n and i + 1 < len(b):
                            succ = b[i + 1]
                            break
                    if succ is not None:
                        break
                if succ is None:
                    continue
                sc = ast.unparse(succ) if hasattr(ast, "unparse") else ""
                # 后继是否是"成功"语义
                is_success = bool(re.match(
                    r"return\s+(True|\{\s*\"ok\"\s*:\s*True)", sc)
                    or re.match(r"\w+\[\"success\"\]\s*=\s*True", sc)
                    or re.match(r"return\s+\{[^}]*\"status\"\s*:\s*\"(ok|success|done)\"", sc))
                if not is_success:
                    continue
                for lineno, kind in swallowed:
                    findings.append({
                        "file": rel, "line": lineno, "kind": kind, "func": fn.name,
                        "severity": "high",
                        "detail": (f"函数 {fn.name}: except 吞异常后，控制流落到成功返回 "
                                   f"`{sc[:48]}`"),
                        "success_stmt": sc[:60],
                    })
            # SC-3：调用结果未赋值
            fsrc = ast.unparse(fn) if hasattr(ast, "unparse") else ""
            if re.search(r'"(ok|success|spoken|delivered|accepted)"\s*:\s*True|'
                         r'success\s*=\s*True|return\s+True', fsrc):
                for n in ast.walk(fn):
                    if isinstance(n, ast.Expr) and isinstance(n.value, ast.Await):
                        code = ast.unparse(n.value)
                        if re.search(r"\.(post|put|push|send|publish|notify)\s*\(", code):
                            findings.append({"file": rel, "line": n.lineno, "kind": "SC-3",
                                             "func": fn.name, "severity": "medium",
                                             "detail": (f"函数 {fn.name}: `{code[:52]}` "
                                                        "结果未赋值 → 无法判定成败")})
    seen, uniq = set(), []
    for f in findings:
        k = (f["file"], f["line"], f["kind"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    by = {}
    for x in uniq:
        by[x["kind"]] = by.get(x["kind"], 0) + 1
    hi = [x for x in uniq if x["severity"] == "high"]
    print(f"    谎报成功候选 {len(uniq)} 处 {by}  (high {len(hi)})")
    for x in hi[:8]:
        print(f"      [{x['kind']}] {x['file']}:{x['line']}  {x['func']}  → {x.get('success_stmt','')}")
    return {"count": len(uniq), "high": len(hi), "by_kind": by, "items": uniq}


def _is_logger_call(call: ast.Call) -> bool:
    """判断是否为 logger.xxx(...) / logging.xxx(...) 调用"""
    f = call.func
    if isinstance(f, ast.Attribute):
        base = f.value
        if isinstance(base, ast.Name) and base.id in ("logger", "log", "logging"):
            return True
        if isinstance(base, ast.Attribute) and base.attr in ("logger", "log"):
            return True
    return False


# ── Stage: deploycontract（部署契约）──────────────────────────────
# 动因：第七轮 P0-11 —— config.py 把 DESKPILOT_API_TOKEN / TASK_REPORT_TOKEN
#       设为**启动硬门槛**（缺失即 raise），但 .env.example / docker-compose.yml
#       / README 全无记载。新用户照 README 走完，容器起不来。
#       且校验藏在 get_conn() 的惰性调用里，**不在启动时抛，而在第一次写库时抛**。
# 判据：代码中「必需（缺失即 raise/退出）」的环境变量
#       vs 部署清单（.env.example / docker-compose*.yml / README）中出现的变量。
MISSING_PATTERNS = [
    r"raise\s+RuntimeError\([^)]*",
    r"raise\s+SystemExit",
    r"sys\.exit\(",
    r"logger\.critical\(",
]


def stage_deploycontract(repo: Path, out: Path) -> dict:
    """检测「代码要求但部署清单未声明」的环境变量。

    三步：
      ① 扫全仓 os.environ / _env("X") / os.getenv("X") 引用 → 所有变量
      ② 标记「必需」：附近有 raise / sys.exit / logger.critical 的变量
      ③ 比对部署清单（.env.example / docker-compose*.yml / README.md）
    """
    env_refs: dict = {}
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm")):
        try:
            src = pr.read_text(encoding="utf-8-sig")
        except Exception:
            continue
        rel = str(pr.relative_to(repo))
        # 第十九轮修正：`_env_int` / `_env_float` / `_env_bool` 等变体必须一并匹配，
        # 否则 BUTLER_PORT / COOLDOWN_SECONDS / LLM_TIMEOUT 等会被误判为"死配置"
        for m in re.finditer(r"""_env(?:_int|_float|_bool|_list|_str)?\(\s*["']([A-Z0-9_]+)["']""", src):
            env_refs.setdefault(m.group(1), set()).add(rel)
        for m in re.finditer(r"""os\.(?:environ|getenv)\s*[.\[]\s*["']?([A-Z0-9_]+)""", src):
            env_refs.setdefault(m.group(1), set()).add(rel)

    # 必需判定：变量出现处附近是否有 raise/exit
    required: dict = {}
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm")):
        try:
            src = pr.read_text(encoding="utf-8-sig")
            tree = ast.parse(src)
        except SyntaxError:
            continue
        rel = str(pr.relative_to(repo))
        lines = src.splitlines()
        for n in ast.walk(tree):
            if not isinstance(n, ast.Raise):
                continue
            ctx = "\n".join(lines[max(0, n.lineno - 6): n.lineno + 2])
            for m in re.finditer(r"""["']([A-Z][A-Z0-9_]{3,})["']""", ctx):
                required[m.group(1)] = (rel, n.lineno)

    # 部署清单
    manifest = ""
    for name in (".env.example", "docker-compose.yml", "docker-compose.dev.yml",
                 "README.md", ".env", "Dockerfile"):
        f = repo / name
        if f.exists():
            try:
                manifest += f.read_text(encoding="utf-8-sig") + "\n"
            except Exception:
                pass

    findings = []
    for var, (rel, lineno) in sorted(required.items()):
        if var in manifest:
            continue
        if var not in env_refs:
            continue  # 不是环境变量（可能是别的常量）
        findings.append({"var": var, "file": rel, "line": lineno,
                         "kind": "必需环境变量未在部署清单声明",
                         "severity": "high",
                         "detail": (f"{var} 在 {rel}:{lineno} 缺失即 raise，"
                                    "但 .env.example / compose / README 均未记载")})
    # 反向：部署清单声明了但代码从不读（死配置）
    dead = []
    for m in re.finditer(r"^\s*([A-Z][A-Z0-9_]{3,})\s*=", manifest, re.M):
        v = m.group(1)
        if v in ("ENV", "PATH", "HOME"):
            continue
        if v not in env_refs and v not in required:
            dead.append(v)
    print(f"    部署契约：必需变量 {len(required)}，未在清单声明 {len(findings)}")
    for x in findings[:6]:
        print(f"      [high] {x['var']}  ({x['file']}:{x['line']})")
    if dead:
        print(f"    清单中声明但代码从不读取: {sorted(set(dead))[:10]}")
    return {"count": len(findings), "required": len(required),
            "dead_manifest": sorted(set(dead)), "items": findings}


# ── Stage: multisource（多真源漂移）───────────────────────────────
# 动因：十五轮总结的**最高频根因** —— 28 条结论中至少 8 条同源：
#       DeskPilot 3 份客户端 / 输出分发 2 份 / get_conn 9 份 / connect 18 处 /
#       成员名 3 处 / 角色白名单 4 份 / 房间映射 3 份。
#       共同特征：**每份都不报错，只是彼此不一致**；且作者现网路径可用 → 永远无症状。
#       任何通用扫描器都发现不了"同一个东西被抄了四份、其中一份少抄了一个"。
def _seq_kind(seq: list) -> str:
    """按内容特征给字面量序列打类别标签，便于分组比对"""
    if all(isinstance(x, str) and re.match(r"^[a-z_][a-z0-9_]{1,20}$", x) for x in seq):
        return "ident-list"      # 标识符列表（角色 id / 成员名 / 功能开关）
    if all(isinstance(x, str) and re.match(r"^[\u4e00-\u9fa5]{2,8}$", x) for x in seq):
        return "zh-list"         # 中文列表（房间名 / 状态名）
    return "mixed"


def stage_multisource(repo: Path, out: Path) -> dict:
    """检测「同一概念被抄成多份且已漂移」。

    三步：
      ① 抽取**字面量序列**赋值（list/tuple 常量，≥3 元素），记 (文件, 变量/行, 元素集, 顺序)
      ② 跨文件配对：元素集合 Jaccard ≥ 0.6 且 同类别 → 判为「同一概念的多份副本」
      ③ 漂移判定：元素集合**不相等** → high（已发生漂移）
                   元素集合相等但顺序不同 → low（仅风格差异）
    """
    seqs = []
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            tree = ast.parse(pr.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            continue
        rel = str(pr.relative_to(repo))
        # ① 赋值型：`FEEDABLE_ROLES = [...]` / `MODES = (...)`
        # ② 内联型：`if x not in ("a","b","c")` —— 第十五轮 P1-43 的三份
        #    角色白名单正是内联型，初版只扫赋值型 → **漏掉全部 3 份**
        for n in ast.walk(tree):
            inline = False
            v = None
            if isinstance(n, (ast.Assign, ast.AnnAssign)):
                v = n.value
            elif isinstance(n, ast.Compare):
                for c in n.comparators:
                    if isinstance(c, (ast.List, ast.Tuple, ast.Set)):
                        v, inline = c, True
                        break
            if v is None or not isinstance(v, (ast.List, ast.Tuple, ast.Set)):
                continue
            # 第十九轮：支持 dict-list —— 第十五轮 P1-43 的 DEFAULT_ROLES
            # 是 [{id:..., name:...}, ...]，初版只解 Constant 元素 → 整类漏报
            key_field = None
            if v.elts and all(isinstance(e, ast.Dict) for e in v.elts):
                common = None
                for e in v.elts:
                    ks = set()
                    for k, vv in zip(e.keys, e.values):
                        if (isinstance(k, ast.Constant) and isinstance(k.value, str)
                                and isinstance(vv, ast.Constant) and isinstance(vv.value, str)):
                            ks.add(k.value)
                    common = ks if common is None else (common & ks)
                if not common:
                    continue
                for pref in ("id", "name", "key", "code", "slug", "role", "member"):
                    if pref in common:
                        key_field = pref
                        break
                if key_field is None:
                    key_field = sorted(common)[0]
            elts = []
            ok = True
            for e in v.elts:
                if key_field and isinstance(e, ast.Dict):
                    got = False
                    for k, vv in zip(e.keys, e.values):
                        if (isinstance(k, ast.Constant) and k.value == key_field
                                and isinstance(vv, ast.Constant) and isinstance(vv.value, str)):
                            elts.append(vv.value)
                            got = True
                            break
                    if not got:
                        ok = False
                        break
                elif isinstance(e, ast.Constant) and isinstance(e.value, (str, int, float)):
                    elts.append(str(e.value))
                else:
                    ok = False
                    break
            if not ok or len(elts) < 3:
                continue
            tgt = "<inline>" if inline else ""
            if not inline:
                if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name):
                    tgt = n.targets[0].id
                elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                    tgt = n.target.id
            seqs.append({"file": rel, "line": n.lineno, "name": tgt,
                         "items": elts, "set": set(elts), "key_field": key_field,
                         "kind": _seq_kind(elts)})

    pairs = []
    for i in range(len(seqs)):
        for j in range(i + 1, len(seqs)):
            a, b = seqs[i], seqs[j]
            if a["file"] == b["file"] or a["kind"] != b["kind"] or a["kind"] == "mixed":
                continue
            inter = len(a["set"] & b["set"])
            union = len(a["set"] | b["set"])
            if union == 0 or inter / union < 0.6:
                continue
            only_a = sorted(a["set"] - b["set"])
            only_b = sorted(b["set"] - a["set"])
            drift = bool(only_a or only_b)
            pair = {
                "a": f"{a['file']}:{a['line']} {a['name']}",
                "b": f"{b['file']}:{b['line']} {b['name']}",
                "kind": a["kind"], "jaccard": round(inter / union, 3),
                "severity": "high" if drift else "low",
                "only_in_a": only_a[:8], "only_in_b": only_b[:8],
                "size_a": len(a["set"]), "size_b": len(b["set"]),
            }
            pairs.append(pair)
    pairs.sort(key=lambda x: (x["severity"] != "high", -x["jaccard"]))
    hi = [x for x in pairs if x["severity"] == "high"]
    print(f"    多真源候选 {len(pairs)} 对（high {len(hi)} 已漂移 / low {len(pairs)-len(hi)} 仅顺序差异）")
    for x in hi[:6]:
        d = f"A仅{x['only_in_a']}" if x["only_in_a"] else ""
        d += f" B仅{x['only_in_b']}" if x["only_in_b"] else ""
        print(f"      [{x['jaccard']:.2f}] {x['a']}  ≈  {x['b']}   {d}")
    return {"count": len(pairs), "high": len(hi), "scanned": len(seqs), "items": pairs[:60]}


# ── Stage: atomicity（数据完整性 / 原子写）─────────────────────────
# 动因：第三轮人工发现 skills/store.py 与 triggers/store.py 的 save()
#       **锁只包内存索引、写在锁外**，且 tmp 名固定为 `{sid}.json.tmp`
#       → 并发保存内容交错 → 磁盘上是损坏 JSON → 重启后技能静默消失。
#       该缺陷形态（崩溃/并发时才丢数据）任何测试都覆盖不到。
WRITE_CALLS = re.compile(
    r"""\.write_text\(|\.write_bytes\(|json\.dump\(|\.writelines\(|open\([^)]*["\']w""")
TMPFIXED_RE = re.compile(
    r"""["\'][^"\']*\.tmp["\']|\.tmp["\']""")
REPLACE_RE = re.compile(r"os\.replace\(|os\.rename\(|Path\.replace\(|\.replace\(")
FSYNC_RE = re.compile(r"fsync\(|flush\(\)")


def _enclosing_func(tree, node):
    cands = [f for f in ast.walk(tree)
             if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node in list(ast.walk(f))]
    return max(cands, key=lambda f: f.lineno) if cands else None


def _lock_span(func):
    """返回函数内 `with ...lock...` 覆盖的行区间列表"""
    spans = []
    if func is None:
        return spans
    for n in ast.walk(func):
        if isinstance(n, (ast.With, ast.AsyncWith)):
            for it in n.items:
                code = ast.unparse(it.context_expr) if hasattr(ast, "unparse") else ""
                if re.search(r"lock|Lock", code):
                    end = getattr(n, "end_lineno", n.lineno) or n.lineno
                    spans.append((n.lineno, end))
    return spans


def stage_atomicity(repo: Path, out: Path) -> dict:
    """检测非原子 / 竞态的文件写入。

    四条判据（独立报告，便于按严重度排序）：
      A1 裸写：write_text/write_bytes/json.dump 无 tmp+replace
      A2 固定 tmp 名：tmp 路径不随进程/时间变化 → 并发互相覆盖
      A3 写在锁外：写调用不在任何 `with lock` 区间内
      A4 无 fsync：写完不刷盘（崩溃时可能丢失）
    """
    findings = []
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            src = pr.read_text(encoding="utf-8-sig")
            tree = ast.parse(src)
        except SyntaxError:
            continue
        rel = str(pr.relative_to(repo))
        lines = src.splitlines()
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            code = ast.unparse(n) if hasattr(ast, "unparse") else ""
            if not WRITE_CALLS.search(code):
                continue
            ln = n.lineno
            func = _enclosing_func(tree, n)
            fsrc = ast.unparse(func) if func is not None else ""
            has_tmp = bool(TMPFIXED_RE.search(fsrc))
            has_replace = bool(REPLACE_RE.search(fsrc))
            spans = _lock_span(func)
            in_lock = any(a <= ln <= b for a, b in spans)
            issues = []
            if not (has_tmp and has_replace):
                issues.append("A1-裸写（无 tmp+replace）")
            if has_tmp:
                # 判断 tmp 名是否随 pid/时间/uuid 变化
                if not re.search(r"getpid|uuid|time\.time|monotonic|randint|mkstemp|NamedTemporary",
                                 fsrc):
                    issues.append("A2-固定 tmp 名（并发互相覆盖）")
            if spans and not in_lock:
                issues.append("A3-写在锁外（锁未覆盖写盘）")
            if not FSYNC_RE.search(fsrc):
                issues.append("A4-无 fsync")
            if not issues:
                continue
            sev = ("high" if ("A1-裸写（无 tmp+replace）" in issues or "A3-写在锁外（锁未覆盖写盘）" in issues)
                   else "medium")
            findings.append({"file": rel, "line": ln, "func": getattr(func, "name", "<module>"),
                             "issues": issues, "severity": sev,
                             "snippet": lines[ln - 1].strip()[:110] if ln <= len(lines) else ""})
    seen, uniq = set(), []
    for f in findings:
        k = (f["file"], f["func"], tuple(f["issues"]))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    uniq.sort(key=lambda x: (x["severity"] != "high", x["file"]))
    hi = [x for x in uniq if x["severity"] == "high"]
    print(f"    原子写缺陷 {len(uniq)} 处（high {len(hi)}）")
    for x in hi[:6]:
        print(f"      {x['file']}:{x['line']} {x['func']}  {'+'.join(x['issues'])}")
    return {"count": len(uniq), "high": len(hi), "items": uniq}


# ── Stage: concurrency（并发/竞态）─────────────────────────────────
def stage_concurrency(repo: Path, out: Path) -> dict:
    """检测并发与竞态缺陷（第三轮发现的同类问题工具化）。

    五条判据：
      C1 create_task 返回值未保存（asyncio 仅弱引用 → 可能被 GC）
      C2 双重检查锁定（if X is None: ... 赋值，无锁保护）
      C3 共享容器在锁外遍历/写入
      C4 事件循环中调用阻塞 IO（open/read/sleep）未走 to_thread
      C5 跨线程共享 sqlite 连接且 check_same_thread=False
    """
    findings = []
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            src = pr.read_text(encoding="utf-8-sig")
            tree = ast.parse(src)
        except SyntaxError:
            continue
        rel = str(pr.relative_to(repo))

        is_async_file = bool(re.search(r"async\s+def\s", src))

        for n in ast.walk(tree):
            # C1: create_task 返回值丢弃
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call):
                code = ast.unparse(n.value) if hasattr(ast, "unparse") else ""
                # 注意：receiver 可能是 loop / asyncio / 其他；且可能在 lambda 体内
                # （第十六轮教训：runner.py:449 写成
                #   `loop.call_soon_threadsafe(lambda: loop.create_task(_run()))`
                #   初版 `^(asyncio\.)?create_task\(` 匹配不到 → 漏报）
                if re.search(r"(?:^|\.)\s*create_task\s*\(", code) and \
                        re.search(r"create_task", code):
                    findings.append({"file": rel, "line": n.lineno, "kind": "C1",
                                     "detail": "create_task 返回值未保存（Task 可能被 GC）",
                                     "severity": "high"})
            # C4: async 函数内阻塞 IO
            if is_async_file and isinstance(n, ast.Call):
                code = ast.unparse(n) if hasattr(ast, "unparse") else ""
                if re.match(r"(open|Path\(.*\)\.read_text|\.read_bytes|time\.sleep)\(", code):
                    fn = _enclosing_func(tree, n)
                    if fn and isinstance(fn, ast.AsyncFunctionDef):
                        fsrc = ast.unparse(fn)
                        if re.search(r"to_thread|run_in_executor", fsrc):
                            continue
                        findings.append({"file": rel, "line": n.lineno, "kind": "C4",
                                         "detail": f"async 函数内阻塞 IO 未走 to_thread: {code[:40]}",
                                         "severity": "medium"})
            # C5: check_same_thread=False
            if isinstance(n, ast.Call):
                code = ast.unparse(n) if hasattr(ast, "unparse") else ""
                if "sqlite3.connect" in code and "check_same_thread=False" in code:
                    findings.append({"file": rel, "line": n.lineno, "kind": "C5",
                                     "detail": "跨线程共享 sqlite 连接（check_same_thread=False）",
                                     "severity": "low"})

        # C2: 双重检查锁定 —— 函数内有 `if X is None` 且赋值 X，但函数体无 with lock
        for fn in [f for f in ast.walk(tree)
                   if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            fsrc = ast.unparse(fn) if hasattr(ast, "unparse") else ""
            if not re.search(r"if\s+\w+\s+is\s+None", fsrc):
                continue
            if re.search(r"global\s+\w+", fsrc) and not re.search(r"with\s+.*lock", fsrc):
                findings.append({"file": rel, "line": fn.lineno, "kind": "C2",
                                 "detail": "模块级单例双重检查无锁（首轮已报 get_conn 竞态）",
                                 "severity": "high"})

    seen, uniq = set(), []
    for f in findings:
        k = (f["file"], f["line"], f["kind"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    byk = {}
    for f in uniq:
        byk[f["kind"]] = byk.get(f["kind"], 0) + 1
    print(f"    并发/竞态缺陷 {len(uniq)} 处  {byk}")
    return {"count": len(uniq), "by_kind": byk, "items": uniq}


# ── Stage: timeunit（数值/单位/时区）───────────────────────────────
NAIVE_RE = re.compile(r"datetime\.now\(|datetime\.utcnow\(|datetime\.fromtimestamp\(")
# T3（第十八轮新增）：wall clock 与 monotonic 混用
# 动因：triggers/engine.py status() 用 time.monotonic() 去减 _last_fired（存的是
#      time.time()）→ cooldown_remaining 天文数字、last_fired_ago 负数。
#      该形态静态可检测：同一函数内同时出现 time.time()/monotonic() 且做减法。
WALL_RE = re.compile(r"\btime\.time\s*\(")
MONO_RE = re.compile(r"\btime\.monotonic\s*\(|\basyncio\.get_event_loop\(\)\.time\(")

AWARE_RE = re.compile(r"datetime\.now\([^)]*tz|timezone\.utc|ZoneInfo|astimezone\(")
MS_RE = re.compile(r"_ms\b|millis|duration_ms|\*\s*1000")
SEC_RE = re.compile(r"_s\b|\bseconds?\b|timeout\s*=|interval")


def stage_timeunit(repo: Path, out: Path) -> dict:
    """检测时间/单位/时区混用。

    T1 naive vs aware：同文件同时出现 datetime.now() 与 astimezone/ZoneInfo → 混用
    T2 秒/毫秒：同一函数内既有 `_ms/*1000` 又有 `_s`/seconds
    T3 time.time() 与 datetime 混用做时间差
    """
    findings = []
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            src = pr.read_text(encoding="utf-8-sig")
            tree = ast.parse(src)
        except SyntaxError:
            continue
        rel = str(pr.relative_to(repo))
        naive = bool(NAIVE_RE.search(src))
        aware = bool(AWARE_RE.search(src))
        if naive and aware:
            findings.append({"file": rel, "line": 0, "kind": "T1",
                             "detail": "同文件混用 naive 与 aware datetime（比较会 TypeError）",
                             "severity": "medium"})
        for fn in [f for f in ast.walk(tree)
                   if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            fsrc = ast.unparse(fn) if hasattr(ast, "unparse") else ""
            if MS_RE.search(fsrc) and SEC_RE.search(fsrc) and re.search(r"\*\s*1000|/\s*1000", fsrc):
                findings.append({"file": rel, "line": fn.lineno, "kind": "T2",
                                 "detail": f"函数 {fn.name} 内混用秒与毫秒",
                                 "severity": "medium"})

        # T3：wall clock vs monotonic 混用
        # 第十八轮：先建立「变量/属性 → 被赋值的时钟函数」映射，再判定相减的两侧
        # 是否同源。triggers/engine.py status() 正是 `now=monotonic()` 减
        # `_last_fired`（存 time.time()）→ cooldown_remaining 天文数字。
        clock_of: dict = {}
        for n in ast.walk(tree):
            if isinstance(n, (ast.Assign, ast.AnnAssign)):
                v = n.value
                if not isinstance(v, ast.Call):
                    continue
                code = ast.unparse(v) if hasattr(ast, "unparse") else ""
                which = None
                if re.match(r"time\.time\s*\(", code):
                    which = "wall"
                elif re.match(r"time\.monotonic\s*\(", code):
                    which = "mono"
                if not which:
                    continue
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in tgts:
                    if isinstance(t, ast.Name):
                        clock_of[t.id] = which
                    elif isinstance(t, ast.Attribute):
                        clock_of[ast.unparse(t) if hasattr(ast, "unparse") else ""] = which
        # 字典下标赋值 self._x[k] = time.time() → 记 self._x
        for n in ast.walk(tree):
            if not isinstance(n, ast.Assign):
                continue
            code = ast.unparse(n.value) if hasattr(ast, "unparse") else ""
            which = ("wall" if re.match(r"time\.time\s*\(", code)
                     else "mono" if re.match(r"time\.monotonic\s*\(", code) else None)
            if not which:
                continue
            for t in n.targets:
                if isinstance(t, ast.Subscript):
                    base = ast.unparse(t.value) if hasattr(ast, "unparse") else ""
                    # 第十八轮：RHS 可能是别名（fire_start = time.time() 后
                    # self._last_fired[k] = fire_start）→ 需透过简单名解析
                    if which is None or not base:
                        continue
                    clock_of[base] = which
                elif isinstance(t, ast.Attribute) and which:
                    pass
        # 二次传播：name = time.time() / monotonic() 的简单名 → 供下标赋值解析
        simple_clock: dict = {}
        for n in ast.walk(tree):
            if isinstance(n, (ast.Assign, ast.AnnAssign)) and isinstance(n.value, ast.Call):
                code = ast.unparse(n.value) if hasattr(ast, "unparse") else ""
                which = ("wall" if re.match(r"time\.time\s*\(", code)
                         else "mono" if re.match(r"time\.monotonic\s*\(", code) else None)
                if not which:
                    continue
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in tgts:
                    if isinstance(t, ast.Name):
                        simple_clock[t.id] = which
        for n in ast.walk(tree):
            if not isinstance(n, ast.Assign) or not n.targets:
                continue
            t = n.targets[0]
            if not isinstance(t, ast.Subscript):
                continue
            base = ast.unparse(t.value) if hasattr(ast, "unparse") else ""
            rhs = ast.unparse(n.value) if hasattr(ast, "unparse") else ""
            if base and rhs in simple_clock:
                clock_of[base] = simple_clock[rhs]

        def _clock_of_expr(e: str) -> str | None:
            for k, v in clock_of.items():
                if k and (k == e or e.startswith(k + ".") or e.startswith(k + "[")):
                    return v
            return None

        for fn in [f for f in ast.walk(tree)
                   if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            fsrc = ast.unparse(fn) if hasattr(ast, "unparse") else ""
            has_wall = bool(WALL_RE.search(fsrc))
            has_mono = bool(MONO_RE.search(fsrc))
            if has_wall and has_mono:
                findings.append({"file": rel, "line": fn.lineno, "kind": "T3",
                                 "detail": (f"函数 {fn.name} 内同时用 time.time() 与 "
                                            "time.monotonic()（相减会得到荒谬值）"),
                                 "severity": "medium"})
                continue
            if not has_mono:
                continue
            # 找出 `X = <monotonic>()` 形式的局部变量
            mono_vars = set(re.findall(r"(\w+)\s*=\s*time\.monotonic\s*\(\)", fsrc))
            mono_vars |= set(re.findall(r"(\w+)\s*=\s*asyncio\.get_event_loop\(\)\.time\s*\(\)", fsrc))
            if not mono_vars:
                continue
            # 别名解析：last = self._last_fired.get(...) → last 的时钟源 = self._last_fired
            alias: dict = {}
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name):
                    alias[n.targets[0].id] = (
                        ast.unparse(n.value) if hasattr(ast, "unparse") else "")
            for m in re.finditer(r"""(\w+)\s*-\s*([\w\.\[\]"'\-]+)""", fsrc):
                lhs, rhs = m.group(1), m.group(2)
                if lhs not in mono_vars:
                    continue
                rhs_expr = alias.get(rhs, rhs)
                rc = _clock_of_expr(rhs_expr) or _clock_of_expr(rhs)
                if rc == "wall":
                    findings.append({"file": rel, "line": fn.lineno, "kind": "T3",
                                     "detail": (f"函数 {fn.name}: monotonic 变量 '{lhs}' 减去 "
                                                f"wall clock 存储的 '{rhs_expr}' → 数值荒谬"),
                                     "severity": "high"})
                    break
                if rc is None and re.search(r"_last|last_|\.get\(|ts\b|_at\b|time\b", rhs):
                    findings.append({"file": rel, "line": fn.lineno, "kind": "T3",
                                     "detail": (f"函数 {fn.name}: monotonic 变量 '{lhs}' 减去 "
                                                f"来源不明的 '{rhs_expr}'（需人工确认时钟源）"),
                                     "severity": "medium"})
                    break
    seen, uniq = set(), []
    for f in findings:
        k = (f["file"], f["line"], f["kind"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    byk = {}
    for f in uniq:
        byk[f["kind"]] = byk.get(f["kind"], 0) + 1
    print(f"    时间/单位/时区 {len(uniq)} 处  {byk}")
    return {"count": len(uniq), "by_kind": byk, "items": uniq}


# ── Stage: identity（判定逻辑中的硬编码身份）──────────────────────
# 动因：第十四轮 P1-42 —— morning/modes/anomaly 三个 critical 模块用
#       snapshot.get("users", {}).get("lidicn", {}) 硬编码成员名，
#       绕过 s.member_by_name() 可配置成员系统，且**静默失效**（取不到 → 空 dict）。
#       该类缺陷形态：对作者本人正常，第三方部署静默降级，任何测试都发现不了。
LOGIC_LINE_RE = re.compile(r"\.get\(|==|\bin\s*\[|entity_id\s*=|\.setdefault\(|users\[")
# 排除种子/默认数据行（纯字面量赋值，不含判定）
SEED_LINE_RE = re.compile(
    r'''^\s*["']?[\w\u4e00-\u9fa5]+["']?\s*[:,]\s*[\[\{"']|^\s*#''')


def _harvest_identity_tokens(repo: Path) -> dict:
    """从种子数据/配置中收集「身份 token」候选：
       ① 成员名（MemberConfig / defaults.py / devices.py 种子）
       ② person.* 实体 ID 的后缀
       ③ 房间名（devices.py 的 room= 取值）
    """
    members, persons, rooms = set(), set(), set()
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            t = pr.read_text(encoding="utf-8-sig")
        except Exception:
            continue
        for m in re.finditer(r"person\.([A-Za-z_][\w]*)", t):
            persons.add(m.group(1))
        for m in re.finditer(
                r'''room\s*=\s*["']([^"']{2,10})["']''', t):
            rooms.add(m.group(1))
        # "members": ["a","b"] / members=[...]
        for m in re.finditer(r"""members["']?\s*[:=]\s*\[([^\]]*)\]""", t):
            for nm in re.findall(r"""["']([^"']+)["']""", m.group(1)):
                members.add(nm)
        # MemberConfig(name="x")
        for m in re.finditer(r"""MemberConfig\s*\([^)]*name\s*=\s*["']([^"']+)["']""", t):
            members.add(m.group(1))
        # member: "x"
        for m in re.finditer(r"""["']member["']\s*:\s*["']([^"']+)["']""", t):
            members.add(m.group(1))
    # 过滤噪声
    # 噪声过滤（第十五轮：初版把 room/confidence/face_detected 等字段名误收为成员名）
    noise = {"type", "name", "id", "version", "enabled", "value", "label", "role",
             "target", "source", "text", "action", "mode", "status", "default",
             "room", "confidence", "face_detected", "last_seen", "member_id",
             "trigger", "via", "arcface", "homeassistant", "unknown", "未知",
             "family", "家人", "count", "ts", "items", "data", "result", "ok",
             "error", "reason", "code", "list", "dict", "true", "false", "none"}
    def _ok(x):
        if len(x) < 2 or x.lower() in noise:
            return False
        if x.startswith("{{") or "{" in x or x == "...":
            return False
        if x.isdigit():
            return False
        return True
    members = {x for x in members if _ok(x)}
    rooms = {x for x in rooms if _ok(x)}
    # person.* 排除 homeassistant 这类非人名
    persons = {x for x in persons if _ok(x) and x.lower() != "homeassistant"}
    return {"members": members, "persons": persons, "rooms": rooms}


def stage_identity(repo: Path, out: Path) -> dict:
    """检测判定逻辑中硬编码的身份/房间 token。

    判据（三层，缺一不可）：
      ① token 来自种子数据（成员名 / person.* 后缀 / 房间名）
      ② 出现在**判定逻辑行**（含 .get( / == / in [ / entity_id= / users[）
      ③ 该行**不是**种子数据定义本身
    """
    toks = _harvest_identity_tokens(repo)
    all_tok = [("member", x) for x in toks["members"]] \
        + [("person", x) for x in toks["persons"]] \
        + [("room", x) for x in toks["rooms"]]
    findings = []
    for pr in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            t = pr.read_text(encoding="utf-8-sig")
        except Exception:
            continue
        rel = str(pr.relative_to(repo))
        for i, ln in enumerate(t.splitlines(), 1):
            if not LOGIC_LINE_RE.search(ln) or SEED_LINE_RE.match(ln):
                continue
            if ln.strip().startswith("#"):
                continue
            for kind, tk in all_tok:
                # 房间名只关心 `in room` 这类比较（中文房间名无引号边界问题）
                pat = (r'''["']%s["']''' % re.escape(tk) if kind != "room"
                       else r'''["']%s["']|in\s+room''' % re.escape(tk))
                if not re.search(pat, ln):
                    continue
                # 分级：
                #   high = 身份被当作**查表键**（.get("X") / users["X"] / == "X"）
                #          → 取不到就静默失效，第十四轮 P1-42 正是此类
                #   low  = 身份被当作**缺省值**（or "X" / default）
                #          → 有兜底，仍可工作，只是不符合该部署环境
                _tk = re.escape(tk)
                # high：身份被当作**查表键** —— .get("X") / == "X" / entity_id="...X"
                #      取不到即静默失效（第十四轮 P1-42 正是此类）
                # low ：身份作缺省值（or "X"）—— 有兜底，仍可工作
                is_key = bool(
                    re.search(r'\.get\(\s*["\']' + _tk + r'["\']', ln)
                    or re.search(r'==\s*["\']' + _tk + r'["\']', ln)
                    or re.search(r'entity_id\s*=\s*["\'][^"\']*' + _tk, ln)
                    or re.search(r'users\[\s*["\']' + _tk + r'["\']', ln)
                )
                findings.append({"file": rel, "line": i, "token": tk, "kind": kind,
                                 "severity": "high" if is_key else "low",
                                 "snippet": ln.strip()[:120],
                                 "note": ("判定逻辑把身份当**查表键**（取不到即静默失效）"
                                          if is_key else "身份作缺省值（有兜底，风险较低）")})
                break
    # 去重
    seen, uniq = set(), []
    for f in findings:
        k = (f["file"], f["line"], f["token"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    by_file = {}
    for f in uniq:
        by_file.setdefault(f["file"], []).append(f)
    hi = [x for x in uniq if x["severity"] == "high"]
    print(f"    判定逻辑硬编码身份 {len(uniq)} 处（high {len(hi)} / low {len(uniq)-len(hi)}）"
          f"（成员 {len(toks['members'])} / person.* {len(toks['persons'])}）")
    for f in hi[:10]:
        print(f"      [high] {f['file']}:{f['line']}  {f['token']}")
    return {"count": len(uniq), "items": uniq,
            "tokens": {k: sorted(v) for k, v in toks.items()}}


# ── Stage: lifecycle（资源生命周期，双通道）────────────────────────
RES_NAME_RE = re.compile(
    r"^_?(?:conn|connection|session|client|pool|db|engine|handle|fd|file)\b", re.I)
RES_CTOR_RE = re.compile(
    r"sqlite3\.connect\(|ClientSession\(|\bopen\s*\(|socket\.socket\(|"
    r"PooledDB|pymysql\.connect|psycopg2\.connect|redis\.Redis\(|"
    r"ThreadPoolExecutor\(|ProcessPoolExecutor\(")
REL_NAME_RE = re.compile(r"^(close|aclose|shutdown|dispose|cleanup|stop|release|"
                         r"teardown|finalize|__exit__|__aexit__)")
RES_SELF_NAME = {"conn", "connection", "session", "client", "pool",
                 "db", "engine", "handle", "fd", "file"}


def _fn_src(n):
    return ast.unparse(n) if hasattr(ast, "unparse") else ""


def _fn_touches(n, names):
    """注意：`_conn` 中的 conn 前面是 `_`（同属 \w），`\bconn\b` 匹配不到
    → 必须用 `(?<!\w)_?name\b`（第十四轮教训：漏了这条会把 store/db.py 的
    close() 判成"不操作资源"，产生假阳性）"""
    src = _fn_src(n)
    return any(re.search(rf"(?<!\w)_?{re.escape(x)}\b", src) for x in names)


def _fn_releases(n):
    return bool(re.search(r"\.(a?close)\s*\(|\.shutdown\s*\(|\.release\s*\(", _fn_src(n)))


def stage_lifecycle(repo: Path, out: Path) -> dict:
    """检测「获取了但从不释放」的资源。双通道：
    A. 模块级全局（`_conn: sqlite3.Connection | None = None`）
    B. 实例属性（`self._conn = sqlite3.connect(...)`）—— 第十四轮新增，
       修复第十三轮漏报（PresenceStore._conn）
    """
    files = list(pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm",
                                         "node_modules", "tests")))
    texts = {}
    for p in files:
        try:
            texts[str(p)] = p.read_text(encoding="utf-8-sig")
        except Exception:
            texts[str(p)] = ""

    findings = []
    for p in files:
        rel = str(p.relative_to(repo))
        src = texts[str(p)]
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        if not RES_CTOR_RE.search(src):
            continue

        # 通道 A：模块级全局
        globals_res = set()
        for n in tree.body:
            names = []
            if isinstance(n, ast.Assign):
                names = [t.id for t in n.targets if isinstance(t, ast.Name)]
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                names = [n.target.id]
            for nm in names:
                if RES_NAME_RE.match(nm):
                    globals_res.add(nm)
        module_true = set()
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and REL_NAME_RE.match(n.name):
                if _fn_touches(n, RES_SELF_NAME) and _fn_releases(n):
                    module_true.add(n.name)
        if globals_res and not module_true:
            findings.append({"file": rel, "channel": "module-global",
                             "names": sorted(globals_res),
                             "kind": "模块级全局资源，无释放方法", "severity": "high"})

        # 通道 B：实例属性
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            attrs, ctor_seen = set(), False
            for n in ast.walk(cls):
                if isinstance(n, (ast.Assign, ast.AnnAssign)):
                    tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                    for t in tgts:
                        if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                                and t.value.id in ("self", "cls") and RES_NAME_RE.match(t.attr)):
                            attrs.add(t.attr)
                            v = n.value
                            if v is not None and RES_CTOR_RE.search(_fn_src(v) or ""):
                                ctor_seen = True
            if not attrs or not ctor_seen:
                continue
            true_rel = set()
            for f in cls.body:
                if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and REL_NAME_RE.match(f.name):
                    if _fn_touches(f, attrs) and _fn_releases(f):
                        true_rel.add(f.name)
            ctx_managed = bool(re.search(
                r"with\s+sqlite3\.connect|async\s+with\s+ClientSession", src))
            if not true_rel and not ctx_managed:
                findings.append({"file": rel, "channel": "instance-attr",
                                 "names": sorted(attrs), "cls": cls.name,
                                 "kind": f"类 {cls.name} 的实例属性资源，无释放方法",
                                 "severity": "high"})

    findings.sort(key=lambda x: (x["severity"] != "high", x["file"]))
    by_ch = {}
    for f in findings:
        by_ch[f["channel"]] = by_ch.get(f["channel"], 0) + 1
    print(f"    资源生命周期：{len(findings)} 处 "
          f"(模块级 {by_ch.get('module-global', 0)} / 实例属性 {by_ch.get('instance-attr', 0)})")
    for x in findings[:8]:
        print(f"      [{x['severity']}] {x['file']}  {x['channel']}  {x['names']}")
    return {"count": len(findings), "by_channel": by_ch, "items": findings}


# ── Stage: errpath（异常路径自身缺陷）──────────────────────────────
def stage_errpath(repo: Path, out: Path) -> dict:
    """检查 except/finally 分支引用的名字是否在作用域内可见。

    误报治理（六轮收敛 78 → 2）：
      with/for/comprehension/walrus/局部import 绑定；模块级 except 用全模块绑定；
      取最内层函数；元组解包；self/cls 恒可见；闭包祖先作用域。
    """
    import builtins
    BUILTIN = set(dir(builtins))
    findings = []
    for p in pyfiles(repo, excludes=(".git", "__pycache__", "vendor", ".norm", "tests")):
        try:
            src = p.read_text(encoding="utf-8-sig")
            tree = ast.parse(src)
        except SyntaxError:
            continue
        rel = str(p.relative_to(repo))

        module_names = set()
        for n in tree.body:
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                for a in n.names:
                    module_names.add((a.asname or a.name).split(".")[0])
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                module_names.add(n.name)
            elif isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        module_names.add(t.id)
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                module_names.add(n.target.id)

        for n in ast.walk(tree):
            if not isinstance(n, ast.ExceptHandler):
                continue
            funcs_with = [f for f in ast.walk(tree)
                          if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
                          and n in list(ast.walk(f))]
            func = max(funcs_with, key=lambda f: f.lineno) if funcs_with else None
            local = set(module_names) | BUILTIN | {"self", "cls"}
            if func is None:
                for x in ast.walk(tree):
                    if isinstance(x, (ast.Import, ast.ImportFrom)):
                        for a in x.names:
                            local.add((a.asname or a.name).split(".")[0])
                    elif isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        local.add(x.name)
                    elif isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
                        local.add(x.id)
                    elif isinstance(x, ast.arg):
                        local.add(x.arg)
            else:
                for f in funcs_with:
                    local |= {a.arg for a in list(f.args.args) + list(f.args.kwonlyargs)}
                for f in funcs_with:
                    for x in ast.walk(f):
                        if isinstance(x, ast.Assign):
                            for t in x.targets:
                                if isinstance(t, ast.Name):
                                    local.add(t.id)
                                elif isinstance(t, (ast.Tuple, ast.List)):
                                    for e in t.elts:
                                        if isinstance(e, ast.Name):
                                            local.add(e.id)
                        elif isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            local.add(x.name)
                        elif isinstance(x, (ast.With, ast.AsyncWith)):
                            for it in x.items:
                                ov = it.optional_vars
                                if isinstance(ov, ast.Name):
                                    local.add(ov.id)
                                elif isinstance(ov, ast.Tuple):
                                    for e in ov.elts:
                                        if isinstance(e, ast.Name):
                                            local.add(e.id)
                        elif isinstance(x, (ast.For, ast.AsyncFor)):
                            tg = x.target
                            if isinstance(tg, ast.Name):
                                local.add(tg.id)
                            elif isinstance(tg, ast.Tuple):
                                for e in tg.elts:
                                    if isinstance(e, ast.Name):
                                        local.add(e.id)
                        elif isinstance(x, ast.comprehension):
                            tg = x.target
                            if isinstance(tg, ast.Name):
                                local.add(tg.id)
                            elif isinstance(tg, ast.Tuple):
                                for e in tg.elts:
                                    if isinstance(e, ast.Name):
                                        local.add(e.id)
                        elif isinstance(x, ast.NamedExpr) and isinstance(x.target, ast.Name):
                            local.add(x.target.id)
                        elif isinstance(x, ast.ExceptHandler) and x.name:
                            local.add(x.name)
                        elif isinstance(x, (ast.Import, ast.ImportFrom)):
                            for a in x.names:
                                local.add((a.asname or a.name).split(".")[0])
                        elif isinstance(x, ast.AnnAssign) and isinstance(x.target, ast.Name):
                            local.add(x.target.id)
                        elif isinstance(x, ast.AugAssign) and isinstance(x.target, ast.Name):
                            local.add(x.target.id)
            if n.name:
                local.add(n.name)
            for x in ast.walk(n):
                if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load):
                    if x.id in local:
                        continue
                    findings.append({"file": rel, "line": x.lineno, "name": x.id,
                                     "kind": "except 分支引用未定义名字（触发时 NameError）"})
                elif isinstance(x, ast.Attribute) and isinstance(x.value, ast.Name):
                    if x.value.id in local or x.value.id in BUILTIN:
                        continue
                    findings.append({"file": rel, "line": x.lineno, "name": x.value.id,
                                     "kind": "except 分支引用未定义模块/对象（触发时 NameError）"})
    seen, uniq = set(), []
    for f in findings:
        k = (f["file"], f["line"], f["name"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    print(f"    异常路径自身缺陷 {len(uniq)} 处")
    for f in uniq[:8]:
        print(f"      {f['file']}:{f['line']}  {f['name']}")
    return {"count": len(uniq), "items": uniq}


# ── Stage: tests（跑项目自带测试套件）──────────────────────────────
def stage_tests(repo: Path, out: Path) -> dict:
    """跑仓库自带 tests/。项目自带测试是**最高信噪比**的缺陷来源。"""
    tdir = repo / "tests"
    if not tdir.exists():
        return {"skipped": "无 tests/ 目录"}
    env = dict(os.environ)
    env["PYTHONPATH"] = ((str(repo / "vendor" / "homesdk" / "src") + os.pathsep)
                         if (repo / "vendor" / "homesdk" / "src").exists() else "") \
        + env.get("PYTHONPATH", "")
    for k in ("DOUBAO_API_KEY", "DESKPILOT_API_TOKEN", "TASK_REPORT_TOKEN",
              "BUTLER_WEB_PASSWORD", "HA_TOKEN", "MEMORY_AGENT_TOKEN"):
        env.setdefault(k, "stub-for-audit")
    cmd = [sys.executable, "-m", "pytest", "tests/", "-q", "--no-header",
           "-p", "no:cacheprovider", "--asyncio-mode=auto"]
    pr = subprocess.run(cmd, cwd=str(repo), capture_output=True, text=True,
                        timeout=900, env=env)
    txt = (pr.stdout or "") + (pr.stderr or "")
    (out / "tests_output.txt").write_text(txt, encoding="utf-8")
    tail = txt.strip().splitlines()[-1] if txt.strip() else ""
    failed = [l.strip() for l in txt.splitlines()
              if l.startswith("FAILED ") or l.startswith("ERROR ")]
    m2 = re.search(r"(\d+) passed", tail)

    # 第二十轮：自动区分「环境失败」vs「真实失败」。
    # 实测：沙盒缺 pytest-asyncio 时 8 个 async 测试"失败"，实为环境噪音；
    # 若不分类，环境噪音会淹没真实失败（第九轮 P0-14 正藏在里面）。
    ENV_MARKERS = (
        "async def functions are not natively supported",
        "ModuleNotFoundError",
        "ImportError while importing",
        "No module named",
        "plugin for your async framework",
        "fixture 'event_loop' not found",
    )
    env_failed, real_failed = [], []
    for f in failed:
        name = f.replace("FAILED ", "").replace("ERROR ", "").split(" - ")[0].split("::")[0]
        # 在该测试的上下文里找环境标记
        blob = txt
        idx = txt.find(name)
        near = blob[idx:idx + 3000] if idx >= 0 else ""
        if any(mk in near for mk in ENV_MARKERS):
            env_failed.append(f)
        else:
            real_failed.append(f)
    print(f"    {tail[:110]}")
    if env_failed:
        print(f"    └─ 环境类失败 {len(env_failed)} 个（依赖缺失，非缺陷）")
    if real_failed:
        print(f"    └─ 真实失败 {len(real_failed)} 个：")
        for f in real_failed[:8]:
            print(f"         {f[:90]}")
    return {"summary": tail, "failed": len(failed),
            "passed": int(m2.group(1)) if m2 else 0,
            "failed_list": failed,
            "env_failed": env_failed, "real_failed": real_failed,
            "note": "已自动分类；real_failed 为待测真实失败"}


# ── Stage: runtime（桩件驱动真实执行覆盖）──────────────────────────
def stage_runtime(repo: Path, out: Path) -> dict:
    """调用 drive.py 做桩件驱动的真实执行，产出 coverage。"""
    drv = Path(__file__).resolve().parent / "drive.py"
    if not drv.exists():
        return {"skipped": "缺 drive.py"}
    pr = subprocess.run([sys.executable, str(drv), "--repo", str(repo), "--out", str(out)],
                        capture_output=True, text=True, timeout=1800)
    txt = (pr.stdout or "") + (pr.stderr or "")
    (out / "runtime_stdout.txt").write_text(txt, encoding="utf-8")
    m = re.search(r"覆盖 ([\d.]+)% \| 函数 (\d+) \| 执行过 (\d+) \| 未执行 (\d+)", txt)
    res = {}
    if m:
        res = {"coverage_pct": float(m.group(1)), "total": int(m.group(2)),
               "alive": int(m.group(3)), "never": int(m.group(4))}
        print(f"    覆盖 {m.group(1)}% | 函数 {m.group(2)} | "
              f"执行过 {m.group(3)} | 未执行 {m.group(4)}")
    for l in txt.splitlines():
        if "⚠ SKIP" in l or l.strip().startswith("SKIP "):
            print("   ", l.strip()[:100])
    return res


# ── Stage: verify（按需实锤）───────────────────────────────────────
def stage_verify(repo: Path, out: Path) -> dict:
    """对已知结论做对照实验验证（数据来自 findings.json，若不存在则跳过）。"""
    f = Path(__file__).resolve().parent / "findings.json"
    if not f.exists():
        print("    无 findings.json，跳过（每条结论应配可执行复现）")
        return {"skipped": "无 findings.json"}
    data = json.loads(f.read_text(encoding="utf-8"))
    print(f"    {len(data)} 条待验证结论（人工/脚本执行）")
    return {"count": len(data)}


STAGES = {
    "bootstrap": stage_bootstrap, "static": stage_static, "graph": stage_graph,
    "tests": stage_tests, "secrets": stage_secrets, "httpcontract": stage_httpcontract,
    "mqtt": stage_mqtt, "dupimpl": stage_dupimpl,
    "multisource": stage_multisource, "successclaim": stage_successclaim,
    "deploycontract": stage_deploycontract, "kwcontract": stage_kwcontract,
    "falsyzero": stage_falsyzero, "lifecycle": stage_lifecycle,
    "errpath": stage_errpath, "identity": stage_identity,
    "atomicity": stage_atomicity, "concurrency": stage_concurrency,
    "timeunit": stage_timeunit,
    "runtime": stage_runtime, "dupfiles": stage_dupfiles,
    "orphans": stage_orphans, "deadcall": stage_deadcall, "cycles": stage_cycles,
    "contract": stage_contract, "verify": stage_verify,
}


def main():
    ap = argparse.ArgumentParser(description="doubao-butler 审计工作流")
    ap.add_argument("stages", nargs="?", default="all",
                    help="逗号分隔的阶段名，或 all")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    repo, out = Path(a.repo).resolve(), Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    order = list(STAGES)
    names = order if a.stages == "all" else [x.strip() for x in a.stages.split(",")]

    # 第二十轮：改为**累积式** summary。
    # 原实现每次运行都整体覆盖 audit_summary.json → 分批跑（本沙盒唯一可行方式）
    # 会互相抹掉，回归集永远只能看到最后一批的结果（首跑仅 2/29 命中根因在此）。
    # 现改为：每阶段结果单写 out/stage_results/<stage>.json，
    #         summary 由磁盘上所有已完成的阶段结果合并而成。
    sdir = out / "stage_results"
    sdir.mkdir(parents=True, exist_ok=True)
    summary = {}
    for f in sdir.glob("*.json"):
        try:
            summary[f.stem] = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            pass
    ran = []
    for nm in names:
        if nm not in STAGES:
            print(f"未知阶段: {nm}")
            continue
        print(f"\n[{nm}] " + "-" * 48)
        try:
            res = STAGES[nm](repo, out)
        except Exception as e:
            res = {"error": f"{type(e).__name__}: {str(e)[:160]}"}
            print(f"    阶段异常: {type(e).__name__}: {str(e)[:120]}")
        summary[nm] = res
        ran.append(nm)
        try:
            (sdir / f"{nm}.json").write_text(
                json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception:
            pass
    summary["_meta"] = {
        "ran_this_time": ran,
        "total_stages_done": len([k for k in summary if not k.startswith("_")]),
        "all_stages": order,
        "pending": [x for x in order if x not in summary],
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    # 兼容：老代码读 items 时不希望看到 _meta，故单独存一份精简版
    (out / "audit_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n==> 汇总: {out / 'audit_summary.json'}"
          f"  （已完成 {summary['_meta']['total_stages_done']}/{len(order)} 阶段"
          f"；未完成: {summary['_meta']['pending'] or '无'}）")


if __name__ == "__main__":
    main()
