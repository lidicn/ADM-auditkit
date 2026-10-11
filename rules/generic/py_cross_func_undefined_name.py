"""py.cross_func_undefined_name —— 甲函数定义的名字，乙函数裸用（NameError）。

来源：AutoForge af_live.py 历史确证缺陷——模块级没有 logger，`_loop()` 里裸用
`logger.debug(...)`，而 `logger = logging.getLogger(...)` 只定义在另一个函数
`_read_inbox()` 内。ticker 线程一旦走到该行即 `NameError: name 'logger' is not
defined` 崩溃（后修复：补模块级 logger）。同类形态在多项目出现过：函数内定义的
helper 缓存/句柄被兄弟函数裸引用，读代码时极难发现——名字"看起来"在文件里存在。

判据（只报**交叉函数**情形，不报"全文件真未定义"——判据局部性：后者来源太杂
（注入的全局、动态注册、pytest 约定），精度不够不进结论）。某函数 f 内的
Name Load X，同时满足：
    ① X 不是 f 的参数/局部赋值/函数内 import 别名/global·nonlocal 声明
       （含嵌套函数里的定义——闭包合法引用不报）
    ② X 不是模块级定义（导入、模块级赋值/函数/类定义、任意函数声明的 global 名）
    ③ X 不是 builtins，也不是模块内建全局（__file__/__name__ 等）
    ④ 但同文件**另一个函数**里有 `X = ...` 裸赋值（Name Store）
    ⇒ 运行到该行必 NameError（除非该行从未被执行——同样是缺陷信号）
self.attr / obj.attr 是 Attribute（.attr 是 str 不是 Name Load），天然不参与。

v1.0.1：AutoForge round-002 实测 32 条命中里发现系统性假阳性——外层函数的负载
收集误用 all_walk 下钻进嵌套函数，把 `def inner(node)` 的 node 负载算成外层未定义
（PITFALLS P1 变体）。改为自己层用 own_walk、嵌套函数作为独立作用域各自分析
（词法祖先闭包已并入 locals）。修复后 round-003 复测。

v1.0.2：round-003/004 又发现第二类假阳性——嵌套 def/class 的**名字**没被当作
外层作用域的局部定义收集，兄弟嵌套函数互调（`def site` + `scan()` 里调 site）
被报 NameError。修法：_collect_scope_names 补收 FunctionDef/AsyncFunctionDef/
ClassDef 的 name。round-004 该类 3 条全灭、dirty 召回未丢。
"""
from __future__ import annotations

import ast
import builtins

from engine.base import BaseRule, Finding, node_source
from engine.helpers import all_walk, own_walk

_BUILTINS = set(dir(builtins)) | {
    "__file__", "__name__", "__spec__", "__loader__", "__package__",
    "__builtins__", "__doc__", "__annotations__", "__debug__", "__class__",
}


def _collect_scope_names(fn) -> tuple[set[str], set[str]]:
    """函数内定义的名字：(裸赋值/except-as/match 绑定/import 别名, global/nonlocal 声明)。"""
    stores: set[str] = set()
    decls: set[str] = set()
    for sub in all_walk(fn):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
            stores.add(sub.id)
        elif isinstance(sub, ast.Global) or isinstance(sub, ast.Nonlocal):
            decls.update(sub.names)
        elif isinstance(sub, ast.ExceptHandler) and sub.name:
            stores.add(sub.name)
        elif isinstance(sub, (ast.MatchAs, ast.MatchStar)) and sub.name:
            stores.add(sub.name)
        elif isinstance(sub, ast.MatchMapping) and sub.rest:
            stores.add(sub.rest)
        elif isinstance(sub, ast.Lambda):
            a = sub.args
            for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs,
                        *([a.vararg] if a.vararg else []), *([a.kwarg] if a.kwarg else [])):
                stores.add(arg.arg)
        elif isinstance(sub, ast.Import):
            for al in sub.names:
                stores.add(al.asname or al.name.split(".")[0])
        elif isinstance(sub, ast.ImportFrom):
            for al in sub.names:
                stores.add(al.asname or al.name)
        elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # 嵌套 def/class 的名字绑定在外层作用域：兄弟函数互调是合法的闭包
            # （AutoForge round-004 实测 3 条全为此类：render_nl 的 nm、
            #   _call_sites 内 site/finish）。all_walk 下钻会把嵌套 def 名
            # 也算进外层 locals——方向正确（外层确实可见）。
            stores.add(sub.name)
    return stores, decls


def _params(fn) -> set[str]:
    a = fn.args
    return {arg.arg for arg in
            (*a.posonlyargs, *a.args, *a.kwonlyargs,
             *([a.vararg] if a.vararg else []), *([a.kwarg] if a.kwarg else []))}


class CrossFuncUndefinedNameRule(BaseRule):
    id = "py.cross_func_undefined_name"
    name = "跨函数裸用他函数的局部名"
    description = ("名字只在甲函数内定义（局部赋值），乙函数裸用 ⇒ 运行到该行 NameError；"
                   "读代码时名字'看起来存在'，极难发现")
    applies_to = []
    mode = "static_ast"
    severity = "high"
    status = "testing"
    version = "1.0.2"

    tests = {
        "dirty": [
            {"name": "logger-defined-in-sibling-func",
             "code": "def worker():\n"
                     "    logger = logging.getLogger(__name__)\n"
                     "\n"
                     "def tick():\n"
                     "    logger.info('tick')"},
            {"name": "cache-defined-in-sibling-func",
             "code": "def load():\n"
                     "    cache = {}\n"
                     "\n"
                     "def get(key):\n"
                     "    return cache[key]"},
        ],
        "clean": [
            {"name": "module-level-logger",
             "code": "logger = logging.getLogger(__name__)\n"
                     "\n"
                     "def worker():\n"
                     "    logger.info('hi')"},
            {"name": "self-attr-not-bare-name",
             "code": "class S:\n"
                     "    def __init__(self):\n"
                     "        self.cache = {}\n"
                     "\n"
                     "    def get(self, k):\n"
                     "        return self.cache[k]"},
            {"name": "param-shadows",
             "code": "def tick(logger):\n"
                     "    logger.info('tick')"},
            {"name": "global-declaration",
             "code": "def reset():\n"
                     "    global _cache\n"
                     "    _cache = {}\n"
                     "\n"
                     "def load():\n"
                     "    return _cache"},
            {"name": "closure-nested-func",
             "code": "def outer():\n"
                     "    state = 1\n"
                     "\n"
                     "    def inner():\n"
                     "        return state\n"
                     "    return inner"},
            {"name": "nested-func-param-not-outer-s-name",
             "code": "def outer(items):\n"
                     "    def inner(node):\n"
                     "        return node.value\n"
                     "    return [inner(i) for i in items]"},
            {"name": "sibling-nested-funcs",
             "code": "def container():\n"
                     "    def site(line):\n"
                     "        return line\n"
                     "\n"
                     "    def scan():\n"
                     "        return site(1)\n"
                     "    return scan"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        # 模块级定义（不进入任何函数/类作用域 —— own_walk 遇作用域停止下钻）
        mod_defined: set[str] = set()
        for n in own_walk(tree):
            if isinstance(n, ast.Import):
                for al in n.names:
                    mod_defined.add(al.asname or al.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom):
                for al in n.names:
                    mod_defined.add(al.asname or al.name)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                mod_defined.add(n.name)
            elif isinstance(n, ast.Assign):
                for t in n.targets:
                    for sub in ast.walk(t):
                        if isinstance(sub, ast.Name):
                            mod_defined.add(sub.id)
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                mod_defined.add(n.target.id)

        funcs = [n for n in all_walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        lambdas = [n for n in all_walk(tree) if isinstance(n, ast.Lambda)]
        own_locals: dict[int, set[str]] = {}
        for fn in funcs + lambdas:
            stores, decls = _collect_scope_names(fn)
            own_locals[id(fn)] = stores | decls | _params(fn)

        # 词法祖先作用域：嵌套函数合法引用外层局部（闭包）——clean-5，不算缺陷
        parent: dict[int, ast.AST] = {}
        for n in all_walk(tree):
            for c in ast.iter_child_nodes(n):
                parent[id(c)] = n

        def locals_with_closure(fn) -> set[str]:
            acc = set(own_locals.get(id(fn), set()))
            cur = parent.get(id(fn))
            while cur is not None:
                if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    acc |= own_locals.get(id(cur), set())
                cur = parent.get(id(cur))
            return acc

        per_fn = [(fn, locals_with_closure(fn)) for fn in funcs + lambdas]

        # 任意函数声明过的 global 名都是模块级可见（压制 clean-4 型假阳性）
        all_decls: set[str] = set()
        for fn in funcs:
            for sub in all_walk(fn):
                if isinstance(sub, (ast.Global, ast.Nonlocal)):
                    all_decls.update(sub.names)
        mod_defined |= all_decls

        # 名字 → 裸赋值它的函数名集合（交叉判定的证据）
        owners: dict[str, set[str]] = {}
        for fn, _locals in per_fn:
            for sub in all_walk(fn):
                if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                    owners.setdefault(sub.id, set()).add(getattr(fn, "name", "<lambda>"))

        out: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        for fn, locals_ in per_fn:
            # 本层负载用 own_walk（不进嵌套作用域——嵌套函数的参数不是外层的名字，
            # all_walk 会把 def inner(node) 的 node 负载算到外层头上，32 条假阳性教训）；
            # Lambda 无 def 语句，用 all_walk 安全。
            it = all_walk(fn) if isinstance(fn, ast.Lambda) else own_walk(fn)
            for sub in it:
                if not (isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load)):
                    continue
                x = sub.id
                if x in locals_ or x in mod_defined or x in _BUILTINS:
                    continue
                others = sorted(owners.get(x, set()) - {getattr(fn, "name", "<lambda>")})
                if not others:
                    continue  # 全文件真未定义：不报（判据局部性，见模块 docstring）
                key = (str(tree.path), sub.lineno)
                if key in seen:
                    continue
                seen.add(key)
                fname = getattr(fn, "name", "<lambda>")
                out.append(Finding(
                    rule_id=self.id, file=str(tree.path), line=sub.lineno,
                    severity=self.severity, title=self.name,
                    detail=(f"`{x}` 只在函数 {others} 里裸赋值，"
                            f"`{fname}()` 裸用 ⇒ 运行到此行 NameError"),
                    evidence=node_source(tree, sub)[:200],
                ))
        return out
