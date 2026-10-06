#!/usr/bin/env python3
"""并发验证层 —— 专治「读代码推断了十几轮，从未跑起来证实」的那类缺陷。

为什么单独一层（第十五轮新增）：
  前十四轮有一条悬案：**P0-2（SQLite 跨线程 / 懒初始化竞态）**。
  它从第一轮就被列为 P0，但十四轮里**从未用测试证实过**。
  第十四轮变异测试给出了原因：
     `inbox.py` 的 `check_same_thread=False` 改成 True，测试**仍绿**
     ⇒ 现有测试从未做过真正的跨线程写入。

  也就是说：这类缺陷**静态读代码永远证不实，必须真跑多线程**。
  属性测试层（S3p）不覆盖并发，变异层（S3m）只能暴露"没覆盖"，
  都无法回答「到底会不会出问题」。这一层可以。

设计原则（沿用全工作流）：
  · 真起线程，不是模拟
  · **确定性优先**：用「放大窗口」代替「随机狂轰」——
    把 _init 换成慢版本，使竞态窗口从毫秒扩到 400ms，
    观察结果从"偶尔复现"变成"必然复现"
  · 有 timeout，绝不挂死测试进程（V23 反测曾把自己陪葬）
  · 对照实验：原写法 vs 修法，差异须能归因到被测缺陷

⚠ 本层自身踩过的坑（必须留在注释里）：
  1. 环境变量名是 **DATA_DIR**，不是 BUTLER_DATA_DIR。
     我用错名字跑了 5 次，全部写到 /app/data/butler.db（残留库），
     导致"表已存在"的假阴性 —— 差点得出「P0-2 不存在」的错误结论。
  2. 探测"初始化是否完成"要用**业务表**（如 dialog_turns），
     不能查 sqlite_master（表不存在也返回 0 行，永远绿）。
  3. config.py 启动期硬校验三个密钥（DOUBAO_API_KEY /
     DESKPILOT_API_TOKEN / TASK_REPORT_TOKEN），缺一即 raise。

用法：
    python3 skills/bug-hunter/scripts/concurrency.py [repo]
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap

REPO_DEFAULT = "/data/workspace/doubao-butler-main"

# 启动期必需（config.py WO-BUT-017/018/022 硬校验）
ENV_SETUP = """
    os.environ["DATA_DIR"] = __TMP__          # ⚠ 是 DATA_DIR，不是 BUTLER_DATA_DIR
    os.environ["BUTLER_WEB_USER"] = "t"
    os.environ["BUTLER_WEB_PASSWORD"] = "t"
    os.environ["BUTLER_JWT_SECRET"] = "x"*32
    os.environ["BUTLER_ALLOW_NO_AUTH"] = "true"
    os.environ["DOUBAO_API_KEY"] = "probe"
    os.environ["DESKPILOT_API_TOKEN"] = "probe"
    os.environ["TASK_REPORT_TOKEN"] = "probe"
    os.environ["HA_TOKEN"] = "probe"
    os.environ["BUTLER_MQTT_HOST"] = "127.0.0.1"
"""

# ── C1：懒初始化竞态（P0-2 核心）───────────────────────────────────────
# 确定性实验：放大窗口，而不是随机狂轰。
C1 = '''
    import os, sys, threading, time, sqlite3
    sys.path.insert(0, "__REPO__")
    os.environ.update(dict(
        DATA_DIR="__TMP__", BUTLER_WEB_USER="t", BUTLER_WEB_PASSWORD="t",
        BUTLER_JWT_SECRET="x"*32, BUTLER_ALLOW_NO_AUTH="true",
        DOUBAO_API_KEY="probe", DESKPILOT_API_TOKEN="probe",
        TASK_REPORT_TOKEN="probe", HA_TOKEN="probe", BUTLER_MQTT_HOST="127.0.0.1"))
    import butler.store.db as db
    print("DB 文件事先存在 =", os.path.exists(os.path.join("__TMP__","butler.db")))

    real_init = db._init
    log, t0 = [], time.time()
    def traced(c):
        log.append((round(time.time()-t0,3), "init:start"))
        time.sleep(0.4)                       # 放大竞态窗口
        real_init(c)
        log.append((round(time.time()-t0,3), "init:done"))
    db._init = traced
    db._conn = None

    def t2():
        time.sleep(0.10)                      # 落在 init 窗口内
        published = db._conn is not None
        log.append((round(time.time()-t0,3), f"T2: _conn 已发布 = {published}"))
        try:
            c = db.get_conn()
            n = [x[0] for x in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            log.append((round(time.time()-t0,3), f"T2: 此刻表数 = {len(n)}"))
        except Exception as e:
            log.append((round(time.time()-t0,3), f"T2 异常 {type(e).__name__}: {str(e)[:60]}"))
    a = threading.Thread(target=db.get_conn); b = threading.Thread(target=t2)
    a.start(); b.start(); a.join(timeout=10); b.join(timeout=10)
    for t, e in sorted(log):
        print(f"  {t:>6}s  {e}")
    # 判据：T2 看到 0 张表 = 拿到半初始化连接
    half = [e for _, e in log if "此刻表数 = 0" in e]
    print("VERDICT", "HALF_INIT" if half else "OK")
'''

# ── C1'：修法对照 ───────────────────────────────────────────────────────
C1FIX = '''
    import os, sys, threading, time, sqlite3, pathlib
    sys.path.insert(0, "__REPO__")
    os.environ.update(dict(
        DATA_DIR="__TMP__", BUTLER_WEB_USER="t", BUTLER_WEB_PASSWORD="t",
        BUTLER_JWT_SECRET="x"*32, BUTLER_ALLOW_NO_AUTH="true",
        DOUBAO_API_KEY="probe", DESKPILOT_API_TOKEN="probe",
        TASK_REPORT_TOKEN="probe", HA_TOKEN="probe", BUTLER_MQTT_HOST="127.0.0.1"))
    import butler.store.db as db
    real_init = db._init
    log, t0 = [], time.time()
    def slow(c):
        time.sleep(0.4); return real_init(c)

    def get_conn_fixed():
        """修法：双重检查 + 初始化完成后才发布。"""
        if db._conn is None:
            with db._lock:
                if db._conn is not None:
                    return db._conn
                s = db.get_settings()
                c = sqlite3.connect(str(pathlib.Path(s.data_dir)/"butler.db"),
                                    check_same_thread=False)
                c.execute("PRAGMA journal_mode=WAL")
                c.execute("PRAGMA synchronous=NORMAL")
                c.execute("PRAGMA busy_timeout=5000")
                c.row_factory = sqlite3.Row
                slow(c)                        # ← 初始化完才发布
                db._conn = c
        return db._conn

    db._conn = None
    def t2f():
        time.sleep(0.10)
        try:
            c = get_conn_fixed()
            n = [x[0] for x in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            log.append((round(time.time()-t0,3), f"T2(修法): 表数 = {len(n)}"))
        except Exception as e:
            log.append((round(time.time()-t0,3), f"T2(修法) 异常 {type(e).__name__}: {e}"))
    a = threading.Thread(target=get_conn_fixed); b = threading.Thread(target=t2f)
    a.start(); b.start(); a.join(timeout=10); b.join(timeout=10)
    for t, e in sorted(log):
        print(f"  {t:>6}s  {e}")
    half = [e for _, e in log if "表数 = 0" in e]
    print("VERDICT", "HALF_INIT" if half else "OK")
'''

# ── C2：跨线程写同一连接 ────────────────────────────────────────────────
C2 = '''
    import os, sys, threading, time
    sys.path.insert(0, "__REPO__")
    os.environ.update(dict(
        DATA_DIR="__TMP__", BUTLER_WEB_USER="t", BUTLER_WEB_PASSWORD="t",
        BUTLER_JWT_SECRET="x"*32, BUTLER_ALLOW_NO_AUTH="true",
        DOUBAO_API_KEY="probe", DESKPILOT_API_TOKEN="probe",
        TASK_REPORT_TOKEN="probe", HA_TOKEN="probe", BUTLER_MQTT_HOST="127.0.0.1"))
    import butler.store.db as db
    db._conn = None
    c = db.get_conn()
    c.execute("CREATE TABLE IF NOT EXISTS probe_c2 (i INTEGER)")
    errs = []
    barrier = threading.Barrier(8)
    def w(k):
        barrier.wait()
        for j in range(25):
            try:
                c.execute("INSERT INTO probe_c2 VALUES (?)", (k*100+j,))
                time.sleep(0.0005)
            except Exception as e:
                errs.append(f"{type(e).__name__}: {str(e)[:50]}"); return
    ts = [threading.Thread(target=w, args=(i,)) for i in range(8)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=20)
    print("并发写异常数 =", len(errs))
    for e in errs[:3]: print("   ", e)
'''

# ── C3：模块级 dict read-modify-write ───────────────────────────────────
C3 = '''
    import threading
    d = dict()
    barrier = threading.Barrier(8)
    def w():
        barrier.wait()
        for j in range(200):
            k = j % 8
            d[k] = d.get(k, 0) + 1          # read-modify-write，非原子
    ts = [threading.Thread(target=w) for _ in range(8)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=10)
    total, expect = sum(d.values()), 8*200
    print(f"TOTAL {total} EXPECT {expect} MATCH {total==expect}")
    print("注意：CPython GIL 下单字节码原子，但 get+1+set 三步不是；")
    print("      本次是否丢更新取决于调度，不能因一次 MATCH 就判安全。")
'''


def _run(code, repo, timeout=90, fresh_dir=True):
    with tempfile.TemporaryDirectory() as tmp:
        # ⚠ 代码块在模块级三引号里带了 4 空格缩进，必须 dedent，
        #   否则子进程 IndentationError（第十五轮踩到）
        src = (textwrap.dedent(code)
                   .replace("__REPO__", repo)
                   .replace("__TMP__", tmp))
        r = subprocess.run([sys.executable, "-c", src],
                           capture_output=True, text=True, timeout=timeout, cwd=repo)
        return r.returncode, r.stdout or "", r.stderr or ""


def run(repo=REPO_DEFAULT, verbose=True):
    print("─" * 72)
    print("并发验证（真起线程 —— 静态读代码证不实的那类）")
    print("─" * 72)
    out = {}
    for name, code, title in [
        ("C1", C1, "SQLite 懒初始化竞态（P0-2 核心，确定性放大窗口）"),
        ("C1*", C1FIX, "修法对照：双重检查 + 初始化完才发布"),
        ("C2", C2, "跨线程写同一连接（check_same_thread=False）"),
        ("C3", C3, "模块级 dict read-modify-write（冷却表/失败计数同构）"),
    ]:
        if verbose:
            print(f"  [{name}] {title}")
        try:
            rc, so, se = _run(code, repo)
        except subprocess.TimeoutExpired:
            print(f"     ⚠ 超时（上限 90s）\n")
            out[name] = {"timeout": True}
            continue
        if verbose:
            for ln in (so or "").strip().splitlines():
                print(f"     {ln}")
            if rc != 0 and (se or "").strip():
                print(f"     rc={rc} {(se.strip().splitlines()[-1])[:100]}")
            print()
        out[name] = {"rc": rc, "out": so, "verdict":
                     ("HALF_INIT" if "VERDICT HALF_INIT" in (so or "")
                      else ("OK" if "VERDICT OK" in (so or "") else None))}
    return out


if __name__ == "__main__":
    r = run(sys.argv[1] if len(sys.argv) > 1 else REPO_DEFAULT)
    print("=" * 72)
    v1, v2 = r.get("C1", {}).get("verdict"), r.get("C1*", {}).get("verdict")
    print(f"C1（原写法）= {v1}   C1*（修法）= {v2}")
    if v1 == "HALF_INIT" and v2 == "OK":
        print("⇒ P0-2 实证成立，且修法有效")
    print("=" * 72)
