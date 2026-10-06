"""Golden sample：塞满各类已知缺陷。用于证明分析器**能检出来**（防假阴性）。

每个缺陷处标 [D-nn] 注释，对应 selftest/expect.json 里期望命中的规则。
本文件**不做语法之外的任何假设**，能被 ast.parse 即可。
"""
import ast, json, os, re, subprocess, tempfile, threading, time
from collections import deque
from pathlib import Path


# [D-01] 异常被静默吞掉
def silent_fail(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        pass


# [D-02] 非原子写：裸 open(...,'w') 无 tmp+replace
def nonatomic_write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


# [D-03] 组合爆炸：嵌套循环递归展开无预算
def expand(items, depth):
    if depth == 0:
        return [items]
    out = []
    for head in items:
        for tail in expand(items, depth - 1):
            out.append([head] + tail)
    return out


# [D-04] 墙上时钟做超时判定
class Lease:
    def __init__(self):
        self.started = time.time()

    def expired(self, window):
        return (time.time() - self.started) > window


# [D-05] 模块级裸 env 解析（脏值 → import 即崩）
TTL = int(os.getenv("SAMPLE_TTL", "60"))
RATE = float(os.getenv("SAMPLE_RATE", "1.0"))


# [D-06] 可变默认参数
def append_to(x, bucket=[]):
    bucket.append(x)
    return bucket


# [D-07] 不可比较的排序键
def sort_by_map(rows):
    return sorted(rows, key=lambda r: r.items())


# [D-08] 文件句柄未关闭（无 with、无 close）
def leak_handle(path):
    fh = open(path, encoding="utf-8")
    return fh.read()


# [D-09] fd 未关闭
def leak_fd(path):
    fd = os.open(path, os.O_RDONLY)
    return fd


# [D-10] 线程无 daemon 无 join
def spawn():
    t = threading.Thread(target=lambda: None)
    t.start()
    return t


# [D-11] 子进程无回收
def run_child():
    return subprocess.Popen(["ls"])


# [D-12] 临时目录无清理
def make_tmp():
    d = tempfile.mkdtemp()
    return d


# [D-13] 调用点传入被调函数不存在的关键字
def helper(name, count=1):
    return name


def use_helper():
    return helper("x", count=2, typo=3)


# [D-14] 子类方法签名收窄（LSP 违背）
class Base:
    def run(self, x):
        return x


class Sub(Base):
    def run(self):
        return None


# [D-15] 解析结果未 isinstance 校验即 .get
def load_cfg(path):
    data = json.loads(Path(path).read_text())
    return data.get("k", None)


# [D-16] 先删后写且无备份
def replace_file(path, text):
    os.unlink(path)
    Path(path).write_text(text, encoding="utf-8")


# [D-17] 实例级容器只增不减
class Collector:
    items: list = None

    def __init__(self):
        self.items = []

    def add(self, x):
        self.items.append(x)


# [D-18] 写盘前不重读（同类其他方法重读 → RMW 不一致）
class CodeStore:
    def __init__(self, path):
        self.path = Path(path)
        self._codes = {}
        self._lock = threading.Lock()

    def _load(self):
        if self.path.is_file():
            self._codes = json.loads(self.path.read_text())

    def _persist(self):
        self.path.write_text(json.dumps(self._codes), encoding="utf-8")

    def create(self, code):        # ← 缺 _load()
        with self._lock:
            self._codes[code] = {"code": code}
            self._persist()

    def consume(self, code):       # ← 有 _load()
        self._load()
        with self._lock:
            self._codes.pop(code, None)
            self._persist()


# [D-19] 除零 / 空序列 max
def ratio(a, b):
    return a / b


def top(xs):
    return max(xs)


# [D-20] 异常路径资源未释放
def read_then_close(path):
    fh = open(path, encoding="utf-8")
    try:
        return fh.read()
    finally:
        pass


# [D-21] 直接下标不判空
def first(xs):
    return xs[0]


# [D-22] 递归无预算
def walk(node, out):
    if node is None:
        return out
    out.append(node)
    return walk(node.get("next"), out)


# ══════════════════════════════════════════════════════════════════
# D-23.. 补充：覆盖 consistency / serialization / errorhandling /
#              observability / auth / testgap 六个 0 命中分析器
# ══════════════════════════════════════════════════════════════════

import json
import os
import time
import threading
from pathlib import Path as _P


# D-23 [TX-04] 删旧成功后、写新前失败 → 不可逆丢失
def overwrite_archive(dirpath, payload):
    p = _P(dirpath)
    for old in p.glob("*.json"):
        old.unlink()          # 先删
    (p / "new.json").write_text(json.dumps(payload))   # 后写（中间失败即丢）


# D-24 [TX-05] 内存状态先改、磁盘后写，且写入失败未回滚
class _Mirror:
    def __init__(self):
        self.state = "created"
        self.disk = {}

    def set_state(self, v):
        self.state = v            # 内存先改
        self.disk["state"] = v    # 磁盘后写（失败则不一致）


# D-25 [SER-02] 序列化与反序列化的键不一致
class _Rec:
    def to_dict(self):
        return {"user_id": 1}

    @classmethod
    def from_dict(cls, d):
        return cls(d["uid"])      # 键漂移：写入 user_id，读取 uid


# D-26 [SER-05] 持久化路径用 default=str 静默字符串化
def persist_bad(path, obj):
    _P(path).write_text(json.dumps(obj, default=str))


# D-27 [ERRH-01] 重试无退出/无退避，且吞掉异常
def retry_forever(fn):
    for _ in range(10000):
        try:
            return fn()
        except Exception:
            pass          # 吞掉 + 无 sleep + 无计数上限语义


# D-28 [ERRH-06] 不区分错误类型：网络错误与逻辑错误同样处理
def handle_err(exc):
    try:
        raise exc
    except Exception:
        return "retry"    # 无论 404 还是超时都重试


# D-29 [OBS-02] 无界累加且落盘
class _Metrics:
    def __init__(self):
        self.samples = []

    def emit(self, v):
        self.samples.append(v)     # 无任何裁剪


# D-30 [OBS-06] 失败路径不记账
def do_without_audit(x):
    try:
        return 1 / x
    except ZeroDivisionError:
        return None                # 无 audit / 无 log


# D-31 [AUTH-04] 凭证集合只增不减
class _TokenBox:
    def __init__(self):
        self.tokens = {}

    def issue(self, t):
        self.tokens[t] = {"at": time.time()}


# D-32 [AUTH-05] 持锁做磁盘 IO
_LOCK = threading.Lock()


def write_under_lock(path, text):
    with _LOCK:
        _P(path).write_text(text)  # 锁内落盘


# D-33 [AUTH-06] 权限判定缺省放行
def can_do(role):
    if role == "admin":
        return True
    else:
        return True                # 默认放行


# D-34 [TST-02] 未实现占位
def resolve_entity(name):
    # TODO: 接 catalog 做真实解析
    return name
