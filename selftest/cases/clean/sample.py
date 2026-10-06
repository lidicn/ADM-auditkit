"""Golden sample：全部是正确写法。用于证明分析器**不乱报**（防假阳性）。

本文件的期望是：**多数分析器应 0 命中**。跑自检时若大量命中即为假阳性回归。
"""
import ast, hmac, json, os, tempfile, threading, time
from collections import deque
from pathlib import Path


# 正确：异常有记录 + 有返回值语义
def safe_load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# 正确：原子写（tmp + fsync + replace + finally 清理）
def atomic_write(path, text):
    p = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


# 正确：单调时钟做超时
class Lease:
    def __init__(self, clock=time.monotonic):
        self.started = clock()

    def expired(self, window, clock=time.monotonic):
        return (clock() - self.started) > window


# 正确：env 解析带兜底
def _env_number(name, default):
    try:
        return float(os.getenv(name, "") or default)
    except ValueError:
        return default


TTL = _env_number("SAMPLE_TTL", 60.0)


# 正确：不可变默认
def append_to(x, bucket=None):
    bucket = [] if bucket is None else bucket
    bucket.append(x)
    return bucket


# 正确：稳定排序键
def sort_by_key(rows):
    return sorted(rows, key=lambda r: (r.get("k", ""), r.get("id", 0)))


# 正确：with 管理句柄
def read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# 正确：daemon 线程
def spawn():
    t = threading.Thread(target=lambda: None, daemon=True)
    t.start()
    return t


# 正确：子进程回收
def run_child():
    p = subprocess.Popen(["true"])
    p.wait()
    return p.returncode


# 正确：临时目录 finally 清理
def with_tmp():
    d = tempfile.mkdtemp()
    try:
        return d
    finally:
        shutil.rmtree(d, ignore_errors=True)


# 正确：常量时间比较
def check(token, expected):
    return hmac.compare_digest(token, expected)


# 正确：解析后 isinstance 校验
def load_cfg(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data.get("k")


# 正确：有界容器
class Collector:
    def __init__(self, max_items=200):
        self.items = deque(maxlen=max_items)

    def add(self, x):
        self.items.append(x)


# 正确：先写后删 + 备份
def replace_file(path, text):
    p = Path(path)
    bak = p.with_suffix(p.suffix + ".bak")
    if p.exists():
        p.replace(bak)
    atomic_write(p, text)
    if bak.exists():
        try:
            bak.unlink()
        except OSError:
            pass


# 正确：RMW 一致（都重读）
class CodeStore:
    def __init__(self, path):
        self.path = Path(path)
        self._codes = {}
        self._lock = threading.Lock()

    def _load(self):
        if self.path.is_file():
            try:
                self._codes = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return

    def _persist(self):
        atomic_write(self.path, json.dumps(self._codes))

    def create(self, code):
        self._load()
        with self._lock:
            self._codes[code] = {"code": code}
            self._persist()

    def consume(self, code):
        self._load()
        with self._lock:
            self._codes.pop(code, None)
            self._persist()


# 正确：除零与空序列防护
def ratio(a, b):
    return a / b if b else 0.0


def top(xs):
    return max(xs) if xs else None


# 正确：空值防护
def first(xs):
    return xs[0] if xs else None
