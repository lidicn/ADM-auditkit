#!/usr/bin/env python3
"""零依赖测试运行器：python tests/run_all.py → total/collectable/ran/failed。"""
from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(f"t_{path.stem}_{id(path)}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here.parent))
    total = collectable = ran = failed = 0
    for f in sorted(here.glob("test_*.py")):
        mod = _load(f)
        names = sorted(n for n in dir(mod) if n.startswith("test_") and callable(getattr(mod, n)))
        total += len(names)
        for n in names:
            collectable += 1
            try:
                getattr(mod, n)()
                ran += 1
            except Exception:
                failed += 1
                print(f"FAIL {f.name}::{n}")
                traceback.print_exc()
    print(f"total={total} collectable={collectable} ran={ran} failed={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
