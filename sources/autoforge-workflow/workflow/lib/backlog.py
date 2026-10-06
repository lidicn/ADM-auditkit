#!/usr/bin/env python3
"""缺陷台账回归复核 —— 把审计从「一轮一扫」变成闭环。

读 baseline/bugs.json 里的已确证缺陷清单，按源码指纹逐条复核：
  - expect=absent 且指纹仍命中  ⇒ still_open
  - expect=absent 且指纹消失    ⇒ fixed（再用 fixed_if 里的正向标记确认是真的修好了，
                                  而不是把代码删掉了/挪走了 —— 后者判 unknown）
  - expect=present（门禁类，锚点应在）且指纹消失 ⇒ unknown（锚点被挪走，无从判定）
输出 rounds/<round>/backlog.json。

用法: backlog.py <audit_root> <round_dir>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def main() -> int:
    audit_root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit")
    round_dir = Path(sys.argv[2] if len(sys.argv) > 2 else audit_root / "rounds" / "round-004")
    round_dir.mkdir(parents=True, exist_ok=True)

    bf = audit_root / "baseline" / "bugs.json"
    if not bf.exists():
        print(json.dumps({"error": f"缺少台账 {bf}"}, ensure_ascii=False))
        return 2
    backlog = json.loads(bf.read_text(encoding="utf-8"))

    results = []
    for bug in backlog.get("bugs", []):
        rel = bug.get("file", "")
        # 相对 audit_root；也允许相对 src
        cands = [audit_root / rel, audit_root / "src" / rel]
        src_path = next((c for c in cands if c.exists()), None)
        rec = {"id": bug["id"], "severity": bug.get("severity"),
               "title": bug.get("title"), "file": rel, "status": "unknown",
               "matched": [], "missing": [], "fixed_markers": [], "note": bug.get("note", "")}
        if src_path is None:
            rec["status"] = "unknown"
            rec["missing"] = ["<文件不存在>"]
            results.append(rec)
            continue

        text = read(src_path)
        for pat in bug.get("patterns", []):
            if re.search(pat, text, re.MULTILINE):
                rec["matched"].append(pat)
            else:
                rec["missing"].append(pat)

        expect = bug.get("expect", "absent")
        if expect == "absent":
            if rec["matched"]:
                rec["status"] = "still_open"
            else:
                # 判 fixed 前先确认修复是「改好了」而不是「删没了」
                markers = [m for m in bug.get("fixed_if", []) if m and m in text]
                rec["fixed_markers"] = markers
                rec["status"] = "fixed" if markers else "unknown"
        else:  # expect == present：锚点型，应仍在
            if rec["matched"]:
                markers = [m for m in bug.get("fixed_if", []) if m and m in text]
                rec["fixed_markers"] = markers
                rec["status"] = "fixed" if markers else "still_open"
            else:
                rec["status"] = "unknown"

        results.append(rec)

    out = round_dir / "backlog.json"
    out.write_text(json.dumps({"round": round_dir.name, "results": results},
                              ensure_ascii=False, indent=2))

    from collections import Counter
    summary = dict(Counter(r["status"] for r in results))
    print(json.dumps({"round": round_dir.name, "summary": summary,
                      "still_open": [r["id"] for r in results if r["status"] == "still_open"],
                      "fixed": [r["id"] for r in results if r["status"] == "fixed"],
                      "unknown": [r["id"] for r in results if r["status"] == "unknown"]},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
