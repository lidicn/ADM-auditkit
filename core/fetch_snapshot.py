#!/usr/bin/env python3
"""AutoForge 增量快照：用 GitHub API 比对 HEAD commit，仅变更时重新拉取源码。

沙箱内 git clone / github.com 直连不可用，因此：
  - 元数据：api.github.com（可用）
  - 源码：codeload.github.com tarball（可用）
输出：state/last_commit.json，并把源码解包到 <root>/src
"""
import json
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

REPO = os.environ.get("AF_REPO", "AutoForge")
# 通过环境变量指定 owner/repo，默认留空以强制显式配置


def http_get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": "af-audit/1.0",
        "Accept": "application/vnd.github+json",
    })
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/workspace/audit")
    owner = os.environ.get("AF_OWNER", "")
    repo = os.environ.get("AF_REPO", "AutoForge")
    ref = os.environ.get("AF_REF", "main")
    if not owner:
        print("[snapshot] AF_OWNER 未设置，跳过远端比对（离线模式）", file=sys.stderr)
        return 2

    state_dir = root / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "last_commit.json"

    api = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        head = json.loads(http_get(f"{api}/commits/{ref}"))
    except Exception as e:  # noqa: BLE001
        print(f"[snapshot] 获取远端 HEAD 失败：{e}", file=sys.stderr)
        return 3
    sha = head["sha"]
    meta = {
        "sha": sha,
        "commit_date": head["commit"]["committer"]["date"],
        "message": head["commit"]["message"].splitlines()[0][:200],
        "ref": ref,
    }

    prev = json.loads(state_file.read_text()) if state_file.exists() else {}
    if prev.get("sha") == sha:
        (state_dir / "changed").write_text("false")
        meta["changed"] = False
        meta["changed_files"] = []
        print(f"[snapshot] 无变更（HEAD={sha[:12]}），本轮复用缓存结果")
    else:
        meta["changed"] = True
        (state_dir / "changed").write_text("true")
        try:
            if prev.get("sha"):
                cmp = json.loads(http_get(f"{api}/compare/{prev['sha']}...{sha}"))
                meta["changed_files"] = [f["filename"] for f in cmp.get("files", [])]
            else:
                meta["changed_files"] = ["<initial full scan>"]
        except Exception as e:  # noqa: BLE001
            print(f"[snapshot] compare 失败：{e}", file=sys.stderr)
            meta["changed_files"] = ["<unknown>"]

        url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}"
        tgz = root / "state" / f"{sha[:12]}.tar.gz"
        tgz.write_bytes(http_get(url, timeout=180))
        with tarfile.open(tgz) as tf:
            tf.extractall(root / "state" / "unpack")
        unpacked = root / "state" / "unpack"
        top = next(p for p in unpacked.iterdir() if p.is_dir())
        src = root / "src"
        if src.exists():
            import shutil
            shutil.rmtree(src)
        top.rename(src)
        tgz.unlink()
        print(f"[snapshot] 已更新源码至 {sha[:12]}，变更文件 {len(meta['changed_files'])} 个")

    state_file.write_text(json.dumps(meta, ensure_ascii=False, indent=2))
    print(json.dumps(meta, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
