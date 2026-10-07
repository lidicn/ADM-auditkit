#!/usr/bin/env python3
"""engine/propose.py —— Phase 4: 元宝迭代通道。

标准化变更提案包生成器，让元宝（网络沙箱 AI）能通过递交提案包来迭代规则，
由维护者审核合入 GitHub。

提案包结构：
  proposals/<YYYYMMDD_HHMMSS>_<name>/
    CHANGE.yaml        提案元数据（title/type/scope/risk/verify_cmd/summary）
    changes.patch      git diff（如果在 git 仓库且有未提交改动）
    files/             新增/修改的文件副本（便于审核）
    evidence/          验证证据
      test_output.txt  测试输出
      rules_list.txt   auditkit rules list 输出

元宝工作流：
  1. 在沙箱里修改 rules/ 或 projects/ 或 engine/
  2. 运行 `auditkit propose <type> <name> --title "..." --summary "..."`
  3. 把生成的提案包目录发给维护者
  4. 维护者审核 CHANGE.yaml + files/ + evidence/，运行 verify_cmd，合入 git

设计原则：
  - 提案包自包含：所有改动文件都在 files/ 里，不依赖沙箱环境
  - 验证证据自动收集：跑测试、列规则，输出到 evidence/
  - 风险分级：rule 改动默认 low，engine 改动默认 medium
  - 不自动提交 git：只生成提案包，合入由维护者决定
"""
from __future__ import annotations

import datetime
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROPOSALS_DIR = ROOT / "proposals"

VALID_TYPES = ("rule", "engine", "profile")
VALID_RISKS = ("low", "medium", "high")


def _yaml_escape(s: str) -> str:
    """简单的 YAML 字符串转义（处理换行和引号）。"""
    if "\n" in s:
        return "|\n" + "\n".join("  " + line for line in s.split("\n"))
    if ":" in s or "#" in s or '"' in s or "'" in s:
        return '"' + s.replace('"', '\\"') + '"'
    return s


def generate_change_yaml(
    title: str,
    ptype: str,
    name: str,
    scope: str,
    risk: str,
    verify_cmd: str,
    summary: str,
    author: str = "yuanbao",
    files_changed: list[str] | None = None,
) -> str:
    """生成 CHANGE.yaml 内容。"""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    files_list = files_changed or []
    files_yaml = "\n".join(f"  - {f}" for f in files_list) if files_list else "  []"

    return f"""# ADM-auditkit 变更提案
# 由 auditkit propose 自动生成，维护者审核后合入

title: {_yaml_escape(title)}
type: {ptype}
name: {name}
scope: {_yaml_escape(scope)}
risk: {risk}
author: {author}
created_at: {now}

# 验证命令：维护者合入前必须运行此命令确认通过
verify_cmd: {_yaml_escape(verify_cmd)}

# 变更摘要：元宝写清楚改了什么、为什么改
summary: {_yaml_escape(summary)}

# 变更文件列表
files_changed:
{files_yaml}
"""


def collect_changed_files() -> list[Path]:
    """收集 git 仓库中未提交的改动文件（新增 + 修改）。"""
    try:
        # 已暂存的改动
        r1 = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True, text=True, cwd=ROOT, timeout=10)
        # 未暂存的改动
        r2 = subprocess.run(
            ["git", "diff", "--name-only"],
            capture_output=True, text=True, cwd=ROOT, timeout=10)
        # 未跟踪的文件
        r3 = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            capture_output=True, text=True, cwd=ROOT, timeout=10)
        files = set()
        for r in (r1, r2, r3):
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n"):
                    if line:
                        files.add(line)
        return sorted(ROOT / f for f in files)
    except Exception:
        return []


def generate_git_diff() -> str:
    """生成 git diff（包含暂存和未暂存）。"""
    try:
        r1 = subprocess.run(
            ["git", "diff", "--cached"],
            capture_output=True, text=True, cwd=ROOT, timeout=30)
        r2 = subprocess.run(
            ["git", "diff"],
            capture_output=True, text=True, cwd=ROOT, timeout=30)
        return (r1.stdout or "") + (r2.stdout or "")
    except Exception as e:
        return f"# git diff 失败: {e}\n"


def run_verification(proposal_dir: Path, ptype: str) -> dict:
    """运行验证命令，收集证据到 evidence/。

    Returns:
        dict with keys: test_passed, test_output, rules_output
    """
    evidence_dir = proposal_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    result = {"test_passed": False, "test_output": "", "rules_output": ""}

    # 1. 跑单元测试
    test_cmd = [sys.executable, "-u", "tests/run_all.py"]
    try:
        p = subprocess.run(test_cmd, capture_output=True, text=True,
                           cwd=ROOT, timeout=120)
        output = p.stdout + p.stderr
        result["test_output"] = output
        result["test_passed"] = (p.returncode == 0 and "failed=0" in output)
    except Exception as e:
        result["test_output"] = f"测试运行失败: {e}"
    (evidence_dir / "test_output.txt").write_text(result["test_output"])

    # 2. 列规则（rule 类型提案必跑）
    if ptype == "rule":
        try:
            p = subprocess.run(
                [sys.executable, "auditkit", "rules", "list"],
                capture_output=True, text=True, cwd=ROOT, timeout=30)
            result["rules_output"] = p.stdout + p.stderr
        except Exception as e:
            result["rules_output"] = f"规则列表获取失败: {e}"
        (evidence_dir / "rules_list.txt").write_text(result["rules_output"])

    return result


def create_proposal(
    ptype: str,
    name: str,
    title: str | None = None,
    summary: str = "",
    scope: str = "",
    risk: str | None = None,
    verify_cmd: str | None = None,
    author: str = "yuanbao",
) -> Path:
    """创建标准化变更提案包。

    Args:
        ptype: 提案类型（rule/engine/profile）
        name: 提案名称（用于目录名，如 py_new_rule）
        title: 提案标题（默认用 name）
        summary: 变更摘要
        scope: 影响范围（默认根据类型推断）
        risk: 风险等级（默认 rule=low, engine=medium, profile=low）
        verify_cmd: 验证命令（默认 python auditkit rules test）
        author: 作者

    Returns:
        提案包目录路径
    """
    if ptype not in VALID_TYPES:
        raise ValueError(f"未知提案类型: {ptype}（可选 {VALID_TYPES}）")

    # 默认值
    title = title or f"{ptype}: {name}"
    if risk is None:
        risk = "medium" if ptype == "engine" else "low"
    if risk not in VALID_RISKS:
        raise ValueError(f"未知风险等级: {risk}（可选 {VALID_RISKS}）")
    if verify_cmd is None:
        verify_cmd = "python -u tests/run_all.py && python auditkit rules test"
    if not scope:
        scope = {
            "rule": "rules/ 目录下的规则变更",
            "engine": "engine/ 目录下的引擎/模式变更",
            "profile": "projects/*/adapter/ 目录下的项目适配变更",
        }[ptype]

    # 创建提案目录
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = name.replace(" ", "_").replace("/", "_")
    proposal_dir = PROPOSALS_DIR / f"{timestamp}_{safe_name}"
    proposal_dir.mkdir(parents=True, exist_ok=True)

    # 收集改动文件
    changed_files = collect_changed_files()
    files_changed_rel = [str(f.relative_to(ROOT)) for f in changed_files]

    # 复制改动文件到 files/
    if changed_files:
        files_dir = proposal_dir / "files"
        for f in changed_files:
            if f.exists() and f.is_file():
                rel = f.relative_to(ROOT)
                dest = files_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest)

    # 生成 git diff
    diff = generate_git_diff()
    if diff.strip():
        (proposal_dir / "changes.patch").write_text(diff)

    # 生成 CHANGE.yaml
    change_yaml = generate_change_yaml(
        title=title, ptype=ptype, name=name, scope=scope,
        risk=risk, verify_cmd=verify_cmd, summary=summary,
        author=author, files_changed=files_changed_rel,
    )
    (proposal_dir / "CHANGE.yaml").write_text(change_yaml)

    # 运行验证
    verification = run_verification(proposal_dir, ptype)

    # 在 CHANGE.yaml 末尾追加验证结果
    with open(proposal_dir / "CHANGE.yaml", "a") as f:
        f.write(f"\n# 自动验证结果\n")
        f.write(f"verification:\n")
        f.write(f"  tests_passed: {verification['test_passed']}\n")
        f.write(f"  files_changed_count: {len(files_changed_rel)}\n")
        if files_changed_rel:
            f.write(f"  files_changed:\n")
            for fc in files_changed_rel:
                f.write(f"    - {fc}\n")

    return proposal_dir


def list_proposals() -> list[Path]:
    """列出所有提案包。"""
    if not PROPOSALS_DIR.exists():
        return []
    return sorted(PROPOSALS_DIR.iterdir())


def show_proposal(proposal_dir: Path) -> str:
    """显示提案包摘要。"""
    change_yaml = proposal_dir / "CHANGE.yaml"
    if not change_yaml.exists():
        return f"[无效提案包] {proposal_dir}（缺少 CHANGE.yaml）"
    content = change_yaml.read_text()
    # 提取关键字段
    lines = []
    for line in content.split("\n"):
        if any(line.startswith(k) for k in ("title:", "type:", "risk:", "author:", "created_at:", "verify_cmd:")):
            lines.append(line)
    files_dir = proposal_dir / "files"
    file_count = sum(1 for _ in files_dir.rglob("*") if _.is_file()) if files_dir.exists() else 0
    evidence_dir = proposal_dir / "evidence"
    evidence_count = sum(1 for _ in evidence_dir.rglob("*") if _.is_file()) if evidence_dir.exists() else 0
    lines.append(f"files_in_package: {file_count}")
    lines.append(f"evidence_files: {evidence_count}")
    return "\n".join(lines)
