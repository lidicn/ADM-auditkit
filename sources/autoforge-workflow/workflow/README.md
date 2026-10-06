# AutoForge 周期安全审计工作流（沙箱版）

目标：每 ~30 分钟对 `github.com/lidicn/AutoForge` 跑一轮可复现、可增量、有图谱支撑的安全审计。

审计焦点（用户选定）：**Agentic 执行链与提示注入** —— NL→IR、MCP 工具参数、执行器、secrets/auth、原子写/flock、canary 回滚、私有 homesdk wheel 供应链。

## 目录

```
/data/workspace/audit/
├── src/                  # 仓库快照（codeload tarball 解包，非 git clone）
├── workflow/
│   ├── af_audit.sh       # 单轮编排入口
│   ├── lib/
│   │   ├── fetch_snapshot.py        # P0 快照/增量（api.github.com compare）
│   │   ├── dep_audit.py             # P1 SBOM/依赖/CI 供应链
│   │   ├── skill_scan.py            # P5 agent/skill 配置面
│   │   ├── aggregate.py             # P6 聚合 + 基线 diff + report.md
│   │   ├── rules/autoforge-agentic.yml  # 15 条项目专属 semgrep 规则
│   │   └── graph/
│   │       ├── build_graph.py       # P4 import 图 + 能力图 + entry→sink 路径
│   │       └── paths_to_findings.py # P4 路径→findings
│   └── README.md
├── rounds/round-NNN/     # 每轮产物：sast/ secrets/ deps/ graph/ skill/ findings.json report.md
├── baseline/             # findings.json 基线（跨轮 diff）
└── state/                # last_commit.json / changed
```

## 单轮六阶段

| 阶段 | 内容 | 工具 | 产物 |
|---|---|---|---|
| P0 | 快照与增量判定 | fetch_snapshot.py | state/changed |
| P1 | 依赖 SBOM / CVE / CI 供应链 | pip-audit、正则 | deps/*.json |
| P2 | SAST（通用 + 项目专属） | semgrep | sast/semgrep.sarif |
| P3 | 密钥泄露 | detect-secrets | secrets/*.json |
| P4 | 图谱可达性 | build_graph.py + networkx | graph/{graph.json,graph.graphml,graph.svg,paths.json,risk-paths.json} |
| P5 | Agentic / Skill 配置面 | skill_scan.py | skill/skill-scan.json |
| P6 | 聚合 + 基线 diff | aggregate.py | findings.json / baseline-diff.json / report.md |

无仓库变更时自动降级为 **lite 轮**（只跑 P4/P5/P6，约 2 分钟）；`--force` 强制全量。

## 运行

```bash
export PATH=/opt/audit/pylibs/bin:/usr/local/bin:$PATH
export PYTHONPATH=/opt/audit/pylibs
bash /data/workspace/audit/workflow/af_audit.sh round-001 --force   # 首轮全量
bash /data/workspace/audit/workflow/af_audit.sh                      # 后续自动编号增量
```

注意：沙箱 `ulimit -f` 默认 100MB，脚本已内置 `ulimit -f unlimited`。

## 环境约束（沙箱实测）

- git clone / github.com 直连与镜像均 403 → 只能走 `api.github.com` + `codeload.github.com`
- CodeQL CLI、Joern、gitleaks、syft、osv-scanner 因发布包下载受限不可用 → 用 semgrep taint + 自研 AST 图谱替代
- SkillSpector 需 Python≥3.12，环境仅 3.10 且无法引导 pip → 降级为 cloudflare/security-audit-skill 方法论 + 自研 skill_scan.py

## 已安装工具

`/opt/audit/pylibs`：semgrep 1.179.0、pip-audit 2.10.1、sarif-tools、networkx 3.4.2、detect-secrets、matplotlib、grimp、pip-licenses
`/usr/local/bin`：ast-grep 0.45.3
`/opt/audit/3rd`：cloudflare security-audit-skill、trailofbits semgrep-rules、0xdea semgrep-rules、SkillSpector 源码（备查）
