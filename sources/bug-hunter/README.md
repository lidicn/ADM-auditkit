# bug-hunter 审计工作流（导出）

## 目录

- `bug-hunter/` —— 通用工作流引擎（与项目无关，可复用到任何 Python 仓库）
  - `SKILL.md` 入口说明：六阶段、三条纪律、已知误报源
  - `scripts/` 各层实现
  - `references/patterns.md` 反模式 + 不变量参考库
- `project-suite/` —— 在 doubao-butler 上的落地资产（项目专属）
  - `audit_helpers.py` 场景注册表（33 场景 / 62 用例）
  - `test_audit_findings.py` pytest 用例
  - `pytest.ini`、`audit.yml` CI 配置

## 快速开始

```bash
bash bug-hunter/scripts/bootstrap.sh          # 装依赖（25 个）
python3 bug-hunter/scripts/pipeline.py <repo> # 跑全流水线
```

常用开关：`--fast` 快速核心扫描 / `--mutate <files>` 变异 / `--property` 属性 /
`--codemap` 图谱 / `--batch <档位>` 分档 / `--mark-read <files>` 推进覆盖度

项目套件单独跑：`pytest project-suite/test_audit_findings.py -q`
