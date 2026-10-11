# ADM-auditkit 审计工作流 Skill

> 给 AI agent（DeepSeek 等）使用的审计工具调用指南。

## 这个工具是什么

ADM-auditkit 是一个多项目代码审计工作流，支持对 AutoForge、doubao-butler、memory-agent 三个项目做自动化安全审计。

它会：
1. 扫描代码，找出潜在的安全缺陷
2. 生成结构化报告（命中数、确证缺陷、高危明细）
3. 输出 Markdown 报告

## 怎么调用

容器跑在 NAS 上，通过 `docker exec` 执行命令：

```bash
# 跑一轮审计
docker exec auditkit python3 /app/auditkit round <project> --round <N>

# 查看缺陷台账
docker exec auditkit python3 /app/auditkit status <project>

# 跑自检门禁（确认分析器没坏）
docker exec auditkit python3 /app/auditkit selftest
```

## 支持的项目

| 项目名 | 仓库 | 说明 |
|---|---|---|
| `autoforge` | lidicn/AutoForge | 自动化构建引擎 |
| `doubao-butler` | lidicn/doubao-butler | 豆包助手 |
| `memory-agent` | lidicn/memory-agent | 记忆 agent |

## 输出

跑完一轮后，报告在 `/audit-out/` 目录：
- `report.md` — 人类可读的审计报告
- `findings/*.json` — 结构化命中数据

## 示例

```bash
# 给 AutoForge 跑第 5 轮审计
docker exec auditkit python3 /app/auditkit round autoforge --round 5

# 看结果
docker exec auditkit cat /audit-out/report.md
```

## 注意事项

1. **先跑 selftest**：每次开始审计前，先跑 `selftest` 确认分析器没坏
2. **增量审计**：`--round N` 是第 N 轮，会自动对比上一轮的变化
3. **输出是候选不是确证**：报告里的缺陷是候选，需要人工确证
4. **20 轮后收敛**：一般跑 20 轮后缺陷会收敛，再跑新发现的很少
