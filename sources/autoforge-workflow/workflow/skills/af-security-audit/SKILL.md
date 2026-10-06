---
name: af-security-audit
description: 对 AutoForge（lidicn/AutoForge）执行单轮安全审计，聚焦 agentic 执行链与提示注入、权限/凭据、原子性与回滚、供应链。触发词：审计 AutoForge、跑一轮审计、af_audit、AutoForge 安全。
allowed-tools: [Read, Grep, Glob, Bash(python3:*), Bash(semgrep:*), Bash(bash /data/workspace/audit/workflow/af_audit.sh:*)]
---

# AutoForge 安全审计

## 何时用
用户要求对 AutoForge 做审计、跑下一轮审计、或核查某个发现时使用。

## 标准流程
1. 跑一轮：`bash /data/workspace/audit/workflow/af_audit.sh [--force]`
2. 读 `<round>/report.md` 与 `baseline-diff.json`，先看 **new** 项
3. 对每个 new 项做人工核验（读源码上下文，排除误报），输出结论与修复建议
4. 更新 `baseline/findings.json`（aggregate 已自动更新）

## 审计焦点（必要视角）
- **NL→IR 信任边界**：自然语言/LLM 输出是否未经校验进入 `af_nl_build`/`af_nl` → `af_apply`
- **MCP 工具参数**：`af_mcp` 入参是否 schema 校验 + 白名单
- **执行器**：`af_executor` 是否有命令白名单/参数级限制
- **凭据**：`af_secrets`/`af_auth` 是否落盘明文、token 是否常量时间比较
- **原子性/并发**：`af_atomic`/`af_flock` 是否被所有写状态路径使用
- **回滚**：`af_canary`/`af_canary_supervisor`/`af_undo` 失败是否真回滚
- **供应链**：`docker/homesdk/` 私有 wheel 无校验、CI 未钉 SHA

## 判定纪律
- 只报可落地的：需给出 file:line + 触发条件 + 影响
- 区分「架构性风险」与「可利用漏洞」，不夸大
- 无证据不写"疑似后门"类结论
