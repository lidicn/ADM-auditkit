#!/usr/bin/env python3
"""doubao-butler 项目专属规则目录（L3 骨架）。

**为什么这里现在没有规则**：config/projects.yaml 明确写着该项目技术栈未确认，
"未探测前不得假定其为 Python 项目"。在 `auditkit profile` 给出真实语言之前，
写 Python AST 规则就是在猜。正确顺序：
  1) auditkit profile <path>   → 落 projects/doubao-butler/adapter/profile_cache.json
  2) 按真实语言选择规则形态（static_ast / cross_lang_text）
  3) 规则写在本包内，applies_to = ["doubao-butler"]，自带 dirty/clean 样本
"""
PROJECT = "doubao-butler"
KNOWN_LANGUAGES = []   # 待 profile 探测后填写
RULES = []             # 当前无可加载规则
