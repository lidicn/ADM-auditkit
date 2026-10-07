#!/usr/bin/env python3
"""通用规则库（对所有项目生效：applies_to = []）。

新增规则的两种方式：
  1. YAML 声明式（首选）：放一个 *.yaml，字段见 rules/generic/py_dynamic_code_exec.yaml
  2. Python 插件式（复杂逻辑）：BaseRule 子类，参考 example_rule.py

规则自带 dirty/clean 样本，`auditkit rules test <id>` 可单独验证；
加载器在装入时自动跑样本，不通过的规则标 broken，不参与审计。
"""
