#!/usr/bin/env python3
"""规则：凭据类环境变量带字面量默认值（密钥烧进源码）。

**来源**：2026-10-12 十项目批量审计（R1 基线轮）跨项目凭据排查确证。
- `DeskPilot/backend/api/v1/butler.py:41` 与 `backend/modules/llm_client.py:24`
  同为 `os.environ.get("BUTLER_WEB_PASSWORD", "e32xl1Pm1gMteXBjuXTM")` ——
  管家生产口令作为**兜底默认值**写进源码，环境未注入时以明文口令静默上岗。
- `DeskPilot/config/deskpilot.yaml:33,65` 明文默认令牌，同一串在 doubao-butler
  的交接文档里被当作跨项目 Bearer 使用 → **一处泄露，两个项目沦陷**。

**为什么是缺陷**：这类写法的危害比直接硬编码更隐蔽——评审时看到的是
`os.environ.get(...)`，会认为是"已环境化"；但默认值让"未配置"这个最常见的
部署状态**静默走明文口令**，既不报错也不告警。跨项目复用同一默认串时，
轮换任何一个项目的密钥都需要改两处代码、发两个版本。

**判据局部性**：只判"环境变量名含凭据语义 + 默认值是非占位符字面量"。
不判该密钥是否真的泄露、不判强度、不判是否已在 git 历史里。

**降噪**：默认值命中占位词表（change/your/xxx/placeholder/...）或为空串、
长度 < 8 时放行——这些是模板占位，不是真凭据。
"""
from __future__ import annotations

import ast
import re

from engine.base import BaseRule, Finding, node_source
from engine.helpers import call_full

_CRED_RE = re.compile(
    r"(TOKEN|PASSWORD|PASSWD|SECRET|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|"
    r"AUTH|WEBHOOK_?SECRET|SIGNING_?KEY|SALT)",
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(
    r"(change|changeme|your_|your-|xxx|placeholder|dummy|example|todo|fixme|"
    r"replace_me|sample|fake|dummy_value|<)",
    re.IGNORECASE,
)
_READERS = {"os.getenv", "os.environ.get", "os.environ.setdefault"}
# 环境变量名以这些后缀结尾时，默认值是**路径**不是凭据（AutoForge af_secrets.py:31
# `os.environ.get("AUTOFORGE_SECRET_DIR", "/run/secrets")` 曾误报，已据此加排除）。
_PATH_SUFFIX_RE = re.compile(r"_(DIR|DIRS|PATH|PATHS|FILE|FILES|ROOT|HOME|FOLDER|MOUNT)$",
                             re.IGNORECASE)
_PATH_DEFAULT_PREFIX = ("/", "./", "../", "~/", "\\", ".\\", "..\\")


class EnvCredentialDefaultRule(BaseRule):
    id = "py.env_credential_default"
    name = "凭据类环境变量带字面量默认值"
    description = (
        "凭据语义的环境变量在 os.getenv/environ.get 里带非空、非占位符的字面量默认值；"
        "环境未注入时以明文密钥静默上岗，跨项目复用同一串时轮换需改多处。"
    )
    applies_to: list[str] = []
    mode = "static_ast"
    severity = "high"
    status = "active"
    version = "1.0.0"
    intent = "discovery"

    tests = {
        "dirty": [
            {"name": "token-with-real-default",
             "code": "import os\n\nBUTLER_TOKEN = os.environ.get(\"BUTLER_WEB_PASSWORD\", \"e32xl1Pm1gMteXBjuXTM\")\n"},
            {"name": "api-key-with-default",
             "code": "import os\n\nKEY = os.getenv(\"MA_API_KEY\", \"app_uH2CtN-bCqigHHNpHFS98OcVWWNV03r\")\n"},
        ],
        "clean": [
            {"name": "empty-default",
             "code": "import os\n\nTOKEN = os.getenv(\"BUTLER_TOKEN\", \"\")\n"},
            {"name": "placeholder-default",
             "code": "import os\n\nTOKEN = os.getenv(\"BUTLER_TOKEN\", \"change_me_please\")\n"},
            {"name": "non-credential-env",
             "code": "import os\n\nLEVEL = os.getenv(\"LOG_LEVEL\", \"INFO\")\n"},
            {"name": "secret-dir-is-a-path",
             "code": "import os\n\nBASE = os.environ.get(\"AUTOFORGE_SECRET_DIR\", \"/run/secrets\")\n"},
        ],
    }

    def run(self, tree, profile=None, adapter=None) -> list[Finding]:
        # AST 契约：parse_unit 返回附着 source/path 的 ast.Module，没有 .ast 属性。
        # 直接 tree.ast 会 AttributeError；此处兼容两种形态，避免静默失效。
        root = getattr(tree, "ast", tree)
        out: list[Finding] = []
        nodes = list(ast.walk(root))

        for node in nodes:
            if not isinstance(node, ast.Call) or len(node.args) < 2:
                continue
            if call_full(node) not in _READERS:
                continue
            name_node, default_node = node.args[0], node.args[1]

            if not (isinstance(name_node, ast.Constant) and isinstance(name_node.value, str)):
                continue
            if not _CRED_RE.search(name_node.value):
                continue
            if _PATH_SUFFIX_RE.search(name_node.value):
                continue          # SECRET_DIR/KEY_PATH 之类：默认值是路径
            if not (isinstance(default_node, ast.Constant) and isinstance(default_node.value, str)):
                continue

            default = default_node.value
            if not default or len(default) < 8 or _PLACEHOLDER_RE.search(default):
                continue
            if default.startswith(_PATH_DEFAULT_PREFIX):
                continue          # 默认值是文件系统路径

            out.append(Finding(
                rule_id=self.id,
                file=str(tree.path),
                line=node.lineno,
                severity=self.severity,
                title=self.name,
                detail=(f"环境变量 `{name_node.value}` 带字面量默认值"
                        f"（长度 {len(default)}），环境未注入时明文密钥静默生效"),
                evidence=node_source(tree, node)[:200],
            ))
        return out
