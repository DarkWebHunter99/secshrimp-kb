#!/usr/bin/env python3
"""
Purpose: MCP (Model Context Protocol) 工具安全审计脚本
         审计 MCP Server 的工具定义、权限配置、输入验证、数据流安全
Auth: 仅限授权使用 — 仅对自有/已授权的 MCP Server 进行安全评估
Dependencies: requests, json, re
Usage:
    python mcp_tool_audit.py --server http://localhost:3000 --audit-all
    python mcp_tool_audit.py --config mcp_server.json --audit-permissions
    python mcp_tool_audit.py --tools-file tools.json --output report.json
"""

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

import requests


class AuditCategory(Enum):
    """审计类别"""
    INPUT_VALIDATION = "input_validation"       # 输入验证
    PERMISSION_MODEL = "permission_model"       # 权限模型
    DATA_FLOW = "data_flow"                     # 数据流安全
    INJECTION_DEFENSE = "injection_defense"     # 注入防御
    PRIVILEGE_CONTROL = "privilege_control"     # 权限控制
    ERROR_HANDLING = "error_handling"           # 错误处理
    LOGGING_AUDIT = "logging_audit"             # 日志审计
    SANDBOX_ISOLATION = "sandbox_isolation"     # 沙箱隔离


class Severity(Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AuditFinding:
    """审计发现"""
    category: AuditCategory
    severity: Severity
    title: str
    description: str
    tool_name: Optional[str] = None
    parameter: Optional[str] = None
    evidence: str = ""
    recommendation: str = ""
    owasp_llm: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None


@dataclass
class MCPToolDefinition:
    """MCP 工具定义"""
    name: str
    description: str
    input_schema: Dict[str, Any] = field(default_factory=dict)
    required_params: List[str] = field(default_factory=list)
    optional_params: List[str] = field(default_factory=list)
    annotations: Dict[str, Any] = field(default_factory=dict)
    server_name: str = ""


@dataclass
class AuditConfig:
    """审计配置"""
    server_url: Optional[str] = None
    config_path: Optional[str] = None
    tools_file: Optional[str] = None
    timeout: int = 15
    test_injection: bool = True
    test_permissions: bool = True
    test_data_flow: bool = True
    test_error_handling: bool = True


# ============================================================
# 审计规则数据库
# ============================================================

# 高风险参数模式
HIGH_RISK_PARAM_PATTERNS = {
    "file_path": {
        "patterns": [r"path", r"file", r"filename", r"directory", r"folder", r"dir"],
        "risks": ["路径遍历", "任意文件读写", "敏感文件泄露"],
        "severity": Severity.HIGH,
        "cwe": "CWE-22",
    },
    "command": {
        "patterns": [r"command", r"cmd", r"exec", r"shell", r"script", r"run"],
        "risks": ["命令注入", "任意代码执行", "沙箱逃逸"],
        "severity": Severity.CRITICAL,
        "cwe": "CWE-78",
    },
    "url": {
        "patterns": [r"url", r"endpoint", r"host", r"server", r"address", r"uri"],
        "risks": ["SSRF", "数据外泄", "恶意下载"],
        "severity": Severity.HIGH,
        "cwe": "CWE-918",
    },
    "query": {
        "patterns": [r"query", r"sql", r"search", r"filter", r"where"],
        "risks": ["SQL 注入", "NoSQL 注入", "数据泄露"],
        "severity": Severity.HIGH,
        "cwe": "CWE-89",
    },
    "template": {
        "patterns": [r"template", r"format", r"pattern", r"layout"],
        "risks": ["SSTI", "模板注入", "信息泄露"],
        "severity": Severity.HIGH,
        "cwe": "CWE-1336",
    },
    "data": {
        "patterns": [r"data", r"body", r"content", r"payload", r"input"],
        "risks": ["数据注入", "XSS", "序列化攻击"],
        "severity": Severity.MEDIUM,
        "cwe": "CWE-20",
    },
    "credential": {
        "patterns": [r"token", r"key", r"secret", r"password", r"auth", r"credential"],
        "risks": ["凭据泄露", "认证绕过", "密钥暴露"],
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
}

# 工具链风险模式
TOOL_CHAIN_RISKS = [
    {
        "name": "文件读取 + 网络请求",
        "tools": ["file", "http", "fetch", "request", "url"],
        "risk": "通过文件读取获取敏感数据后通过 HTTP 外泄",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "数据库 + 网络请求",
        "tools": ["database", "sql", "query", "http", "fetch"],
        "risk": "数据库查询结果通过网络外泄",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "命令执行 + 文件读取",
        "tools": ["exec", "shell", "command", "file", "read"],
        "risk": "命令执行结果通过文件读取泄露",
        "severity": Severity.CRITICAL,
    },
    {
        "name": "文件读取 + 邮件",
        "tools": ["file", "read", "email", "mail", "smtp"],
        "risk": "文件内容通过邮件外泄",
        "severity": Severity.HIGH,
    },
    {
        "name": "数据库 + 邮件",
        "tools": ["database", "sql", "email", "mail"],
        "risk": "数据库数据通过邮件外泄",
        "severity": Severity.HIGH,
    },
]

# 注入测试 payload
INJECTION_PAYLOADS = [
    {
        "name": "path_traversal",
        "param_type": "file_path",
        "payloads": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "~/.ssh/id_rsa",
            "C:\\Users\\*\\.ssh\\id_rsa",
        ],
        "indicators": ["root:", "[boot loader]", "-----BEGIN", "ssh-rsa"],
    },
    {
        "name": "command_injection",
        "param_type": "command",
        "payloads": [
            "id",
            "whoami",
            "cat /etc/passwd",
            "| ls -la",
            "; net user",
            "`id`",
            "$(whoami)",
        ],
        "indicators": ["uid=", "root", "admin", "Administrator"],
    },
    {
        "name": "ssrf",
        "param_type": "url",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:3306",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_PING",
        ],
        "indicators": ["ami-id", "instance-id", "redis_version", "mysql"],
    },
    {
        "name": "sql_injection",
        "param_type": "query",
        "payloads": [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users;--",
            "1' AND 1=1--",
        ],
        "indicators": ["syntax error", "mysql", "postgresql", "sqlite"],
    },
    {
        "name": "template_injection",
        "param_type": "template",
        "payloads": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "{{config}}",
            "{{self.__class__.__mro__[1].__subclasses__()}}",
        ],
        "indicators": ["49", "SECRET", "password", "__class__"],
    },
]


class MCPToolAuditor:
    """MCP 工具安全审计器"""

    def __init__(self, config: AuditConfig):
        self.config = config
        self.findings: List[AuditFinding] = []
        self.tools: List[MCPToolDefinition] = []

    def audit(self) -> List[AuditFinding]:
        """执行完整审计流程"""
        logging.info("[*] 开始 MCP 工具安全审计")

        # 1. 加载工具定义
        self._load_tools()

        if not self.tools:
            logging.error("[!] 未发现 MCP 工具，审计终止")
            return self.findings

        logging.info(f"[*] 发现 {len(self.tools)} 个 MCP 工具")

        # 2. 工具元数据审计
        self._audit_tool_metadata()

        # 3. 输入验证审计
        self._audit_input_validation()

        # 4. 权限模型审计
        if self.config.test_permissions:
            self._audit_permission_model()

        # 5. 数据流审计
        if self.config.test_data_flow:
            self._audit_data_flow()

        # 6. 注入防御审计
        if self.config.test_injection:
            self._audit_injection_defense()

        # 7. 错误处理审计
        if self.config.test_error_handling:
            self._audit_error_handling()

        # 8. 工具链风险评估
        self._audit_tool_chain()

        # 9. 日志审计能力评估
        self._audit_logging()

        logging.info(f"[*] 审计完成，发现 {len(self.findings)} 个安全问题")
        return self.findings

    def _load_tools(self):
        """加载 MCP 工具定义"""
        # 方法1: 从配置文件加载
        if self.config.config_path:
            self._load_from_config()
            return

        # 方法2: 从工具文件加载
        if self.config.tools_file:
            self._load_from_file()
            return

        # 方法3: 从 MCP Server API 加载
        if self.config.server_url:
            self._load_from_server()

    def _load_from_config(self):
        """从 MCP Server 配置文件加载"""
        try:
            with open(self.config.config_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            # MCP Server 配置格式
            servers = config.get("mcpServers", config.get("servers", {}))
            for server_name, server_config in servers.items():
                tools = server_config.get("tools", [])
                for tool in tools:
                    self.tools.append(MCPToolDefinition(
                        name=tool.get("name", "unknown"),
                        description=tool.get("description", ""),
                        input_schema=tool.get("inputSchema", {}),
                        required_params=tool.get("inputSchema", {}).get("required", []),
                        optional_params=[
                            p for p in tool.get("inputSchema", {}).get("properties", {}).keys()
                            if p not in tool.get("inputSchema", {}).get("required", [])
                        ],
                        annotations=tool.get("annotations", {}),
                        server_name=server_name,
                    ))

            logging.info(f"[+] 从配置加载 {len(self.tools)} 个工具")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(f"[!] 配置加载失败: {e}")

    def _load_from_file(self):
        """从工具定义文件加载"""
        try:
            with open(self.config.tools_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            tools_list = data if isinstance(data, list) else data.get("tools", [])
            for tool in tools_list:
                self.tools.append(MCPToolDefinition(
                    name=tool.get("name", "unknown"),
                    description=tool.get("description", ""),
                    input_schema=tool.get("inputSchema", tool.get("input_schema", {})),
                    required_params=tool.get("inputSchema", {}).get("required", []),
                    annotations=tool.get("annotations", {}),
                ))

            logging.info(f"[+] 从文件加载 {len(self.tools)} 个工具")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(f"[!] 文件加载失败: {e}")

    def _load_from_server(self):
        """从 MCP Server API 加载"""
        try:
            # MCP 协议: tools/list 请求
            resp = requests.post(
                self.config.server_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                },
                timeout=self.config.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                tools = data.get("result", {}).get("tools", [])
                for tool in tools:
                    self.tools.append(MCPToolDefinition(
                        name=tool.get("name", "unknown"),
                        description=tool.get("description", ""),
                        input_schema=tool.get("inputSchema", {}),
                        required_params=tool.get("inputSchema", {}).get("required", []),
                        annotations=tool.get("annotations", {}),
                    ))
                logging.info(f"[+] 从 Server 加载 {len(self.tools)} 个工具")
            else:
                logging.warning(f"[-] Server 返回状态码: {resp.status_code}")
        except requests.RequestException as e:
            logging.error(f"[!] Server 连接失败: {e}")

    def _audit_tool_metadata(self):
        """审计工具元数据"""
        logging.info("[*] 审计工具元数据...")

        for tool in self.tools:
            # 检查描述是否足够详细
            if len(tool.description) < 20:
                self.findings.append(AuditFinding(
                    category=AuditCategory.LOGGING_AUDIT,
                    severity=Severity.LOW,
                    title=f"工具描述不充分: {tool.name}",
                    description=f"工具 '{tool.name}' 的描述过短（{len(tool.description)} 字符），不利于安全评估",
                    tool_name=tool.name,
                    evidence=f"描述: {tool.description}",
                    recommendation="提供详细的工具描述，包括功能、参数说明、安全注意事项",
                ))

            # 检查是否有安全注解
            if not tool.annotations:
                self.findings.append(AuditFinding(
                    category=AuditCategory.PERMISSION_MODEL,
                    severity=Severity.MEDIUM,
                    title=f"缺少安全注解: {tool.name}",
                    description=f"工具 '{tool.name}' 未定义安全注解（readOnlyHint/destructiveHint/idempotentHint）",
                    tool_name=tool.name,
                    recommendation="添加 MCP 安全注解，明确工具的读写属性和幂等性",
                    owasp_llm=["LLM06"],
                ))

            # 检查 readOnlyHint
            annotations = tool.annotations
            if annotations.get("readOnlyHint") is None:
                self.findings.append(AuditFinding(
                    category=AuditCategory.PERMISSION_MODEL,
                    severity=Severity.LOW,
                    title=f"缺少 readOnlyHint: {tool.name}",
                    description=f"工具 '{tool.name}' 未声明是否为只读操作",
                    tool_name=tool.name,
                    recommendation="设置 readOnlyHint=true/false，帮助 Agent 判断工具安全性",
                ))

    def _audit_input_validation(self):
        """审计输入验证"""
        logging.info("[*] 审计输入验证...")

        for tool in self.tools:
            schema = tool.input_schema
            properties = schema.get("properties", {})

            if not properties:
                self.findings.append(AuditFinding(
                    category=AuditCategory.INPUT_VALIDATION,
                    severity=Severity.HIGH,
                    title=f"缺少输入 Schema: {tool.name}",
                    description=f"工具 '{tool.name}' 未定义输入参数 Schema",
                    tool_name=tool.name,
                    recommendation="定义完整的 JSON Schema，包括类型、格式、范围、正则约束",
                    owasp_llm=["LLM01"],
                    cwe_id="CWE-20",
                ))
                continue

            # 检查每个参数的验证规则
            for param_name, param_def in properties.items():
                # 检查是否有类型定义
                if "type" not in param_def:
                    self.findings.append(AuditFinding(
                        category=AuditCategory.INPUT_VALIDATION,
                        severity=Severity.MEDIUM,
                        title=f"参数缺少类型: {tool.name}.{param_name}",
                        description=f"参数 '{param_name}' 未定义类型",
                        tool_name=tool.name,
                        parameter=param_name,
                        recommendation="为参数添加 type 定义",
                    ))

                # 检查高风险参数
                for risk_type, risk_info in HIGH_RISK_PARAM_PATTERNS.items():
                    for pattern in risk_info["patterns"]:
                        if re.search(pattern, param_name, re.IGNORECASE):
                            # 检查是否有足够的验证
                            has_validation = any(
                                k in param_def
                                for k in ["pattern", "enum", "minimum", "maximum", "minLength", "maxLength", "format"]
                            )

                            if not has_validation:
                                self.findings.append(AuditFinding(
                                    category=AuditCategory.INPUT_VALIDATION,
                                    severity=risk_info["severity"],
                                    title=f"高风险参数缺少验证: {tool.name}.{param_name}",
                                    description=f"参数 '{param_name}' 匹配高风险模式 '{risk_type}'，但缺少验证规则",
                                    tool_name=tool.name,
                                    parameter=param_name,
                                    evidence=f"风险: {', '.join(risk_info['risks'])}",
                                    recommendation=f"添加 pattern/enum/format 等验证规则，防御 {risk_type}",
                                    owasp_llm=["LLM01"],
                                    cwe_id=risk_info["cwe"],
                                ))
                            break  # 每个参数只报一次

    def _audit_permission_model(self):
        """审计权限模型"""
        logging.info("[*] 审计权限模型...")

        # 统计高风险工具数量
        high_risk_count = 0
        for tool in self.tools:
            desc_lower = tool.description.lower()
            name_lower = tool.name.lower()
            combined = f"{desc_lower} {name_lower}"

            high_risk_keywords = ["exec", "shell", "command", "write", "delete", "file", "database", "admin"]
            if any(kw in combined for kw in high_risk_keywords):
                high_risk_count += 1

        if high_risk_count > len(self.tools) * 0.5:
            self.findings.append(AuditFinding(
                category=AuditCategory.PERMISSION_MODEL,
                severity=Severity.HIGH,
                title="高风险工具比例过高",
                description=f"超过 50% 的工具具有高风险特征（{high_risk_count}/{len(self.tools)}）",
                evidence=f"高风险工具: {high_risk_count}, 总工具: {len(self.tools)}",
                recommendation="1. 最小权限原则 2. 工具分级管理 3. 高风险工具需要人工确认",
                owasp_llm=["LLM06"],
            ))

        # 检查是否有权限控制机制
        for tool in self.tools:
            if not tool.annotations.get("requiresConfirmation"):
                desc_lower = tool.description.lower()
                if any(kw in desc_lower for kw in ["delete", "drop", "remove", "execute", "write"]):
                    self.findings.append(AuditFinding(
                        category=AuditCategory.PERMISSION_MODEL,
                        severity=Severity.HIGH,
                        title=f"危险操作无需确认: {tool.name}",
                        description=f"工具 '{tool.name}' 执行危险操作但未要求确认",
                        tool_name=tool.name,
                        recommendation="添加 requiresConfirmation=true 注解",
                        owasp_llm=["LLM06"],
                    ))

    def _audit_data_flow(self):
        """审计数据流安全"""
        logging.info("[*] 审计数据流...")

        # 检查工具是否可能处理敏感数据
        for tool in self.tools:
            desc_lower = tool.description.lower()
            name_lower = tool.name.lower()
            params_str = json.dumps(tool.input_schema).lower()

            sensitive_patterns = [
                (r"password|secret|token|key|credential", "凭据"),
                (r"email|mail|phone|address", "个人信息"),
                (r"credit.?card|ssn|social.?security", "财务/身份信息"),
                (r"api.?key|access.?token|bearer", "API 凭据"),
            ]

            for pattern, data_type in sensitive_patterns:
                if re.search(pattern, f"{desc_lower} {name_lower} {params_str}"):
                    self.findings.append(AuditFinding(
                        category=AuditCategory.DATA_FLOW,
                        severity=Severity.MEDIUM,
                        title=f"敏感数据处理: {tool.name}",
                        description=f"工具 '{tool.name}' 可能处理{data_type}",
                        tool_name=tool.name,
                        evidence=f"匹配模式: {pattern}",
                        recommendation="1. 数据脱敏 2. 访问控制 3. 审计日志 4. 输出过滤",
                        owasp_llm=["LLM06"],
                    ))
                    break

    def _audit_injection_defense(self):
        """审计注入防御"""
        logging.info("[*] 审计注入防御...")

        for tool in self.tools:
            schema = tool.input_schema
            properties = schema.get("properties", {})

            for param_name, param_def in properties.items():
                # 检查参数类型
                param_type = param_def.get("type")

                # 检查是否有注入防御
                for injection in INJECTION_PAYLOADS:
                    # 匹配参数类型
                    param_matches = False
                    for risk_type, risk_info in HIGH_RISK_PARAM_PATTERNS.items():
                        if injection["param_type"] == risk_type:
                            for pattern in risk_info["patterns"]:
                                if re.search(pattern, param_name, re.IGNORECASE):
                                    param_matches = True
                                    break
                            break

                    if not param_matches:
                        continue

                    # 检查是否有防御措施
                    has_defense = any(
                        k in param_def
                        for k in ["pattern", "enum", "format", "minLength", "maxLength"]
                    )

                    if not has_defense:
                        self.findings.append(AuditFinding(
                            category=AuditCategory.INJECTION_DEFENSE,
                            severity=Severity.HIGH,
                            title=f"注入防御不足: {tool.name}.{param_name}",
                            description=f"参数 '{param_name}' 可能受 {injection['name']} 攻击，但缺少防御",
                            tool_name=tool.name,
                            parameter=param_name,
                            evidence=f"攻击类型: {injection['name']}",
                            recommendation=f"添加 pattern/enum/format 验证，防御 {injection['name']}",
                            owasp_llm=["LLM01"],
                        ))
                        break  # 每个参数只报一次

    def _audit_error_handling(self):
        """审计错误处理"""
        logging.info("[*] 审计错误处理...")

        # 检查工具是否有错误处理注解
        for tool in self.tools:
            if not tool.annotations.get("errorHandling"):
                self.findings.append(AuditFinding(
                    category=AuditCategory.ERROR_HANDLING,
                    severity=Severity.LOW,
                    title=f"缺少错误处理声明: {tool.name}",
                    description=f"工具 '{tool.name}' 未声明错误处理策略",
                    tool_name=tool.name,
                    recommendation="添加 errorHandling 注解，说明错误类型和处理方式",
                ))

    def _audit_tool_chain(self):
        """审计工具链风险"""
        logging.info("[*] 审计工具链风险...")

        tool_names = [t.name.lower() for t in self.tools]
        tool_descs = [t.description.lower() for t in self.tools]
        all_text = " ".join(tool_names + tool_descs)

        for chain in TOOL_CHAIN_RISKS:
            matches = []
            for keyword in chain["tools"]:
                if keyword in all_text:
                    matches.append(keyword)

            if len(matches) >= 2:  # 至少匹配 2 个关键词
                self.findings.append(AuditFinding(
                    category=AuditCategory.PRIVILEGE_CONTROL,
                    severity=chain["severity"],
                    title=f"工具链风险: {chain['name']}",
                    description=f"检测到工具链风险: {chain['risk']}",
                    evidence=f"匹配关键词: {', '.join(matches)}",
                    recommendation="1. 工具调用序列审计 2. 异常检测 3. 数据流控制 4. 最小权限",
                    owasp_llm=["LLM01", "LLM06"],
                ))

    def _audit_logging(self):
        """审计日志能力"""
        logging.info("[*] 审计日志能力...")

        has_logging = any(
            "log" in t.description.lower() or "audit" in t.description.lower()
            for t in self.tools
        )

        if not has_logging:
            self.findings.append(AuditFinding(
                category=AuditCategory.LOGGING_AUDIT,
                severity=Severity.MEDIUM,
                title="缺少审计日志工具",
                description="MCP Server 未提供审计日志相关工具",
                recommendation="添加审计日志工具，记录工具调用历史和安全事件",
                owasp_llm=["LLM06"],
            ))

    # ----------------------------------------------------------
    # 输出方法
    # ----------------------------------------------------------

    def print_results(self):
        """格式化输出审计结果"""
        if not self.findings:
            print("\n[-] 未发现安全问题")
            return

        print(f"\n{'='*60}")
        print("  MCP 工具安全审计报告")
        print(f"{'='*60}")

        severity_icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }

        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order[f.severity])

        for i, f in enumerate(sorted_findings, 1):
            icon = severity_icons[f.severity]
            print(f"\n  {icon} [{f.severity.value.upper()}] {f.title}")
            print(f"  类别: {f.category.value}")
            print(f"  描述: {f.description}")
            if f.tool_name:
                print(f"  工具: {f.tool_name}")
            if f.parameter:
                print(f"  参数: {f.parameter}")
            if f.evidence:
                print(f"  证据: {f.evidence[:150]}")
            if f.recommendation:
                print(f"  修复: {f.recommendation}")
            if f.owasp_llm:
                print(f"  OWASP: {', '.join(f.owasp_llm)}")
            if f.cwe_id:
                print(f"  CWE: {f.cwe_id}")

        summary = {}
        for f in self.findings:
            summary[f.severity.value] = summary.get(f.severity.value, 0) + 1

        print(f"\n{'='*60}")
        print(f"  总计: {len(self.findings)} 个安全问题")
        for sev, count in sorted(summary.items()):
            print(f"  {severity_icons[Severity(sev)]} {sev.upper()}: {count}")
        print(f"{'='*60}")

    def export_json(self, filepath: str):
        """导出 JSON 报告"""
        data = {
            "total_tools": len(self.tools),
            "total_findings": len(self.findings),
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "server": t.server_name,
                    "required_params": t.required_params,
                }
                for t in self.tools
            ],
            "findings": [
                {
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "tool_name": f.tool_name,
                    "parameter": f.parameter,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "owasp_llm": f.owasp_llm,
                    "cwe_id": f.cwe_id,
                }
                for f in self.findings
            ],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logging.info(f"[+] JSON 报告已导出: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="MCP 工具安全审计脚本（仅限授权使用）",
        epilog="⚠️  仅对自有或已授权的 MCP Server 进行安全评估"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--server", help="MCP Server URL")
    group.add_argument("--config", help="MCP Server 配置文件路径")
    group.add_argument("--tools-file", help="工具定义文件路径 (JSON)")

    parser.add_argument("--audit-all", action="store_true", help="执行全部审计")
    parser.add_argument("--audit-permissions", action="store_true", help="仅审计权限模型")
    parser.add_argument("--audit-input", action="store_true", help="仅审计输入验证")
    parser.add_argument("--audit-injection", action="store_true", help="仅审计注入防御")
    parser.add_argument("-o", "--output", help="输出 JSON 报告路径")

    args = parser.parse_args()

    print("⚠️  请确认你已获得目标 MCP Server 的测试授权")
    confirm = input("确认已获授权？(y/N): ")
    if confirm.lower() != "y":
        sys.exit(0)

    config = AuditConfig(
        server_url=args.server,
        config_path=args.config,
        tools_file=args.tools_file,
        test_injection=args.audit_all or args.audit_injection,
        test_permissions=args.audit_all or args.audit_permissions,
        test_data_flow=args.audit_all,
        test_error_handling=args.audit_all,
    )

    auditor = MCPToolAuditor(config)
    findings = auditor.audit()
    auditor.print_results()

    if args.output:
        auditor.export_json(args.output)


if __name__ == "__main__":
    main()
