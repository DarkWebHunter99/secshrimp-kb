#!/usr/bin/env python3
"""
Purpose: Elasticsearch 检测查询构建器
         将 Sigma 规则和自定义规则转换为 Elasticsearch DSL 查询
         支持：Sigma → ES 转换、查询优化、模板管理、批量查询构建
Auth: 仅限授权使用 — 仅用于安全检测和日志分析
Dependencies: pyyaml, json
Usage:
    python elastic_query_builder.py --sigma rules/suspicious_powershell.yml --output query.json
    python elastic_query_builder.py --query-type process_creation --event-id 4688 --output query.json
    python elastic_query_builder.py --batch --sigma-dir rules/ --output-dir queries/
"""

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

try:
    import yaml
except ImportError:
    yaml = None


class QueryType(Enum):
    """查询类型"""
    PROCESS_CREATION = "process_creation"
    NETWORK_CONNECTION = "network_connection"
    FILE_MODIFICATION = "file_modification"
    REGISTRY_MODIFICATION = "registry_modification"
    LOGON_EVENT = "logon_event"
    POWERSHELL = "powershell"
    WMI = "wmi"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE_INSTALL = "service_install"
    DNS_QUERY = "dns_query"
    GENERIC = "generic"


class Severity(Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DetectionRule:
    """检测规则定义"""
    title: str
    id: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    tags: List[str] = field(default_factory=list)
    logsource: Dict[str, str] = field(default_factory=dict)
    detection: Dict[str, Any] = field(default_factory=dict)
    falsepositives: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class ESQuery:
    """Elasticsearch 查询"""
    query: Dict[str, Any]
    title: str = ""
    description: str = ""
    severity: str = ""
    tags: List[str] = field(default_factory=list)
    index: str = "winlogbeat-*"  # 默认索引


# ============================================================
# 字段映射（Sigma → Elasticsearch/Winlogbeat）
# ============================================================

# Winlogbeat 字段映射
FIELD_MAPPINGS = {
    # Windows 事件字段
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "User": "winlog.event_data.SubjectUserName",
    "TargetUserName": "winlog.event_data.TargetUserName",
    "TargetDomainName": "winlog.event_data.TargetDomainName",
    "LogonType": "winlog.event_data.LogonType",
    "IpAddress": "winlog.event_data.IpAddress",
    "IpPort": "winlog.event_data.IpPort",
    "WorkstationName": "winlog.event_data.WorkstationName",
    "SubjectUserName": "winlog.event_data.SubjectUserName",
    "SubjectDomainName": "winlog.event_data.SubjectDomainName",
    "ProcessId": "winlog.event_data.ProcessId",
    "NewProcessId": "winlog.event_data.NewProcessId",
    "NewProcessName": "winlog.event_data.NewProcessName",
    "TargetFilename": "winlog.event_data.TargetFilename",
    "Hashes": "winlog.event_data.Hashes",
    "ScriptBlockText": "winlog.event_data.ScriptBlockText",
    "Message": "winlog.event_data.Message",
    "EventID": "winlog.event_id",
    "Channel": "winlog.channel",
    "Provider": "winlog.provider",

    # Sysmon 字段
    "DestinationPort": "destination.port",
    "DestinationHostname": "destination.domain",
    "DestinationIp": "destination.ip",
    "SourceIp": "source.ip",
    "SourcePort": "source.port",
    "Initiated": "winlog.event_data.Initiated",
    "RuleName": "winlog.event_data.RuleName",

    # 通用字段
    "ComputerName": "winlog.computer_name",
    "TimeCreated": "@timestamp",
}

# 索引模式映射
INDEX_MAPPINGS = {
    "windows": "winlogbeat-*",
    "process_creation": "winlogbeat-*",
    "network_connection": "winlogbeat-*",
    "file_event": "winlogbeat-*",
    "registry_event": "winlogbeat-*",
    "sysmon": "winlogbeat-*",
    "security": "winlogbeat-*",
    "powershell": "winlogbeat-*",
    "linux": "filebeat-*",
    "web": "filebeat-*",
    "proxy": "filebeat-*",
    "firewall": "filebeat-*",
    "dns": "filebeat-*",
}


# ============================================================
# 查询构建器核心
# ============================================================

class ElasticQueryBuilder:
    """Elasticsearch 查询构建器"""

    def __init__(self):
        self.queries: List[ESQuery] = []

    def build_from_sigma(self, sigma_path: str) -> Optional[ESQuery]:
        """从 Sigma 规则文件构建 ES 查询"""
        if yaml is None:
            logging.error("[!] 需要安装 pyyaml: pip install pyyaml")
            return None

        try:
            with open(sigma_path, "r", encoding="utf-8") as f:
                sigma = yaml.safe_load(f)
        except (FileNotFoundError, yaml.YAMLError) as e:
            logging.error(f"[!] Sigma 规则加载失败: {e}")
            return None

        rule = DetectionRule(
            title=sigma.get("title", "Unknown"),
            id=sigma.get("id", ""),
            description=sigma.get("description", ""),
            severity=Severity(sigma.get("level", "medium")),
            tags=sigma.get("tags", []),
            logsource=sigma.get("logsource", {}),
            detection=sigma.get("detection", {}),
            falsepositives=sigma.get("falsepositives", []),
            references=sigma.get("references", []),
        )

        return self._convert_sigma_to_es(rule)

    def build_from_params(self, query_type: str, **kwargs) -> ESQuery:
        """从参数构建查询"""
        qtype = QueryType(query_type) if query_type in [e.value for e in QueryType] else QueryType.GENERIC

        if qtype == QueryType.PROCESS_CREATION:
            return self._build_process_creation_query(**kwargs)
        elif qtype == QueryType.NETWORK_CONNECTION:
            return self._build_network_query(**kwargs)
        elif qtype == QueryType.POWERSHELL:
            return self._build_powershell_query(**kwargs)
        elif qtype == QueryType.LOGON_EVENT:
            return self._build_logon_query(**kwargs)
        else:
            return self._build_generic_query(**kwargs)

    def build_from_template(self, template_name: str, **kwargs) -> ESQuery:
        """从预定义模板构建查询"""
        templates = {
            # --- 进程执行检测 ---
            "suspicious_process": self._build_suspicious_process_query,
            "encoded_powershell": self._build_encoded_powershell_query,
            "process_injection": self._build_process_injection_query,
            "lateral_movement_psexec": self._build_psexec_query,
            "credential_dumping": self._build_credential_dump_query,

            # --- 网络检测 ---
            "suspicious_dns": self._build_suspicious_dns_query,
            "c2_communication": self._build_c2_communication_query,
            "data_exfiltration": self._build_data_exfil_query,
            "port_scanning": self._build_port_scan_query,

            # --- 持久化检测 ---
            "scheduled_task_creation": self._build_scheduled_task_query,
            "service_installation": self._build_service_install_query,
            "registry_persistence": self._build_registry_persistence_query,
            "wmi_persistence": self._build_wmi_persistence_query,

            # --- 权限提升 ---
            "uac_bypass": self._build_uac_bypass_query,
            "token_manipulation": self._build_token_manipulation_query,
        }

        builder = templates.get(template_name)
        if builder:
            return builder(**kwargs)
        else:
            logging.error(f"[!] 未知模板: {template_name}")
            return self._build_generic_query(**kwargs)

    # ----------------------------------------------------------
    # Sigma → ES 转换
    # ----------------------------------------------------------

    def _convert_sigma_to_es(self, rule: DetectionRule) -> ESQuery:
        """将 Sigma 规则转换为 ES 查询"""
        conditions = rule.detection.get("condition", "")
        selection = rule.detection.get("selection", {})
        filters = {k: v for k, v in rule.detection.items() if k.startswith("filter")}

        # 构建 selection 查询
        selection_query = self._convert_selection(selection)

        # 构建 filter 查询
        filter_queries = []
        for filter_name, filter_data in filters.items():
            filter_queries.append(self._convert_selection(filter_data))

        # 组合查询
        must_clauses = [selection_query]
        must_not_clauses = filter_queries

        # 解析 condition 字符串
        if "not" in conditions.lower():
            # 包含排除条件
            query = {
                "bool": {
                    "must": must_clauses,
                    "must_not": must_not_clauses
                }
            }
        else:
            query = {"bool": {"must": must_clauses}}

        # 包装为 ES 查询
        es_query = {
            "query": query,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 100,
            "_source": ["@timestamp", "winlog.event_id", "winlog.channel",
                        "process.executable", "process.command_line",
                        "winlog.event_data.*"],
        }

        # 确定索引
        logsource = rule.logsource
        index_key = logsource.get("product", logsource.get("category", "windows"))
        index = INDEX_MAPPINGS.get(index_key, "winlogbeat-*")

        return ESQuery(
            query=es_query,
            title=rule.title,
            description=rule.description,
            severity=rule.severity.value,
            tags=rule.tags,
            index=index,
        )

    def _convert_selection(self, selection: Dict) -> Dict:
        """将 Sigma selection 转换为 ES bool query"""
        must_clauses = []

        for field_name, value in selection.items():
            if field_name.startswith("_"):
                continue

            # 映射字段名
            es_field = FIELD_MAPPINGS.get(field_name, f"winlog.event_data.{field_name}")

            # 处理修饰符
            if "|" in field_name:
                parts = field_name.split("|")
                base_field = parts[0].strip()
                modifier = parts[1].strip()
                es_field = FIELD_MAPPINGS.get(base_field, f"winlog.event_data.{base_field}")

                if modifier == "contains":
                    if isinstance(value, list):
                        should_clauses = [{"wildcard": {es_field: f"*{v}*"}} for v in value]
                        must_clauses.append({"bool": {"should": should_clauses, "minimum_should_match": 1}})
                    else:
                        must_clauses.append({"wildcard": {es_field: f"*{value}*"}})

                elif modifier == "startswith":
                    if isinstance(value, list):
                        should_clauses = [{"prefix": {es_field: v}} for v in value]
                        must_clauses.append({"bool": {"should": should_clauses, "minimum_should_match": 1}})
                    else:
                        must_clauses.append({"prefix": {es_field: value}})

                elif modifier == "endswith":
                    if isinstance(value, list):
                        should_clauses = [{"wildcard": {es_field: f"*{v}"}} for v in value]
                        must_clauses.append({"bool": {"should": should_clauses, "minimum_should_match": 1}})
                    else:
                        must_clauses.append({"wildcard": {es_field: f"*{value}"}})

                elif modifier == "all":
                    # 所有条件都必须匹配
                    if isinstance(value, list):
                        for v in value:
                            must_clauses.append({"match": {es_field: v}})

                elif modifier == "contains|all":
                    if isinstance(value, list):
                        for v in value:
                            must_clauses.append({"wildcard": {es_field: f"*{v}*"}})

            else:
                # 标准匹配
                if isinstance(value, list):
                    should_clauses = []
                    for v in value:
                        if "*" in str(v) or "?" in str(v):
                            should_clauses.append({"wildcard": {es_field: v}})
                        else:
                            should_clauses.append({"term": {es_field: v}})
                    must_clauses.append({"bool": {"should": should_clauses, "minimum_should_match": 1}})
                elif isinstance(value, str) and ("*" in value or "?" in value):
                    must_clauses.append({"wildcard": {es_field: value}})
                else:
                    must_clauses.append({"term": {es_field: value}})

        if len(must_clauses) == 1:
            return must_clauses[0]
        return {"bool": {"must": must_clauses}}

    # ----------------------------------------------------------
    # 预定义查询模板
    # ----------------------------------------------------------

    def _build_process_creation_query(self, **kwargs) -> ESQuery:
        """进程创建查询"""
        event_id = kwargs.get("event_id", 1)  # Sysmon Event ID 1
        image = kwargs.get("image")
        command_line = kwargs.get("command_line")

        must_clauses = [{"term": {"winlog.event_id": event_id}}]

        if image:
            must_clauses.append({"wildcard": {"process.executable": f"*{image}*"}})
        if command_line:
            must_clauses.append({"wildcard": {"process.command_line": f"*{command_line}*"}})

        return ESQuery(
            query={"query": {"bool": {"must": must_clauses}}, "size": 100},
            title=f"Process Creation (Event ID: {event_id})",
            index="winlogbeat-*",
        )

    def _build_network_query(self, **kwargs) -> ESQuery:
        """网络连接查询"""
        dest_ip = kwargs.get("dest_ip")
        dest_port = kwargs.get("dest_port")

        must_clauses = [{"term": {"winlog.event_id": 3}}]  # Sysmon Event ID 3

        if dest_ip:
            must_clauses.append({"term": {"destination.ip": dest_ip}})
        if dest_port:
            must_clauses.append({"term": {"destination.port": dest_port}})

        return ESQuery(
            query={"query": {"bool": {"must": must_clauses}}, "size": 100},
            title="Network Connection",
            index="winlogbeat-*",
        )

    def _build_powershell_query(self, **kwargs) -> ESQuery:
        """PowerShell 执行查询"""
        script_text = kwargs.get("script_text")

        must_clauses = [
            {"term": {"winlog.channel": "Microsoft-Windows-PowerShell/Operational"}},
            {"term": {"winlog.event_id": 4104}},  # Script Block Logging
        ]

        if script_text:
            must_clauses.append({"wildcard": {"winlog.event_data.ScriptBlockText": f"*{script_text}*"}})

        return ESQuery(
            query={"query": {"bool": {"must": must_clauses}}, "size": 100},
            title="PowerShell Execution",
            index="winlogbeat-*",
        )

    def _build_logon_query(self, **kwargs) -> ESQuery:
        """登录事件查询"""
        logon_type = kwargs.get("logon_type")
        user = kwargs.get("user")

        must_clauses = [{"term": {"winlog.event_id": 4624}}]

        if logon_type:
            must_clauses.append({"term": {"winlog.event_data.LogonType": logon_type}})
        if user:
            must_clauses.append({"wildcard": {"winlog.event_data.TargetUserName": f"*{user}*"}})

        return ESQuery(
            query={"query": {"bool": {"must": must_clauses}}, "size": 100},
            title=f"Logon Events (Type: {logon_type or 'All'})",
            index="winlogbeat-*",
        )

    def _build_suspicious_process_query(self, **kwargs) -> ESQuery:
        """可疑进程执行"""
        suspicious_processes = [
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
            "bitsadmin.exe", "wmic.exe", "psexesvc.exe",
        ]

        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"process.executable": [f"\\{p}" for p in suspicious_processes]}},
                        ]
                    }
                },
                "size": 100,
            },
            title="Suspicious Process Execution",
            severity="high",
            index="winlogbeat-*",
        )

    def _build_encoded_powershell_query(self, **kwargs) -> ESQuery:
        """编码 PowerShell 执行"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"process.command_line": "*powershell*"}},
                            {"bool": {
                                "should": [
                                    {"wildcard": {"process.command_line": "*-enc*"}},
                                    {"wildcard": {"process.command_line": "*-EncodedCommand*"}},
                                    {"wildcard": {"process.command_line": "*FromBase64String*"}},
                                    {"wildcard": {"process.command_line": "*bypass*"}},
                                    {"wildcard": {"process.command_line": "*hidden*"}},
                                    {"wildcard": {"process.command_line": "*noprofile*"}},
                                ],
                                "minimum_should_match": 1
                            }}
                        ]
                    }
                },
                "size": 100,
            },
            title="Encoded PowerShell Execution",
            severity="high",
            index="winlogbeat-*",
        )

    def _build_process_injection_query(self, **kwargs) -> ESQuery:
        """进程注入检测"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"process.command_line": "*VirtualAlloc*"}},
                            {"wildcard": {"process.command_line": "*WriteProcessMemory*"}},
                            {"wildcard": {"process.command_line": "*CreateRemoteThread*"}},
                            {"wildcard": {"process.command_line": "*NtCreateThreadEx*"}},
                            {"wildcard": {"process.command_line": "*QueueUserAPC*"}},
                            {"wildcard": {"process.command_line": "*SetWindowsHookEx*"}},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 100,
            },
            title="Process Injection Detection",
            severity="critical",
            index="winlogbeat-*",
        )

    def _build_psexec_query(self, **kwargs) -> ESQuery:
        """PsExec 检测"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"winlog.event_data.NewProcessName": "*PSEXESVC*"}},
                            {"wildcard": {"process.command_line": "*\\\\*\\ADMIN$*"}},
                            {"term": {"winlog.event_id": 7045}},  # Service Install
                            {"wildcard": {"winlog.event_data.ServiceFileName": "*psexec*"}},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 100,
            },
            title="PsExec Detection",
            severity="high",
            index="winlogbeat-*",
        )

    def _build_credential_dump_query(self, **kwargs) -> ESQuery:
        """凭据转储检测"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"process.command_line": "*mimikatz*"}},
                            {"wildcard": {"process.command_line": "*sekurlsa*"}},
                            {"wildcard": {"process.command_line": "*kerberos*"}},
                            {"wildcard": {"process.command_line": "*lsadump*"}},
                            {"wildcard": {"process.command_line": "*token::elevate*"}},
                            {"wildcard": {"process.command_line": "*privilege::debug*"}},
                            {"wildcard": {"process.command_line": "*Invoke-Mimikatz*"}},
                            {"wildcard": {"process.command_line": "*Invoke-DCSync*"}},
                            {"wildcard": {"process.command_line": "*Invoke-Kerberoast*"}},
                            {"wildcard": {"process.command_line": "*rubeus*"}},
                            {"wildcard": {"process.command_line": "*--dump-hash*"}},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 100,
            },
            title="Credential Dumping Detection",
            severity="critical",
            index="winlogbeat-*",
        )

    def _build_suspicious_dns_query(self, **kwargs) -> ESQuery:
        """可疑 DNS 查询"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"dns.question.name": "*.onion"}},
                            {"wildcard": {"dns.question.name": "*.bit"}},
                            {"wildcard": {"dns.question.name": "*.top"}},
                            {"wildcard": {"dns.question.name": "*.xyz"}},
                            {"regexp": {"dns.question.name": "[a-z]{20,}\\.com"}},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 100,
            },
            title="Suspicious DNS Queries",
            severity="medium",
            index="filebeat-*",
        )

    def _build_c2_communication_query(self, **kwargs) -> ESQuery:
        """C2 通信检测"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"http.request.uri": "*random_bin.bin*"}},
                            {"wildcard": {"http.request.uri": "*/[a-f0-9]{32}/*"}},
                            {"wildcard": {"user_agent.original": "*CobaltStrike*"}},
                            {"wildcard": {"user_agent.original": "*Metasploit*"}},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 100,
            },
            title="C2 Communication Detection",
            severity="critical",
            index="filebeat-*",
        )

    def _build_data_exfil_query(self, **kwargs) -> ESQuery:
        """数据外泄检测"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"http.request.method": "POST"}},
                            {"range": {"http.request.body.bytes": {"gte": 10000}}},
                        ]
                    }
                },
                "size": 100,
            },
            title="Data Exfiltration (Large HTTP POST)",
            severity="high",
            index="filebeat-*",
        )

    def _build_port_scan_query(self, **kwargs) -> ESQuery:
        """端口扫描检测"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"winlog.event_id": 3}},
                        ]
                    }
                },
                "aggs": {
                    "by_source": {
                        "terms": {"field": "source.ip", "size": 20},
                        "aggs": {
                            "unique_dests": {
                                "cardinality": {"field": "destination.ip"}
                            },
                            "unique_ports": {
                                "cardinality": {"field": "destination.port"}
                            },
                            "scan_suspected": {
                                "bucket_selector": {
                                    "buckets_path": {"ports": "unique_ports"},
                                    "script": "params.ports > 20"
                                }
                            }
                        }
                    }
                },
                "size": 0,
            },
            title="Port Scanning Detection",
            severity="high",
            index="winlogbeat-*",
        )

    def _build_scheduled_task_query(self, **kwargs) -> ESQuery:
        """计划任务创建"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"winlog.event_id": 4698}},
                            {"term": {"winlog.event_id": 106}},  # Task Scheduler
                            {"wildcard": {"process.command_line": "*schtasks*/create*"}},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 100,
            },
            title="Scheduled Task Creation",
            severity="medium",
            index="winlogbeat-*",
        )

    def _build_service_install_query(self, **kwargs) -> ESQuery:
        """服务安装"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"winlog.event_id": 7045}},
                            {"wildcard": {"process.command_line": "*sc\\\\.exe*create*"}},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 100,
            },
            title="Service Installation",
            severity="medium",
            index="winlogbeat-*",
        )

    def _build_registry_persistence_query(self, **kwargs) -> ESQuery:
        """注册表持久化"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"winlog.event_id": 13}},  # Sysmon Registry Value Set
                        ],
                        "should": [
                            {"wildcard": {"winlog.event_data.TargetObject": "*CurrentVersion\\Run*"}},
                            {"wildcard": {"winlog.event_data.TargetObject": "*CurrentVersion\\RunOnce*"}},
                            {"wildcard": {"winlog.event_data.TargetObject": "*CurrentVersion\\Explorer\\Shell*"}},
                            {"wildcard": {"winlog.event_data.TargetObject": "*Winlogon\\Shell*"}},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 100,
            },
            title="Registry Persistence",
            severity="high",
            index="winlogbeat-*",
        )

    def _build_wmi_persistence_query(self, **kwargs) -> ESQuery:
        """WMI 持久化"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"process.command_line": "*__FilterToConsumerBinding*"}},
                            {"wildcard": {"process.command_line": "*EventFilter*"}},
                            {"wildcard": {"process.command_line": "*CommandLineEventConsumer*"}},
                            {"wildcard": {"process.command_line": "*ActiveScriptEventConsumer*"}},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 100,
            },
            title="WMI Persistence",
            severity="critical",
            index="winlogbeat-*",
        )

    def _build_uac_bypass_query(self, **kwargs) -> ESQuery:
        """UAC 绕过"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"process.command_line": "*eventvwr.exe*"}},
                            {"wildcard": {"process.command_line": "*fodhelper.exe*"}},
                            {"wildcard": {"process.command_line": "*sdclt.exe*"}},
                            {"wildcard": {"process.command_line": "*computerdefaults.exe*"}},
                            {"wildcard": {"process.command_line": "*cmstp.exe*"}},
                            {"wildcard": {"process.command_line": "*msconfig.exe*"}},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 100,
            },
            title="UAC Bypass Detection",
            severity="high",
            index="winlogbeat-*",
        )

    def _build_token_manipulation_query(self, **kwargs) -> ESQuery:
        """令牌操纵"""
        return ESQuery(
            query={
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"process.command_line": "*ImpersonateLoggedOnUser*"}},
                            {"wildcard": {"process.command_line": "*DuplicateTokenEx*"}},
                            {"wildcard": {"process.command_line": "*SetThreadToken*"}},
                            {"wildcard": {"process.command_line": "*AdjustTokenPrivileges*"}},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "size": 100,
            },
            title="Token Manipulation",
            severity="high",
            index="winlogbeat-*",
        )

    def _build_generic_query(self, **kwargs) -> ESQuery:
        """通用查询"""
        must_clauses = []
        for key, value in kwargs.items():
            if key.startswith("field_"):
                field_name = key.replace("field_", "")
                must_clauses.append({"term": {field_name: value}})

        if not must_clauses:
            must_clauses.append({"match_all": {}})

        return ESQuery(
            query={"query": {"bool": {"must": must_clauses}}, "size": 100},
            title="Generic Query",
            index="winlogbeat-*",
        )

    # ----------------------------------------------------------
    # 输出方法
    # ----------------------------------------------------------

    def print_query(self, es_query: ESQuery):
        """打印查询"""
        print(f"\n{'='*60}")
        print(f"  查询: {es_query.title}")
        print(f"  索引: {es_query.index}")
        if es_query.severity:
            print(f"  严重程度: {es_query.severity}")
        if es_query.tags:
            print(f"  标签: {', '.join(es_query.tags[:5])}")
        print(f"{'='*60}")
        print(json.dumps(es_query.query, indent=2, ensure_ascii=False))

    def export_query(self, es_query: ESQuery, filepath: str):
        """导出查询到文件"""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump({
                "title": es_query.title,
                "description": es_query.description,
                "severity": es_query.severity,
                "tags": es_query.tags,
                "index": es_query.index,
                "query": es_query.query,
            }, f, indent=2, ensure_ascii=False)
        logging.info(f"[+] 查询已导出: {filepath}")

    def list_templates(self):
        """列出所有可用模板"""
        templates = [
            ("suspicious_process", "可疑进程执行"),
            ("encoded_powershell", "编码 PowerShell 执行"),
            ("process_injection", "进程注入检测"),
            ("lateral_movement_psexec", "PsExec 横向移动"),
            ("credential_dumping", "凭据转储"),
            ("suspicious_dns", "可疑 DNS 查询"),
            ("c2_communication", "C2 通信检测"),
            ("data_exfiltration", "数据外泄检测"),
            ("port_scanning", "端口扫描检测"),
            ("scheduled_task_creation", "计划任务创建"),
            ("service_installation", "服务安装"),
            ("registry_persistence", "注册表持久化"),
            ("wmi_persistence", "WMI 持久化"),
            ("uac_bypass", "UAC 绕过"),
            ("token_manipulation", "令牌操纵"),
        ]

        print(f"\n{'='*60}")
        print("  可用查询模板")
        print(f"{'='*60}")
        for name, desc in templates:
            print(f"  {name:30s} - {desc}")
        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Elasticsearch 检测查询构建器（仅限授权使用）",
        epilog="⚠️  仅用于安全检测和日志分析"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sigma", help="Sigma 规则文件路径")
    group.add_argument("--template", help="查询模板名称")
    group.add_argument("--list-templates", action="store_true", help="列出所有模板")
    group.add_argument("--query-type", help="查询类型 (process_creation/network/powershell/logon)")

    parser.add_argument("--event-id", type=int, help="事件 ID")
    parser.add_argument("--image", help="进程名")
    parser.add_argument("--command-line", help="命令行关键词")
    parser.add_argument("--dest-ip", help="目标 IP")
    parser.add_argument("--dest-port", type=int, help="目标端口")
    parser.add_argument("--logon-type", type=int, help="登录类型")
    parser.add_argument("--user", help="用户名")
    parser.add_argument("--script-text", help="PowerShell 脚本内容关键词")
    parser.add_argument("-o", "--output", help="输出 JSON 文件路径")

    args = parser.parse_args()

    builder = ElasticQueryBuilder()

    if args.list_templates:
        builder.list_templates()
        return

    if args.sigma:
        es_query = builder.build_from_sigma(args.sigma)
    elif args.template:
        kwargs = {k: v for k, v in vars(args).items() if v is not None and k not in ["sigma", "template", "list_templates", "query_type", "output"]}
        es_query = builder.build_from_template(args.template, **kwargs)
    elif args.query_type:
        kwargs = {k: v for k, v in vars(args).items() if v is not None and k not in ["sigma", "template", "list_templates", "query_type", "output"]}
        es_query = builder.build_from_params(args.query_type, **kwargs)
    else:
        parser.print_help()
        return

    if es_query:
        builder.print_query(es_query)
        if args.output:
            builder.export_query(es_query, args.output)


if __name__ == "__main__":
    main()
