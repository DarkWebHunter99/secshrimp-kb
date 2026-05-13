#!/usr/bin/env python3
"""
Purpose: 安全测试报告生成器 — 将检测结果生成为格式化报告
         支持：JSON、HTML、Markdown、CSV 格式导出
Auth: 报告内容可能包含敏感漏洞信息，请妥善保管
Dependencies: jinja2 (HTML 报告), json, csv, datetime
Usage:
    from report_generator import ReportGenerator

    report = ReportGenerator(title="SQL注入检测报告", target="example.com")
    report.add_finding(severity="high", title="Union-based SQL Injection", ...)
    report.export_html("report.html")
    report.export_json("report.json")
"""

import csv
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    @property
    def color(self) -> str:
        return {"critical": "#c0392b", "high": "#e74c3c", "medium": "#f39c12", "low": "#3498db", "info": "#95a5a6"}[self.value]

    @property
    def emoji(self) -> str:
        return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[self.value]


@dataclass
class Finding:
    """漏洞发现"""
    title: str
    severity: Severity
    description: str
    url: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    recommendation: str = ""
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None                   # CWE-XXX
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "references": self.references,
            "tags": self.tags,
            "timestamp": self.timestamp,
        }


@dataclass
class ReportMeta:
    """报告元数据"""
    title: str
    target: str
    author: str = "代码虾 (CodeShrimp)"
    date: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))
    version: str = "1.0"
    scope: str = ""
    disclaimer: str = "本报告仅供授权人员查阅，不得泄露"


class ReportGenerator:
    """
    安全报告生成器
    
    用法：
    1. 创建实例，指定报告标题和目标
    2. 通过 add_finding 添加发现
    3. 调用 export_* 方法导出报告
    """

    def __init__(self, title: str, target: str, **kwargs):
        self.meta = ReportMeta(title=title, target=target, **kwargs)
        self.findings: List[Finding] = []

    def add_finding(self, severity: str, title: str, **kwargs) -> Finding:
        """
        添加一条发现
        
        Args:
            severity: critical|high|medium|low|info
            title: 发现标题
            **kwargs: Finding 其他字段
        """
        finding = Finding(
            severity=Severity(severity),
            title=title,
            **kwargs,
        )
        self.findings.append(finding)
        return finding

    def get_sorted_findings(self) -> List[Finding]:
        """按严重程度排序"""
        return sorted(self.findings, key=lambda f: f.severity.weight, reverse=True)

    def get_summary(self) -> dict:
        """统计摘要"""
        summary = {"total": len(self.findings)}
        for sev in Severity:
            count = sum(1 for f in self.findings if f.severity == sev)
            summary[sev.value] = count
        return summary

    # ----------------------------------------------------------
    # 导出方法
    # ----------------------------------------------------------

    def export_json(self, filepath: str):
        """导出 JSON 格式报告"""
        data = {
            "meta": {
                "title": self.meta.title,
                "target": self.meta.target,
                "author": self.meta.author,
                "date": self.meta.date,
                "scope": self.meta.scope,
            },
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.get_sorted_findings()],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def export_markdown(self, filepath: str):
        """导出 Markdown 格式报告"""
        lines = [
            f"# {self.meta.title}",
            f"",
            f"- **目标**: {self.meta.target}",
            f"- **日期**: {self.meta.date}",
            f"- **作者**: {self.meta.author}",
            f"",
            f"## 摘要",
            f"",
        ]
        summary = self.get_summary()
        lines.append(f"| 严重程度 | 数量 |")
        lines.append(f"|----------|------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if summary.get(sev, 0) > 0:
                lines.append(f"| {sev.upper()} | {summary[sev]} |")
        lines.append(f"| **总计** | {summary['total']} |")
        lines.append("")

        lines.append("## 发现详情")
        lines.append("")
        for i, finding in enumerate(self.get_sorted_findings(), 1):
            lines.append(f"### {i}. [{finding.severity.value.upper()}] {finding.title}")
            lines.append(f"")
            lines.append(f"**描述**: {finding.description}")
            if finding.url:
                lines.append(f"**URL**: `{finding.url}`")
            if finding.parameter:
                lines.append(f"**参数**: `{finding.parameter}`")
            if finding.payload:
                lines.append(f"**Payload**: `{finding.payload}`")
            if finding.evidence:
                lines.append(f"**证据**: `{finding.evidence}`")
            if finding.recommendation:
                lines.append(f"**修复建议**: {finding.recommendation}")
            if finding.cwe_id:
                lines.append(f"**CWE**: {finding.cwe_id}")
            lines.append("")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def export_csv(self, filepath: str):
        """导出 CSV 格式"""
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["#", "Severity", "Title", "URL", "Parameter", "Description", "Recommendation"])
            for i, finding in enumerate(self.get_sorted_findings(), 1):
                writer.writerow([
                    i,
                    finding.severity.value,
                    finding.title,
                    finding.url,
                    finding.parameter,
                    finding.description,
                    finding.recommendation,
                ])

    def export_html(self, filepath: str):
        """导出 HTML 格式报告"""
        # TODO: 使用 Jinja2 模板生成美观的 HTML 报告
        # 包含：摘要图表、颜色标记、可折叠详情
        summary = self.get_summary()
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>{self.meta.title}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }}
        .summary {{ display: flex; gap: 15px; margin: 20px 0; }}
        .summary-card {{ padding: 15px 25px; border-radius: 8px; color: white; font-weight: bold; }}
        .finding {{ background: white; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid; }}
        .severity-badge {{ padding: 3px 8px; border-radius: 4px; color: white; font-size: 0.85em; }}
        code {{ background: #ecf0f1; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{self.meta.title}</h1>
        <p>目标: {self.meta.target} | 日期: {self.meta.date} | 作者: {self.meta.author}</p>
    </div>
    <div class="summary">
        <div class="summary-card" style="background:{Severity.CRITICAL.color}">Critical: {summary.get('critical',0)}</div>
        <div class="summary-card" style="background:{Severity.HIGH.color}">High: {summary.get('high',0)}</div>
        <div class="summary-card" style="background:{Severity.MEDIUM.color}">Medium: {summary.get('medium',0)}</div>
        <div class="summary-card" style="background:{Severity.LOW.color}">Low: {summary.get('low',0)}</div>
        <div class="summary-card" style="background:{Severity.INFO.color}">Info: {summary.get('info',0)}</div>
    </div>
    <h2>发现详情</h2>
"""
        for i, finding in enumerate(self.get_sorted_findings(), 1):
            html += f"""
    <div class="finding" style="border-left-color:{finding.severity.color}">
        <h3>#{i} {finding.title}
            <span class="severity-badge" style="background:{finding.severity.color}">{finding.severity.value.upper()}</span>
        </h3>
        <p>{finding.description}</p>
        {f'<p>URL: <code>{finding.url}</code></p>' if finding.url else ''}
        {f'<p>修复建议: {finding.recommendation}</p>' if finding.recommendation else ''}
    </div>
"""
        html += f"""
    <hr>
    <p style="color:#95a5a6; font-size:0.85em;">{self.meta.disclaimer}</p>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

    def export(self, filepath: str):
        """根据文件扩展名自动选择导出格式"""
        ext = os.path.splitext(filepath)[1].lower()
        exporters = {
            ".json": self.export_json,
            ".html": self.export_html,
            ".md": self.export_markdown,
            ".csv": self.export_csv,
        }
        exporter = exporters.get(ext)
        if not exporter:
            raise ValueError(f"不支持的格式: {ext}，支持: {list(exporters.keys())}")
        exporter(filepath)


# ============================================================
# 快捷函数
# ============================================================

def quick_report(findings: List[dict], title: str, target: str, output: str):
    """
    快速生成报告（适用于其他工具调用）
    
    Args:
        findings: [{"severity": "high", "title": "...", "description": "...", ...}, ...]
        title: 报告标题
        target: 目标
        output: 输出文件路径
    """
    report = ReportGenerator(title=title, target=target)
    for f in findings:
        report.add_finding(**f)
    report.export(output)
