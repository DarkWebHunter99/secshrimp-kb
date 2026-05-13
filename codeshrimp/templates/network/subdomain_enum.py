#!/usr/bin/env python3
"""
Purpose: 子域名自动化枚举工具
         支持：字典爆破、证书透明度日志、DNS 记录、子域名接管检测
Auth: 仅限授权使用 — 未经书面授权禁止对任何目标执行枚举
Dependencies: requests, dnslib, colorama
Usage:
    python subdomain_enum.py -t example.com
    python subdomain_enum.py -t example.com --wordlist subdomains.txt --output results.json
"""

import argparse
import json
import logging
import random
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import requests
import dns.resolver
from dns.exception import DNSException


class DiscoveryMethod(Enum):
    """发现方法"""
    WORDLIST = "wordlist"           # 字典爆破
    CERTIFICATE = "certificate"       # 证书透明度日志
    ALTERNATE = "alternate"           # 替换法
    PERMUTATION = "permutation"      # 变异法


@dataclass
class SubdomainResult:
    """子域名发现结果"""
    domain: str
    ip_addresses: List[str] = field(default_factory=list)
    method: DiscoveryMethod = DiscoveryMethod.WORDLIST
    status_code: Optional[int] = None
    http_server: Optional[str] = None
    takeover_vulnerable: bool = False
    cname: Optional[str] = None
    notes: str = ""


@dataclass
class EnumConfig:
    """枚举配置"""
    target_domain: str
    wordlist_path: Optional[str] = None
    max_workers: int = 50
    timeout: int = 5
    verify_ssl: bool = False
    use_cert_transparency: bool = True
    use_wordlist: bool = True
    use_alternate: bool = True
    use_permutation: bool = False
    check_takeover: bool = True


# ============================================================
# 字典数据
# ============================================================

# 默认子域名字典
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "store", "app", "mobile", "cdn", "static", "assets",
    "img", "images", "css", "js", "media", "upload", "download",
    "portal", "secure", "auth", "login", "sso", "oauth", "cas",
    "dashboard", "panel", "console", "manage", "manage2", "admin2",
    "webmail", "email", "smtp", "pop", "imap", "ns1", "ns2",
    "dns", "mx", "ns", "ns3", "ns4", "ns5",
    "vpn", "remote", "rdp", "ssh", "telnet",
    "db", "database", "mysql", "postgres", "mongodb", "redis",
    "elastic", "elasticsearch", "search", "solr",
    "cache", "memcache", "memcached", "varnish",
    "jenkins", "gitlab", "github", "git",
    "ci", "cd", "build", "deploy", "release",
    "docs", "wiki", "help", "support",
    "forum", "community", "blog", "news",
    "m", "mobile", "touch", "wap",
    "beta", "alpha", "demo", "sandbox",
    "internal", "intranet", "extranet",
    "backup", "bak", "old", "legacy",
    "stage", "staging", "uat", "pre", "preprod",
    "prod", "production", "live",
    "aws", "azure", "gcp", "cloud",
    "s3", "storage", "blob", "cdn2",
    "monitor", "nagios", "zabbix", "prometheus",
    "grafana", "kibana", "log", "logs", "splunk",
    "ldap", "ad", "domain", "dc",
    "proxy", "squid", "nginx", "apache",
    "firewall", "fw", "ids", "ips",
    "sandbox", "malware", "threat",
    "partner", "vendor", "client",
    "api2", "api3", "v2", "v3",
    "web1", "web2", "web3", "server1", "server2",
    "host", "node", "pod", "container",
]

# 常见 DNS 记录类型
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]

# 子域名接管检测的 CNAME 指纹
TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here.",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "The specified bucket does not exist",
    "s3-website": "The specified bucket does not exist",
    "cloudapp.net": "No such app",
    "cloudfront.net": "The distribution does not exist",
    "azurewebsites.net": "No such site",
    "azurestaticapps.net": "No such site",
    "vercel.app": "Could not be found",
    "netlify.app": "Not found",
    "firebaseapp.com": "Requested site was not found",
    "shopify.com": "Shop could not be found",
    "wordpress.com": "Do you want to register",
    "tumblr.com": "There's nothing here",
    "surge.sh": "project not found",
}


class SubdomainEnumerator:
    """子域名枚举器核心类"""

    def __init__(self, config: EnumConfig):
        self.config = config
        self.results: List[SubdomainResult] = []
        self.found_domains: Set[str] = set()

    def enumerate(self) -> List[SubdomainResult]:
        """执行完整的子域名枚举流程"""
        logging.info(f"[*] 开始子域名枚举: {self.config.target_domain}")

        # 1. 字典爆破
        if self.config.use_wordlist:
            self._wordlist_enum()

        # 2. 证书透明度日志查询
        if self.config.use_cert_transparency:
            self._certificate_enum()

        # 3. 替换法（交替枚举）
        if self.config.use_alternate:
            self._alternate_enum()

        # 4. 变异法
        if self.config.use_permutation:
            self._permutation_enum()

        # 5. 去重并解析 DNS
        self._resolve_all()

        # 6. 检查子域名接管
        if self.config.check_takeover:
            self._check_takeover()

        logging.info(f"[*] 枚举完成，发现 {len(self.results)} 个子域名")
        return self.results

    def _wordlist_enum(self):
        """字典爆破"""
        logging.info("[*] 字典爆破...")

        wordlist = self._load_wordlist()

        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.config.target_domain}"
            if self._resolve_dns(full_domain):
                return SubdomainResult(
                    domain=full_domain,
                    method=DiscoveryMethod.WORDLIST,
                )
            return None

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {executor.submit(check_subdomain, w): w for w in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result and result.domain not in self.found_domains:
                    self.found_domains.add(result.domain)
                    self.results.append(result)
                    logging.info(f"  [+] {result.domain} (字典爆破)")

    def _certificate_enum(self):
        """证书透明度日志查询"""
        logging.info("[*] 证书透明度日志查询...")

        # 使用 crt.sh API
        url = f"https://crt.sh/?q=.{self.config.target_domain}&output=json"

        try:
            resp = requests.get(url, timeout=self.config.timeout, verify=False)
            if resp.status_code != 200:
                logging.warning("[-] 证书透明度查询失败")
                return

            data = resp.json()
            subdomains = set()

            for cert in data:
                name_value = cert.get("name_value", "")
                # name_value 可能包含多个域名，用换行分隔
                for name in name_value.split("\n"):
                    name = name.strip()
                    if name and name.endswith(f".{self.config.target_domain}"):
                        subdomains.add(name)

            for subdomain in subdomains:
                if subdomain not in self.found_domains:
                    self.found_domains.add(subdomain)
                    self.results.append(SubdomainResult(
                        domain=subdomain,
                        method=DiscoveryMethod.CERTIFICATE,
                    ))
                    logging.info(f"  [+] {subdomain} (证书透明度)")

        except requests.RequestException as e:
            logging.error(f"[!] 证书透明度查询异常: {e}")

    def _alternate_enum(self):
        """替换法枚举（基于已知子域名）"""
        logging.info("[*] 替换法枚举...")

        if not self.results:
            logging.warning("[-] 无已知子域名，跳过替换法")
            return

        # 从已有结果中提取子域名前缀
        known_prefixes = set()
        for r in self.results:
            prefix = r.domain.replace(f".{self.config.target_domain}", "")
            known_prefixes.add(prefix)

        # 替换列表
        replacements = ["www", "www1", "www2", "web", "web1", "web2", "dev", "staging", "test", "api", "app"]

        new_subdomains = set()
        for prefix in known_prefixes:
            for repl in replacements:
                if prefix != repl:
                    new_domain = f"{repl}.{self.config.target_domain}"
                    if new_domain not in self.found_domains:
                        new_subdomains.add(new_domain)

        # 检查新子域名
        for subdomain in new_subdomains:
            if self._resolve_dns(subdomain):
                self.found_domains.add(subdomain)
                self.results.append(SubdomainResult(
                    domain=subdomain,
                    method=DiscoveryMethod.ALTERNATE,
                ))
                logging.info(f"  [+] {subdomain} (替换法)")

    def _permutation_enum(self):
        """变异法枚举"""
        logging.info("[*] 变异法枚举...")

        if not self.results:
            return

        # 常见变异模式
        patterns = ["-", ".", "_"]

        known_prefixes = [r.domain.split(".")[0] for r in self.results]
        subdomain_parts = self.config.target_domain.split(".")

        new_subdomains = set()

        # 模式1: prefix + suffix
        for prefix in known_prefixes:
            for part in subdomain_parts:
                if part != "com" and part != "net" and part != "org":
                    for sep in patterns:
                        new = f"{prefix}{sep}{part}.{self.config.target_domain}"
                        new_subdomains.add(new)

        # 模式2: env + prefix
        envs = ["dev", "staging", "test", "prod", "uat", "qa"]
        for prefix in known_prefixes:
            for env in envs:
                new = f"{env}-{prefix}.{self.config.target_domain}"
                new_subdomains.add(new)

        # 检查新子域名
        for subdomain in new_subdomains[:100]:  # 限制数量
            if subdomain not in self.found_domains:
                if self._resolve_dns(subdomain):
                    self.found_domains.add(subdomain)
                    self.results.append(SubdomainResult(
                        domain=subdomain,
                        method=DiscoveryMethod.PERMUTATION,
                    ))
                    logging.info(f"  [+] {subdomain} (变异法)")

    def _resolve_all(self):
        """解析所有发现的子域名的 DNS 记录"""
        logging.info("[*] 解析 DNS 记录...")

        for result in self.results:
            ip_addresses, cname = self._resolve_full(result.domain)
            result.ip_addresses = ip_addresses
            result.cname = cname

            # 检查 HTTP 状态码
            try:
                resp = requests.get(
                    f"http://{result.domain}",
                    timeout=self.config.timeout,
                    verify=False,
                    allow_redirects=False,
                )
                result.status_code = resp.status_code
                result.http_server = resp.headers.get("Server", "")
            except requests.RequestException:
                pass

            time.sleep(0.1)  # 避免 DNS 限速

    def _check_takeover(self):
        """检查子域名接管漏洞"""
        logging.info("[*] 检查子域名接管...")

        for result in self.results:
            if result.cname:
                for provider, fingerprint in TAKEOVER_FINGERPRINTS.items():
                    if provider in result.cname:
                        # 访问子域名检查接管指纹
                        try:
                            resp = requests.get(
                                f"http://{result.domain}",
                                timeout=self.config.timeout,
                                verify=False,
                            )
                            if fingerprint in resp.text:
                                result.takeover_vulnerable = True
                                result.notes = f"潜在的子域名接管: CNAME 指向 {provider}"
                                logging.warning(f"  [!] {result.domain} 可能存在子域名接管漏洞")
                        except requests.RequestException:
                            pass

    def _load_wordlist(self) -> List[str]:
        """加载字典文件"""
        if self.config.wordlist_path:
            try:
                with open(self.config.wordlist_path, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                logging.warning(f"[!] 字典文件未找到: {self.config.wordlist_path}，使用默认字典")

        return DEFAULT_WORDLIST

    def _resolve_dns(self, domain: str) -> bool:
        """快速 DNS 解析（仅检查是否存在 A 记录）"""
        try:
            answers = dns.resolver.resolve(domain, "A", timeout=self.config.timeout)
            return len(answers) > 0
        except (DNSException, dns.resolver.NXDOMAIN):
            return False

    def _resolve_full(self, domain: str) -> tuple[List[str], Optional[str]]:
        """完整 DNS 解析，返回 IP 列表和 CNAME"""
        ip_addresses = []
        cname = None

        try:
            # 解析 A 记录
            answers = dns.resolver.resolve(domain, "A", timeout=self.config.timeout)
            for ans in answers:
                ip_addresses.append(str(ans.address))
        except (DNSException, dns.resolver.NoAnswer):
            pass

        try:
            # 解析 CNAME
            answers = dns.resolver.resolve(domain, "CNAME", timeout=self.config.timeout)
            for ans in answers:
                cname = str(ans.target).rstrip(".")
                break
        except (DNSException, dns.resolver.NoAnswer):
            pass

        try:
            # 解析 AAAA 记录（IPv6）
            answers = dns.resolver.resolve(domain, "AAAA", timeout=self.config.timeout)
            for ans in answers:
                ip_addresses.append(str(ans.address))
        except (DNSException, dns.resolver.NoAnswer):
            pass

        return ip_addresses, cname

    def print_results(self):
        """格式化输出检测结果"""
        if not self.results:
            print("\n[-] 未发现子域名")
            return

        print(f"\n{'='*60}")
        print("  子域名枚举报告")
        print(f"{'='*60}")

        for r in self.results:
            print(f"\n  [{r.method.value.upper()}] {r.domain}")
            if r.ip_addresses:
                print(f"  IP: {', '.join(r.ip_addresses)}")
            if r.cname:
                print(f"  CNAME: {r.cname}")
            if r.status_code:
                print(f"  HTTP: {r.status_code}")
                if r.http_server:
                    print(f"  Server: {r.http_server}")
            if r.takeover_vulnerable:
                print(f"  ⚠️  子域名接管漏洞: {r.notes}")

        takeover_count = sum(1 for r in self.results if r.takeover_vulnerable)
        print(f"\n{'='*60}")
        print(f"  总计: {len(self.results)} 个子域名")
        if takeover_count > 0:
            print(f"  ⚠️  子域名接管漏洞: {takeover_count} 个")
        print(f"{'='*60}")

    def export_json(self, filepath: str):
        """导出 JSON 格式报告"""
        data = {
            "target_domain": self.config.target_domain,
            "total_subdomains": len(self.results),
            "takeover_vulnerable": sum(1 for r in self.results if r.takeover_vulnerable),
            "results": [
                {
                    "domain": r.domain,
                    "ip_addresses": r.ip_addresses,
                    "method": r.method.value,
                    "status_code": r.status_code,
                    "http_server": r.http_server,
                    "cname": r.cname,
                    "takeover_vulnerable": r.takeover_vulnerable,
                    "notes": r.notes,
                }
                for r in self.results
            ],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logging.info(f"[+] JSON 报告已导出: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="子域名自动化枚举工具（仅限授权使用）",
        epilog="⚠️  未经授权使用本工具属于违法行为"
    )
    parser.add_argument("-t", "--target", required=True, help="目标域名")
    parser.add_argument("-w", "--wordlist", help="字典文件路径")
    parser.add_argument("--no-cert", action="store_true", help="禁用证书透明度查询")
    parser.add_argument("--no-wordlist", action="store_true", help="禁用字典爆破")
    parser.add_argument("--no-alternate", action="store_true", help="禁用替换法")
    parser.add_argument("--permutation", action="store_true", help="启用变异法")
    parser.add_argument("--no-takeover", action="store_true", help="禁用子域名接管检查")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="并发数")
    parser.add_argument("--timeout", type=int, default=5, help="DNS/HTTP 超时(秒)")
    parser.add_argument("-o", "--output", help="输出 JSON 报告路径")

    args = parser.parse_args()

    print("⚠️  请确认你已获得目标域名的枚举授权")
    confirm = input("确认已获授权？(y/N): ")
    if confirm.lower() != "y":
        sys.exit(0)

    config = EnumConfig(
        target_domain=args.target,
        wordlist_path=args.wordlist,
        max_workers=args.concurrency,
        timeout=args.timeout,
        use_cert_transparency=not args.no_cert,
        use_wordlist=not args.no_wordlist,
        use_alternate=not args.no_alternate,
        use_permutation=args.permutation,
        check_takeover=not args.no_takeover,
    )

    enumerator = SubdomainEnumerator(config)
    results = enumerator.enumerate()
    enumerator.print_results()

    if args.output:
        enumerator.export_json(args.output)


if __name__ == "__main__":
    main()
