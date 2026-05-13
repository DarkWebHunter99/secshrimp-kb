# 安全编程库参考手册

_2026-05-09 代码虾整理 — 持续更新_

---

## 1. Python 安全编程库

### 网络与协议

| 库 | 用途 | 安装 | 适用场景 |
|---|---|---|---|
| `scapy` | 数据包构造/嗅探/注入 | `pip install scapy` | ARP 欺骗、端口扫描、协议 fuzzing |
| `httpx` | 异步 HTTP 客户端 | `pip install httpx` | 高并发扫描、异步爬虫 |
| `aiohttp` | 异步 HTTP 服务端+客户端 | `pip install aiohttp` | 异步扫描器、C2 回连 |
| `paramiko` | SSH2 协议库 | `pip install paramiko` | SSH 暴力破解、远程命令执行 |
| `impacket` | Windows 协议套件 | `pip install impacket` | SMB/WMI/Kerberos/NTLM 攻击 |
| `dpkt` | 轻量级数据包解析 | `pip install dpkt` | PCAP 分析、流量特征提取 |
| `pydivert` | Windows WinDivert 封装 | `pip install pydivert` | Windows 流量拦截/修改 |
| `mitmproxy` | HTTP/HTTPS 中间人代理 | `pip install mitmproxy` | 流量分析、API 逆向、漏洞发现 |

### Web 安全

| 库 | 用途 | 安装 | 适用场景 |
|---|---|---|---|
| `beautifulsoup4` | HTML 解析 | `pip install beautifulsoup4` | 页面爬取、XSS 反射检测 |
| `playwright` | 浏览器自动化 | `pip install playwright` | DOM XSS 检测、爬虫、截图 |
| `selenium` | 浏览器自动化（经典） | `pip install selenium` | 同上，兼容性更广 |
| `mitmproxy` | 代理框架 | `pip install mitmproxy` | Burp 替代、自动化流量分析 |
| `urllib3` | HTTP 底层库 | `pip install urllib3` | 低层 HTTP 控制、连接池 |

### 密码学与认证

| 库 | 用途 | 安装 | 适用场景 |
|---|---|---|---|
| `pycryptodome` | 加密算法套件 | `pip install pycryptodome` | AES/RSA/哈希、JWT 解析 |
| `cryptography` | 现代加密库 | `pip install cryptography` | X.509、TLS、密钥管理 |
| `jwt` | JWT 编解码 | `pip install PyJWT` | JWT 伪造/验证测试 |
| `hashlib` | 标准库哈希 | 内置 | MD5/SHA 暴力破解、彩虹表 |
| `bcrypt` | 密码哈希 | `pip install bcrypt` | 密码强度测试 |

### 二进制与逆向

| 库 | 用途 | 安装 | 适用场景 |
|---|---|---|---|
| `capstone` | 反汇编引擎 | `pip install capstone` | Shellcode 分析、指令识别 |
| `keystone` | 汇编引擎 | `pip install keystone` | Shellcode 生成 |
| `unicorn` | CPU 模拟器 | `pip install unicorn` | 恶意软件沙箱分析 |
| `pefile` | PE 文件解析 | `pip install pefile` | 恶意软件特征提取 |
| `elftools` | ELF 文件解析 | `pip install pyelftools` | Linux 恶意软件分析 |
| `yara-python` | YARA 规则匹配 | `pip install yara-python` | 恶意软件扫描引擎 |
| `frida` | 动态插桩 | `pip install frida` | 运行时 Hook、API 监控 |

### 漏洞利用与渗透

| 库 | 用途 | 安装 | 适用场景 |
|---|---|---|---|
| `pwntools` | CTF/Exploit 开发框架 | `pip install pwntools` | ROP 链、格式化字符串、堆利用 |
| `ropper` | ROP gadget 查找 | `pip install ropper` | 二进制漏洞利用 |
| `angr` | 二进制分析框架 | `pip install angr` | 符号执行、路径探索 |
| `z3-solver` | SMT 求解器 | `pip install z3-solver` | 约束求解、密码分析 |
| `hypothesis` | 属性测试/Fuzzing | `pip install hypothesis` | API 输入 Fuzzing、解析器测试、协议变异 |

### 检测与日志

| 库 | 用途 | 安装 | 适用场景 |
|---|---|---|---|
| `sigma` | Sigma 规则引擎 | `pip install sigma-py` | 规则解析、多后端转换 |
| `elasticsearch` | ES 客户端 | `pip install elasticsearch` | 日志查询、检测规则部署 |
| `splunk-sdk` | Splunk SDK | `pip install splunk-sdk` | Splunk 搜索、告警管理 |
| `jq` | JSON 处理 | `pip install jq` | 日志字段提取、数据转换 |

---

## 2. Go 安全编程库

### 网络

| 库 | 用途 | 场景 |
|---|---|---|
| `net/http` | 标准库 HTTP | HTTP 扫描器、代理 |
| `github.com/google/gopacket` | 数据包处理 | 流量嗅探、协议分析 |
| `github.com/txthinking/socks5` | SOCKS5 代理 | 代理隧道 |
| `github.com/gorilla/websocket` | WebSocket | C2 通信、实时数据 |

### 二进制

| 库 | 用途 | 场景 |
|---|---|---|
| `debug/pe` / `debug/elf` | 标准库 PE/ELF 解析 | 恶意软件特征提取 |
| `github.com/capstone-engine/capstone` | CGO 绑定反汇编 | Shellcode 分析 |

### 并发模式

```go
// 信号量模式 — 控制并发扫描数
semaphore := make(chan struct{}, maxConcurrency)
for _, target := range targets {
    semaphore <- struct{}{}
    go func(t string) {
        defer func() { <-semaphore }()
        scan(t)
    }(target)
}
```

---

## 3. PowerShell 安全模块

| 模块 | 用途 | 场景 |
|---|---|---|
| `PowerView` | AD 枚举 | 域渗透信息收集 |
| `PowerUp` | 权限提升 | 提权路径发现 |
| `Invoke-Mimikatz` | 凭据转储 | 内网横向移动 |
| `Get-WinEvent` | Windows 事件查询 | 检测规则验证 |
| `PSReflect` | .NET 反射调用 | API 调用、EDR 绕过 |

---

## 4. 库选型决策树

```
需要做什么？
├── 网络扫描/协议分析
│   ├── Python: scapy (构造) / httpx (HTTP) / impacket (Windows)
│   ├── Go: gopacket (底层) / net/http (HTTP)
│   └── 选择依据: 并发需求 → Go, 快速原型 → Python
├── Web 安全测试
│   ├── 爬虫+分析: beautifulsoup4 + httpx
│   ├── DOM 测试: playwright (推荐) / selenium
│   └── 流量拦截: mitmproxy
├── 二进制分析
│   ├── 静态: pefile + capstone + yara-python
│   ├── 动态: frida / unicorn
│   └── Exploit: pwntools + z3-solver
├── 检测规则
│   ├── Sigma: sigma-py (解析) → elastic/splunk (部署)
│   ├── YARA: yara-python (扫描引擎)
│   └── Suricata: 规则文件 (无 Python 库，直接部署)
└── 日志分析
    ├── ELK: elasticsearch + jq
    ├── Splunk: splunk-sdk
    └── 通用: pandas + jq
```

---

## 5. 新增/值得关注的库（2026）

| 库 | 亮点 | 关注原因 |
|---|---|---|
| `aiosqlite` | 异步 SQLite | 异步扫描器本地数据库 |
| `hypothesis` | 属性测试 | Fuzzing API 输入 |
| `rich` | 终端美化 | 安全工具报告输出 |
| `typer` | CLI 框架 | 安全工具命令行界面 |
| `pydantic` | 数据验证 | 配置文件/输入验证 |
| `structlog` | 结构化日志 | 安全工具日志标准化 |
| `orjson` | 高性能 JSON | 大规模日志处理 |
| `dnspython` | DNS 库 | 子域名枚举、DNS 安全 |

---

## 6. hypothesis — 属性测试与安全 Fuzzing 详解

### 简介

`hypothesis` 是 Python 的属性测试（property-based testing）框架，通过自动生成输入数据来发现边界条件和异常。在安全领域，它可用于：

- **协议 Fuzzing**: 生成畸形输入测试解析器健壮性
- **API 输入验证**: 自动发现注入点和边界溢出
- **加密实现验证**: 测试加解密函数的数学属性
- **序列化/反序列化**: 发现类型混淆和边界错误

### 安装

```bash
pip install hypothesis
# 可选扩展
pip install hypothesis[datetime]  # 日期时间策略
pip install hypothesis-json        # JSON 结构生成
```

### 核心 API

```python
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

# 基础策略
def test_sql_injection_parser():
    """测试 SQL 注入检测器对各种输入的健壮性"""
    @given(st.text(min_size=1, max_size=1000))
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    def _inner(user_input: str):
        # 不应抛出异常，只应返回 bool
        result = detect_sql_injection(user_input)
        assert isinstance(result, bool)
    _inner()

# 组合策略 — 模拟 HTTP 请求
def test_ssrf_detector():
    """测试 SSRF 检测器对各种 URL 格式的处理"""
    url_strategy = st.one_of(
        st.from_regex(r"http://[a-z]{1,10}\.example\.com/[a-z]{1,5}"),
        st.from_regex(r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/[a-z]{1,5}"),
        st.text(min_size=1, max_size=200),  # 模糊输入
    )

    @given(url=url_strategy)
    def _inner(url: str):
        result = detect_ssrf(url)
        assert isinstance(result, bool)
    _inner()
```

### 安全测试常用策略

```python
from hypothesis import strategies as st

# 1. SQL 注入 Payload 生成
sql_payloads = st.one_of(
    st.sampled_from(["'", "\"", ";", "--", "/\*", "OR", "UNION"]),
    st.text(alphabet="'\";-/* ", min_size=1, max_size=50),
    st.binary(min_size=1, max_size=100),
)

# 2. XSS Payload 生成
xss_payloads = st.one_of(
    st.from_regex(r"<script>[a-z]{1,20}\(\)</script>"),
    st.from_regex(r"javascript:[a-z]{1,20}"),
    st.text(min_size=1, max_size=200),
)

# 3. 路径遍历
def path_traversal_strings():
    prefix = st.sampled_from(["../", "..\\", "..%2f", "..%5c", "%2e%2e/"])
    suffix = st.sampled_from(["etc/passwd", "windows/win.ini", "proc/self/environ"])
    return st.builds(lambda p, s: p + s, prefix, suffix)

# 4. 二进制格式变异
def fuzz_pe_header():
    """生成畸形 PE 头"""
    return st.binary(min_size=64, max_size=1024)
```

### 与 pytest 集成

```python
import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

class TestSQLiDetector:
    """SQL 注入检测器属性测试"""

    @given(st.text(min_size=1, max_size=500))
    @settings(max_examples=200)
    def test_no_false_panic(self, payload: str):
        """检测器不应因任意输入崩溃"""
        detector = SQLiDetector()
        result = detector.detect(payload)
        assert result in (True, False)

    @given(st.sampled_from([
        "' OR '1'='1",
        "1 UNION SELECT NULL--",
        "' AND SLEEP(5)--",
    ]))
    def test_known_payloads_detected(self, payload: str):
        """已知 payload 必须被检出"""
        detector = SQLiDetector()
        assert detector.detect(payload) is True
```

### Fuzzing 配置建议

| 场景 | max_examples | deadline | HealthCheck |
|------|-------------|----------|-------------|
| 快速单元测试 | 100 | 200ms | 默认 |
| 安全扫描器验证 | 500 | None | suppress too_slow |
| 协议 Fuzzing | 1000+ | None | suppress too_slow, large_base_example |
| CI/CD 集成 | 200 | 500ms | 默认 |

### 注意事项

1. **确定性**: 设置 `@settings(database=None)` 避免 hypothesis 数据库缓存影响结果
2. **性能**: `max_examples` 过大会导致测试很慢，安全场景建议 200-500
3. **可复现**: hypothesis 自动记录最小失败用例，用 `--hypothesis-seed=N` 固定随机种子
4. **假设过滤**: `assume(condition)` 过滤无效输入，但过度使用会降低覆盖率

---

## 7. structlog — 安全工具结构化日志

### 简介

`structlog` 是 Python 的结构化日志库，将日志输出为结构化数据（JSON/键值对），而非纯文本。在安全工具中，结构化日志能：

- **自动化分析**: JSON 格式日志可被 SIEM/ELK 直接解析
- **上下文关联**: 每条日志携带完整上下文（目标、payload、结果）
- **审计合规**: 结构化日志满足安全审计要求
- **调试效率**: 开发时彩色美化输出，生产时 JSON 输出

### 安装

```bash
pip install structlog
```

### 核心 API

```python
import structlog

# 配置 structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.ConsoleRenderer() if DEBUG else structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

log = structlog.get_logger()

# 基础用法
log.info("ssrf_test_started", target="http://example.com", param="url")
log.warning("waf_detected", waf="Cloudflare", status=403)
log.error("connection_failed", target="10.0.0.1", port=3306, error=str(e))
```

### 安全工具集成模式

```python
import structlog
from dataclasses import dataclass

# 1. 扫描器日志 — 每个请求/响应结构化记录
def log_scan_request(log, url: str, payload: str, method: str):
    """记录扫描请求"""
    log.info(
        "scan_request",
        url=url,
        payload=payload[:100],  # 截断避免日志过大
        method=method,
        phase="request",
    )

def log_scan_response(log, url: str, status: int, length: int, evidence: str = ""):
    """记录扫描响应"""
    log.info(
        "scan_response",
        url=url,
        status_code=status,
        response_length=length,
        evidence=evidence[:200] if evidence else "",
        phase="response",
    )

# 2. 漏洞发现日志 — 每个发现结构化记录
def log_vulnerability(log, vuln_type: str, url: str, param: str, payload: str, severity: str):
    """记录漏洞发现"""
    log.warning(
        "vulnerability_found",
        vuln_type=vuln_type,
        url=url,
        parameter=param,
        payload=payload,
        severity=severity,
        phase="discovery",
    )

# 3. 攻击链日志 — 多步骤攻击完整记录
def log_attack_chain(log, chain_id: str, step: int, action: str, result: str):
    """记录攻击链步骤"""
    log.info(
        "attack_chain_step",
        chain_id=chain_id,
        step=step,
        action=action,
        result=result,
        phase="exploitation",
    )
```

### 与安全工具结合

```python
# 示例：SSRF 检测器集成 structlog
import structlog

log = structlog.get_logger("ssrf_tester")

class SSRFTester:
    def detect(self, url, param):
        log.info("detection_started", target=url, parameter=param)

        for payload in self.payloads:
            log.debug("testing_payload", payload=payload[:80])
            result = self._send(url, param, payload)
            if result.vulnerable:
                log.warning(
                    "ssrf_confirmed",
                    payload=payload,
                    evidence=result.evidence,
                    severity="critical",
                )

        log.info("detection_completed", findings=len(self.results))
```

### 输出格式对比

| 格式 | 输出示例 | 适用场景 |
|------|---------|----------|
| ConsoleRenderer | `[2m[2026-05-12 12:00][0m \x1b[1minfo\x1b[0m ssrf_test_started target=http://...` | 开发调试 |
| JSONRenderer | `{"event": "ssrf_test_started", "target": "http://...", "level": "info", "timestamp": "2026-05-12T12:00:00Z"}` | 生产/SIEM |
| KeyValuesRenderer | `target=http://... phase=request level=info` | 简洁终端 |

### 最佳实践

1. **始终传递上下文**: `log.info("event", key=value)` 而非 `log.info(f"event {value}")`
2. **日志分级**: debug=请求详情, info=阶段进度, warning=发现, error=失败
3. **敏感数据脱敏**: payload 截断、凭据 mask、PII 过滤
4. **绑定处理器**: `log = log.bind(tool="ssrf_tester", version="2.0")` 自动附加元数据
5. **异步兼容**: structlog 天然支持 asyncio，无需额外配置

---

## 8. cryptography — 现代加密库详解

### 简介

`cryptography` 是 Python 最主流的加密库，提供原语（primitives）和高层配方（recipes）两种 API 层级。相比 pycryptodome，cryptography 更安全（默认使用 OpenSSL）、API 更现代、维护更活跃。在安全工具中用于：

- **TLS/证书分析**: 解析 X.509 证书、检测弱加密套件
- **密钥管理**: RSA/AES/ECC 密钥生成、交换、签名
- **密码学攻击**: 哈希碰撞、密钥恢复、侧信道分析
- **数据保护**: Fernet 对称加密、HMAC 验证

### 安装

```bash
pip install cryptography
```

### 核心 API

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
import os

# 1. AES-GCM 加密（推荐）
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-GCM 认证加密"""
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

# 2. RSA 密钥生成与签名
def rsa_sign(private_key, message: bytes) -> bytes:
    """RSA-PSS 签名"""
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# 3. X.509 证书解析
def parse_cert(cert_pem: bytes):
    """解析 PEM 证书"""
    cert = load_pem_x509_certificate(cert_pem, default_backend())
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before,
        "not_after": cert.not_valid_after,
        "serial": hex(cert.serial_number),
        "sig_algorithm": cert.signature_algorithm_oid._name,
    }
```

### 安全测试常用模式

```python
# 1. JWT 伪造测试（不依赖 PyJWT）
import hmac, hashlib, base64, json

def forge_jwt(header: dict, payload: dict, secret: str) -> str:
    """使用 HMAC-SHA256 伪造 JWT"""
    def b64url(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()
    
    signing_input = f"{b64url(header)}.{b64url(payload)}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    return f"{signing_input}.{sig_b64}"

# 2. 弱密钥检测
def check_weak_key(key_bytes: bytes) -> str:
    """检测常见弱密钥"""
    weak_patterns = {
        b'\x00' * len(key_bytes): "全零密钥",
        b'\xff' * len(key_bytes): "全FF密钥",
        bytes(range(len(key_bytes) % 256)) * (len(key_bytes) // (len(key_bytes) % 256) + 1): "顺序字节密钥",
    }
    for pattern, desc in weak_patterns.items():
        if key_bytes == pattern[:len(key_bytes)]:
            return desc
    return "未检测到已知弱密钥"

# 3. TLS 证书链验证
def verify_cert_chain(cert_pem: bytes, ca_pem: bytes) -> bool:
    """验证证书链"""
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import padding
    
    cert = load_pem_x509_certificate(cert_pem)
    ca = load_pem_x509_certificate(ca_pem)
    
    try:
        ca.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False
```

### 与安全工具结合

```python
# 检测目标 TLS 配置
def audit_tls_config(hostname: str, port: int = 443):
    """审计 TLS 配置"""
    import ssl
    
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.connect((hostname, port))
        cert = s.getpeercert()
        cipher = s.cipher()
        
        results = {
            "protocol": s.version(),
            "cipher": cipher[0],
            "bits": cipher[2],
        }
        
        # 检测弱配置
        if "TLSv1" in results["protocol"] and "1.3" not in results["protocol"]:
            results["warning"] = "使用旧版 TLS 协议"
        if results["bits"] < 256:
            results["warning"] = "加密强度不足 256 位"
        
        return results
```

### 注意事项

1. **始终使用 `cryptography.hazmat`**: 底层原语在 `hazmat` 包中，需要明确选择
2. **避免 ECB 模式**: 始终使用 GCM/CCM 等认证加密模式
3. **密钥长度**: RSA ≥ 2048 位，AES ≥ 256 位
4. **随机数**: 使用 `os.urandom()` 或 `secrets` 模块，不要用 `random`

---

_持续更新。发现好库就记一笔。_
