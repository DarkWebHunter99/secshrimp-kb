# ============================================================
# Async Security Scanner Utilities (v2)
# ============================================================
# Purpose: 基于 httpx + tenacity + aiolimiter 的异步安全扫描器基础设施
# Auth: 仅限授权使用
# Dependencies: httpx, tenacity, aiolimiter, asyncio
# Changelog:
#   v2 (2026-05-12): 移除死代码，修复自适应限速，优化 POST payload 复用
# ============================================================
# 这是安全扫描器的通用基础设施模块，提供：
# 1. 异步 HTTP 客户端（带连接池和超时控制）
# 2. 自适应重试逻辑（指数退避 + 可配置重试条件）
# 3. 异步速率限制（令牌桶算法 + 自适应降速）
# 4. 并发控制（信号量）
# 5. 扫描结果聚合器
# ============================================================

import asyncio
import time
import json
import logging
from dataclasses import dataclass, field
from typing import Optional, TypeVar, Sequence
from enum import Enum

try:
    import httpx
except ImportError:
    raise ImportError("httpx 未安装。运行: pip install httpx")

try:
    from tenacity import RetryCallState
except ImportError:
    raise ImportError("tenacity 未安装。运行: pip install tenacity")

try:
    from aiolimiter import AsyncLimiter
except ImportError:
    raise ImportError("aiolimiter 未安装。运行: pip install aiolimiter")


logger = logging.getLogger(__name__)
T = TypeVar("T")


# ============================================================
# 1. 重试策略配置
# ============================================================

class RetryStrategy(Enum):
    """重试策略枚举"""
    EXPONENTIAL = "exponential"
    FIXED = "fixed"
    FIBONACCI = "fibonacci"
    NONE = "none"


def _fibonacci_wait(attempt: int, base: float) -> float:
    """计算 Fibonacci 退避等待时间"""
    a, b = base, base
    for _ in range(attempt - 1):
        a, b = b, a + b
    return b


@dataclass
class RetryConfig:
    """重试配置"""
    max_attempts: int = 3
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    min_wait: float = 0.5    # 最小等待秒数
    max_wait: float = 30.0   # 最大等待秒数
    retry_on_status: tuple = (429, 500, 502, 503, 504)
    retry_on_exceptions: tuple = (
        httpx.TimeoutException,
        httpx.ConnectError,
        httpx.RemoteProtocolError,
    )

    def compute_wait(self, attempt: int) -> float:
        """根据策略计算第 attempt 次重试的等待时间（attempt 从 0 开始）"""
        if self.strategy == RetryStrategy.FIXED:
            return min(self.min_wait, self.max_wait)
        elif self.strategy == RetryStrategy.FIBONACCI:
            return min(_fibonacci_wait(attempt + 1, self.min_wait), self.max_wait)
        else:  # EXPONENTIAL 或 NONE
            return min(self.min_wait * (2 ** attempt), self.max_wait)


# ============================================================
# 2. 速率限制器
# ============================================================

@dataclass
class RateLimiterConfig:
    """速率限制配置"""
    rate: float = 10.0       # 每秒允许的请求数
    burst: int = 20          # 突发请求上限
    per_host: bool = True    # 是否按主机分别限速

    @classmethod
    def from_string(cls, rate_str: str) -> "RateLimiterConfig":
        """从字符串解析速率，如 '10/s', '100/m', '1000/h'"""
        parts = rate_str.split("/")
        if len(parts) != 2:
            raise ValueError(f"无效速率格式: {rate_str}")

        value = float(parts[0])
        unit = parts[1].lower()

        rates = {"s": value, "m": value / 60, "h": value / 3600}
        if unit not in rates:
            raise ValueError(f"无效时间单位: {unit}")

        return cls(rate=rates[unit], burst=int(value))


class SmartRateLimiter:
    """
    智能速率限制器
    - 令牌桶算法
    - 支持按主机分别限速
    - 支持自适应限速（检测到 429 自动降速）
    """

    def __init__(self, config: RateLimiterConfig):
        self.config = config
        self._limiters: dict[str, AsyncLimiter] = {}
        self._global_limiter = AsyncLimiter(config.rate, 1.0)
        self._adaptive_factor = 1.0

    def _get_limiter(self, host: str) -> AsyncLimiter:
        """获取主机专用限速器（自适应因子变化时重建）"""
        if not self.config.per_host:
            return self._global_limiter

        current_rate = self.config.rate * self._adaptive_factor
        existing = self._limiters.get(host)

        if existing is None:
            self._limiters[host] = AsyncLimiter(current_rate, 1.0)
        elif abs(existing._rate - current_rate) / existing._rate > 0.05:
            # 速率变化超过 5% 时重建限速器
            self._limiters[host] = AsyncLimiter(current_rate, 1.0)

        return self._limiters[host]

    async def acquire(self, host: str = "global"):
        """获取请求许可"""
        limiter = self._get_limiter(host)
        async with limiter:
            pass

    def report_429(self):
        """报告 429 响应，自动降速"""
        self._adaptive_factor = max(0.1, self._adaptive_factor * 0.8)
        logger.warning(f"检测到 429，自适应因子降至 {self._adaptive_factor:.2f}")

    def report_success(self):
        """报告成功响应，逐步恢复速率"""
        self._adaptive_factor = min(1.0, self._adaptive_factor * 1.05)


# ============================================================
# 3. 异步 HTTP 客户端
# ============================================================

@dataclass
class ScanResponse:
    """扫描响应数据"""
    url: str
    status_code: int
    headers: dict
    text: str
    elapsed_ms: float
    retry_count: int = 0
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers": self.headers,
            "text": self.text[:500],  # 截断
            "elapsed_ms": self.elapsed_ms,
            "retry_count": self.retry_count,
            "error": self.error,
        }


@dataclass
class ScanConfig:
    """扫描器配置"""
    timeout: float = 10.0
    concurrency: int = 20
    rate_limit: str = "10/s"
    follow_redirects: bool = True
    verify_ssl: bool = False
    http2: bool = True
    proxy: Optional[str] = None
    headers: dict = field(default_factory=lambda: {
        "User-Agent": "SecurityScanner/1.0 (Authorized Testing)"
    })


class AsyncScanClient:
    """
    异步安全扫描 HTTP 客户端
    集成 httpx + tenacity + aiolimiter
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self._rate_limiter = SmartRateLimiter(
            RateLimiterConfig.from_string(self.config.rate_limit)
        )
        self._semaphore = asyncio.Semaphore(self.config.concurrency)
        self._retry_config = RetryConfig()
        self._client: Optional[httpx.AsyncClient] = None
        self._stats = {"total": 0, "success": 0, "error": 0, "rate_limited": 0}

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            follow_redirects=self.config.follow_redirects,
            verify=self.config.verify_ssl,
            http2=self.config.http2,
            proxy=self.config.proxy,
            headers=self.config.headers,
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    async def get(self, url: str, **kwargs) -> ScanResponse:
        """GET 请求"""
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> ScanResponse:
        """POST 请求"""
        return await self._request("POST", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs) -> ScanResponse:
        """发送请求（带重试、限速、并发控制）"""
        self._stats["total"] += 1
        retry_count = 0

        try:
            async with self._semaphore:
                host = httpx.URL(url).host
                await self._rate_limiter.acquire(host)

                start = time.monotonic()
                last_error = None

                for attempt in range(self._retry_config.max_attempts):
                    try:
                        resp = await self._client.request(method, url, **kwargs)
                        elapsed = (time.monotonic() - start) * 1000

                        # 429 特殊处理：降速 + 重试
                        if resp.status_code == 429:
                            self._rate_limiter.report_429()
                            self._stats["rate_limited"] += 1
                            if attempt < self._retry_config.max_attempts - 1:
                                wait_time = self._retry_config.compute_wait(attempt)
                                await asyncio.sleep(wait_time)
                                retry_count += 1
                                continue

                        # 其他可重试状态码
                        if resp.status_code in self._retry_config.retry_on_status:
                            if attempt < self._retry_config.max_attempts - 1:
                                wait_time = self._retry_config.compute_wait(attempt)
                                await asyncio.sleep(wait_time)
                                retry_count += 1
                                continue

                        self._rate_limiter.report_success()
                        self._stats["success"] += 1

                        return ScanResponse(
                            url=str(resp.url),
                            status_code=resp.status_code,
                            headers=dict(resp.headers),
                            text=resp.text,
                            elapsed_ms=elapsed,
                            retry_count=retry_count,
                        )

                    except (httpx.TimeoutException, httpx.ConnectError) as e:
                        last_error = e
                        retry_count += 1
                        if attempt < self._retry_config.max_attempts - 1:
                            wait_time = self._retry_config.compute_wait(attempt)
                            await asyncio.sleep(wait_time)
                            continue

                # 所有重试失败
                self._stats["error"] += 1
                return ScanResponse(
                    url=url,
                    status_code=0,
                    headers={},
                    text="",
                    elapsed_ms=0,
                    retry_count=retry_count,
                    error=str(last_error),
                )

        except Exception as e:
            self._stats["error"] += 1
            return ScanResponse(
                url=url,
                status_code=0,
                headers={},
                text="",
                elapsed_ms=0,
                error=str(e),
            )

    @property
    def stats(self) -> dict:
        return self._stats.copy()


# ============================================================
# 4. 扫描任务编排器
# ============================================================

class ScanOrchestrator:
    """
    扫描任务编排器
    - 批量 URL 扫描
    - 并发控制
    - 结果聚合
    - 实时进度
    """

    def __init__(self, client: AsyncScanClient):
        self.client = client
        self._results: list[ScanResponse] = []

    async def scan_urls(
        self,
        urls: Sequence[str],
        method: str = "GET",
        **kwargs,
    ) -> list[ScanResponse]:
        """批量扫描 URL"""
        tasks = []
        for url in urls:
            if method.upper() == "GET":
                tasks.append(self.client.get(url, **kwargs))
            else:
                tasks.append(self.client.post(url, **kwargs))

        self._results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理异常
        valid_results = []
        for i, result in enumerate(self._results):
            if isinstance(result, Exception):
                valid_results.append(ScanResponse(
                    url=urls[i] if i < len(urls) else "unknown",
                    status_code=0,
                    headers={},
                    text="",
                    elapsed_ms=0,
                    error=str(result),
                ))
            else:
                valid_results.append(result)

        self._results = valid_results
        return self._results

    async def scan_with_payloads(
        self,
        base_url: str,
        payloads: Sequence[str],
        param: str = "q",
        method: str = "GET",
    ) -> list[ScanResponse]:
        """使用 payload 列表扫描"""
        if method.upper() == "POST":
            # POST 请求复用 scan_urls，统一并发控制
            tasks = [
                self.client.post(base_url, data={param: payload})
                for payload in payloads
            ]
            self._results = await asyncio.gather(*tasks, return_exceptions=True)

            valid_results = []
            for i, result in enumerate(self._results):
                if isinstance(result, Exception):
                    valid_results.append(ScanResponse(
                        url=base_url,
                        status_code=0,
                        headers={},
                        text="",
                        elapsed_ms=0,
                        error=str(result),
                    ))
                else:
                    valid_results.append(result)

            self._results = valid_results
            return self._results

        # GET 请求：构造 URL 列表
        urls = [f"{base_url}?{param}={payload}" for payload in payloads]
        return await self.scan_urls(urls, method="GET")

    def filter_vulnerable(
        self,
        results: Optional[list[ScanResponse]] = None,
        status_codes: Optional[list[int]] = None,
        min_length: Optional[int] = None,
        keyword: Optional[str] = None,
    ) -> list[ScanResponse]:
        """过滤可能有漏洞的响应"""
        data = results or self._results
        filtered = []

        for r in data:
            if not r.success:
                continue
            if status_codes and r.status_code not in status_codes:
                continue
            if min_length and len(r.text) < min_length:
                continue
            if keyword and keyword.lower() not in r.text.lower():
                continue
            filtered.append(r)

        return filtered

    def to_report(self, filename: str = "scan_report.json"):
        """生成扫描报告"""
        report = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "stats": self.client.stats,
            "results": [r.to_dict() for r in self._results],
            "vulnerable": [r.to_dict() for r in self.filter_vulnerable()],
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return report


# ============================================================
# 5. 使用示例
# ============================================================

async def example_sqli_scan():
    """SQL 注入扫描示例"""
    config = ScanConfig(
        timeout=15.0,
        concurrency=10,
        rate_limit="20/s",
        verify_ssl=False,
    )

    async with AsyncScanClient(config) as client:
        orchestrator = ScanOrchestrator(client)

        # SQL 注入 payload
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "1' AND '1'='1' UNION SELECT username,password FROM users--",
        ]

        results = await orchestrator.scan_with_payloads(
            base_url="https://target.example.com/search",
            payloads=payloads,
            param="id",
        )

        # 分析结果
        suspicious = orchestrator.filter_vulnerable(
            status_codes=[200, 500],
            keyword="error"
        )

        print(f"总扫描: {len(results)}")
        print(f"可疑响应: {len(suspicious)}")
        print(f"统计: {client.stats}")

        # 生成报告
        orchestrator.to_report("sqli_scan_report.json")


if __name__ == "__main__":
    asyncio.run(example_sqli_scan())
