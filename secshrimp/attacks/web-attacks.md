# Web 攻击手法

> **难度：** ★★★☆☆ | **前置知识：** HTTP 协议基础、HTML/JS 基础
> 
> 最后更新：2026-05-14

---

## SQL 注入 (SQL Injection)

**经典手法：**
- 联合查询注入：`' UNION SELECT 1,2,3--`
- 盲注：布尔盲注、时间盲注
- 堆叠查询：`; DROP TABLE users--`
- 二次注入：在存储时注入，在其他查询中触发

**WAF 绕过：**
- 大小写混用：`uNiOn SeLeCt`
- 注释绕过：`UN/**/ION SEL/**/ECT`
- 编码绕过：URL 编码、双重编码、Unicode
- 内联注释 MySQL 特性：`/*!50000UNION*//*!50000SELECT*/`
- HTTP 参数污染：`id=1&id=2`（不同服务器取值不同）

---

## XSS (Cross-Site Scripting)

**类型：**
- 反射型：URL 参数直接回显
- 存储型：存入数据库，其他用户触发
- DOM 型：纯前端 JS 渲染触发

**绕过技巧：**
- 事件处理器：`onerror`, `onload`, `onfocus`, `onmouseover`
- 编码绕过：HTML 实体、JS Unicode、Base64
- SVG/MathML：`<svg onload=alert(1)>`
- 模板字面量：反引号替代括号
- CSP 绕过：JSONP 端点、base 标签、dns-prefetch

→ 防御详见 [`defense/web-defense.md`](../defense/web-defense.md)

---

## SSRF (Server-Side Request Forgery)

**协议利用：**
- `file:///etc/passwd` — 本地文件读取
- `http://169.254.169.254/` — 云元数据
- `gopher://` — 构造任意 TCP 包（Redis、MySQL、FastCGI）
- `dict://` — 探测服务

**绕过技巧：**
- IP 进制转换：`0x7f000001` = `127.0.0.1`
- DNS 重绑定：域名先解析到外网，再解析到内网
- URL 解析差异：`http://evil@127.0.0.1:80`
- 302 跳转绕过：外网 302 到内网

**SSRF → RCE 链路：**
- 云环境：SSRF → 元数据 → IAM 凭证 → 枚举服务 → 提权 → 执行
- Redis：SSRF → 未授权 → 写 SSH Key / Webshell / 计划任务
- MySQL：SSRF → 未授权 → 写文件
- FastCGI：SSRF → PHP 代码执行

---

## 反序列化漏洞

**Java：**
- CommonCollections 利用链（CC1-CC7）
- CommonsBeanutils、Spring、Fastjson
- JRMP/JMX 利用
- Shiro 550/721（RememberMe 反序列化）

**PHP：**
- `unserialize()` + POP 链
- Phar 反序列化（不需要 `unserialize`）
- Symfony、Laravel、Yii 的 POP 链

**Python：**
- `pickle.loads()` 任意代码执行
- `yaml.load()`（非 safe_load）
- `marshal` / `shelve`

---

## 文件上传绕过

- 双重扩展名：`shell.php.jpg`
- 大小写绕过：`shell.PhP`
- `.htaccess` / `web.config` 覆盖
- `%00` 截断（旧版本 PHP/Java）
- Content-Type 伪造
- 图片马 + 文件包含
- 竞争条件上传

---

## JWT 攻击

- 算法替换攻击：`alg: "none"` 或 RS256 → HS256
- 弱密钥爆破：`jwt-cracker`、字典攻击
- JWK / jku 注入
- Kid 注入：`kid: "../../dev/null"` + `alg: none`

---

## Session 攻击

**Session Fixation（会话固定）：**
- 攻击者预设 session ID，诱导受害者使用
- 登录后 session 绑定攻击者的 ID
- **典型载体：** URL 参数注入（`?PHPSESSID=xxx`）、Cookie 注入
- **实例：** CVE-2021-47923 — OpenCart OCSESSID 可被任意设置

**Session Hijacking（会话劫持）：**
- 窃取有效 session token → 冒充用户
- 窃取路径：XSS 读取 cookie、网络嗅探、日志泄露、MITM

**Cookie 安全属性：**
- `HttpOnly` — 禁止 JS 读取
- `Secure` — 仅 HTTPS 传输
- `SameSite=Strict/Lax` — 防 CSRF
- `Domain`/`Path` — 缩小作用域

**固定 vs 劫持：** 固定 = 预先注入（主动），劫持 = 事后窃取（被动）

---

## 竞争条件 (Race Condition / TOCTOU)

**原理：** 两个并发操作同时访问共享资源，结果取决于执行时序。CWE-362/367/364

**常见场景：**
- 余额/积分操作：重复请求绕过检查 → 双花
- 优惠券/令牌：并发请求同一优惠码 → 多次使用
- 文件上传：检查后写入前的竞态窗口 → webshell
- 注册/邀请码：同一码被多人同时使用

**检测方法：**
- Burp Intruder 高并发线程（Turbo Intruder）
- 多线程 curl 脚本
- 浏览器多标签同时提交

**利用技巧：**
- Burp Suite：Intruder → Resource Pool → 高并发
- Turbo Intruder：`race(100, ...)` 100 个并发
- Python `asyncio` + `aiohttp` 批量并发

**防御：**
- 数据库行锁 / `SELECT FOR UPDATE` 原子操作
- 乐观锁（版本号）
- 悲观锁 / 分布式锁（Redis `SETNX`）
- 幂等性设计：token / nonce 机制
- 原子操作：`UPDATE users SET balance = balance - amount WHERE id = ? AND balance >= amount`

---

## GraphQL 攻击

**内省攻击：**
```graphql
{
  __schema {
    types { name fields { name type { name } } }
  }
}
```

**批量查询攻击：** 单次请求 1000 个查询，绕过速率限制

**深度嵌套 DoS：** 无限嵌套拖垮数据库

**IDOR / 授权绕过：** GraphQL 不自动鉴权，篡改 ID 查询他人数据

**批量赋值：** 注入 schema 未暴露但后端接受的字段（如 `role: "ADMIN"`）

**Alias 攻击：** 用 alias 绕过查询深度限制（深度=2，实际执行 100 次）

**防御：** 禁用内省、查询深度限制（5-10 层）、复杂度分析、字段级授权、持久化查询

---

## OAuth / OIDC 攻击

**授权码窃取：**
- redirect_uri 参数篡改 → 授权码发送到攻击者
- 开放重定向利用

**Token 泄露：**
- PKCE 绕过（不使用 PKCE 时）
- Token 放在 URL 中被 Referer 泄露
- Weak state 参数 → CSRF 绑定攻击

**JWT 令牌攻击：**
- `alg: none` 绕过签名验证
- RS256 → HS256 算法替换
- 空签名：`header.payload.`

---

## XML 外部实体注入 (XXE)

**基本 XXE：**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

** Blind XXE：** 通过 OOB（Out-of-Band）外带数据

**防御：** 禁用外部实体（`setFeature FEATURE_SECURE_PROCESSING`）、使用 JSON 替代 XML

---

_→ 参见 [`QUICK-REF.md`](../QUICK-REF.md) 获取速查 Payload_
_→ 防御策略详见 [`defense/web-defense.md`](../defense/web-defense.md)_

---

## 📎 相关主题

- **防御：** [defense/web-defense.md](../defense/web-defense.md) — Web 安全防御策略
- **工具：** [	ools/burp-suite.md](../tools/burp-suite.md) — Burp Suite 实战
- **速查：** [QUICK-REF.md](../QUICK-REF.md) — SQL 注入 / SSRF 速查
- **AI 安全：** [i-security/prompt-injection.md](../ai-security/prompt-injection.md) — Prompt Injection（新型注入攻击）
