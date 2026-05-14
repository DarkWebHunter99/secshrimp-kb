# Web 防御策略

> **难度：** ★★★☆☆ | **前置知识：** Web 开发基础
> 
> 最后更新：2026-05-14

---

## 输入验证与输出编码

**核心原则：**
- 永远不信任用户输入
- 白名单验证 > 黑名单过滤
- 在使用点验证，不仅在前端
- 输出编码根据上下文（HTML/JS/CSS/URL）选择

**SQL 注入防御：**
- 参数化查询（Prepared Statements）
- ORM 框架（但不完全安全，注意原生查询）
- 最小权限数据库账户
- 错误信息不泄露数据库结构

**XSS 防御：**
- 输出编码（context-aware encoding）
- Content-Security-Policy (CSP)
- HttpOnly Cookie
- DOM 净化库（DOMPurify）
- 模板引擎自动转义

---

## 认证与会话管理

- 强密码策略 + 密码强度检查
- 多因素认证 (MFA)
- 会话固定防护（登录后重新生成 Session ID）
- 安全的 Session ID 生成（CSPRNG，≥128 位熵）
- 超时和注销机制（空闲 15-30 分钟）
- 限速和账户锁定（防暴力破解）
- OAuth/OIDC 安全配置

**Cookie 安全属性（必设）：**
```
Set-Cookie: sessionid=...;
  HttpOnly      # 禁止 JS 读取
  Secure        # 仅 HTTPS 传输
  SameSite=Lax  # 防 CSRF
  Path=/        # 限制作用域
```

---

## API 安全

- 速率限制
- 输入验证
- JWT 安全配置（强密钥、短过期、正确的算法）
- CORS 白名单配置
- API Key 管理
- 请求大小限制
- 日志和监控

→ API 攻击详见 [`attacks/api-cicd-attacks.md`](../attacks/api-cicd-attacks.md)

---

## 安全头配置

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

---

## GraphQL 安全防御

- 查询深度限制（最大 5-10 层）
- 查询复杂度分析
- 批量查询限制（单请求 ≤10 个）
- 禁用内省（生产环境）
- 字段级授权
- 持久化查询 (Persisted Queries)
- 按复杂度限速

→ GraphQL 攻击详见 [`attacks/web-attacks.md`](../attacks/web-attacks.md) GraphQL 章节

---

## Session 安全加固

**防 Session Fixation：** 登录后销毁旧 session、创建新 session，禁止 URL 传递 Session ID

**防 Session Hijacking：** 强制 HTTPS（HSTS）、HttpOnly + Secure + SameSite cookie、Session IP/UA 变更告警

**JWT 安全：** 短过期（15-30 分钟）+ Refresh Token、RS256/ES256（非对称）、严格验证 alg/iss/aud/exp

**Refresh Token 安全：** HttpOnly Cookie 存储、一次性使用（rotation）、绑定客户端、吊销机制

---

## 竞争条件防御

**原子操作（最重要）：**
```sql
-- ❌ 错误
SELECT balance FROM users WHERE id = 1;  -- 检查
UPDATE users SET balance = balance - 100 WHERE id = 1;  -- 使用

-- ✅ 正确
UPDATE users SET balance = balance - 100 WHERE id = 1 AND balance >= 100;
-- 检查 affected rows
```

**幂等性设计：** Token/Nonce 机制 + 数据库唯一约束

**文件上传安全：** 先存临时目录 → 验证 → 移动到最终目录（不可预测路径）

→ 竞争条件攻击详见 [`attacks/web-attacks.md`](../attacks/web-attacks.md)

---

_→ 参见 [`defense/network-defense.md`](network-defense.md) 获取网络层防御_
_→ 参见 [`defense/endpoint-defense.md`](endpoint-defense.md) 获取端点防护_
