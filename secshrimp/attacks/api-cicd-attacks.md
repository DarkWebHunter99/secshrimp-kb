# API 与 CI/CD 攻击

> **难度：** ★★★☆☆ | **前置知识：** REST/GraphQL API 基础、CI/CD 概念
> 
> 最后更新：2026-05-14

---

## REST API 攻击

**BOLA / IDOR（对象级授权绕过）：**
```http
# 篡改 ID 查询他人数据
GET /api/users/456/orders HTTP/1.1
Authorization: Bearer <token_123>
# 如果服务端只验证 token 不验证资源归属 → IDOR
```

**API 速率限制绕过：**
- IP 轮换：代理池 / VPN 切换
- Header 欺骗：`X-Forwarded-For`、`X-Real-IP`
- HTTP/2 复用：单连接多流

**Mass Assignment（批量赋值）：**
```json
{"name": "hacker", "email": "hacker@evil.com", "role": "admin", "isVerified": true}
# 如果后端直接绑定请求体到模型 → 权限提升
```

**API 版本绕过：** 旧版 API 未下线，权限宽松

**检测：** 监控 4xx 错误率突增、单用户访问大量不同资源 ID、请求体字段数异常

**防御：** 对象级授权校验、字段白名单、旧版及时下线、多维限速、API 网关

---

## GraphQL 高级攻击

**Alias 攻击（查询折叠）：**
```graphql
query {
  a1: user(id:1) { email }
  a2: user(id:2) { email }
  # ... 100 个 alias，深度=2 但执行 100 次
}
```

**Directive 注入：**
```graphql
query ($showAdmin: Boolean!) {
  users {
    name
    passwordHash @include(if: $showAdmin)
  }
}
# 如果 $showAdmin 可被客户端控制 → 敏感字段泄露
```

**Subscription 劫持：**
- 订阅实时事件时 chatId 未鉴权 → 监听所有聊天室

**NoSQL 注入：**
```graphql
query {
  users(filter: { name: { "$ne": "" } }) {
    id email passwordHash
  }
}
# 返回所有用户！
```

---

## OAuth 2.0 / OIDC 攻击

**授权码窃取：** redirect_uri 篡改 / 开放重定向利用

**Token 泄露：** 不使用 PKCE 时授权码可被拦截

**State 参数攻击：** 弱 state → CSRF 绑定攻击

---

## WebSocket 攻击

- 跨站 WebSocket 劫持（CSWSH）
- 缺少认证/授权
- 消息注入
- DoS（大量连接）

---

## GraphQL vs REST 安全对比

| 维度 | REST | GraphQL |
|------|------|---------|
| 端点暴露 | 多端点多攻击面 | 单端点，但内省暴露全 schema |
| 速率限制 | 按端点限速 | 需要按查询复杂度限速 |
| 授权 | 端点级授权 | 字段级授权，更细粒度 |
| 注入 | SQL/OS 注入 | NoSQL/注入 + 深度嵌套 DoS |
| 批量攻击 | 多请求 | 单请求多查询 |

---

_→ 参见 [`attacks/web-attacks.md`](web-attacks.md) 获取 Web 攻击基础_
_→ 参见 [`defense/web-defense.md`](../defense/web-defense.md) 获取 API 安全防御_
