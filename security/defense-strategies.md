# Defense Strategies - 防御策略

_安全虾的防御弹药库。_

---

## 一、Web 防御

### 1. 输入验证与输出编码

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

### 2. 认证与会话管理

- 强密码策略 + 密码强度检查
- 多因素认证 (MFA)
- 会话固定防护
- 安全的 Session ID 生成
- 超时和注销机制
- 限速和账户锁定（防暴力破解）
- OAuth/OIDC 安全配置

### 3. API 安全

- 速率限制
- 输入验证
- JWT 安全配置（强密钥、短过期、正确的算法）
- CORS 白名单配置
- API Key 管理
- 请求大小限制
- 日志和监控

---

## 二、网络防御

### 1. 网络分段

- VLAN 隔离不同业务区域
- 零信任网络架构
- 微分段（主机级防火墙规则）
- DMZ 设计
- 管理网络与业务网络分离

### 2. 入侵检测

**IDS/IPS 规则编写：**
- Snort/Suricata 规则语法
- 基于特征的检测
- 基于异常的检测
- 检测规则调优（减少误报）

**关键监控指标：**
- 异常外联流量
- 端口扫描行为
- 横向移动模式
- DNS 异常查询
- TLS 证书异常
- Beacon 模式检测

### 3. DNS 安全

- DNSSEC 部署
- DNS over HTTPS/TLS
- DNS 日志监控
- DGA 检测
- DNS 隧道检测（异常 TXT 记录、超长子域名）
- Sinkhole 恶意域名

---

## 三、端点防护

### 1. EDR 部署与调优

- 进程监控（创建、注入、 hollowing）
- 文件系统监控
- 注册表监控
- 网络连接监控
- 内存扫描
- 行为分析引擎

### 2. 应用白名单

- 仅允许已知可信程序执行
- PowerShell Constrained Language Mode
- 脚本执行策略
- 宏安全设置

### 3. 补丁管理

- 漏洞分级（CVSS + 实际风险）
- 补丁测试流程
- 紧急补丁快速通道
- 第三方软件更新
- 固件更新

### 4. 凭证保护

- LAPS（本地管理员密码管理）
- Credential Guard（Windows）
- 禁止明文凭据存储
- 密码管理器
- 服务账户管理（gMSA）

---

## 四、AI/LLM 防御

### 1. Prompt Injection 防御

**输入层：**
- 输入过滤和净化
- 指令和用户数据分离标记
- 输入长度限制
- 可疑模式检测

**模型层：**
- 系统提示加固
- 输出分类器
- 温度参数调整
- 负面采样训练

**输出层：**
- 输出审查和过滤
- 敏感信息检测
- 幻觉检测
- 人工审核关键操作

### 2. Agent 安全加固

**权限最小化：**
- 工具调用白名单
- 参数验证和消毒
- 操作审批流程
- 资源访问限制

**隔离与沙箱：**
- Agent 执行环境隔离
- 网络隔离
- 文件系统隔离
- API 调用限制

**监控与审计：**
- 所有工具调用日志
- 决策过程可追溯
- 异常行为检测
- 定期安全审计

### 3. 数据保护

- 系统提示不包含敏感信息
- RAG 知识库访问控制
- 输出脱敏
- 对话历史安全存储
- DLP 集成

---

## 五、云安全加固

详见 `cloud-container-security.md` 中的防御部分。

**关键原则：**
- 最小权限（IAM/ServiceAccount）
- 纵深防御（多层安全控制）
- 不可变基础设施（IaC + GitOps）
- 持续监控（CloudTrail/Config/Audit Logs）
- 自动化响应（安全事件自动处理）
- 零信任（不信任任何内部流量）

---

## 六、安全运营框架

### 威胁狩猎 (Threat Hunting)

1. **假设驱动** — 基于 MITRE ATT&CK 框架提出假设
2. **数据收集** — SIEM/EDR/网络日志
3. **分析技术** — 统计异常、行为基线、关联分析
4. **验证与响应** — 确认威胁 → 事件响应

### 事件响应 (Incident Response)

1. **准备** — 预案、工具、团队、演练
2. **识别** — 检测、分诊、严重度评估
3. **遏制** — 短期遏制、长期遏制
4. **根除** — 清除威胁、修复漏洞
5. **恢复** — 系统恢复、验证、监控
6. **经验教训** — 复盘、改进、更新预案

### 安全成熟度模型

| 等级 | 阶段 | 特征 |
|------|------|------|
| 1 | 初始 | 被动响应，无正式流程 |
| 2 | 可管理 | 基本工具和流程 |
| 3 | 定义 | 标准化流程，主动检测 |
| 4 | 量化 | 度量驱动，持续优化 |
| 5 | 优化 | 自动化，威胁情报驱动 |

---

## 七、高级检测策略

### 1. LOLBins 检测（Living-off-the-Land）

攻击者越来越多地利用系统自带工具（LOLBins）执行恶意操作，绕过应用白名单。

**关键 LOLBins 及检测要点：**

| 工具 | 恶意用途 | 检测方法 |
|------|----------|----------|
| `certutil.exe` | 下载/解码恶意文件 | 监控 `-urlcache`、`-decode` 参数，Sysmon Event ID 1 |
| `mshta.exe` | 执行 HTA 恶意脚本 | 监控远程 URL 参数，Event ID 1 + 网络连接 |
| `regsvr32.exe` | 执行远程脚本（SCT） | 监控 `/i:http` 参数，AppData 路径执行 |
| `rundll32.exe` | 加载恶意 DLL | 监控非标准路径 DLL 加载，Event ID 7 |
| `wmic.exe` | 远程执行/下载 | 监控 `/format:` 和远程 XSL，Event ID 1 |
| `powershell.exe` | 一切 | Script Block Logging (Event ID 4104)，AMSI |
| `bitsadmin.exe` | 下载恶意文件 | 监控 `/transfer` 和 `/create`，Event ID 1 |

**检测规则示例（Sigma）：**
```yaml
title: Suspicious Certutil Download
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-split'
      - '-f'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1027
```

### 2. 供应链攻击防御

**软件供应链安全：**

- **依赖审计：** `npm audit`、`pip audit`、`go mod verify` 定期检查
- **SBOM 管理：** Software Bill of Materials 追踪所有组件
- **签名验证：** 验证下载包的 GPG/代码签名
- **锁定文件：** `package-lock.json`、`go.sum` 提交到版本控制
- **私有镜像：** 关键依赖使用内部镜像源

**CI/CD 安全：**

- 构建环境隔离（容器化构建）
- 最小权限的 CI/CD Token
- 构建产物签名
- 部署审批流程
- Secret 管理（Vault/AWS Secrets Manager）

**检测指标：**

- 异常的包发布行为（新维护者、异常时间发布）
- 包体积突变（可能被注入恶意代码）
- 依赖图中的异常依赖链
- Typosquatting 检测（包名相似攻击）

### 3. 内存取证对抗检测

攻击者使用内存规避技术（如进程注入、反射加载）时，防御方需要相应的检测能力。

**检测技术：**

- **Sysmon Event ID 10：** 进程访问监控，检测跨进程注入
- **内存完整性检查：** 代码段哈希比对，检测 inline hook
- **ETW（Event Tracing for Windows）：** 内核级事件追踪
- **Kernel Callback 监控：** 检测 PsSetCreateProcessNotifyRoutine 注册

**关键检测点：**

| 攻击技术 | 检测方法 | 数据源 |
|----------|----------|--------|
| 进程 Hollowing | 内存镜像 vs 磁盘文件比对 | Sysmon ID 10 + 内存扫描 |
| 反射 DLL 加载 | 非映射内存区域的可执行页 | VirtualAlloc 监控 |
| APC 注入 | 异常 APC 队列操作 | ETW Kernel 事件 |
| Thread Hijacking | 线程上下文异常修改 | Sysmon ID 8 |
| Process Doppelgänging | 事务文件操作 | Sysmon ID 11 + ETW |

---

## 八、Session 安全加固

### 1. Session 管理最佳实践

**Session ID 生成：**
- 使用 CSPRNG（密码学安全伪随机数生成器）
- 至少 128 位熵（推荐 160+）
- 避免使用时间戳、IP、User-Agent 等可预测值
- 登录后重新生成 Session ID（防 Session Fixation）

**Cookie 安全属性（必设）：**
```
Set-Cookie: sessionid=...;
  HttpOnly      # 禁止 JS 读取
  Secure        # 仅 HTTPS 传输
  SameSite=Lax  # 防 CSRF（Strict 更严但影响用户体验）
  Path=/        # 限制作用域
  Domain=.example.com  # 限制子域
```

**超时策略：**
- 空闲超时：15-30 分钟（敏感系统更短）
- 绝对超时：8-24 小时
- 重新认证：关键操作前要求重新验证
- 并发会话控制：限制同时登录数

### 2. 防 Session Fixation

**根本措施：**
- 登录后销毁旧 session，创建新 session
- Session ID 不通过 URL 传递（禁止 `?PHPSESSID=xxx`）
- 服务端验证 session 与客户端 IP/UA 绑定（可选，注意移动端切换网络）

**检测方法：**
- 监控登录前后 session ID 是否变化
- 检查 session cookie 的 `HttpOnly`/`Secure`/`SameSite` 属性
- 日志中记录 session 创建/销毁事件

### 3. 防 Session Hijacking

**传输层：**
- 强制 HTTPS（HSTS 头：`Strict-Transport-Security: max-age=31536000; includeSubDomains`）
- 禁止 HTTP 降级

**存储层：**
- HttpOnly 防 XSS 窃取
- Secure 防中间人嗅探
- 考虑 Session Token 绑定 TLS 会话（Session Ticket）

**监控层：**
- Session IP/UA 变更告警
- 异常地理位置登录检测
- 同一 session 多地同时使用检测

### 4. Token 安全（JWT/OAuth）

**JWT 最佳实践：**
- 短过期时间（15-30 分钟）+ Refresh Token
- 使用 RS256/ES256（非对称），不推荐 HS256（对称密钥暴露风险）
- 严格验证 `alg`、`iss`、`aud`、`exp` 声明
- 不在 JWT 中存储敏感信息（JWT payload 可被 base64 解码）

**Refresh Token 安全：**
- 存储在 HttpOnly Cookie 中（不暴露给 JS）
- 一次性使用（rotation）
- 绑定客户端（device fingerprint）
- 吊销机制（黑名单/版本号）

### 5. 会话固定应急响应

**发现 session 劫持时：**
1. 立即销毁受影响 session
2. 强制该用户所有 session 注销
3. 检查 session 日志：登录 IP、时间、操作记录
4. 评估是否有横向移动或数据泄露
5. 通知用户修改密码
6. 检查是否有 XSS 漏洞导致 cookie 泄露

---

_最好的攻击者，也是最了解防御的人。_

---

## 九、竞争条件防御

### 1. 代码层防御

**原子操作（最重要）：**

```sql
-- ❌ 错误：检查和使用分离
SELECT balance FROM users WHERE id = 1;
-- 应用层判断 if balance >= amount
UPDATE users SET balance = balance - 100 WHERE id = 1;

-- ✅ 正确：单条 SQL 原子操作
UPDATE users SET balance = balance - 100 WHERE id = 1 AND balance >= 100;
-- 检查 affected rows，为 0 则余额不足
```

**数据库锁：**
```sql
-- 悲观锁：SELECT FOR UPDATE
BEGIN;
SELECT balance FROM users WHERE id = 1 FOR UPDATE;  -- 加行锁
-- ... 操作 ...
UPDATE users SET balance = new_balance WHERE id = 1;
COMMIT;

-- 乐观锁：版本号
UPDATE users SET balance = balance - 100, version = version + 1
WHERE id = 1 AND version = @expected_version AND balance >= 100;
-- affected rows = 0 → 版本冲突，重试
```

**分布式锁（Redis）：**
```python
import redis
r = redis.Redis()

lock_key = f"lock:user:{user_id}"
with r.lock(lock_key, timeout=5, blocking_timeout=2):
    # 临界区操作
    balance = r.hget(f"user:{user_id}", "balance")
    if int(balance) >= amount:
        r.hincrby(f"user:{user_id}", "balance", -amount)
```

### 2. 幂等性设计

**Token/Nonce 机制：**
```
1. 客户端请求 → 服务端生成唯一 token（UUID）→ 返回给客户端
2. 客户端提交操作时带上 token
3. 服务端检查 token 是否已使用：
   - 未使用 → 执行操作 → 标记 token 已使用
   - 已使用 → 返回之前的结果（不重复执行）
```

**数据库唯一约束：**
```sql
-- 订单表：order_id 唯一约束防止重复创建
CREATE TABLE orders (
    id BIGINT PRIMARY KEY,
    order_id VARCHAR(64) UNIQUE,  -- 幂等键
    user_id BIGINT,
    amount DECIMAL(10,2),
    created_at TIMESTAMP
);
```

### 3. 文件上传竞态防御

**安全的上传流程：**
```
1. 上传到临时目录（随机文件名）
2. 验证文件类型（magic bytes + 扩展名 + MIME）
3. 验证通过 → 移动到最终目录（不可预测的路径）
4. 验证失败 → 删除临时文件

关键：临时目录中的文件在验证通过前不可被访问/执行
```

**Nginx 配置示例：**
```nginx
# 禁止上传目录执行 PHP
location ~* /uploads/.*\.php$ {
    deny all;
}

# 临时上传目录
location /tmp/uploads/ {
    internal;  # 只能内部重定向访问
}
```

### 4. 业务逻辑层防御

| 场景 | 防御方案 |
|------|----------|
| 余额操作 | 数据库原子 UPDATE + 余额检查 |
| 优惠券使用 | 唯一约束 + 幂等 token |
| 邀请码 | 唯一约束 + 事务 |
| 积分兑换 | 乐观锁 + 重试机制 |
| 限时抢购 | Redis 原子 DECR + 令牌桶 |

### 5. 检测竞争条件攻击

**日志分析：**
- 同一用户/IP 短时间内大量相同请求
- 异常的响应时间分布（竞态窗口命中时响应更快）
- 同一资源的并发修改记录

**WAF 规则：**
```yaml
# 检测高频并发请求
title: High Frequency Parallel Requests
condition: rate(src_ip, 10) > 50  # 10 秒内同一 IP 超过 50 次请求
action: block
duration: 60
```

---

## 十、GraphQL 安全防御

### 1. 查询安全

**深度限制：**
```javascript
// Apollo Server 示例
const server = new ApolloServer({
  schema,
  validationRules: [
    depthLimit(7),  // 最大查询深度 7 层
    createComplexityRule({
      maximumComplexity: 1000,  // 最大复杂度
      estimators: [simpleEstimator({ defaultComplexity: 1 })]
    })
  ]
});
```

**复杂度分析：**
- 为每个字段分配成本（默认 1，列表 ×10，嵌套 ×5）
- 总成本超限 → 拒绝执行
- 返回 `extensions: { complexity: { ... } }` 方便调试

**批量查询限制：**
```javascript
// 限制单请求查询数量
const MAX_BATCH_SIZE = 10;
app.use('/graphql', (req, res, next) => {
  if (Array.isArray(req.body) && req.body.length > MAX_BATCH_SIZE) {
    return res.status(400).json({ error: 'Batch size exceeds limit' });
  }
  next();
});
```

**持久化查询 (Persisted Queries)：**
```javascript
// 只允许预注册的查询
const server = new ApolloServer({
  schema,
  persistedQueries: {
    cache: new MemcachedCache(),
    ttl: 900  // 15 分钟缓存
  }
});
// 客户端发送查询哈希而非完整查询文本
// 服务端只接受已注册的查询
```

### 2. 授权与鉴权

**字段级授权：**
```graphql
type Query {
  # 公开字段
  posts: [Post]
  
  # 需要认证
  myOrders: [Order] @auth(requires: USER)
  
  # 需要管理员
  allUsers: [User] @auth(requires: ADMIN)
}
```

**DataLoader 批量加载（防 N+1）：**
```python
# 每个请求创建新的 DataLoader 实例
def user_loader(user_ids):
    users = db.users.find({'_id': {'$in': user_ids}})
    return {u['_id']: u for u in users}

# 使用
loader = DataLoader(user_loader)
user = await loader.load(user_id)
```

### 3. 输入验证

**白名单验证所有参数：**
```graphql
# 好：强类型 input
input CreateUserInput {
  name: String! @constraint(minLength: 1, maxLength: 100)
  email: String! @constraint(format: email)
}

# 坏：接受任意 JSON
input FilterInput {
  filter: JSON  # 危险！可能包含操作符注入
}
```

**序列化敏感数据：**
- User 类型不暴露 `passwordHash` 字段
- 使用 `@hidden` 或自定义解析器过滤敏感字段
- 内省结果中不包含内部类型

### 4. 运行时防护

**查询日志与监控：**
- 记录所有查询的复杂度和执行时间
- 监控异常：高频内省、大批量查询、深度嵌套
- 查询性能追踪：慢查询告警

**速率限制（按复杂度）：**
```python
# 不按请求数，按查询复杂度限速
def rate_limit(query_complexity):
    current = redis.get(f"rate:{user_id}")
    if current + query_complexity > MAX_COMPLEXITY_PER_MINUTE:
        raise RateLimitExceeded
    redis.incrby(f"rate:{user_id}", query_complexity)
```

**WAF 规则示例：**
```yaml
title: GraphQL Introspection Query
detection:
  selection:
    http_request|contains:
      - '__schema'
      - '__type'
      - 'IntrospectionQuery'
  condition: selection
level: medium
action: block
---

## 十一、ADCS 防御
