# Burp Suite 工具笔记

> **难度：** ★★★☆☆ | **用途：** Web 渗透测试核心工具
> 
> 最后更新：2026-05-14

---

## 核心模块

| 模块 | 用途 | 使用场景 |
|------|------|----------|
| **Proxy** | 拦截和修改 HTTP 请求/响应 | 手工测试、参数篡改 |
| **Intruder** | 自动化攻击 | 暴力破解、参数 fuzz、枚举 |
| **Repeater** | 手工重放请求 | 漏洞验证、WAF 测试 |
| **Scanner** | 自动化漏洞扫描 | 快速发现已知漏洞 |
| **Sequencer** | 随机性分析 | Session token 预测 |
| **Decoder** | 编码/解码 | URL/Base64/HTML/Unicode |
| **Comparer** | 差异对比 | 响应对比、枚举结果分析 |

## 实战技巧

### Proxy 高级配置

**自动替换规则：**
- Proxy → Options → Match and Replace
- 自动移除安全头：删除 `X-Frame-Options`、`Content-Security-Policy`
- 自动注入 Header：添加 `X-Forwarded-For: 127.0.0.1`
- 自动替换 Cookie：修改认证状态

**HTTPS 拦截：**
- 安装 Burp CA 证书到浏览器
- Proxy → Options → Proxy Listeners → 编辑 → Certificate tab
- 使用 "Generate CA-signed certificate" 为目标域签名

**WebSocket 拦截：**
- Proxy → Options → WebSocket Support 启用
- 可拦截和修改 WebSocket 帧

### Intruder 攻击模式

| 模式 | 用途 | 示例 |
|------|------|------|
| **Sniper** | 单参数逐个替换 | 逐个测试 SQL 注入点 |
| **Battering Ram** | 所有位置相同 payload | 同一 payload 注入多个参数 |
| **Pitchfork** | 多参数一一对应 | 用户名+密码字典配对 |
| **Cluster Bomb** | 多参数全组合 | 用户名×密码全组合爆破 |

**Turbo Intruder（高并发）：**
```python
# Turbo Intruder 脚本示例：竞态条件测试
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, wordwords[0])
    for i in range(30):
        engine.openGate('race')

engine.openGate('race')
```

**资源池配置：**
- Thread Count: 50（高并发）
> Thread Count: 50（高并发）
- 大字典用 "Guzzle" 而不是 "Cluster Bomb"

### Repeater 技巧

**Ctrl+R** 发送到 Repeater，**Ctrl+Shift+R** 发送到新 Repeater 标签

**文件上传测试：**
1. 正常上传请求 → Repeater
2. 修改 Content-Type、文件扩展名、Magic Bytes
3. 逐项替换，观察响应差异

**SQL 注入绕过 WAF：**
```
# 分块传输绕过
Transfer-Encoding: chunked

0

SELECT * FROM users WHERE id=1 OR 1=1--
```

### 宏录制（Session 处理）

**用途：** 自动处理 CSRF token、登录刷新、Session 续期

1. Proxy → Options → Session Handling Rules → Add
2. Rules → Add → Check `Session is invalid` → Run a macro
3. 录制宏：登录流程 → 获取 token → 使用 token
4. 在 Burp Repeater/Intruder 中自动应用

### 扩展推荐

| 扩展 | 用途 | 推荐度 |
|------|------|--------|
| **HackBar** | 快速编码/解码、SQL/XSS payload | ⭐⭐⭐⭐⭐ |
| **Turbo Intruder** | 高并发攻击、竞态条件 | ⭐⭐⭐⭐⭐ |
| **Autorize** | 越权测试自动化 | ⭐⭐⭐⭐⭐ |
| **Logger++** | 增强日志、导出请求 | ⭐⭐⭐⭐ |
| **JSON Beautifier** | JSON 响应格式化 | ⭐⭐⭐⭐ |
| **Active Scan++** | 增强主动扫描 | ⭐⭐⭐⭐ |
| **Retire.js** | JavaScript 库漏洞检测 | ⭐⭐⭐ |
| **Cognito** | JWT token 分析和编辑 | ⭐⭐⭐ |
| **Scan Check Builder** | 自定义扫描规则 | ⭐⭐⭐ |

### 快捷键速查

| 快捷键 | 功能 |
|--------|------|
| `Ctrl+R` | 发送到 Repeater |
| `Ctrl+I` | 发送到 Intruder |
| `Ctrl+Shift+D` | 发送到 Decoder |
| `Ctrl+Space` | 完成自动补全 |
| `Ctrl+U` | URL 编码选中文本 |
| `Ctrl+Shift+U` | URL 解码选中文本 |

## WAF 绕过技巧

**分块传输绕过：**
```
POST / HTTP/1.1
Transfer-Encoding: chunked

a
0 SELECT 1
0
```

**HTTP 参数污染：**
```
GET /page?id=1&id=2 HTTP/1.1
# 不同 Web 服务器取值不同：
# Apache: id=1,2
# IIS: id=1
# Nginx: id=2
```

**Unicode 绕过：**
```
# 不同编码的同义字符
SELECT → %53%45%4C%45%43%54
admin → %61%64%6D%69%6E
' OR 1=1 → %27%20%4F%52%20%31%3D%31
```

## 与其他工具配合

**Burp + SQLMap：**
```bash
# 导出 Burp 请求到文件
# Repeater → 右键 → Save item → 保存为 .txt
# SQLMap 使用
sqlmap -r request.txt --batch --dbs
```

**Burp + Metasploit：**
```bash
# Burp 发现漏洞 → 导出 PoC → MSF 利用
# 或通过 CSRF 表单配合 msfvenom
```

**Burp + Nuclei：**
```bash
# Burp 导出站点地图 → 转换为 Nuclei 格式
# Nuclei 扫描 Burp 发现的端点
nuclei -l urls.txt -t cves/
```

---

_→ 攻击手法详见 [`attacks/web-attacks.md`](../attacks/web-attacks.md)_
_→ 防御详见 [`defense/web-defense.md`](../defense/web-defense.md)_
