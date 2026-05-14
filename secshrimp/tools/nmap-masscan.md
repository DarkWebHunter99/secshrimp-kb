# Nmap / Masscan 工具笔记

> **难度：** ★★☆☆☆ | **用途：** 网络扫描与服务发现
> 
> 最后更新：2026-05-14

---

## Nmap 常用扫描

```bash
# 快速端口发现（最常用）
nmap -sS -T4 -F --top-ports 1000 <target>

# 全端口扫描（必做）
nmap -sS -p- -T4 --min-rate 1000 <target>

# 服务版本 + 操作系统检测
nmap -sV -sC -O <target>

# UDP 扫描（慢但必要）
nmap -sU --top-ports 20 <target>

# 脚本扫描
nmap --script vuln <target>
nmap --script "smb-*" -p 445 <target>
nmap --script "http-enum,http-title,http-headers" -p 80,443 <target>

# 输出所有格式
nmap -oA result -sV -sC <target>
```

## NSE 脚本分类

| 类别 | 用途 | 常用脚本 |
|------|------|----------|
| auth | 认证绕过 | mysql-brute, ssh-brute |
| broadcast | 局域网发现 | broadcast-netbios, broadcast-arp |
| brute | 暴力破解 | http-brute, ftp-brute, smb-brute |
| discovery | 信息收集 | http-title, ssl-cert, smb-enum-shares |
| dos | 拒绝服务 | http-slowloris（⚠️ 需授权） |
| exploit | 漏洞利用 | smb-vuln-ms17-010（⚠️ 需授权） |
| fuzzer | 模糊测试 | http-method-fuzzer |
| malware | 恶意软件检测 | ssl-heartbleed |
| safe | 安全脚本 | http-enum, ssl-cert |
| vuln | 漏洞检测 | http-shellshock, ssl-poodle |

## 扫描策略

**阶段式扫描（隐蔽 → 全面）：**

```bash
# Phase 1: 存活探测
nmap -sn 10.0.0.0/24 -oG alive.txt

# Phase 2: 快速端口
nmap -sS -T4 -F --top-ports 1000 -oN quick.txt

# Phase 3: 全端口
nmap -sS -p- -T4 --min-rate 1000 -oN full.txt

# Phase 4: 服务识别
nmap -sV -sC -p <open_ports> -oN service.txt

# Phase 5: 漏洞扫描
nmap --script vuln -p <open_ports> -oN vuln.txt
```

**绕过 IDS/IPS：**
```bash
# 碎片包
nmap -f -p 80,443 <target>

# 随机顺序
nmap -r -p 80,443 <target>

# 慢速扫描
nmap -T2 --max-rate 100 -p 80,443 <target>

# 诱饵 IP
nmap -D RND:10 <target>

# 源端口欺骗
nmap --source-port 53 <target>

# MAC 欺骗
nmap --spoof-mac 0 <target>
```

## Masscan（高速扫描）

```bash
# 全端口扫描（10 秒内完成）
masscan 10.0.0.0/8 -p0-65535 --rate=10000 -oL masscan.txt

# 扫描特定端口
masscan 192.168.0.0/16 -p22,80,443,3389 --rate=5000

# 输出兼容 Nmap 格式
masscan 10.0.0.0/24 -p0-65535 -oX masscan.xml
nmap -iL masscan.xml -sV -sC  # 后续用 Nmap 识别服务

# 随机源 IP
masscan 10.0.0.0/8 -p80 --src-ip 192.168.1.100
```

**Masscan vs Nmap：**
| 特性 | Masscan | Nmap |
|------|---------|------|
| 速度 | 极快（秒级） | 较慢（分钟级） |
| 端口识别 | 仅端口状态 | 服务版本+OS |
| 准确性 | 较低 | 高 |
| 用途 | 大范围端口发现 | 精确服务识别 |

**最佳实践：** Masscan 先发现开放端口 → Nmap 再精确识别

## 常用结果解析

```bash
# 从 Nmap 输出中提取开放端口
grep "open" nmap.txt | awk '{print $1}' | cut -d'/' -f1

# 从 Nmap XML 中提取
grep -oP 'portid="\K[^"]+' nmap.xml | sort -u

# 从 Masscan 中提取
grep "open" masscan.txt | awk '{print $4}' | sort -u
```

## 与其他工具配合

**Nmap → Metasploit：**
```bash
# Nmap 发现漏洞 → MSF 利用
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target>
exploit
```

**Nmap → BloodHound：**
```bash
# Nmap 发现域控 → BloodHound 分析攻击路径
nmap -p 88,135,139,389,445,636 <dc_ip>
```

**Nmap → ffuf：**
```bash
# Nmap 发现 Web 端口 → ffuf 目录扫描
ffuf -u http://<target>:8080/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

---

_→ 网络攻击详见 [`attacks/network-attacks.md`](../attacks/network-attacks.md)_
_→ 网络防御详见 [`defense/network-defense.md`](../defense/network-defense.md)_
