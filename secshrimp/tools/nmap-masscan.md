# Nmap / Masscan 工具笔记

> **难度：** ★★☆☆☆ | **用途：** 网络扫描与服务发现
> 
> 最后更新：2026-05-14

---

## Nmap 常用扫描模式

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

## NSE 脚本分类

| 类别 | 用途 |
|------|------|
| auth | 认证绕过检测 |
| brute | 暴力破解 |
| discovery | 信息收集 |
| dos | 拒绝服务（⚠️ 需授权） |
| exploit | 漏洞利用（⚠️ 需授权） |
| fuzzer | 模糊测试 |
| malware | 恶意软件检测 |
| vuln | 漏洞检测 |

## 实用技巧

- `-T4` 日常够用，`-T5` 容易触发 IDS
- `--min-rate 1000` 保证扫描速度
- `-Pn` 跳过主机发现（防 ICMP 过滤）
- `--reason` 显示端口状态判断依据
- `-oA` 同时输出三种格式（nmap/grepable/xml）

## 信息收集工具速查

| 工具 | 用途 |
|------|------|
| Amass | 子域名枚举（被动+主动） |
| Subfinder | 被动子域名发现 |
| httpx | HTTP 存活探测 + 技术栈识别 |
| Naabu | 快速端口扫描 |
| theHarvester | 邮件/域名/子域名收集 |
| Shodan/Censys/Fofa | 互联网资产搜索 |

---

_→ 参见 [`defense/network-defense.md`](../defense/network-defense.md) 获取 IDS/IPS 检测_
