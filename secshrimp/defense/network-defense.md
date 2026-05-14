# 网络防御策略

> **难度：** ★★★☆☆ | **前置知识：** 网络基础、TCP/IP 协议
> 
> 最后更新：2026-05-14

---

## 网络分段

- VLAN 隔离不同业务区域
- 零信任网络架构
- 微分段（主机级防火墙规则）
- DMZ 设计
- 管理网络与业务网络分离

---

## 入侵检测 (IDS/IPS)

**Snort/Suricata 规则编写：**
- 基于特征的检测
- 基于异常的检测
- 检测规则调优（减少误报）

**关键监控指标：**
| 指标 | 说明 |
|------|------|
| 异常外联流量 | 内网主机连接未知外部 IP |
| 端口扫描行为 | 短时间内大量端口探测 |
| 横向移动模式 | 内网间异常 SMB/RDP/WinRM 连接 |
| DNS 异常查询 | 高频查询、TXT 记录异常、DGA 域名 |
| TLS 证书异常 | 自签名证书、证书域名不匹配 |
| Beacon 模式检测 | 定时外联（C2 通信特征） |

---

## DNS 安全

- DNSSEC 部署
- DNS over HTTPS/TLS
- DNS 日志监控
- DGA 检测
- DNS 隧道检测（异常 TXT 记录、超长子域名）
- Sinkhole 恶意域名

---

## LOLBins 检测（Living-off-the-Land）

攻击者利用系统自带工具绕过应用白名单。

| 工具 | 恶意用途 | 检测方法 |
|------|----------|----------|
| `certutil.exe` | 下载/解码恶意文件 | 监控 `-urlcache`、`-decode`，Sysmon ID 1 |
| `mshta.exe` | 执行 HTA 脚本 | 监控远程 URL 参数，Event ID 1 + 网络连接 |
| `regsvr32.exe` | 执行远程脚本（SCT） | 监控 `/i:http`，AppData 路径执行 |
| `rundll32.exe` | 加载恶意 DLL | 监控非标准路径 DLL 加载，Event ID 7 |
| `wmic.exe` | 远程执行/下载 | 监控 `/format:` 和远程 XSL，Event ID 1 |
| `powershell.exe` | 一切 | Script Block Logging (Event ID 4104)，AMSI |
| `bitsadmin.exe` | 下载恶意文件 | 监控 `/transfer` 和 `/create`，Event ID 1 |

**Sigma 规则示例：**
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

---

## 远程管理工具安全

远程管理工具（ScreenConnect、SimpleHelp、AnyDesk 等）是攻击者高价值目标。

**部署原则：**
- 不直接暴露在互联网，通过 VPN 或零信任访问
- 独立 VLAN/子网
- 限制源 IP 白名单

**认证加固：** 强制 MFA、SAML/OIDC 集成、禁用本地账户

**检测：** 监控异常远程管理进程启动、配置文件篡改、异常反向 Shell 连接

→ 远程管理工具详见 [`defense/endpoint-defense.md`](endpoint-defense.md)

---

## 事件响应流程

1. **准备** — 预案、工具、团队、演练
2. **识别** — 检测、分诊、严重度评估
3. **遏制** — 短期遏制（隔离网络）、长期遏制
4. **根除** — 清除威胁、修复漏洞
5. **恢复** — 系统恢复、验证、监控
6. **经验教训** — 复盘、改进、更新预案

---

_→ 参见 [`defense/web-defense.md`](web-defense.md) 获取应用层防御_
_→ 参见 [`defense/endpoint-defense.md`](endpoint-defense.md) 获取端点防护_

---

## 相关主题

- **网络攻击:** [attacks/network-attacks.md](../attacks/network-attacks.md) - 内网渗透 / 域渗透
- **端点防护:** [endpoint-defense.md](endpoint-defense.md) - EDR / LOLBins 检测
- **工具:** [tools/nmap-masscan.md](../tools/nmap-masscan.md) - 网络扫描
