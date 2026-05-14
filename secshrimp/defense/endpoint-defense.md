# 端点防护策略

> **难度：** ★★★☆☆ | **前置知识：** 系统管理基础
> 
> 最后更新：2026-05-14

---

## EDR 部署与调优

**核心监控能力：**
- 进程监控（创建、注入、hollowing）
- 文件系统监控
- 注册表监控
- 网络连接监控
- 内存扫描
- 行为分析引擎

**关键检测点：**
| 攻击技术 | 检测方法 | 数据源 |
|----------|----------|--------|
| 进程 Hollowing | 内存镜像 vs 磁盘文件比对 | Sysmon ID 10 + 内存扫描 |
| 反射 DLL 加载 | 非映射内存区域的可执行页 | VirtualAlloc 监控 |
| APC 注入 | 异常 APC 队列操作 | ETW Kernel 事件 |
| Thread Hijacking | 线程上下文异常修改 | Sysmon ID 8 |
| Process Doppelgänging | 事务文件操作 | Sysmon ID 11 + ETW |

---

## 应用白名单

- 仅允许已知可信程序执行
- PowerShell Constrained Language Mode
- 脚本执行策略
- 宏安全设置

---

## 补丁管理

- 漏洞分级（CVSS + 实际风险）
- 补丁测试流程
- 紧急补丁快速通道（高危 CVE 24 小时内）
- 第三方软件更新
- 固件更新

---

## 凭证保护

- LAPS（本地管理员密码管理）
- Credential Guard（Windows）
- 禁止明文凭据存储
- 密码管理器
- 服务账户管理（gMSA）

---

## 远程管理工具加固

**最小暴露面：** 通过 VPN/零信任访问、独立 VLAN、限制源 IP

**认证：** 强制 MFA、SAML/OIDC、禁用本地账户

**版本管理：** 远程管理工具漏洞从披露到利用 < 7 天，建立紧急补丁通道

**Sigma 规则示例：**
```yaml
title: Suspicious ScreenConnect Process Execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\ScreenConnect.ClientService.exe'
      - '\\ScreenConnect.WindowsClient.exe'
    ParentImage|endswith:
      - '\\w3wp.exe'       # IIS 进程 = 可能的漏洞利用
      - '\\cmd.exe'
  condition: selection
level: critical
```

**替代方案评估：**
| 工具 | 风险 | 建议 |
|------|------|------|
| ScreenConnect | ⚠️ 高 | 补丁及时，但攻击面大 |
| SimpleHelp | 🔴 极高 | 2026 年多次 CVE，建议迁移 |
| AnyDesk | ⚠️ 中 | 需评估当前版本 |
| RustDesk | ✅ 低 | 开源可控，自建服务器 |
| Tailscale | ✅ 低 | 零信任，最安全 |

---

## 安全成熟度模型

| 等级 | 阶段 | 特征 |
|------|------|------|
| 1 | 初始 | 被动响应，无正式流程 |
| 2 | 可管理 | 基本工具和流程 |
| 3 | 定义 | 标准化流程，主动检测 |
| 4 | 量化 | 度量驱动，持续优化 |
| 5 | 优化 | 自动化，威胁情报驱动 |

---

_→ 参见 [`defense/network-defense.md`](network-defense.md) 获取网络层防御_

---

## 相关主题

- **网络防御:** [network-defense.md](network-defense.md) - IDS/IPS / LOLBins 检测
- **云安全:** [cloud-defense.md](cloud-defense.md) - 云环境端点安全
- **工具:** [tools/bloodhound-mimikatz.md](../tools/bloodhound-mimikatz.md) - 域渗透工具
