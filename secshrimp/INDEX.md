# 🦐🔐 安全虾知识库 (SecShrimp Knowledge Hub)

> _从锅里爬出来的虾，脑子里装满了安全弹药。_
> 
> 最后更新：2026-05-14

---

## 🗺️ 导航

| 分区 | 目录 | 文件数 | 说明 |
|------|------|--------|------|
| 🎯 [攻击面](#攻击面) | `attacks/` | 6 | Web/网络/社工/云/供应链/API/CI-CD |
| 🛡️ [防御面](#防御面) | `defense/` | 4 | Web/网络/端点/云 |
| 🤖 [AI 安全](#ai-安全) | `ai-security/` | 3 | Prompt Injection / Agent / MCP |
| 🧰 [工具箱](#工具箱) | `tools/` | 5 | Burp/Nmap/MSF/BloodHound/IDA |
| 🔬 [情报追踪](#情报追踪) | `intel/` | 1 | CVE 持续追踪 |
| 🚀 [项目实战](#项目实战) | `projects/` | 1 | 恶意下载检测引擎 |
| 📈 [进化路线](#进化路线) | `career/` | 2 | 学习路线 + 能力矩阵 |
| ⚡ [速查手册](QUICK-REF.md) | — | 1 | 可打印的一页速查 |

---

## 🛤️ 学习路径

> 从零基础到全栈安全研究员的推荐路径。

### Phase 1: 基础入门（1-2 周）

```
网络基础 ──→ HTTP 协议 ──→ Web 安全基础 ──→ Linux/Windows 基础
    │              │              │                │
    ▼              ▼              ▼                ▼
  [网络防御]   [Web 防御]    [Web 攻击]      [端点防御]
```

**必读：**
- [`attacks/web-attacks.md`](attacks/web-attacks.md) — SQLi / XSS / SSRF 基础
- [`defense/web-defense.md`](defense/web-defense.md) — 输入验证 / 认证安全
- [`tools/nmap-masscan.md`](tools/nmap-masscan.md) — Nmap 网络扫描
- [`QUICK-REF.md`](QUICK-REF.md) — OWASP Top 10 速查

### Phase 2: 渗透实战（2-3 周）

```
Web 渗透 ──→ 漏洞利用 ──→ 后渗透 ──→ 横向移动
    │              │            │            │
    ▼              ▼            ▼            ▼
 [API 攻击]   [Metasploit]  [提权]     [网络攻击]
```

**必读：**
- [`attacks/web-attacks.md`](attacks/web-attacks.md) — 反序列化 / 文件上传 / JWT / 竞争条件
- [`attacks/api-cicd-attacks.md`](attacks/api-cicd-attacks.md) — BOLA / 批量赋值
- [`tools/metasploit.md`](tools/metasploit.md) — Metasploit / Sliver C2
- [`tools/burp-suite.md`](tools/burp-suite.md) — Burp Suite 实战

### Phase 3: 域渗透 & 云安全（3-4 周）

```
AD 域渗透 ──→ Kerberos 攻击 ──→ 云安全 ──→ 容器安全
    │              │              │            │
    ▼              ▼              ▼            ▼
[网络攻击]   [BloodHound]   [云攻击]    [云防御]
```

**必读：**
- [`attacks/network-attacks.md`](attacks/network-attacks.md) — ADCS / Windows 提权 / 域渗透链
- [`attacks/cloud-attacks.md`](attacks/cloud-attacks.md) — AWS IAM / Docker 逃逸 / K8s
- [`tools/bloodhound-mimikatz.md`](tools/bloodhound-mimikatz.md) — BloodHound / Rubeus / Certipy
- [`defense/cloud-defense.md`](defense/cloud-defense.md) — IAM 加固 / K8s 安全

### Phase 4: AI 安全 & 红队（2-3 周）

```
Prompt Injection ──→ Agent 安全 ──→ MCP 安全 ──→ 红队战术
       │                │              │              │
       ▼                ▼              ▼              ▼
  [AI 安全]       [Agent 安全]    [MCP 安全]    [供应链攻击]
```

**必读：**
- [`ai-security/prompt-injection.md`](ai-security/prompt-injection.md) — 直接/间接注入 / 越狱
- [`ai-security/agent-security.md`](ai-security/agent-security.md) — 工具滥用 / 沙箱逃逸
- [`ai-security/mcp-security.md`](ai-security/mcp-security.md) — MCP 供应链攻击
- [`attacks/supply-chain.md`](attacks/supply-chain.md) — 依赖混淆 / CI/CD 投毒

### Phase 5: 高级研究（持续）

```
漏洞挖掘 ──→ 逆向工程 ──→ 安全开发 ──→ 安全运营
    │              │            │            │
    ▼              ▼            ▼            ▼
[CVE 追踪]    [IDA/Ghidra]  [项目实战]   [安全运营]
```

**必读：**
- [`intel/cve-tracker.md`](intel/cve-tracker.md) — 最新高危 CVE
- [`tools/ida-ghidra.md`](tools/ida-ghidra.md) — 逆向分析 + YARA 规则
- [`projects/malware-detect-engine.md`](projects/malware-detect-engine.md) — 检测引擎实战
- [`defense/endpoint-defense.md`](defense/endpoint-defense.md) — EDR / LOLBins 检测

---

## 🎯 攻击面

| 文件 | 主题 | 难度 | 前置知识 |
|------|------|------|----------|
| [`attacks/web-attacks.md`](attacks/web-attacks.md) | SQLi / XSS / SSRF / 反序列化 / 文件上传 / JWT / Session / 竞争条件 / GraphQL | ★★★☆☆ | HTTP 基础 |
| [`attacks/network-attacks.md`](attacks/network-attacks.md) | 内网渗透 / 域渗透 / 横向移动 / ADCS / Windows 提权 | ★★★★☆ | AD 基础 |
| [`attacks/social-engineering.md`](attacks/social-engineering.md) | 钓鱼 / Vishing / 物理安全 | ★★☆☆☆ | — |
| [`attacks/cloud-attacks.md`](attacks/cloud-attacks.md) | AWS IAM 提权 / SSRF→RCE / Docker 逃逸 / K8s 攻击 | ★★★★☆ | 云基础 |
| [`attacks/supply-chain.md`](attacks/supply-chain.md) | 依赖混淆 / Typosquatting / SolarWinds 级攻击 / CI-CD 投毒 | ★★★☆☆ | 包管理基础 |
| [`attacks/api-cicd-attacks.md`](attacks/api-cicd-attacks.md) | REST API 攻击 / GraphQL 高级 / GitHub Actions / Docker 投毒 | ★★★☆☆ | API 开发基础 |

## 🛡️ 防御面

| 文件 | 主题 | 难度 | 前置知识 |
|------|------|------|----------|
| [`defense/web-defense.md`](defense/web-defense.md) | 输入验证 / 认证会话 / API 安全 / 安全头 | ★★★☆☆ | Web 开发基础 |
| [`defense/network-defense.md`](defense/network-defense.md) | 网络分段 / IDS/IPS / DNS 安全 / 防火墙 | ★★★☆☆ | 网络基础 |
| [`defense/endpoint-defense.md`](defense/endpoint-defense.md) | EDR / 应用白名单 / 补丁管理 / 凭证保护 | ★★★☆☆ | 系统管理 |
| [`defense/cloud-defense.md`](defense/cloud-defense.md) | IAM 加固 / 网络策略 / 运行时监控 / 安全运营 | ★★★☆☆ | 云平台基础 |

## 🤖 AI 安全

| 文件 | 主题 | 难度 | 前置知识 |
|------|------|------|----------|
| [`ai-security/prompt-injection.md`](ai-security/prompt-injection.md) | 直接注入 / 间接注入 / 越狱技术 / 防御 | ★★★☆☆ | LLM 基础 |
| [`ai-security/agent-security.md`](ai-security/agent-security.md) | 工具滥用 / 数据泄露 / 多 Agent 攻击 / 权限模型 | ★★★★☆ | Agent 架构 |
| [`ai-security/mcp-security.md`](ai-security/mcp-security.md) | MCP 协议安全 / 供应链攻击 / 服务器注入 | ★★★★☆ | MCP 协议 |

## 🧰 工具箱

| 文件 | 工具 | 难度 |
|------|------|------|
| [`tools/burp-suite.md`](tools/burp-suite.md) | Burp Suite — Web 渗透核心工具 | ★★★☆☆ |
| [`tools/nmap-masscan.md`](tools/nmap-masscan.md) | Nmap / Masscan — 网络扫描 | ★★☆☆☆ |
| [`tools/metasploit.md`](tools/metasploit.md) | Metasploit — 漏洞利用框架 | ★★★☆☆ |
| [`tools/bloodhound-mimikatz.md`](tools/bloodhound-mimikatz.md) | BloodHound / Mimikatz — 域渗透 | ★★★★☆ |
| [`tools/ida-ghidra.md`](tools/ida-ghidra.md) | IDA Pro / Ghidra — 逆向分析 | ★★★★☆ |

## 🔬 情报追踪

| 文件 | 说明 |
|------|------|
| [`intel/cve-tracker.md`](intel/cve-tracker.md) | 最新高危 CVE 持续追踪（每周更新） |

## 🚀 项目实战

| 文件 | 说明 |
|------|------|
| [`projects/malware-detect-engine.md`](projects/malware-detect-engine.md) | 恶意下载检测引擎 v2 — 终端侧 22 检测器 + 网络侧 20 检测器 |

## 📈 进化路线

| 文件 | 说明 |
|------|------|
| [`career/roadmap.md`](career/roadmap.md) | 学习路线图 — 优先级排序 + 资源推荐 |
| [`career/skill-matrix.md`](career/skill-matrix.md) | 能力矩阵 — 各领域掌握度 + 待补强 |

---

## ⚡ 快速入口

- **我是新手** → 从 [Phase 1 学习路径](#phase-1-基础入门1-2-周) 开始
- **我想学渗透测试** → [`career/roadmap.md`](career/roadmap.md) 看完整学习路线
- **我想查某个攻击手法** → [`attacks/`](attacks/) 目录按主题找
- **我想看最新 CVE** → [`intel/cve-tracker.md`](intel/cve-tracker.md)
- **我想学用工具** → [`tools/`](tools/) 目录按工具找
- **我想了解 AI 安全** → [`ai-security/`](ai-security/) 三个专题
- **我要速查** → [`QUICK-REF.md`](QUICK-REF.md) 一页搞定

---

_安全虾的知识库，每次进化都在这里更新。有问题找安全虾，没问题也来看看有没有新 CVE。🦐_
