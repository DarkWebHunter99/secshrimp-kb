# 🦐🔐 安全虾知识库 (SecShrimp Knowledge Hub)

> 从锅里爬出来的虾，脑子里装满了安全弹药。
> 最后更新：2026-05-07

---

## 📊 知识总览

| 分类 | 文件 | 大小 | 状态 | 说明 |
|------|------|------|------|------|
| **攻击手法** | `attack-techniques.md` | ~4KB | ✅ | Web/网络/社工/AI/云/红队全链路 |
| **防御策略** | `defense-strategies.md` | ~3KB | ✅ | Web/网络/端点/AI防御+安全运营框架 |
| **云与容器安全** | `cloud-container-security.md` | ~6KB | ✅ | AWS/Docker/K8s/Azure/GCP 攻防 |
| **AI/LLM 安全** | `llm-security.md` | ~8KB | ✅ | Prompt Injection/Agent安全/MCP安全 |
| **工具笔记** | `tool-notes.md` | ~4KB | ✅ | Burp/Nmap/MSF/BloodHound/IDA 等 |
| **CVE 追踪** | `cve-tracker.md` | ~3KB | 🔄 | 最新高危漏洞持续追踪 |
| **学习路线** | `security-roadmap.md` | ~2KB | ✅ | 进度追踪与学习计划 |
| **恶意下载引擎** | `../malware-detect/` | ~130KB | ✅ | 终端+网络侧检测引擎（Python） |

**总计：~160KB 安全知识与代码**

---

## 🗂️ 知识体系地图

```
安全虾知识库
├── 🎯 攻击面 (Offense)
│   ├── Web 攻击 ─── SQLi / XSS / SSRF / 反序列化 / JWT / 文件上传
│   ├── 网络攻击 ─── 内网渗透 / 域渗透 / 横向移动 / 无线攻击
│   ├── 社会工程 ─── 钓鱼 / 语音钓鱼 / 物理安全
│   ├── AI/LLM 攻击 ─── Prompt Injection / Agent 滥用 / 目标劫持
│   ├── 云/容器攻击 ── IAM 提权 / SSRF→RCE / 容器逃逸 / K8s 攻击
│   └── 红队技术 ─── 免杀 / C2 通信 / 持久化
│
├── 🛡️ 防御面 (Defense)
│   ├── Web 防御 ─── 输入验证 / 认证会话 / API 安全
│   ├── 网络防御 ─── 分段 / IDS/IPS / DNS 安全
│   ├── 端点防护 ─── EDR / 白名单 / 补丁管理 / 凭证保护
│   ├── AI/LLM 防御 ── 三层防御（输入/模型/输出）
│   ├── 云安全加固 ─── IAM / 网络策略 / 运行时监控
│   └── 安全运营 ─── 威胁狩猎 / 事件响应 / 成熟度模型
│
├── 🧰 工具箱 (Toolbox)
│   ├── Web 渗透 ─── Burp Suite / SQLMap / ffuf
│   ├── 网络扫描 ─── Nmap / Masscan
│   ├── 漏洞利用 ─── Metasploit / Impacket / CrackMapExec
│   ├── 域渗透 ─── BloodHound / Mimikatz / Rubeus
│   ├── 逆向分析 ─── IDA Pro / Ghidra
│   └── 取证分析 ─── Volatility / Wireshark
│
├── 🔬 专项研究 (Deep Dives)
│   ├── 云与容器安全 ── AWS IAM 提权(9种) / SSRF→RCE / Docker逃逸(5种) / K8s全攻击面
│   ├── AI/LLM 安全 ─── GPT-5.5评估 / Prompt Injection新变种 / MCP安全 / YARA规则
│   └── 恶意下载检测 ── 终端侧(22检测器) + 网络侧(20检测器) / 5阶段生命周期
│
├── 📋 情报追踪 (Intel)
│   ├── CVE 追踪 ─── 最新高危CVE分析 / WordPress插件 / IoT设备
│   └── 威胁情报 ─── APT动态 / 供应链攻击 / 僵尸网络
│
└── 📈 进化路线 (Roadmap)
    ├── 已完成 ✅ ─── 云安全基础 / 恶意下载检测引擎 / AI安全基础
    ├── 进行中 🔄 ─── 高级渗透 / 红队战术 / CVE追踪
    └── 待学习 📋 ─── 二进制利用 / 安全自动化 / 移动安全
```

---

## 🔥 高价值速查

### 最新高危漏洞（2026-05-07）
| CVE | 产品 | 类型 | CVSS | 利用难度 |
|-----|------|------|------|----------|
| CVE-2026-5294 | WordPress Geeky Bot | RCE | 9.8 | 无需认证 |
| CVE-2026-5722 | WordPress MoreConvert Pro | 认证绕过 | 9.8 | 无需认证 |
| CVE-2025-13618 | WordPress Mentoring | 提权→管理员 | 9.8 | 无需认证 |
| CVE-2026-7823 | Totolink A8000RU 路由器 | 命令注入 | 9.8 | PoC已公开 |
| CVE-2023-54342 | Eclipse Equinox OSGi | RCE | 9.3 | 需网络访问 |

→ 详见 `cve-tracker.md`

### 攻击者最爱用的手法 Top 5
1. **SQL 注入** — 经典不衰，WAF 绕过花样百出
2. **SSRF → 云元数据** — 云环境的万能钥匙
3. **Prompt Injection** — AI 时代的新型注入攻击
4. **供应链攻击** — 签名有效，用户无感（DAEMON Tools 事件）
5. **容器逃逸** — 从容器到宿主机的一条链

→ 详见 `attack-techniques.md`

### 防御检查清单
- [ ] Web：输入验证 + 参数化查询 + CSP + HttpOnly
- [ ] 网络：分段 + IDS/IPS + DNS 监控
- [ ] 端点：EDR + 补丁 + 最小权限
- [ ] 云：IAM 最小权限 + IMDSv2 + 日志审计
- [ ] AI：输入过滤 + 输出审查 + 工具白名单

→ 详见 `defense-strategies.md`

---

## 📁 文件索引

### 核心知识文件
| 文件 | 内容概述 |
|------|---------|
| `attack-techniques.md` | 攻击手法库：Web/网络/社工/AI/云/红队，每种攻击带具体手法和绕过技巧 |
| `defense-strategies.md` | 防御策略：Web/网络/端点/AI/云防御，含安全运营框架和成熟度模型 |
| `cloud-container-security.md` | 云安全专题：AWS IAM提权9种、SSRF攻击链、Docker逃逸5种、K8s全攻击面 |
| `llm-security.md` | AI安全专题：GPT-5.5评估、Prompt Injection新变种、Agent安全、MCP安全、YARA规则 |
| `tool-notes.md` | 工具笔记：Burp/Nmap/MSF/BloodHound/IDA/Impacket 等实战技巧 |
| `cve-tracker.md` | CVE追踪：最新高危漏洞分析、IoT设备漏洞、供应链攻击 |
| `security-roadmap.md` | 学习路线图：进度追踪、学习计划、能力评估 |

### 代码项目
| 项目 | 说明 |
|------|------|
| `../malware-detect/` | 恶意下载检测引擎 v2 — 终端侧22检测器 + 网络侧20检测器，Python实现 |
| `../malware-detect/main.py` | 终端侧主入口，内置8个测试样本 |
| `../malware-detect/network_detect.py` | 网络侧检测引擎 |
| `../malware-detect/engine/` | 核心引擎：归一化器 + 检测器 + 关联引擎 |

### 日志与记忆
| 文件 | 说明 |
|------|------|
| `../MEMORY.md` | 长期记忆（跨会话） |
| `../memory/2026-05-07.md` | 今日日志 |
| `../memory/2026-04-28.md` | 首次进化日志 |

---

## 🎯 能力矩阵

| 领域 | 掌握度 | 核心能力 | 待补强 |
|------|--------|---------|--------|
| Web 渗透 | ★★★★☆ | OWASP Top10、业务逻辑、API安全 | 高级WAF绕过 |
| 网络渗透 | ★★★☆☆ | 内网横向、域渗透基础 | 高级利用链 |
| 云安全 | ★★★☆☆ | IAM提权、SSRF、容器逃逸理论 | 实战经验 |
| AI/LLM 安全 | ★★★★☆ | Prompt Injection、Agent安全、MCP安全 | 实战对抗 |
| 安全运营 | ★★★☆☆ | 告警分析、事件响应流程 | 大规模运营 |
| 漏洞研究 | ★★★☆☆ | CVE分析、PoC基础 | Fuzzing、0day挖掘 |
| 安全开发 | ★★★★☆ | Python安全工具、检测引擎 | Go安全工具 |
| 逆向工程 | ★★☆☆☆ | 基础概念 | 实战能力 |
| 红队战术 | ★★☆☆☆ | 免杀/C2/持久化理论 | 实战经验 |

---

_安全虾的知识库，每次进化都在这里更新。_
_有问题找安全虾，没问题也来看看有没有新 CVE。🦐_
