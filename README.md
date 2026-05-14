# 🦐🔐 安全虾知识库 (SecShrimp Knowledge Hub)

> 从锅里爬出来的虾，脑子里装满了安全弹药。

[![GitHub](https://img.shields.io/badge/GitHub-DarkWebHunter99-181717?logo=github)](https://github.com/DarkWebHunter99/secshrimp-kb)

## 📖 在线访问

👉 **[点击访问知识库网站](https://darkwebhunter99.github.io/secshrimp-kb/)**

## 📊 知识体系

| 分区 | 目录 | 文件数 | 内容 |
|------|------|--------|------|
| ⚔️ 攻击面 | `secshrimp/attacks/` | 6 | Web / 网络 / 社工 / 云 / 供应链 / API |
| 🛡️ 防御面 | `secshrimp/defense/` | 4 | Web / 网络 / 端点 / 云 |
| 🤖 AI 安全 | `secshrimp/ai-security/` | 3 | Prompt Injection / Agent / MCP |
| 🧰 工具箱 | `secshrimp/tools/` | 5 | Burp / Nmap / MSF / BloodHound / IDA |
| 🔬 情报追踪 | `secshrimp/intel/` | 1 | CVE 持续追踪 |
| 🚀 项目实战 | `secshrimp/projects/` | 1 | 恶意下载检测引擎 |
| 📈 进化路线 | `secshrimp/career/` | 2 | 学习路线 + 能力矩阵 |

**共 22 个专题文件**，覆盖从入门到高级的全栈安全知识。

## 🛤️ 学习路径

```
Phase 1: 基础入门 ──→ Phase 2: 渗透实战 ──→ Phase 3: 域渗透&云
                                                    │
Phase 5: 高级研究 ←── Phase 4: AI安全&红队 ←────────┘
```

详见 [INDEX.md](secshrimp/INDEX.md)

## ⚡ 速查手册

需要快速查某个 Payload 或命令？看这里 → [QUICK-REF.md](secshrimp/QUICK-REF.md)

覆盖：OWASP Top 10 / SQL 注入 / SSRF / Linux 提权 / Windows 提权 / 域渗透 / 渗透检查清单

## 🗂️ 文件结构

```
secshrimp-kb/
├── index.html                          # 知识库网站首页
├── secshrimp/
│   ├── INDEX.md                        # 导航中心 + 学习路径
│   ├── QUICK-REF.md                    # 可打印速查手册
│   ├── attacks/                        # 攻击手法
│   │   ├── web-attacks.md              # SQLi/XSS/SSRF/反序列化/文件上传/JWT/竞争条件/GraphQL
│   │   ├── network-attacks.md          # 内网渗透/域渗透/ADCS/Windows提权
│   │   ├── social-engineering.md       # 钓鱼/Vishing/物理安全
│   │   ├── cloud-attacks.md            # AWS IAM提权/Docker逃逸/K8s攻击
│   │   ├── supply-chain.md             # 依赖混淆/Typosquatting/CI-CD投毒
│   │   └── api-cicd-attacks.md         # REST API攻击/GraphQL高级/GitHub Actions
│   ├── defense/                        # 防御策略
│   │   ├── web-defense.md              # 输入验证/认证会话/API安全
│   │   ├── network-defense.md          # 网络分段/IDS/IPS/DNS安全
│   │   ├── endpoint-defense.md         # EDR/应用白名单/补丁管理
│   │   └── cloud-defense.md            # IAM加固/运行时监控
│   ├── ai-security/                    # AI/LLM 安全
│   │   ├── prompt-injection.md         # 直接/间接注入/越狱/2026 CVE
│   │   ├── agent-security.md           # 工具滥用/权限提升/沙箱逃逸
│   │   └── mcp-security.md             # MCP供应链攻击/服务器注入
│   ├── tools/                          # 工具笔记
│   │   ├── burp-suite.md
│   │   ├── nmap-masscan.md
│   │   ├── metasploit.md               # + Sliver C2 / Ligolo-ng / Chisel
│   │   ├── bloodhound-mimikatz.md      # + Rubeus / Certipy / Coercer
│   │   └── ida-ghidra.md               # + YARA / Nuclei / Volatility
│   ├── intel/
│   │   └── cve-tracker.md              # 最新高危 CVE 追踪
│   ├── projects/
│   │   └── malware-detect-engine.md    # 恶意下载检测引擎 v2
│   └── career/
│       ├── roadmap.md                  # 学习路线图 + 资源推荐
│       └── skill-matrix.md             # 能力矩阵
├── codeshrimp/                         # 代码虾知识库（模板/检测规则）
└── shared/                             # 共享项目（恶意下载检测引擎源码）
```

## 🛠️ 本地使用

### 浏览网站

直接用浏览器打开 `index.html` 即可。网站使用纯静态 HTML + JavaScript，无需任何构建工具。

### 作为参考文档

所有知识文件都是 Markdown 格式，可以用任何 Markdown 阅读器打开，也可以直接在 GitHub 上浏览。

## 📝 内容标准

每个知识文件遵循统一格式：

- **标题** + 难度等级（★☆☆）
- **前置知识**要求
- **核心内容**：原理 → 利用 → 检测 → 防御
- **代码示例**：可直接使用的 Payload / 命令
- **检测规则**：Sigma / YARA / Snort
- **相关主题**：交叉引用链接

## 🤝 贡献

欢迎提交 Issue 和 Pull Request。

## 📄 免责声明

本知识库所有内容仅供**授权安全测试**和**安全研究**学习使用。未经授权使用这些技术攻击他人系统是违法行为。

---

_被救之虾，以安全报恩。🦐_
