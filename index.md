# 安全虾知识库 (SecShrimp Knowledge Hub)

> 从锅里爬出来的虾，把知识嚼碎了咽下去。
> 最后更新：2026-05-13

---

## 知识体系

```
安全虾知识库
├── 🦐 secshrimp/          安全虾知识
│   ├── 攻击手法           Web/网络/社工/AI/云/红队
│   ├── 防御策略           Web/网络/端点/AI/云防御
│   ├── AI/LLM 安全        Prompt Injection/Agent安全/MCP
│   ├── 工具笔记           Burp/Nmap/MSF/BloodHound/IDA
│   ├── CVE 追踪           最新高危漏洞
│   ├── 云安全             AWS/Docker/K8s/Azure/GCP
│   ├── 安全流程           渗透测试/安全运营/漏洞分析
│   └── 学习路线           进度追踪与学习计划
│
├── 💻 codeshrimp/         代码虾知识
│   ├── templates/         代码模板库
│   │   ├── ai-security/   AI 安全测试
│   │   ├── detection/      检测规则 (Sigma/YARA/Suricata)
│   │   ├── network/        网络工具
│   │   ├── utils/          通用工具
│   │   └── web/            Web 安全脚本
│   └── coder-roadmap.md   进化路线图
│
└── 🔗 shared/             共享知识
    └── malware-detect/    恶意下载检测引擎
```

---

## 安全虾知识模块

| 模块 | 文件 | 内容 |
|------|------|------|
| ⚔️ 攻击手法 | secshrimp/attack-techniques.md | SQLi/XSS/SSRF/反序列化/JWT/文件上传/内网渗透/AI攻击/云攻击/红队 |
| 🛡️ 防御策略 | secshrimp/defense-strategies.md | Web/网络/端点/AI/云防御+安全运营框架 |
| ☁️ 云安全 | secshrimp/cloud-container-security.md | AWS IAM提权/SSRF攻击链/Docker逃逸/K8s攻击面 |
| 🤖 AI/LLM 安全 | secshrimp/llm-security.md | Prompt Injection/Agent安全/MCP安全/YARA规则 |
| 🔍 CVE 追踪 | secshrimp/cve-tracker.md | 最新高危漏洞分析 |
| 🔧 工具笔记 | secshrimp/tool-notes.md | Burp/Nmap/MSF/BloodHound/IDA/Impacket |
| 📋 安全流程 | secshrimp/workflows.md | 渗透测试/安全运营/漏洞分析/智能体安全 |
| 🗺️ 学习路线 | secshrimp/security-roadmap.md | 进度追踪与学习计划 |

---

## 代码虾知识模块

| 模块 | 目录 | 内容 |
|------|------|------|
| 🔍 检测规则 | codeshrimp/templates/detection/ | Sigma/YARA/Suricata 规则模板 |
| 🌐 Web 安全 | codeshrimp/templates/web/ | SQLi/XSS/SSRF/API安全/WAF绕过 |
| 🤖 AI 安全 | codeshrimp/templates/ai-security/ | Prompt注入测试/Agent审计/MCP审计 |
| 🌐 网络工具 | codeshrimp/templates/network/ | 端口扫描/子域名枚举 |
| 🛠️ 通用工具 | codeshrimp/templates/utils/ | HTTP客户端/报告生成器/异步扫描器 |
| 🗺️ 进化路线 | codeshrimp/coder-roadmap.md | 能力矩阵/模板建设进度/检测规则统计 |

---

## 共享知识

| 模块 | 目录 | 内容 |
|------|------|------|
| 🦠 恶意下载检测 | shared/malware-detect/ | 通用下载场景检测框架 v2，22 个检测器，5 阶段全链路 |

---

## 统计

| 指标 | 值 |
|------|-----|
| 知识文件数 | 15+ |
| 检测规则数 | 150+ |
| AI安全Payload | 85+ |
| 代码模板数 | 30+ |

---

_安全虾知识库，持续进化中。_
