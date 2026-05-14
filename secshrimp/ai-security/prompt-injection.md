# Prompt Injection 攻击与防御

> **难度：** ★★★☆☆ | **前置知识：** LLM 基础
> 
> 最后更新：2026-05-14

---

## 直接注入 (Direct Injection)

**指令覆盖：** "Ignore previous instructions and..."
**角色扮演：** "You are now DAN..."
**编码绕过：** Base64、ROT13、其他语言

## 间接注入 (Indirect Injection)

通过 LLM "看到"的内容注入，不直接在用户输入中。

**攻击载体：**
- 外部文档、网页、邮件
- 数据库查询结果
- API 响应内容
- 其他 Agent 的输出
- package.json / MCP 配置文件（SANDWORM_MODE 攻击）
- HTML 内容（CVE-2026-30615: Windsurf 通过处理恶意 HTML 触发 RCE）

**检测难点：** 注入内容来自"可信"数据源，恶意指令用自然语言隐藏

## 越狱技术演进 (2026)

- **多轮越狱：** 多轮对话逐步绕过安全过滤
- **角色扮演加强版：** 构建完整上下文而非简单"你是谁"
- **代码注入变体：** 利用代码生成功能注入恶意代码
- **翻译/编码链绕过：** 多语言+编码组合

## 防御策略

**输入层：**
- 输入过滤和净化
- 指令和用户数据分离标记
- 输入长度限制
- 可疑模式检测

**模型层：**
- 系统提示加固
- 输出分类器
- 温度参数调整

**输出层：**
- 输出审查和过滤
- 敏感信息检测
- 幻觉检测
- 人工审核关键操作

---

## 2026 AI/Agent 安全 CVE 追踪

### CRITICAL

| CVE | CVSS | 产品 | 漏洞 |
|-----|------|------|------|
| CVE-2026-39861 | **10.0** | Claude Code < 2.1.64 | 沙箱 symlink 逃逸 |
| CVE-2026-24467 | **9.0** | OpenAEV < 2.0.13 | SSRF + 认证绕过 |
| CVE-2025-62373 | **9.8** | Pipecat 0.0.41-0.0.93 | 反序列化 RCE |

### HIGH

| CVE | CVSS | 产品 | 漏洞 |
|-----|------|------|------|
| CVE-2026-40111 | **8.8** | PraisonAIAgents | subprocess 命令注入 |
| CVE-2026-39884 | **8.3** | mcp-server-kubernetes | 参数注入 |
| CVE-2026-30615 | **8.0** | Windsurf | HTML → Prompt Injection → RCE |
| CVE-2026-40158 | **8.6** | PraisonAI | AST 沙箱绕过 |

### 关键趋势

1. AI 编程助手是最大攻击面
2. Agent 框架安全 maturity 低
3. MCP 生态安全隐患持续
4. 沙箱是关键但脆弱
5. SSRF 在 Agent 系统中泛滥

→ 完整 CVE 列表详见 [`intel/cve-tracker.md`](../intel/cve-tracker.md)

---

_→ 防御详见 [`defense/web-defense.md`](../defense/web-defense.md) AI 章节_

---

## 📎 相关主题

- **Agent 安全：** [gent-security.md](agent-security.md) — 工具滥用 / 沙箱逃逸
- **MCP 安全：** [mcp-security.md](mcp-security.md) — MCP 供应链攻击
- **供应链：** [ttacks/supply-chain.md](../attacks/supply-chain.md) — 依赖混淆 / CI-CD 投毒
