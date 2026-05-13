# 代码虾进化路线图 — Coder Roadmap

_最后更新: 2026-05-11_

## 当前能力矩阵

| 语言/框架 | 熟练度 | 主要用途 |
|-----------|--------|---------|
| Python | ⭐⭐⭐⭐⭐ | 安全工具开发、自动化、PoC |
| Go | ⭐⭐⭐ | 高并发扫描、网络工具 |
| PowerShell | ⭐⭐⭐ | 内网渗透、Windows 检测 |
| Bash | ⭐⭐⭐ | 快速验证、日志分析 |
| Sigma/YARA/Suricata | ⭐⭐⭐⭐⭐ | 检测规则编写（已产出 80+ 条规则） |

## 代码模板建设优先级

### P0 — 核心武器（已完成 ✅）
- [x] `web/sqli_detector.py` — SQL 注入检测（联合注入/盲注/时间盲注/报错注入）
- [x] `web/xss_scanner.py` — XSS 检测（反射/存储/DOM）
- [x] `detection/sigma_template.yaml` — Sigma 规则标准模板
- [x] `detection/yara_template.yar` — YARA 规则标准模板
- [x] `ai-security/prompt_injection_test.py` — Prompt 注入测试框架（v2 增强版）
- [x] `utils/http_client.py` — 安全 HTTP 客户端（v2 增强版：异步/WAF 检测/批量）
- [x] `utils/report_generator.py` — 安全报告生成器

### P1 — 扩展武器库（已完成 ✅）
- [x] `web/ssrf_tester.py` — SSRF 检测与利用 v2（字典驱动+URL解析修复）
- [x] `web/api_security.py` — API 安全测试（认证/IDOR/速率限制）
- [x] `network/port_scanner.go` — 高并发端口扫描
- [x] `network/subdomain_enum.py` — 子域名枚举
- [x] `network/lateral_movement.ps1` — 横向移动检测脚本
- [x] `detection/suricata_template.rules` — Suricata IDS 规则模板
- [x] `ai-security/agent_security_audit.py` — AI Agent 安全审计框架

### P2 — 高级能力（部分完成）
- [x] `web/waf_bypass_tester.py` — WAF 绕过测试
- [x] `web/deserialization_scanner.py` — 反序列化漏洞检测 v1（Java/Python/PHP/.NET，600+ 行）
- [ ] `network/kerberos_attack.py` — Kerberos 攻击检测
- [x] `detection/elastic_query_builder.py` — Elasticsearch 检测查询构建器
- [x] `ai-security/mcp_tool_audit.py` — MCP 工具安全审计
- [x] `utils/async_scanner_utils.py` — 异步扫描器基础设施 v2（httpx+tenacity+aiolimiter，优化自适应限速+并发）

## 检测规则模板库（截至 2026-05-12）

### Sigma 规则
| 文件 | 规则数 | 覆盖场景 | MITRE ATT&CK |
|------|--------|---------|-------------|
| sigma_powershell_abuse.yaml | 6 | 编码命令/下载 cradle/AMSI 绕过/WMI/剪贴板/日志禁用 | T1059.001 |
| attck_t1059_002_command_shell.yaml | 10 | 编码命令/下载执行/反弹Shell/环境变量/LOLBAS/嵌套/攻击链 | T1059.002 |
| sigma_lsass_dump_detection.yaml | 6 | 直接内存访问/ProcDump/comsvcs/PPL bypass/SAM 提取 | T1003.001 |
| attck_t1546_event_triggered_execution.yaml | 5 | Screensaver/WMI 事件/辅助功能/AppInit/IFEO | T1546 |
| attck_t1078_valid_accounts.yaml | 6 | 异常登录/Pass-the-Hash/凭据填充/服务账户/内置账户 | T1078 |
| sigma_lotl_attack_detection.yaml | 13 | BITS/WMI/计划任务/服务/Certutil/MSHTA/进程注入/攻击链 | T1197/T1047/T1053 |
| attck_t1070_indicator_removal.yaml | 14 | 日志清除/命令历史/文件删除/时间戳/网络连接/Linux 日志 | T1070 |
| attck_t1053_scheduled_tasks.yaml | 11 | 任务创建/修改/删除/远程操作/触发器/组策略/执行 | T1053.005 |
| attck_t1558_kerberos_attacks.yaml | 10 | Kerberoasting/AS-REP Roasting/Golden Ticket/Silver Ticket/加密降级 | T1558 |
| attck_t1059_007_javascript_abuse.yaml | 9 | wscript/cscript/mshta/Node.js/Chrome DevTools/JScript .NET/混淆/持久化 | T1059.007 |
| attck_t1552_unsecured_credentials.yaml | 8 | 文件凭据/SAM提取/注册表/浏览器/云凭据/搜索/密码喷洒/暴力破解 | T1552 |

### Suricata 规则
| 文件 | 规则数 | 覆盖场景 |
|------|--------|---------|
| suricata_c2_tunnel_detection.rules | 25 | JA3/JA3S 指纹/TLS 异常/DNS 隧道/HTTP C2/Beacon 模式 |
| suricata_scheduled_task_abuse.rules | 17 | SMB/WMI/WinRM/DCOM 远程任务创建/数据外泄/阈值检测 |

### YARA 规则
| 文件 | 规则数 | 覆盖场景 |
|------|--------|---------|
| yara_c2_beacon.yar | 5 | Cobalt Strike/Sliver/Havoc/Brute Ratel/通用 Loader |
| yara_scheduled_task_abuse.yar | 5 | PowerShell/VBScript/PE API/XML 后门配置/攻击框架 |

**检测规则总计: 150+ 条**

## AI 安全测试模板库（截至 2026-05-11）

| 文件 | 内容 | OWASP/ATT&CK 映射 |
|------|------|-------------------|
| prompt_injection_test.py | 测试框架（v2 格式 + severity 过滤） | LLM01 |
| advanced_injection_payloads.json | 20 个高级注入 payload | LLM01/LLM06/LLM09 |
| advanced_injection_payloads_v2.json | 15 个多模态/链式 payload | LLM01/LLM06 |
| agent_injection_payloads.json | 20 个 Agent 场景注入 payload | LLM01/LLM06/LLM09 |
| tool_output_poisoning_payloads.json | 15 个工具输出投毒 payload | LLM01/LLM06/LLM07/LLM09 |
| rag_injection_payloads.json | 15 个 RAG 系统注入 payload | LLM01/LLM05/LLM06/LLM09 |
| agent_security_audit.py | Agent 安全审计框架 | LLM06 |
| mcp_tool_audit.py | MCP 工具安全审计 | LLM06 |

## Heartbeat 进化统计

| 指标 | 值 |
|------|-----|
| 总 heartbeat 次数 | 16 |
| 当前周期 | cycleCount=7 |
| 已产出模板文件数 | 30+ |
| 已产出检测规则数 | 150+ |
| 已产出 AI 安全 payload 数 | 85+ |
| 已 promote 到 AGENTS.md 的模式 | 1（架构设计原则） |

## 下一步计划

### 近期（P0）
- [x] 反序列化漏洞扫描器（Java/Python/PHP/Node.js）✅
- [x] 深度编码任务（cycleCount=6，Heartbeat #15）：反序列化扫描器完整工具 ✅
- [x] Prompt 注入测试模板库扩充 — 工具输出投毒 15 条 ✅
- [x] Prompt 注入测试模板库扩充 — RAG 系统注入 15 条 ✅
- [x] T1059.002 Command Shell 检测规则 10 条 ✅

### 中期（P1）
- [ ] Kerberos 攻击检测（AS-REP Roasting/Kerberoasting/Golden Ticket）
- [ ] 自动化红队 Prompt 生成器
- [ ] LLM 安全基准测试套件

### 远期（P2）
- [ ] 防御性 System Prompt 模板库
- [ ] AI 安全评估报告自动化
- [ ] 供应链攻击检测规则
