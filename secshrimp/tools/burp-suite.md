# Burp Suite 工具笔记

> **难度：** ★★★☆☆ | **用途：** Web 渗透核心工具
> 
> 最后更新：2026-05-14

---

## 核心功能

| 模块 | 用途 |
|------|------|
| **Proxy** | 拦截和修改 HTTP 请求/响应 |
| **Intruder** | 自动化攻击（暴力破解、参数 fuzz） |
| **Repeater** | 手工重放和测试请求 |
| **Scanner** | 自动化漏洞扫描（Pro 版） |
| **Sequencer** | 随机性分析（Session token 等） |

## 实战技巧

- **自动替换：** Proxy → Options → Match and Replace（自动替换头、参数）
- **Intruder Payload：** 用 `§` 标记多个位置，pitchfork/cluster bomb 模式
- **宏录制：** 自动处理 CSRF token、登录刷新
- **Bypass WAF：** chunked 编码、分块传输绕过

## 推荐扩展

| 扩展 | 用途 |
|------|------|
| HackBar | 快速编码/解码 |
| Logger++ | 增强日志 |
| Autorize | 权限测试自动化 |
| JSON Beautifier | JSON 格式化 |
| Turbo Intruder | 高并发 Intruder |

## 热键

- `Ctrl+R` → 发送到 Repeater
- `Ctrl+I` → 发送到 Intruder
- `Ctrl+Shift+D` → 发送到 Decoder

---

_→ 参见 [`attacks/web-attacks.md`](../attacks/web-attacks.md) 获取 Web 攻击手法_

---

## 相关主题

- **Web 攻击:** [attacks/web-attacks.md](../attacks/web-attacks.md) - SQLi / XSS / SSRF
- **Web 防御:** [defense/web-defense.md](../defense/web-defense.md) - 安全头 / 认证
- **API 攻击:** [attacks/api-cicd-attacks.md](../attacks/api-cicd-attacks.md) - API 安全测试
