# 供应链攻击

> **难度：** ★★★☆☆ | **前置知识：** 包管理基础（npm/pip/maven）、CI/CD 概念
> 
> 最后更新：2026-05-14

---

## 依赖混淆 (Dependency Confusion)

**原理：** 包管理器默认从公共仓库拉取版本号更高的包，攻击者在公共仓库注册与企业内部包同名的恶意包。

**利用条件：**
- 企业内部包名未在公共仓库注册
- 内部 registry 优先级低于公共仓库
- 未锁定版本或校验 hash

**攻击流程：**
```
枚举目标（公开源码/CI日志/package.json泄露）
→ 注册同名包（版本 99.0.0）
→ 注入恶意代码（postinstall 脚本）
→ 窃取数据（环境变量/.npmrc/API Key/SSH Key）
→ 反弹 shell / C2
```

**真实案例：** Alex Birsan (2021) 攻击 Apple/Microsoft/Tesla 等 35+ 家公司

**防御：** 使用 scoped 包 `@company/`、锁定版本 + hash 校验、私有 registry 优先、`--ignore-scripts`

---

## Typosquatting（恶意包注入）

**手法：**
```
requests    → requestss / requesets / rnquests
django      → dajngo / django2
flask       → flak / flaskk
lodash      → lodahsh / 1odash
express     → exprez / exprss
```

**进阶变种：**
- 字符替换：`l` → `1`、`o` → `0`、`rn` → `m`
- 域名级 typosquatting：`pypi.org` → `pyp1.org`
- 品牌滥用：注册看似官方的包名

**防御：** 锁定版本 + hash、安装前检查包的下载量/维护者/仓库

---

## 软件供应链攻击（SolarWinds 级）

**攻击链：**
```
入侵开发者工作站/CI/CD → 修改源码/构建流程 → 后门编译进发布包
→ 官方更新渠道分发 → 用户安装「正版」= 安装后门
```

**著名案例：**

| 事件 | 年份 | 影响 |
|------|------|------|
| SolarWinds Sunburst | 2020 | 18000+ 组织，美国政府 |
| Codecov Bash Uploader | 2021 | CI/CD 凭证泄露 |
| ua-parser-js | 2021 | npm 劫持，挖矿+密码窃取 |
| 3CX Desktop App | 2023 | 60万+ 用户，Lazarus |
| xz-utils backdoor | 2024 | Linux SSH 后门 |
| SANDWORM_MODE | 2026 | 首个在野 MCP 供应链攻击 |

**防御：** SBOM（软件物料清单）、SLSA 框架、代码签名 + 可重现构建、审计 CI/CD

---

## CI/CD 管道攻击

**GitHub Actions 攻击：**

```yaml
# 危险：PR 标题直接插入 shell → 命令注入
- run: echo "PR title: ${{ github.event.pull_request.title }}"

# 危险：使用分支引用（可被篡改）
- uses: actions/checkout@main
# 安全：固定到 SHA
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
```

**Docker 镜像投毒：**
- 基础镜像攻击：使用未知来源镜像
- 多阶段构建泄露：`docker history` 提取中间层 secrets
- 镜像签名验证（Cosign / Notary）

**检测：** 审计 workflow 变更、Secret 扫描（gitleaks）、异常 GITHUB_TOKEN 使用

**防御：** 最小权限 GITHUB_TOKEN、OIDC 替代长期凭证、镜像签名 + 策略验证

---

_→ 参见 [`ai-security/mcp-security.md`](../ai-security/mcp-security.md) 获取 MCP 供应链攻击详情_

---

## 相关主题

- **MCP 安全:** [ai-security/mcp-security.md](../ai-security/mcp-security.md) - MCP 供应链攻击
- **API/CI-CD:** [api-cicd-attacks.md](api-cicd-attacks.md) - GitHub Actions / Docker 投毒
- **防御:** [defense/endpoint-defense.md](../defense/endpoint-defense.md) - 依赖审计 / 补丁管理
