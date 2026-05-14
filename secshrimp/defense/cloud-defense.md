# 云安全加固策略

> **难度：** ★★★☆☆ | **前置知识：** 云平台基础（AWS/Azure/GCP）
> 
> 最后更新：2026-05-14

---

## 核心原则

- **最小权限**（IAM/ServiceAccount）
- **纵深防御**（多层安全控制）
- **不可变基础设施**（IaC + GitOps）
- **持续监控**（CloudTrail/Config/Audit Logs）
- **自动化响应**（安全事件自动处理）
- **零信任**（不信任任何内部流量）

---

## AWS 安全加固

**IAM 最小权限：**
- 定期审计 IAM 策略（`aws iam simulate-principal-policy`）
- 禁用根账户访问密钥
- 强制 MFA
- 使用 IAM Roles 替代长期凭证

**EC2 安全：**
- IMDSv2 强制启用（防 SSRF 元数据攻击）
- 安全组最小化（仅开放必要端口）
- 实例级 IAM Role 最小权限

**S3 安全：**
- 默认私有（Block Public Access）
- 加密（SSE-S3 / SSE-KMS）
- 访问日志启用
- 策略条件限制 VPC/来源 IP

---

## Azure 安全加固

- Managed Identity 最小权限
- Azure AD Conditional Access
- Key Vault 密钥管理
- Network Security Group (NSG) 微分段
- Azure Defender 威胁检测

---

## GCP 安全加固

- Service Account 密钥轮换
- Organization Policy 约束
- VPC Service Controls
- Cloud Armor WAF
- Security Command Center

---

## Kubernetes 安全

**Pod 安全：**
```yaml
# Pod Security Standards (restricted)
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  automountServiceAccountToken: false  # 不自动挂载 SA token
  securityContext:
    runAsNonRoot: true
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false
  containers:
  - name: app
    securityContext:
      capabilities:
        drop: ["ALL"]  # 丢弃所有 capabilities
```

**RBAC 最小权限：**
- 审计所有 ClusterRoleBinding
- 限制 ServiceAccount 权限
- 禁用匿名访问

**网络策略：**
```yaml
# 默认拒绝所有入站
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

**运行时安全：** Falco / Sysdig 监控异常系统调用

---

## 恶意下载检测引擎

Security Researcher自研的检测引擎，覆盖终端侧和网络侧：

- **终端侧：** 22 个检测器，5 阶段生命周期
- **网络侧：** 20 个检测器，行为 + 数据包双维度
- 详见 [`projects/malware-detect-engine.md`](../projects/malware-detect-engine.md)

---

_→ 攻击手法详见 [`attacks/cloud-attacks.md`](../attacks/cloud-attacks.md)_

---

## 相关主题

- **云攻击:** [attacks/cloud-attacks.md](../attacks/cloud-attacks.md) - AWS IAM 提权 / Docker 逃逸
- **端点防护:** [endpoint-defense.md](endpoint-defense.md) - EDR / 凭证保护
- **项目:** [projects/malware-detect-engine.md](../projects/malware-detect-engine.md) - 检测引擎
