# 社会工程攻击

> **难度：** ★★☆☆☆ | **前置知识：** 无
> 
> 最后更新：2026-05-14

---

## 钓鱼攻击 (Phishing)

**邮件钓鱼：**
- SPF/DKIM/DMARC 绕过
- HTML 邮件模板伪造（品牌冒充）
- 附件：Office 宏、HTA、LNK、ISO（绕过 MOTW）
- 链接：域名仿冒、URL 缩短、二维码

**鱼叉钓鱼 (Spear Phishing)：**
- 目标信息收集（LinkedIn、社交媒体、企业官网）
- 定制化内容和诱饵（参考目标近期事件/兴趣）
- 水坑攻击：入侵目标常访问的网站

**语音钓鱼 (Vishing)：**
- 来电显示伪造（VoIP）
- IT 支持社工（冒充 Help Desk）
- 双因素认证绕过（实时获取验证码）

**短信钓鱼 (Smishing)：**
- 短链接 + 紧急通知
- 冒充银行/快递/政府机构

---

## 物理安全

- USB 投放（Rubber Ducky、BadUSB、O.MG Cable）
- 尾随进入（Tailgating）
- 门禁卡克隆（Proxmark）
- 网络接口物理接入
- 垃圾翻找（Dumpster Diving）

---

## 防御

- 安全意识培训（定期钓鱼演练）
- 邮件网关（沙箱附件检测）
- 多因素认证（减少凭证被盗影响）
- 物理安全策略（访客管理、设备锁）
- 事件响应流程

---

_→ 参见 [`defense/web-defense.md`](../defense/web-defense.md) 获取邮件安全防御_
