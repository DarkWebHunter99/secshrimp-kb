# IDA Pro / Ghidra / 分析工具

> **难度：** ★★★★☆ | **用途：** 逆向工程与恶意软件分析
> 
> 最后更新：2026-05-14

---

## IDA Pro 快捷键

| 快捷键 | 功能 |
|--------|------|
| `G` | 跳转到地址 |
| `X` | 交叉引用 |
| `F5` | 反编译（Hex-Rays） |
| `N` | 重命名 |
| `;` | 添加注释 |
| `Space` | 图表视图切换 |

## Ghidra 基本流程

1. 导入二进制文件
2. 自动分析（Auto Analysis）
3. 函数列表 → 找 main/关键函数
4. 反编译器窗口查看伪代码
5. 重命名函数和变量
6. 导出分析结果

## 分析技巧

- **字符串搜索：** 找提示信息、URL、错误消息
- **导入表分析：** API 调用推断功能
- **交叉引用：** 追踪数据流和调用链
- **补丁对比：** 新旧版本 diff 找漏洞修复点

---

## YARA 规则引擎

### 规则结构

```yara
rule RuleName {
    meta:
        author = "SecShrimp"
        severity = "high"
        mitre_attack = "T1027"
    strings:
        $s1 = "malicious_string" ascii wide
        $r1 = /powershell[- ]{1,5}(-enc|-e)/ ascii nocase
        $h1 = { 4D 5A 90 00 }  // MZ header
    condition:
        uint16(0) == 0x5A4D and filesize < 500KB and 2 of ($s*)
}
```

### 字符串修饰符

| 修饰符 | 含义 |
|--------|------|
| `ascii` | ASCII 字符串 |
| `wide` | UTF-16LE 字符串 |
| `nocase` | 不区分大小写 |
| `fullword` | 全词匹配 |
| `xor` | XOR 编码 |
| `base64` | Base64 编码 |

### 文件类型判断

```yara
uint16(0) == 0x5A4D          // PE (MZ)
uint32(0) == 0x464C457F      // ELF
uint32(0) == 0xCAFEBABE      // Java class
uint32(0) == 0x504B0304      // ZIP/JAR/Office
```

### YARA vs Sigma vs Snort

| 特性 | YARA | Sigma | Snort |
|------|------|-------|-------|
| 目标 | 文件/内存 | 日志/SIEM | 网络流量 |
| 粒度 | 二进制/字符串 | 事件日志 | 网络包 |
| 用途 | 恶意软件检测 | 威胁狩猎 | IDS/IPS |

---

## Nuclei — 模板化漏洞扫描器

```bash
# 扫描
nuclei -u https://target.com
nuclei -l urls.txt -severity critical,high

# 指定模板
nuclei -u target.com -t cves/
nuclei -u target.com -t http/wordpress/

# 集成流程
subfinder -d target.com -silent | httpx -silent | nuclei -severity critical,high
```

### 自定义模板

```yaml
id: custom-sqli-detection
info:
  name: Custom SQL Injection
  severity: high
  tags: sqli,web
requests:
  - method: GET
    path:
      - "{{BaseURL}}/?id=1'"
    matchers:
      - type: regex
        regex:
          - "mysql_fetch"
          - "ORA-\d{5}"
```

---

## Volatility 3 — 内存取证

```bash
# 系统识别
volatility3 -f memory.dmp windows.info

# 进程列表
volatility3 -f memory.dmp windows.pslist
volatility3 -f memory.dmp windows.pstree  # 带隐藏进程检测

# 恶意代码检测
volatility3 -f memory.dmp windows.malfind

# 网络连接
volatility3 -f memory.dmp windows.netscan

# 凭据提取
volatility3 -f memory.dmp windows.hashdump
volatility3 -f memory.dmp windows.lsadump

# 注册表
volatility3 -f memory.dmp windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

# 时间线
volatility3 -f memory.dmp timeliner.Timeliner
```

### 实战流程

```
系统识别 → 进程分析 → 恶意代码检测 → 网络取证 → 凭据提取 → 持久化检测 → 时间线
```

### 反取证检测

| 攻击技术 | 检测方法 |
|----------|----------|
| 进程隐藏（DKOM） | `pstree` 双向遍历 |
| 进程 Hollowing | `malfind` RWX + `memmap` 对比 |
| 反射 DLL | `malfind` PE header + 无 DLL 记录 |

---

_→ 参见 [`intel/cve-tracker.md`](../intel/cve-tracker.md) 获取最新 CVE_

---

## 相关主题

- **CVE 追踪:** [intel/cve-tracker.md](../intel/cve-tracker.md) - 最新漏洞
- **项目:** [projects/malware-detect-engine.md](../projects/malware-detect-engine.md) - 恶意软件检测
- **防御:** [defense/endpoint-defense.md](../defense/endpoint-defense.md) - 端点安全
