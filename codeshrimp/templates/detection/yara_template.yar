// Purpose: YARA 规则标准模板 — 用于恶意软件检测、文件特征匹配、内存扫描
// Auth: 检测规则可开源共享，使用时请确认扫描目标合法
// Dependencies: YARA >= 4.3 (yara/yarac)
// Usage:
//   yara -r my_rule.yar /path/to/scan
//   yara -C compiled_rules.yarc /path/to/scan    (编译后更快)
//   yarac my_rule.yar compiled_rules.yarc         (预编译)

rule Template_Rule_Name {
    // ============================================================
    // 元数据
    // ============================================================
    meta:
        description = "规则用途描述"
        author = "代码虾 (CodeShrimp)"
        date = "2026-04-28"
        modified = "2026-04-28"
        reference = "https://attack.mitre.org/techniques/Txxxx/"
        hash = "样本 SHA256（如果有参考样本）"
        severity = "medium"                      // informational|low|medium|high|critical
        tlp = "WHITE"                            // TLP 分类
        confidence = "medium"                    // low|medium|high

    // ============================================================
    // 字符串特征
    // ============================================================
    strings:
        // --- 文本字符串 ---
        $s1 = "suspicious string" ascii wide      // ascii + wide (Unicode) 匹配
        $s2 = "malicious function" nocase         // 大小写不敏感

        // --- 十六进制字符串 ---
        $hex1 = { E8 ?? ?? ?? ?? 8B [2-4] 50 }   // ?? 通配符, [2-4] 跳跃

        // --- 正则表达式 ---
        $re1 = /cmd\.exe\s+\/c\s+[a-zA-Z0-9+\/=]{20,}/ nocase
        $re2 = /https?:\/\/[a-z0-9\-\.]+\/[a-z]{8,12}\.php/ nocase

        // --- 按类别分组（便于 condition 引用） ---
        // 文件类型特征
        // $pe_header = "MZ"
        // $elf_header = { 7F 45 4C 46 }

        // 可疑 API 调用
        // $api_virtualalloc = "VirtualAlloc" ascii wide
        // $api_createprocess = "CreateProcess" ascii wide
        // $api_writeprocessmem = "WriteProcessMemory" ascii wide

        // 加密/编码相关
        // $crypto_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    // ============================================================
    // 条件逻辑
    // ============================================================
    condition:
        // --- 常见模式 ---

        // 模式1: 匹配任意 N 个字符串
        // any of ($s*) or any of ($hex*)

        // 模式2: 至少 N 个来自某组
        // 2 of ($s1, $s2, $s3)

        // 模式3: 组合条件 + 文件大小限制
        // filesize < 2MB and
        //   (any of ($s*) or all of ($hex*))

        // 模式4: 在特定偏移位置匹配
        // $s1 at 0 and $hex1 in (100..500)

        // 模式5: 循环匹配（每个匹配计数）
        // for any of ($s*) : (# > 3)

        // 模式6: PE 文件特征
        // uint16(0) == 0x5A4D and                 // MZ header
        //   filesize < 5MB and
        //   any of them

        // TODO: 替换为实际条件
        any of them
}

// ============================================================
// 补充规则模板（按需复制）
// ============================================================

// --- 多文件关联规则 ---
// rule Related_Files {
//     meta:
//         description = "检测相关文件家族"
//     strings:
//         $marker = "unique_family_marker"
//     condition:
//         $marker
// }

// --- 内存扫描规则 ---
// rule Memory_Scan_Template {
//     meta:
//         description = "内存中检测 shellcode 特征"
//         scope = "memory"
//     strings:
//         $shellcode = { FC 48 83 E4 F0 E8 C0 00 00 00 }
//     condition:
//         $shellcode
// }

// --- Webshell 检测规则 ---
// rule Webshell_Template {
//     meta:
//         description = "检测常见 Webshell 特征"
//         filetype = "php|asp|aspx|jsp"
//     strings:
//         $php_eval = "eval(" ascii wide
//         $php_system = "system(" ascii wide
//         $php_base64 = "base64_decode(" ascii wide
//     condition:
//         any of them
// }
