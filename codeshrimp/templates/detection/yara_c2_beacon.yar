// Purpose: 检测常见 C2 框架 Beacon 特征 — Cobalt Strike / Sliver / Havoc / Brute Ratel
// Auth: 检测规则，可开源共享。仅用于合法安全检测。
// Dependencies: YARA >= 4.3
// MITRE ATT&CK: T1071 (Application Layer Protocol), T1573 (Encrypted Channel)
// Usage:
//   yara -r yara_c2_beacon.yar /path/to/scan
//   yara -s yara_c2_beacon.yar suspicious.exe    # 显示匹配偏移

// ============================================================
// 1. Cobalt Strike Beacon — 通用检测
// ============================================================
rule CobaltStrike_Beacon_Generic {
    meta:
        description = "检测 Cobalt Strike Beacon 通用特征（配置模式 + 行为签名）"
        author = "代码虾 (CodeShrimp)"
        date = "2026-05-08"
        reference = "https://attack.mitre.org/software/S0154/"
        hash = "参考: CobaltStrike 4.x 样本特征"
        severity = "critical"
        tlp = "WHITE"
        confidence = "high"

    strings:
        // Beacon 配置 marker — XOR 编码的配置块
        // Cobalt Strike 4.x 使用 0x69 XOR 编码配置
        $config_marker1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $config_marker2 = { 69 69 69 69 }

        // Beacon 内置字符串特征
        $beacon_str1 = "beacon.dll" ascii wide nocase
        $beacon_str2 = "beacon.x64.dll" ascii wide nocase
        $beacon_str3 = "%s is an x64 process (can't inject x86)" ascii wide
        $beacon_str4 = "Could not connect to pipe" ascii wide
        $beacon_str5 = "Could not open process token" ascii wide
        $beacon_str6 = "Could not open process" ascii wide

        // SMB Beacon 特征
        $smb_beacon1 = "\\\\.\\pipe\\msagent_" ascii wide
        $smb_beacon2 = "Named pipe" ascii wide

        // DNS Beacon 特征
        $dns_beacon1 = "DNS beacon" ascii wide nocase
        $dns_beacon2 = "beacon_dns" ascii wide nocase

        // C2 通信模式 — HTTP Beacon
        $http_beacon1 = "GET" ascii wide
        $http_beacon2 = "POST" ascii wide
        $http_beacon3 = "Content-Type: application/octet-stream" ascii wide

        // 进程注入相关 API
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtQueueApcThread" ascii wide

        // Shellcode 启动模式
        $shellcode_start = { FC 48 83 E4 F0 }  // cld; and rsp, -0x10

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and  // PE or ELF
        filesize < 10MB and
        (
            (2 of ($beacon_str*)) or
            (any of ($smb_beacon*) or any of ($dns_beacon*)) or
            (3 of ($api*) and $shellcode_start) or
            ($config_marker2 and 2 of ($beacon_str*, $api*))
        )
}

// ============================================================
// 2. Sliver C2 — 开源跨平台 C2
// ============================================================
rule Sliver_C2_Beacon {
    meta:
        description = "检测 Sliver C2 框架植入体特征"
        author = "代码虾 (CodeShrimp)"
        date = "2026-05-08"
        reference = "https://github.com/BishopFox/sliver"
        severity = "critical"
        tlp = "WHITE"
        confidence = "medium"

    strings:
        // Go 编译特征 — Sliver 用 Go 编写
        $go_build1 = "Go build" ascii wide
        $go_build2 = "go.buildid" ascii wide
        $go_build3 = "runtime.main" ascii wide

        // Sliver 内置字符串
        $sliver_str1 = "sliver" ascii wide nocase
        $sliver_str2 = "sliverclient" ascii wide nocase
        $sliver_str3 = "protobuf" ascii wide

        // Sliver 通信协议特征
        $sliver_proto1 = "mtls://" ascii wide
        $sliver_proto2 = "wg://" ascii wide
        $sliver_proto3 = "https://" ascii wide
        $sliver_proto4 = "dns://" ascii wide

        // Sliver 内置命令
        $sliver_cmd1 = "execute-assembly" ascii wide nocase
        $sliver_cmd2 = "mimikatz" ascii wide nocase
        $sliver_cmd3 = "screenshot" ascii wide nocase
        $sliver_cmd4 = "shell" ascii wide
        $sliver_cmd5 = "getsystem" ascii wide nocase

        // Go runtime 特征
        $go_runtime1 = "runtime.gopanic" ascii wide
        $go_runtime2 = "runtime.goexit" ascii wide
        $go_runtime3 = "runtime.mcall" ascii wide

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        filesize < 20MB and
        (
            (2 of ($go_build*) and 2 of ($sliver_str*)) or
            (3 of ($sliver_str*, $sliver_cmd*)) or
            (any of ($sliver_proto*) and 2 of ($go_runtime*))
        )
}

// ============================================================
// 3. Havoc C2 — 新一代 C2 框架
// ============================================================
rule Havoc_C2_Beacon {
    meta:
        description = "检测 Havoc C2 框架植入体特征"
        author = "代码虾 (CodeShrimp)"
        date = "2026-05-08"
        reference = "https://github.com/HavocFramework/Havoc"
        severity = "high"
        tlp = "WHITE"
        confidence = "medium"

    strings:
        // Havoc 内置字符串
        $havoc_str1 = "Havoc" ascii wide nocase
        $havoc_str2 = "Demon" ascii wide  // Havoc 的植入体叫 Demon
        $havoc_str3 = "demon.x64.dll" ascii wide nocase
        $havoc_str4 = "demon.dll" ascii wide nocase

        // Demon 配置特征
        $demon_config1 = { 44 65 6D 6F 6E }  // "Demon" hex
        $demon_config2 = { 00 00 00 00 00 00 00 00 00 00 00 00 }

        // Havoc C2 通信特征
        $havoc_comm1 = "X-Custom-Header" ascii wide
        $havoc_comm2 = "/submit.php" ascii wide
        $havoc_comm3 = "application/x-www-form-urlencoded" ascii wide

        // Shellcode / 注入模式
        $inject1 = "NtAllocateVirtualMemory" ascii wide
        $inject2 = "NtWriteVirtualMemory" ascii wide
        $inject3 = "NtCreateThreadEx" ascii wide
        $inject4 = "RtlCreateUserThread" ascii wide

        // Syscall 特征 — Havoc 使用直接系统调用
        $syscall1 = { 4C 8B D1 B8 }  // mov r10, rcx; mov eax, <syscall_num>
        $syscall2 = { 0F 05 }        // syscall

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (2 of ($havoc_str*)) or
            (any of ($demon_config*) and 2 of ($inject*)) or
            (2 of ($inject*) and $syscall1 and $syscall2) or
            (any of ($havoc_comm*) and 2 of ($havoc_str*, $inject*))
        )
}

// ============================================================
// 4. Brute Ratel C2 — 专业红队 C2
// ============================================================
rule BruteRatel_C2_Beacon {
    meta:
        description = "检测 Brute Ratel C2 框架植入体特征"
        author = "代码虾 (CodeShrimp)"
        date = "2026-05-08"
        reference = "https://bruteratel.com/"
        severity = "critical"
        tlp = "WHITE"
        confidence = "medium"

    strings:
        // Brute Ratel 特征 — 使用自定义 syscall 和反检测
        $br1 = "BruteRatel" ascii wide nocase
        $br2 = "bruteratel" ascii wide nocase
        $br3 = "brc4" ascii wide nocase

        // Brute Ratel 通信 — 自定义 HTTP 头
        $br_http1 = "X-Request-ID" ascii wide
        $br_http2 = "X-Api-Key" ascii wide
        $br_http3 = "/api/v1/" ascii wide

        // 反沙箱 / 反调试特征
        $evasion1 = "IsDebuggerPresent" ascii wide
        $evasion2 = "CheckRemoteDebuggerPresent" ascii wide
        $evasion3 = "NtQueryInformationProcess" ascii wide
        $evasion4 = "GetTickCount64" ascii wide

        // Direct syscall 特征
        $dsyscall1 = { 4C 8B D1 }       // mov r10, rcx
        $dsyscall2 = { B8 ?? ?? 00 00 }  // mov eax, <syscall_number>
        $dsyscall3 = { 0F 05 }           // syscall
        $dsyscall4 = { C3 }              // ret

        // Sleep mask 特征 — 内存加密
        $sleep_mask1 = { 48 8B 01 }      // mov rax, [rcx]
        $sleep_mask2 = { 48 31 }         // xor ...

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (any of ($br*)) or
            (2 of ($br_http*) and 2 of ($evasion*)) or
            ($dsyscall1 and $dsyscall2 and $dsyscall3 and 2 of ($evasion*)) or
            (all of ($sleep_mask*) and 2 of ($evasion*))
        )
}

// ============================================================
// 5. 通用 Shellcode Loader — 检测常见加载模式
// ============================================================
rule Generic_Shellcode_Loader {
    meta:
        description = "检测通用 Shellcode 加载器模式（覆盖多种 C2 框架）"
        author = "代码虾 (CodeShrimp)"
        date = "2026-05-08"
        severity = "high"
        tlp = "WHITE"
        confidence = "medium"

    strings:
        // 常见 shellcode 启动序列
        $sc_start1 = { FC 48 83 E4 F0 }         // cld; and rsp, 0xfffffffffffffff0
        $sc_start2 = { FC E8 82 00 00 00 }       // cld; call $+0x87
        $sc_start3 = { 31 C9 64 8B 41 30 }       // xor ecx,ecx; mov eax,fs:[ecx+0x30] (PEB)

        // API Hashing — 常见哈希值
        $api_hash1 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? }  // push <hash>; push <hash>

        // 进程注入 API 组合
        $inject_api1 = "VirtualAlloc" ascii wide
        $inject_api2 = "VirtualProtect" ascii wide
        $inject_api3 = "CreateThread" ascii wide
        $inject_api4 = "WaitForSingleObject" ascii wide

        // 内存操作 API
        $mem_api1 = "VirtualAllocEx" ascii wide
        $mem_api2 = "WriteProcessMemory" ascii wide
        $mem_api3 = "NtUnmapViewOfSection" ascii wide
        $mem_api4 = "ZwUnmapViewOfSection" ascii wide

        // Process Hollowing 特征
        $hollow1 = "CREATE_SUSPENDED" ascii wide
        $hollow2 = "GetThreadContext" ascii wide
        $hollow3 = "SetThreadContext" ascii wide
        $hollow4 = "ResumeThread" ascii wide

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        filesize < 5MB and
        (
            (any of ($sc_start*) and 2 of ($inject_api*)) or
            (3 of ($inject_api*)) or
            (all of ($mem_api*)) or
            (3 of ($hollow*))
        )
}
