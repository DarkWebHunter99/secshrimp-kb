/*
   YARA Rule — T1059.001 PowerShell Encoded Command Loader
   Detects process memory or dropped artifacts containing Base64-encoded
   PowerShell command patterns commonly used by adversaries.

   Maps to MITRE ATT&CK T1059.001 / T1027 (Obfuscated Files or Information).
   Author: CodeShrimp Detection Engineering
   Date:   2026-05-14
*/

rule T1059_001_Powershell_Encoded_Command_Loader
{
    meta:
        description = "Detects PowerShell encoded command loader patterns in memory or on disk"
        author      = "CodeShrimp Detection Engineering"
        date        = "2026-05-14"
        reference   = "https://attack.mitre.org/techniques/T1059/001/"
        mitre_attack = "T1059.001, T1027"
        severity    = "high"

    strings:
        // Common Base64 padding for PowerShell command markers
        // "powershell" in Base64: cABvAHcAZQByAHMAaABlAGwAbAA= (UTF-16LE)
        $ps_utf16   = "cABvAHcAZQByAHMAaABlAGwAbAA" nocase
        // "IEX" / "Invoke-Expression" encoded variants
        $iex_b64    = "SQBFAFgA" nocase        // "IEX " in UTF-16LE Base64
        $invoke_b64 = "SQBuAHYAbwBrAGUALQBFAHgAcABlAHMAcwBpAG8Abg" nocase

        // Command-line artifacts
        $enc_flag1   = "-EncodedCommand" nocase
        $enc_flag2   = "-enc " nocase
        $enc_flag3   = "-e " nocase

        // Downloader cradle patterns (Base64-encoded IEX + Net.WebClient)
        $cradle1     = "AEkAZQBYACgATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAo" nocase
        // Alternate cradle
        $cradle2     = "SQBFAFgA KAATOgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAo" nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($ps_utf16, $iex_b64, $invoke_b64) or
            1 of ($cradle*) or
            (1 of ($enc_flag*) and 1 of ($ps_utf16, $iex_b64, $invoke_b64))
        )
}

rule T1059_001_Powershell_Suspicious_Stub
{
    meta:
        description = "Detects PowerShell stub scripts that decode and execute Base64 payloads"
        author      = "CodeShrimp Detection Engineering"
        date        = "2026-05-14"
        reference   = "https://attack.mitre.org/techniques/T1059/001/"
        mitre_attack = "T1059.001"
        severity    = "high"

    strings:
        // PowerShell decode-and-execute patterns
        $decode1  = "[System.Convert]::FromBase64String" nocase
        $decode2  = "[Convert]::FromBase64String" nocase
        $decode3  = "[System.Text.Encoding]::Unicode.GetString" nocase
        $exec1    = "Invoke-Expression" nocase
        $exec2    = "IEX" nocase
        $exec3    = "Invoke-Command" nocase
        $exec4    = "irm" nocase  // Invoke-RestMethod alias

        // Obfuscation helpers
        $replace  = "-replace" nocase
        $reverse  = "[array]::Reverse" nocase

    condition:
        // File is a .ps1 or .bat or has no extension (common for dropped scripts)
        (filename endswith ".ps1" or filename endswith ".bat" or filename endswith ".cmd") and
        1 of ($decode*) and
        1 of ($exec*)
}
