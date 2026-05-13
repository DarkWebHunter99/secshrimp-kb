/*
Purpose: YARA 规则 — T1053.005 Scheduled Task 滥用脚本检测
Auth: 仅限授权使用
Coverage: T1053.005 (Scheduled Task) abuse via scripts
Reference: https://attack.mitre.org/techniques/T1053/005/
Created: 2026-05-12
*/

// ============================================================
// 1. PowerShell 计划任务创建脚本
// ============================================================

rule Scheduled_Task_Powershell_Create
{
    meta:
        description = "检测通过 PowerShell 创建计划任务的脚本"
        author = "CodeShrimp"
        date = "2026-05-12"
        mitre_att&ck = "T1053.005"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1053/005/"

    strings:
        // PowerShell 计划任务 Cmdlet
        $cmdlet1 = "Register-ScheduledTask" ascii wide nocase
        $cmdlet2 = "New-ScheduledTask" ascii wide nocase
        $cmdlet3 = "Set-ScheduledTask" ascii wide nocase
        $cmdlet4 = "Unregister-ScheduledTask" ascii wide nocase

        // schtasks 命令行
        $schtasks1 = "schtasks.exe" ascii wide nocase
        $schtasks2 = "schtasks /create" ascii wide nocase
        $schtasks3 = "schtasks /change" ascii wide nocase

        // 可疑 Action 内容
        $action1 = "-enc " ascii wide nocase
        $action2 = "-EncodedCommand" ascii wide nocase
        $action3 = "Invoke-Expression" ascii wide nocase
        $action4 = "IEX(" ascii wide nocase
        $action5 = "DownloadString" ascii wide nocase
        $action6 = "DownloadFile" ascii wide nocase
        $action7 = "Net.WebClient" ascii wide nocase
        $action8 = "Start-Process" ascii wide nocase

        // 高权限标记
        $priv1 = "RunLevel" ascii wide nocase
        $priv2 = "Highest" ascii wide nocase
        $priv3 = "SYSTEM" ascii wide nocase
        $priv4 = "NT AUTHORITY" ascii wide nocase

    condition:
        (any of ($cmdlet*) or any of ($schtasks*)) and
        (2 of ($action*) or any of ($priv*))
}

// ============================================================
// 2. VBScript/JScript 计划任务创建
// ============================================================

rule Scheduled_Task_Script_Create
{
    meta:
        description = "检测通过 VBScript/JScript 创建计划任务的脚本"
        author = "CodeShrimp"
        date = "2026-05-12"
        mitre_att&ck = "T1053.005"
        severity = "high"

    strings:
        // WMI 计划任务接口
        $wmi1 = "Win32_ScheduledJob" ascii wide nocase
        $wmi2 = "MSFT_ScheduledTask" ascii wide nocase
        $wmi3 = "Schedule.Service" ascii wide nocase

        // COM 对象创建
        $com1 = "CreateObject(\"Schedule.Service\")" ascii wide nocase
        $com2 = "CreateObject(\"WScript.Shell\")" ascii wide nocase

        // 计划任务相关方法
        $method1 = ".RegisterTaskDefinition" ascii wide nocase
        $method2 = ".RegisterTask" ascii wide nocase
        $method3 = ".Connect" ascii wide nocase
        $method4 = "TaskFolder" ascii wide nocase

        // 可疑执行内容
        $exec1 = "cmd.exe /c" ascii wide nocase
        $exec2 = "powershell" ascii wide nocase
        $exec3 = "wscript" ascii wide nocase
        $exec4 = "cscript" ascii wide nocase

    condition:
        (any of ($wmi*) or any of ($com*)) and
        any of ($method*) and
        any of ($exec*)
}

// ============================================================
// 3. 二进制文件中的计划任务 API 调用
// ============================================================

rule Scheduled_Task_API_Usage
{
    meta:
        description = "检测 PE 文件中调用计划任务相关 Windows API"
        author = "CodeShrimp"
        date = "2026-05-12"
        mitre_att&ck = "T1053.005"
        severity = "medium"

    strings:
        // Task Scheduler API
        $api1 = "NetScheduleJobAdd" ascii wide
        $api2 = "NetScheduleJobDel" ascii wide
        $api3 = "NetScheduleJobEnum" ascii wide
        $api4 = "NetScheduleJobGetInfo" ascii wide
        $api5 = "ITaskService" ascii wide
        $api6 = "ITaskFolder" ascii wide
        $api7 = "ITaskDefinition" ascii wide
        $api8 = "IPersistFile" ascii wide

        // DLL 加载
        $dll1 = "mstask.dll" ascii wide
        $dll2 = "taskschd.dll" ascii wide
        $dll3 = "schtasks.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            3 of ($api*) or
            any of ($dll*)
        )
}

// ============================================================
// 4. 计划任务后门配置文件
// ============================================================

rule Scheduled_Task_Backdoor_Config
{
    meta:
        description = "检测包含可疑计划任务后门配置的文件"
        author = "CodeShrimp"
        date = "2026-05-12"
        mitre_att&ck = "T1053.005"
        severity = "critical"

    strings:
        // XML 任务定义特征
        $xml1 = "<?xml version" ascii wide
        $xml2 = "<Task" ascii wide
        $xml3 = "<Actions>" ascii wide
        $xml4 = "<Exec>" ascii wide
        $xml5 = "<Command>" ascii wide

        // 可疑命令内容
        $cmd1 = "cmd.exe /c echo" ascii wide nocase
        $cmd2 = "powershell -w hidden" ascii wide nocase
        $cmd3 = "powershell -nop -w hidden" ascii wide nocase
        $cmd4 = "powershell -ep bypass" ascii wide nocase
        $cmd5 = "mshta vbscript" ascii wide nocase
        $cmd6 = "regsvr32 /s /n /u" ascii wide nocase
        $cmd7 = "rundll32 javascript" ascii wide nocase
        $cmd8 = "certutil -decode" ascii wide nocase

        // 高权限配置
        $priv1 = "RunLevel>Highest" ascii wide
        $priv2 = "LogonType" ascii wide
        $priv3 = "NT AUTHORITY\\SYSTEM" ascii wide

    condition:
        ($xml1 at 0 or $xml1 near 0) and
        3 of ($xml*) and
        (2 of ($cmd*) or any of ($priv*))
}

// ============================================================
// 5. 计划任务持久化利用框架
// ============================================================

rule Scheduled_Task_Exploit_Framework
{
    meta:
        description = "检测利用计划任务进行持久化的攻击框架"
        author = "CodeShrimp"
        date = "2026-05-12"
        mitre_att&ck = "T1053.005"
        severity = "critical"

    strings:
        // 常见攻击工具特征
        $tool1 = "Invoke-ScheduledTaskBackdoor" ascii wide nocase
        $tool2 = "Install-ScheduledTask" ascii wide nocase
        $tool3 = "Enable-ScheduledTask" ascii wide nocase

        // SharpStay / SitScape 等工具
        $sharp1 = "ScheduledTask" ascii wide
        $sharp2 = "Persistence" ascii wide
        $sharp3 = "TaskScheduler" ascii wide

        // Metasploit / Cobalt Strike 特征
        $msf1 = "exploit/windows" ascii wide
        $msf2 = "post/windows" ascii wide
        $cs1 = "beacon" ascii wide
        $cs2 = "payload" ascii wide

        // 可疑字符串组合
        $sus1 = "schtasks" ascii wide nocase
        $sus2 = "/create" ascii wide nocase
        $sus3 = "/sc" ascii wide nocase
        $sus4 = "/tn" ascii wide nocase

    condition:
        (any of ($tool*) or
         (2 of ($sharp*) and any of ($msf*, $cs*))) or
        (all of ($sus*))
}
