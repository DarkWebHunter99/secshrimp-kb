# Purpose: Windows 内网横向移动检测脚本
#          检测常见横向移动技术的痕迹：PsExec、WMI、WinRM、RDP、Pass-the-Hash 等
# Auth: 仅限授权使用 — 仅在已授权的系统上运行检测
# Dependencies: Windows PowerShell 5.1+, 管理员权限
# Usage:
#   .\lateral_movement.ps1 -CheckAll
#   .\lateral_movement.ps1 -CheckLogonEvents -Hours 24
#   .\lateral_movement.ps1 -CheckNetworkConnections -Output report.json

[CmdletBinding()]
param(
    [switch]$CheckAll = $false,
    [switch]$CheckLogonEvents = $false,
    [switch]$CheckNetworkConnections = $false,
    [switch]$CheckScheduledTasks = $false,
    [switch]$CheckServices = $false,
    [switch]$CheckWMIActivity = $false,
    [switch]$CheckRemoteRegistry = $false,
    [switch]$CheckPsExec = $false,
    [switch]$CheckPassTheHash = $false,
    [int]$Hours = 24,
    [string]$Output = "",
    [string]$OutputFormat = "text"  # text | json
)

# ============================================================
# 全局变量
# ============================================================

$Script:Results = @()
$Script:StartTime = (Get-Date).AddHours(-$Hours)
$Script:RiskLevels = @{
    "Critical" = "🔴"
    "High"     = "🟠"
    "Medium"   = "🟡"
    "Low"      = "🔵"
    "Info"     = "⚪"
}

function Add-Result {
    param(
        [string]$Category,
        [string]$RiskLevel,
        [string]$Title,
        [string]$Description,
        [string]$Evidence = "",
        [string]$Mitigation = ""
    )

    $Script:Results += [PSCustomObject]@{
        Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category    = $Category
        RiskLevel   = $RiskLevel
        Emoji       = $Script:RiskLevels[$RiskLevel]
        Title       = $Title
        Description = $Description
        Evidence    = $Evidence
        Mitigation  = $Mitigation
    }
}

# ============================================================
# 模块 1: 登录事件分析
# ============================================================

function Test-LogonEvents {
    Write-Host "`n[*] 分析登录事件 (最近 $Hours 小时)..." -ForegroundColor Cyan

    try {
        # Event ID 4624: 成功登录
        # Logon Types: 2(Interactive), 3(Network), 4(Batch), 5(Service),
        #              7(Unlock), 8(NetworkCleartext), 9(NewCredentials),
        #              10(RemoteInteractive), 11(CachedInteractive)

        $logonEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4624
            StartTime = $Script:StartTime
        } -ErrorAction SilentlyContinue | Select-Object -First 500

        if (-not $logonEvents) {
            Write-Host "  [-] 未找到登录事件" -ForegroundColor Gray
            return
        }

        # 按登录类型统计
        $logonTypes = @{
            2  = "Interactive"
            3  = "Network"
            4  = "Batch"
            5  = "Service"
            7  = "Unlock"
            8  = "NetworkCleartext"
            9  = "NewCredentials"
            10 = "RemoteInteractive(RDP)"
            11 = "CachedInteractive"
        }

        $networkLogons = @()
        $rdpLogons = @()
        $suspiciousAccounts = @()

        foreach ($event in $logonEvents) {
            $xml = [xml]$event.ToXml()
            $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
            $ns.AddNamespace("ev", "http://schemas.microsoft.com/win/2004/08/events/event")

            $logonType = $xml.SelectSingleNode("//ev:Data[@Name='LogonType']", $ns).InnerText
            $targetUser = $xml.SelectSingleNode("//ev:Data[@Name='TargetUserName']", $ns).InnerText
            $sourceIP = $xml.SelectSingleNode("//ev:Data[@Name='IpAddress']", $ns).InnerText
            $sourceComputer = $xml.SelectSingleNode("//ev:Data[@Name='WorkstationName']", $ns).InnerText

            $lt = [int]$logonType

            # 检测网络登录（可能用于横向移动）
            if ($lt -eq 3 -and $sourceIP -ne "-" -and $sourceIP -ne "::1" -and $sourceIP -ne "127.0.0.1") {
                $networkLogons += @{
                    Time     = $event.TimeCreated
                    User     = $targetUser
                    SourceIP = $sourceIP
                    Computer = $sourceComputer
                }
            }

            # 检测 RDP 登录
            if ($lt -eq 10) {
                $rdpLogons += @{
                    Time     = $event.TimeCreated
                    User     = $targetUser
                    SourceIP = $sourceIP
                }
            }

            # 检测可疑账户（admin/backup/service 且来自非本地）
            if ($targetUser -match "^(admin|administrator|backup|svc|service|test|guest)" -and $sourceIP -ne "-" ) {
                $suspiciousAccounts += @{
                    Time = $event.TimeCreated
                    User = $targetUser
                    SourceIP = $sourceIP
                    LogonType = $logonTypes[$lt]
                }
            }
        }

        # 报告结果
        if ($networkLogons.Count -gt 50) {
            Add-Result -Category "Logon" -RiskLevel "Medium" `
                -Title "大量网络登录事件" `
                -Description "检测到 $($networkLogons.Count) 次网络登录，可能存在自动化横向移动" `
                -Evidence "最近登录来源: $(($networkLogons | Select-Object -First 5 | ForEach-Object { $_.SourceIP }) -join ', ')" `
                -Mitigation "检查登录来源 IP 是否合法，关注非工作时间的登录"
        }

        foreach ($rdp in $rdpLogons) {
            if ($rdp.SourceIP -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)") {
                Add-Result -Category "Logon" -RiskLevel "High" `
                    -Title "外部 RDP 登录" `
                    -Description "检测到来自外部 IP 的 RDP 登录" `
                    -Evidence "用户: $($rdp.User), 来源: $($rdp.SourceIP), 时间: $($rdp.Time)" `
                    -Mitigation "确认此 RDP 登录是否授权，建议限制 RDP 仅内网访问"
            }
        }

        foreach ($susp in $suspiciousAccounts | Select-Object -First 10) {
            Add-Result -Category "Logon" -RiskLevel "Medium" `
                -Title "特权账户远程登录" `
                -Description "特权账户从远程登录" `
                -Evidence "账户: $($susp.User), 来源: $($susp.SourceIP), 类型: $($susp.LogonType)" `
                -Mitigation "确认特权账户的远程登录是否合规"
        }

        Write-Host "  [+] 网络登录: $($networkLogons.Count), RDP: $($rdpLogons.Count), 可疑账户: $($suspiciousAccounts.Count)" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] 登录事件分析失败: $_" -ForegroundColor Red
    }
}

# ============================================================
# 模块 2: 网络连接分析
# ============================================================

function Test-NetworkConnections {
    Write-Host "`n[*] 分析网络连接..." -ForegroundColor Cyan

    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

        # 横向移动常用端口
        $lateralPorts = @{
            135    = "RPC/DCOM"
            139    = "NetBIOS-SSN"
            445    = "SMB"
            3389   = "RDP"
            5985   = "WinRM-HTTP"
            5986   = "WinRM-HTTPS"
            22     = "SSH"
            23     = "Telnet"
            5800   = "VNC-HTTP"
            5900   = "VNC"
            6667   = "IRC"
            4444   = "常见反向Shell"
            5555   = "常见反向Shell"
            6379   = "Redis"
            27017  = "MongoDB"
        }

        $suspiciousConns = @()
        $connCount = @{}

        foreach ($conn in $connections) {
            $port = $conn.RemotePort
            $remoteIP = $conn.RemoteAddress
            $procId = $conn.OwningProcess
            $procName = try { (Get-Process -Id $procId -ErrorAction SilentlyContinue).ProcessName } catch { "Unknown" }

            # 检测横向移动端口
            if ($lateralPorts.ContainsKey($port)) {
                $suspiciousConns += @{
                    LocalPort   = $conn.LocalPort
                    RemoteIP    = $remoteIP
                    RemotePort  = $port
                    Service     = $lateralPorts[$port]
                    ProcessName = $procName
                    ProcessId   = $procId
                }
            }

            # 统计连接数（检测端口扫描）
            $key = "$remoteIP"
            if (-not $connCount.ContainsKey($key)) {
                $connCount[$key] = 0
            }
            $connCount[$key]++
        }

        # 报告可疑连接
        foreach ($conn in $suspiciousConns) {
            if ($conn.RemotePort -in @(4444, 5555)) {
                Add-Result -Category "Network" -RiskLevel "Critical" `
                    -Title "可疑反向Shell连接" `
                    -Description "检测到常见反向Shell端口的连接" `
                    -Evidence "进程: $($conn.ProcessName) (PID: $($conn.ProcessId)), 目标: $($conn.RemoteIP):$($conn.RemotePort) ($($conn.Service))" `
                    -Mitigation "立即调查此连接，检查进程是否合法"
            }
            elseif ($conn.RemotePort -in @(135, 445, 139)) {
                Add-Result -Category "Network" -RiskLevel "Low" `
                    -Title "SMB/RPC 连接" `
                    -Description "检测到 SMB 或 RPC 连接（可能是正常的管理活动）" `
                    -Evidence "进程: $($conn.ProcessName), 目标: $($conn.RemoteIP):$($conn.RemotePort) ($($conn.Service))" `
                    -Mitigation "确认 SMB/RPC 连接的目标是否合法"
            }
            elseif ($conn.RemotePort -in @(5985, 5986)) {
                Add-Result -Category "Network" -RiskLevel "Medium" `
                    -Title "WinRM 连接" `
                    -Description "检测到 WinRM 远程管理连接" `
                    -Evidence "进程: $($conn.ProcessName), 目标: $($conn.RemoteIP):$($conn.RemotePort)" `
                    -Mitigation "确认 WinRM 连接是否授权"
            }
        }

        # 检测端口扫描（单 IP 大量连接）
        foreach ($entry in $connCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5) {
            if ($entry.Value -gt 20) {
                Add-Result -Category "Network" -RiskLevel "High" `
                    -Title "疑似端口扫描" `
                    -Description "单一目标 IP 存在大量连接" `
                    -Evidence "目标: $($entry.Key), 连接数: $($entry.Value)" `
                    -Mitigation "检查是否存在内部端口扫描活动"
            }
        }

        Write-Host "  [+] 可疑连接: $($suspiciousConns.Count)" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] 网络连接分析失败: $_" -ForegroundColor Red
    }
}

# ============================================================
# 模块 3: 计划任务检测
# ============================================================

function Test-ScheduledTasks {
    Write-Host "`n[*] 检查计划任务..." -ForegroundColor Cyan

    try {
        $tasks = Get-ScheduledTask | Where-Object {
            $_.State -ne 'Disabled' -and
            $_.TaskPath -notlike '\Microsoft\*'
        }

        $suspiciousPatterns = @(
            @{ Pattern = "(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32)"; Desc = "可疑执行程序" }
            @{ Pattern = "(?i)(-enc|-encodedcommand|bypass|noprofile|hidden|windowstyle hidden)"; Desc = "可疑 PowerShell 参数" }
            @{ Pattern = "(?i)(downloadstring|downloadfile|invoke-expression|iex|start-bitstransfer)"; Desc = "可疑下载/执行操作" }
            @{ Pattern = "(?i)(net (user|localgroup|share)|sc \\.|schtasks|at\s)"; Desc = "可疑系统管理命令" }
        )

        foreach ($task in $tasks) {
            try {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                $actions = $task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
                $actionStr = $actions -join " | "

                foreach ($pattern in $suspiciousPatterns) {
                    if ($actionStr -match $pattern.Pattern) {
                        Add-Result -Category "ScheduledTask" -RiskLevel "High" `
                            -Title "可疑计划任务: $($task.TaskName)" `
                            -Description "计划任务包含 $($pattern.Desc)" `
                            -Evidence "路径: $($task.TaskPath)$($task.TaskName), 执行: $actionStr" `
                            -Mitigation "检查此任务是否授权创建"
                        break
                    }
                }
            }
            catch { }
        }

        Write-Host "  [+] 已检查 $($tasks.Count) 个计划任务" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] 计划任务检查失败: $_" -ForegroundColor Red
    }
}

# ============================================================
# 模块 4: 服务检测（PsExec 遗留服务）
# ============================================================

function Test-Services {
    Write-Host "`n[*] 检查可疑服务..." -ForegroundColor Cyan

    try {
        $services = Get-WmiObject Win32_Service | Where-Object { $_.State -eq 'Running' }

        # PsExec 遗留服务特征
        $psexecPattern = "^(PSEXESVC|psexec)$"
        # 可疑服务名模式
        $suspiciousPatterns = @(
            "(?i)^PSEXESVC$",
            "(?i)^remcom",
            "(?i)^nc(NCAT|netcat)",
            "(?i)^msfree",
            "(?i)^[a-f0-9]{8}$",  # 随机十六进制名称
            "(?i)^update[0-9]{1,4}$",
            "(?i)^svc[0-9]{1,4}$"
        )

        foreach ($svc in $services) {
            foreach ($pattern in $suspiciousPatterns) {
                if ($svc.Name -match $pattern -or $svc.DisplayName -match $pattern) {
                    Add-Result -Category "Service" -RiskLevel "High" `
                        -Title "可疑服务: $($svc.Name)" `
                        -Description "检测到可疑服务名称模式" `
                        -Evidence "服务: $($svc.Name), 显示名: $($svc.DisplayName), 路径: $($svc.PathName), 状态: $($svc.State)" `
                        -Mitigation "调查此服务的来源和用途"
                    break
                }
            }

            # 检查从非标准路径运行的服务
            if ($svc.PathName -match "^[^C].*:.*" -or $svc.PathName -match "^\\\\") {
                Add-Result -Category "Service" -RiskLevel "Medium" `
                    -Title "非标准路径服务: $($svc.Name)" `
                    -Description "服务从非标准路径或远程路径运行" `
                    -Evidence "路径: $($svc.PathName)" `
                    -Mitigation "验证此服务的合法性"
            }
        }

        Write-Host "  [+] 已检查 $($services.Count) 个服务" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] 服务检查失败: $_" -ForegroundColor Red
    }
}

# ============================================================
# 模块 5: WMI 活动检测
# ============================================================

function Test-WMIActivity {
    Write-Host "`n[*] 检查 WMI 活动..." -ForegroundColor Cyan

    try {
        # 检查 WMI 事件订阅（常用于持久化）
        $subscriptions = Get-WMIObject -Class __FilterToConsumerBinding -Namespace root\subscription -ErrorAction SilentlyContinue

        if ($subscriptions) {
            foreach ($sub in $subscriptions) {
                Add-Result -Category "WMI" -RiskLevel "Critical" `
                    -Title "WMI 事件订阅" `
                    -Description "检测到 WMI 事件订阅（常用于持久化和横向移动）" `
                    -Evidence "Filter: $($sub.Filter), Consumer: $($sub.Consumer)" `
                    -Mitigation "检查此订阅是否授权，WMI 持久化是高级攻击技术"
            }
        }

        # 检查 WMI 远程连接（通过 COM 对象）
        $wmiProcess = Get-Process -Name "wmiprvse" -ErrorAction SilentlyContinue
        if ($wmiProcess) {
            Write-Host "  [+] WMI 服务进程运行中 (PID: $($wmiProcess.Id -join ', '))" -ForegroundColor Green
        }

        # 检查最近的 WMI 命令执行
        $wmiEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-WMI-Activity/Operational'
            Id = 5861
            StartTime = $Script:StartTime
        } -ErrorAction SilentlyContinue | Select-Object -First 20

        if ($wmiEvents) {
            foreach ($evt in $wmiEvents) {
                Add-Result -Category "WMI" -RiskLevel "Medium" `
                    -Title "WMI 提供程序加载" `
                    -Description "检测到 WMI 提供程序加载事件" `
                    -Evidence "时间: $($evt.TimeCreated), 消息: $($evt.Message.Substring(0, [Math]::Min(200, $evt.Message.Length)))" `
                    -Mitigation "确认 WMI 活动是否正常"
            }
        }
    }
    catch {
        Write-Host "  [!] WMI 活动检查失败: $_" -ForegroundColor Red
    }
}

# ============================================================
# 模块 6: PsExec 检测
# ============================================================

function Test-PsExec {
    Write-Host "`n[*] 检查 PsExec 使用痕迹..." -ForegroundColor Cyan

    try {
        # 检查 PsExec 服务
        $psexecSvc = Get-Service -Name "PSEXESVC" -ErrorAction SilentlyContinue
        if ($psexecSvc) {
            Add-Result -Category "PsExec" -RiskLevel "Medium" `
                -Title "PsExec 服务存在" `
                -Description "检测到 PsExec 服务（可能用于横向移动）" `
                -Evidence "服务状态: $($psexecSvc.Status)" `
                -Mitigation "确认 PsExec 使用是否授权"
        }

        # 检查 PsExec 管道
        $psexecPipe = Get-ChildItem "\\.\pipe\" | Where-Object { $_.Name -like "*psexec*" -or $_.Name -like "*remcom*" }
        if ($psexecPipe) {
            Add-Result -Category "PsExec" -RiskLevel "Medium" `
                -Title "PsExec 命名管道" `
                -Description "检测到 PsExec 相关命名管道" `
                -Evidence "管道: $($psexecPipe.Name -join ', ')" `
                -Mitigation "确认是否有管理员正在使用 PsExec"
        }

        # 检查 Admin$ 共享是否可访问（PsExec 依赖）
        $adminShare = Get-WmiObject Win32_Share | Where-Object { $_.Name -eq "ADMIN$" }
        if ($adminShare) {
            Add-Result -Category "PsExec" -RiskLevel "Low" `
                -Title "ADMIN$ 共享已启用" `
                -Description "ADMIN$ 管理共享已启用（PsExec 和其他工具依赖此共享）" `
                -Evidence "共享路径: $($adminShare.Path)" `
                -Mitigation "如不需要远程管理，可禁用 ADMIN$ 共享"
        }

        Write-Host "  [+] PsExec 检查完成" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] PsExec 检查失败: $_" -ForegroundColor Red
    }
}

# ============================================================
# 模块 7: Pass-the-Hash 检测
# ============================================================

function Test-PassTheHash {
    Write-Host "`n[*] 检查 Pass-the-Hash 痕迹..." -ForegroundColor Cyan

    try {
        # 检测 NTLM 登录（Event ID 4624, LogonType 3, Authentication Package = NTLM）
        $ntlmLogons = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4624
            StartTime = $Script:StartTime
        } -ErrorAction SilentlyContinue | Select-Object -First 500 | Where-Object {
            $_.Message -match "Authentication Package:\s*NTLM" -and
            $_.Message -match "Logon Type:\s*3"
        }

        $pthCount = 0
        foreach ($event in $ntlmLogons) {
            # PtH 特征：NTLM 认证 + 网络登录 + 来自非本地 IP
            if ($event.Message -match "Source Network Address:\s*(\S+)" -and
                $Matches[1] -notin @("-", "::1", "127.0.0.1")) {
                $pthCount++
            }
        }

        if ($pthCount -gt 20) {
            Add-Result -Category "PassTheHash" -RiskLevel "High" `
                -Title "大量 NTLM 网络登录" `
                -Description "检测到大量 NTLM 网络登录，可能存在 Pass-the-Hash 攻击" `
                -Evidence "NTLM 网络登录数: $pthCount (最近 $Hours 小时)" `
                -Mitigation "1. 启用 Credential Guard 2. 限制 NTLM 使用 3. 监控异常 NTLM 登录模式"
        }
        elseif ($pthCount -gt 0) {
            Add-Result -Category "PassTheHash" -RiskLevel "Low" `
                -Title "NTLM 网络登录" `
                -Description "检测到 NTLM 网络登录（正常环境中也可能存在）" `
                -Evidence "NTLM 网络登录数: $pthCount" `
                -Mitigation "关注登录模式和来源 IP"
        }

        Write-Host "  [+] NTLM 网络登录: $pthCount" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] Pass-the-Hash 检查失败: $_" -ForegroundColor Red
    }
}

# ============================================================
# 报告输出
# ============================================================

function Out-Report {
    if ($Script:Results.Count -eq 0) {
        Write-Host "`n[-] 未检测到横向移动痕迹" -ForegroundColor Green
        return
    }

    Write-Host "`n$('='*60)" -ForegroundColor White
    Write-Host "  横向移动检测报告" -ForegroundColor White
    Write-Host "$('='*60)" -ForegroundColor White

    # 按风险等级排序
    $riskOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3; "Info" = 4 }
    $sorted = $Script:Results | Sort-Object { $riskOrder[$_.RiskLevel] }

    foreach ($r in $sorted) {
        Write-Host "`n  $($r.Emoji) [$($r.RiskLevel.ToUpper())] $($r.Title)" -ForegroundColor $(if ($r.RiskLevel -in @("Critical","High")) {"Red"} elseif ($r.RiskLevel -eq "Medium") {"Yellow"} else {"Gray"})
        Write-Host "  类别: $($r.Category)" -ForegroundColor Gray
        Write-Host "  描述: $($r.Description)" -ForegroundColor Gray
        if ($r.Evidence) { Write-Host "  证据: $($r.Evidence)" -ForegroundColor Gray }
        if ($r.Mitigation) { Write-Host "  修复: $($r.Mitigation)" -ForegroundColor Cyan }
    }

    Write-Host "`n$('='*60)" -ForegroundColor White
    Write-Host "  总计: $($Script:Results.Count) 个发现" -ForegroundColor White
    Write-Host "$('='*60)" -ForegroundColor White

    # JSON 导出
    if ($Output -ne "") {
        $jsonOutput = $Script:Results | ConvertTo-Json -Depth 5
        $jsonOutput | Out-File -FilePath $Output -Encoding UTF8
        Write-Host "`n[+] 报告已导出: $Output" -ForegroundColor Green
    }
}

# ============================================================
# 主入口
# ============================================================

Write-Host @"
⚠️  Windows 内网横向移动检测脚本
    仅限授权使用 — 仅在已授权的系统上运行
    需要管理员权限
"@ -ForegroundColor Yellow

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] 请以管理员权限运行此脚本" -ForegroundColor Red
    exit 1
}

if ($CheckAll) {
    $CheckLogonEvents = $true
    $CheckNetworkConnections = $true
    $CheckScheduledTasks = $true
    $CheckServices = $true
    $CheckWMIActivity = $true
    $CheckPsExec = $true
    $CheckPassTheHash = $true
}

if ($CheckLogonEvents)        { Test-LogonEvents }
if ($CheckNetworkConnections)  { Test-NetworkConnections }
if ($CheckScheduledTasks)      { Test-ScheduledTasks }
if ($CheckServices)            { Test-Services }
if ($CheckWMIActivity)         { Test-WMIActivity }
if ($CheckPsExec)              { Test-PsExec }
if ($CheckPassTheHash)         { Test-PassTheHash }

Out-Report
