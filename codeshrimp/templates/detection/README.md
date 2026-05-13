# 检测规则模板

Sigma / YARA / Suricata 检测规则模板库，覆盖 MITRE ATT&CK 常见技术。

| 文件 | 类型 | 说明 |
|------|------|------|
| `attck_t1053_scheduled_tasks.yaml` | Sigma/YAML | Scheduled Task Abuse Detection Suite |
| `attck_t1059_002_command_shell.yaml` | Sigma/YAML | Windows Command Shell Abuse Detection Suite |
| `attck_t1059_007_javascript_abuse.yaml` | Sigma/YAML | JavaScript/Scripting Abuse Detection Suite |
| `attck_t1070_indicator_removal.yaml` | Sigma/YAML | Indicator Removal on Host - T1070 Detection Suite |
| `attck_t1078_valid_accounts.yaml` | Sigma/YAML | Anomalous Logon from Unusual Source IP |
| `attck_t1546_event_triggered_execution.yaml` | Sigma/YAML | Event Triggered Execution - Accessibility Features Hijack |
| `attck_t1552_unsecured_credentials.yaml` | Sigma/YAML | Unsecured Credentials Detection Suite |
| `attck_t1558_kerberos_attacks.yaml` | Sigma/YAML | Kerberos Attack Detection Suite |
| `elastic_query_builder.py` | Python | Purpose: Elasticsearch 检测查询构建器 |
| `sigma_lolbas_proxy_execution.yaml` | Sigma/YAML | LOLBAS 代理执行 — 可疑下载/执行链 |
| `sigma_lotl_attack_detection.yaml` | Sigma/YAML | Living off the Land (LOTL) Attack Detection Suite |
| `sigma_lsass_dump_detection.yaml` | Sigma/YAML | LSASS Memory Dumping via Direct Access |
| `sigma_powershell_abuse.yaml` | Sigma/YAML | Suspicious PowerShell Encoded Command Execution |
| `sigma_template.yaml` | Sigma/YAML | 检测规则标题（简明描述检测的行为） |
| `suricata_c2_tunnel_detection.rules` | Suricata | Purpose: Suricata C2 隧道与加密流量检测规则集 |
| `suricata_scheduled_task_abuse.rules` | Suricata | Purpose: Suricata IDS 规则 — T1053.005 Scheduled Task 网络检测 |
| `suricata_template.rules` | Suricata | Purpose: Suricata IDS 规则模板 — 网络层安全检测 |
| `yara_c2_beacon.yar` | YARA | yara_c2_beacon |
| `yara_scheduled_task_abuse.yar` | YARA | yara_scheduled_task_abuse |
| `yara_template.yar` | YARA | yara_template |

_自动生成于 2026-05-13_
