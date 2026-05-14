# T1059.001 — PowerShell Encoded Command Detection Suite

**MITRE ATT&CK:** T1059.001 (Command and Scripting Interpreter: PowerShell)  
**Created:** 2026-05-14  
**Author:** CodeShrimp Detection Engineering  
**Status:** Stable  

## Attack Scenario

Adversaries abuse PowerShell's `-EncodedCommand` / `-enc` flag to pass Base64-encoded
恶意 commands. This bypasses basic command-line logging and evade string-based detection.
Common in post-exploitation, credential harvesting, and payload download cradles.

### Real-World Examples
- **Sandworm Team** (2016 Ukraine Power Attack) — PowerShell credential harvesting in memory
- **Akira Ransomware** — PowerShell volume shadow copy deletion
- **APT19 / APT-C-36** — Fileless PowerShell download cradles

## Rules Included

| File | Type | Scope |
|------|------|-------|
| `T1059_001_sigma.yml` | Sigma | Windows process creation logs (Sysmon / Security) |
| `T1059_001_yara.yar` | YARA | Memory / disk artifact scanning |
| `T1059_001_suricata.rules` | Suricata | Network traffic (HTTP, DNS) |

## Deployment Notes

### Sigma
- Requires Sysmon (Event ID 1) or Windows Security Event 4688 with command-line logging
- Convert to target SIEM format with `sigma-cli` or Uncoder.IO
- Tune `falsepositives` section for your environment

### YARA
- Scan running processes or dropped script files
- Rule 1 targets PE files with embedded encoded PowerShell
- Rule 2 targets `.ps1` / `.bat` script files

### Suricata
- Requires HTTP and DNS logging enabled
- `$HOME_NET` / `$EXTERNAL_NET` must be defined in `suricata.yaml`
- Tune `dsize` thresholds based on baseline traffic
