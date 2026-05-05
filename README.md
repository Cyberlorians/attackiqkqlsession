# AttackIQ Defender XDR KQL CTF Scenarios

## Scenario 01 - Credentials In Registry Script

### What Happened

AttackIQ ran a PowerShell script that simulates looking for credentials stored in the Windows registry.

### Your Challenge

Find the script name, the account that ran it, and the exact command line.

### KQL Skill

Use `DeviceProcessEvents` to search process command lines on one workstation.

### How To Think About It

This is a process question. The script ran through PowerShell, so the useful evidence is in `ProcessCommandLine`. Start with the target device, search for the scenario keyword, then show the columns that prove what ran.

### Run This Query

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has "credentials_in_registry"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

### Answer

- Script: `credentials_in_registry.ps1`
- Process: `powershell.exe`
- Account: `xadmin`
- Parent: `python.exe` running `attack_graph.py`

### Why It Works

- `DeviceProcessEvents` shows executed processes.
- `DeviceName == TargetDevice` keeps the hunt on the AttackIQ workstation.
- `ProcessCommandLine has "credentials_in_registry"` finds the scenario without needing the full filename first.
- `InitiatingProcessFileName` and `InitiatingProcessCommandLine` show AttackIQ's parent process.

## Scenario 02 - Dump SAM Registry Hive

Find the command that tried to save the local SAM registry hive.

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has_all ("reg save", "hklm\\sam")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

Answer:

- Command: `reg save hklm\sam C:\Users\xadmin\AppData\Local\Temp\sam`
- Output path: `C:\Users\xadmin\AppData\Local\Temp\sam`

## Scenario 03 - Browser WebCache Collection

Find the PowerShell and `esentutl.exe` activity used to collect browser WebCache data.

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName in~ ("powershell.exe", "esentutl.exe")
| where ProcessCommandLine has_any ("collect_database_webcache", "WebCache", "esentutl")
   or InitiatingProcessCommandLine has "collect_database_webcache"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

Answer:

- Script: `collect_database_webcache.ps1`
- Child process: `esentutl.exe`
- Parent process: `powershell.exe`
- Target path includes `C:\Users\xadmin\AppData\Local\Microsoft\Windows\WebCache`

## Scenario 04 - Kerberoasting With Rubeus

Find the staged Rubeus file.

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "rubeus"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

Answer:

- File: `Rubeus.exe`
- SHA256: `1e1fe8a1730bf8caabd867fd2f990b0e52aee0f9f8635578ff8b18c0950b616c`

## Scenario 05 - Invoke-Kerberoast PowerShell Files

Find the PowerShell Kerberoast files staged on disk.

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "kerberoast"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

Answer:

- `call-invoke-kerberoast.ps1`
- `invoke-kerberoast.ps1`

## Scenario 06 - LSASS Minidump

Find the LSASS dump file.

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName endswith ".dmp" or FolderPath has "pid_"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

Answer:

- Dump file: `pid_976_2ztj_d6a.dmp`
- Path clue: folder path contains `pid_`

## Scenario 07 - PwDump7

Find Defender's PwDump verdict.

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where Title has "PWDump" or FileName has "pwdump"
| project Timestamp, DeviceName, Title, Severity, EntityType, FileName, SHA256
| order by Timestamp asc
```

Answer:

- Artifact: `pwdump7.zip`
- Defender verdict: `'PWDump' hacktool was prevented`

## Scenario 08 - gsecdump

Find Defender's gsecdump-related verdict.

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where Title has "Vigorf" or FileName has "gsecdump"
| project Timestamp, DeviceName, Title, Severity, EntityType, FileName, SHA256
| order by Timestamp asc
```

Answer:

- Staged file: `gsecdump-0.7-win32.zip`
- Defender verdict: `'Vigorf' malware was prevented`

## Scenario 09 - LaZagne Cleanup

Find LaZagne file creation and cleanup.

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

Answer:

- Artifact: `laZagne_windows_x64.exe`
- Evidence: `ActionType` shows it was created and later deleted.

## Scenario 10 - Obfuscated Mimikatz Script

Find the Mimikatz-style PowerShell script artifact.

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "mimikatz"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

Answer:

- Script artifact: `mimikatz_dump_passwords_v2.ps1`

## Scenario 11 - Original Mimikatz Package

Find the original Mimikatz package in alert evidence.

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "mimikatz" or Title has "Mimikatz credential theft tool"
| project Timestamp, DeviceName, Title, Severity, EntityType, FileName, SHA256
| order by Timestamp asc
```

Answer:

- Artifact: `mimikatz-x64.zip`
- Defender verdict: `Mimikatz credential theft tool`
- SHA256: `29a3e90d067a848bac1d7301e22d6ac7b6979c89be10373b98a47845e94c45b8`
