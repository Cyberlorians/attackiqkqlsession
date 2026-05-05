# AttackIQ Defender XDR KQL CTF Scenarios

<details>
<summary><strong>Scenario 01 - Credentials In Registry Script</strong></summary>

### What Happened

AttackIQ ran a PowerShell script that simulates looking for credentials stored in the Windows registry.

### Your Challenge

Find the timestamp, device, account, process name, exact command line, parent process name, and parent command line for the credentials-in-registry script.

### KQL Skill & How To Hunt

Use `DeviceProcessEvents` when the question is about a command that ran. Start by scoping to the AttackIQ workstation.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

Then search the command line for the scenario keyword: `credentials_in_registry`.

<blockquote>

<details>
<summary>Hint</summary>

Filter on `ProcessCommandLine`. The useful clue is `credentials_in_registry`.

</details>

<details>
<summary>Answer</summary>

Final KQL:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has "credentials_in_registry"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

Result:

- Script: `credentials_in_registry.ps1`
- Process: `powershell.exe`
- Account: `xadmin`
- Parent: `python.exe` running `attack_graph.py`

Why it works:

- `ProcessCommandLine` shows the full PowerShell command.
- `credentials_in_registry` is the unique scenario clue.
- `InitiatingProcessFileName` and `InitiatingProcessCommandLine` show the AttackIQ parent process.

</details>

</blockquote>

</details>

<details>
<summary><strong>Scenario 02 - Dump SAM Registry Hive</strong></summary>

### What Happened

The attacker tried to save the local SAM registry hive.

### Your Challenge

Find where the command tried to save the SAM hive.

### KQL Skill & How To Hunt

Use `DeviceProcessEvents` for command-line evidence. Use `has_all` when both clues must appear in the same command.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

### Run This Query

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where ProcessCommandLine has_all ("reg save", "hklm\\sam")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

### Answer

- Command: `reg save hklm\sam C:\Users\xadmin\AppData\Local\Temp\sam`
- Output path: `C:\Users\xadmin\AppData\Local\Temp\sam`

</details>

<details>
<summary><strong>Scenario 03 - Browser WebCache Collection</strong></summary>

### What Happened

PowerShell launched `esentutl.exe` to collect browser WebCache data.

### Your Challenge

Find the PowerShell script, the child process, and the browser cache path.

### KQL Skill & How To Hunt

Use process rows and parent-process columns. `FileName` is the process that ran. `InitiatingProcessFileName` is the process that launched it.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

### Run This Query

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

### Answer

- Script: `collect_database_webcache.ps1`
- Child process: `esentutl.exe`
- Parent process: `powershell.exe`
- Target path includes `C:\Users\xadmin\AppData\Local\Microsoft\Windows\WebCache`

</details>

<details>
<summary><strong>Scenario 04 - Kerberoasting With Rubeus</strong></summary>

### What Happened

The attacker staged Rubeus for Kerberoasting.

### Your Challenge

Find the staged Rubeus file and its hash.

### KQL Skill & How To Hunt

Use `DeviceFileEvents` when the evidence is a file created or staged on disk.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

### Run This Query

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "rubeus"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

### Answer

- File: `Rubeus.exe`
- SHA256: `1e1fe8a1730bf8caabd867fd2f990b0e52aee0f9f8635578ff8b18c0950b616c`

</details>

<details>
<summary><strong>Scenario 05 - Invoke-Kerberoast PowerShell Files</strong></summary>

### What Happened

The attacker staged PowerShell Kerberoasting files.

### Your Challenge

Find the Kerberoast PowerShell files staged on disk.

### KQL Skill & How To Hunt

Use `DeviceFileEvents` and search for a broad filename clue first.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

### Run This Query

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "kerberoast"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

### Answer

- `call-invoke-kerberoast.ps1`
- `invoke-kerberoast.ps1`

</details>

<details>
<summary><strong>Scenario 06 - LSASS Minidump</strong></summary>

### What Happened

The attacker tried to dump LSASS memory.

### Your Challenge

Find the dump file and where it landed.

### KQL Skill & How To Hunt

Use `DeviceFileEvents` and hunt file patterns. Dump files often end with `.dmp`.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

### Run This Query

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName endswith ".dmp" or FolderPath has "pid_"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

### Answer

- Dump file: `pid_976_2ztj_d6a.dmp`
- Path clue: folder path contains `pid_`

</details>

<details>
<summary><strong>Scenario 07 - PwDump7</strong></summary>

### What Happened

The attacker staged PwDump7, and Defender prevented the hacktool.

### Your Challenge

Find Defender's PwDump verdict.

### KQL Skill & How To Hunt

Use `AlertEvidence` when the question asks what Defender called or did with the activity.

Starter:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

### Run This Query

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where Title has "PWDump" or FileName has "pwdump"
| project Timestamp, DeviceName, Title, Severity, EntityType, FileName, SHA256
| order by Timestamp asc
```

### Answer

- Artifact: `pwdump7.zip`
- Defender verdict: `'PWDump' hacktool was prevented`

</details>

<details>
<summary><strong>Scenario 08 - gsecdump</strong></summary>

### What Happened

The attacker staged `gsecdump`, but Defender used a different detection name.

### Your Challenge

Find Defender's verdict and the staged file.

### KQL Skill & How To Hunt

Use `AlertEvidence` and search both the tool name and Defender's detection name.

Starter:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

### Run This Query

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where Title has "Vigorf" or FileName has "gsecdump"
| project Timestamp, DeviceName, Title, Severity, EntityType, FileName, SHA256
| order by Timestamp asc
```

### Answer

- Staged file: `gsecdump-0.7-win32.zip`
- Defender verdict: `'Vigorf' malware was prevented`

</details>

<details>
<summary><strong>Scenario 09 - LaZagne Cleanup</strong></summary>

### What Happened

The attacker staged LaZagne, then cleanup removed it.

### Your Challenge

Find evidence that LaZagne was created and later deleted.

### KQL Skill & How To Hunt

Use `DeviceFileEvents` and keep `ActionType`; it tells you whether the file was created, deleted, or changed.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

### Run This Query

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "lazagne"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

### Answer

- Artifact: `laZagne_windows_x64.exe`
- Evidence: `ActionType` shows it was created and later deleted.

</details>

<details>
<summary><strong>Scenario 10 - Obfuscated Mimikatz Script</strong></summary>

### What Happened

The attacker used a Mimikatz-style PowerShell script instead of a simple `mimikatz.exe` process.

### Your Challenge

Find the script artifact.

### KQL Skill & How To Hunt

Use `DeviceFileEvents` when the tool appears as a script or staged file instead of a process name.

Starter:

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

### Run This Query

```kusto
let TargetDevice = "usm262346";
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "mimikatz"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```

### Answer

- Script artifact: `mimikatz_dump_passwords_v2.ps1`

</details>

<details>
<summary><strong>Scenario 11 - Original Mimikatz Package</strong></summary>

### What Happened

The attacker staged the classic Mimikatz package.

### Your Challenge

Find the Mimikatz artifact, Defender verdict, and hash.

### KQL Skill & How To Hunt

Use `AlertEvidence` when the answer needs Defender's verdict and hash.

Starter:

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
```

### Run This Query

```kusto
let TargetDevice = "usm262346";
AlertEvidence
| where Timestamp > ago(14d)
| where DeviceName == TargetDevice
| where FileName has "mimikatz" or Title has "Mimikatz credential theft tool"
| project Timestamp, DeviceName, Title, Severity, EntityType, FileName, SHA256
| order by Timestamp asc
```

### Answer

- Artifact: `mimikatz-x64.zip`
- Defender verdict: `Mimikatz credential theft tool`
- SHA256: `29a3e90d067a848bac1d7301e22d6ac7b6979c89be10373b98a47845e94c45b8`

</details>
